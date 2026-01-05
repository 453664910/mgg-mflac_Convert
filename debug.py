# -*- coding: utf-8 -*-

import frida
import os
import sys
import argparse
import logging
import time
from datetime import datetime


def _on_message(message, data):
    """
    接收 Frida JS 脚本 send()/throw 等消息。
    """
    try:
        mtype = message.get("type")
        if mtype == "send":
            payload = message.get("payload")
            logging.info(f"[JS send] {payload}")
        elif mtype == "error":
            # JS 运行时报错（非常关键，通常就是它导致 rpc.exports 没注册）
            desc = message.get("description")
            stack = message.get("stack")
            logging.error("[JS error] " + (desc or ""))
            if stack:
                logging.error("[JS stack]\n" + stack)
        else:
            logging.info(f"[JS message] {message}")
    except Exception as e:
        logging.error(f"解析 JS 消息失败: {e}")


def run_diag(process_name="QQMusic.exe", js_path="hook_qq_music.js", wait_seconds=3.0):
    """
    诊断模式：只负责验证脚本是否真正成功运行并注册 rpc.exports.decrypt
    不执行任何文件处理。
    """
    if not os.path.exists(js_path):
        logging.error(f"找不到脚本文件: {os.path.abspath(js_path)}")
        return 2

    try:
        session = frida.attach(process_name)
    except frida.ProcessNotFoundError:
        logging.error(f"未找到进程 {process_name}，请先启动目标程序后再运行 --diag")
        return 2
    except Exception as e:
        logging.error(f"attach 失败: {e}")
        return 2

    try:
        with open(js_path, "r", encoding="utf-8") as f:
            raw_js = f.read()

        # 给原始 JS 外面包一层 try/catch，把“顶层初始化异常”主动 send 回来
        wrapped_js = f"""
        (function() {{
          try {{
            send({{"stage":"boot","time":"{datetime.now().isoformat()}","msg":"js wrapper entered"}});

            {raw_js}

            // 如果能运行到这里，说明脚本顶层没有崩
            send({{"stage":"boot","msg":"js wrapper finished (top-level ok)"}});

            // 尝试在 JS 侧确认 rpc.exports 是否存在 decrypt
            try {{
              var hasDecrypt = (typeof rpc !== "undefined") && rpc.exports && (typeof rpc.exports.decrypt === "function");
              send({{"stage":"exports","hasDecrypt":hasDecrypt, "exportKeys": rpc && rpc.exports ? Object.keys(rpc.exports) : null }});
            }} catch (e) {{
              send({{"stage":"exports","error": String(e)}})
            }}

          }} catch (e) {{
            // 顶层异常会直接导致 rpc.exports 未注册，这就是你当前症状的最常见根因
            send({{"stage":"fatal","error": String(e), "stack": e && e.stack ? String(e.stack) : null }});
            throw e;
          }}
        }})();
        """

        script = session.create_script(wrapped_js)
        script.on("message", _on_message)
        script.load()
    except Exception as e:
        logging.error(f"加载/运行脚本失败: {e}")
        try:
            session.detach()
        except Exception:
            pass
        return 2

    # Python 侧也尝试探测 decrypt 是否可调用（不真正调用）
    # 注意：如果 rpc 没注册，这里通常会报 RPCException
    try:
        # 仅做属性访问/探测
        _ = script.exports_sync
        # 某些 Frida 版本 hasattr 会触发 RPC，因此用 try-getattr 更稳
        try:
            decrypt_attr = getattr(script.exports_sync, "decrypt")
            logging.info("Python 侧：找到 exports_sync.decrypt（但仍需看 JS 侧 hasDecrypt=true 才算真注册）")
            _ = decrypt_attr  # 不调用
        except Exception as e:
            logging.error(f"Python 侧：无法获取 exports_sync.decrypt: {e}")
    except Exception as e:
        logging.error(f"Python 侧：exports_sync 不可用（多半 rpc 未注册）: {e}")

    logging.info(f"诊断模式等待 {wait_seconds} 秒收集 JS 消息...")
    time.sleep(float(wait_seconds))

    try:
        session.detach()
    except Exception:
        pass

    logging.info("诊断结束。请把控制台输出（尤其是 [JS error]/[JS send] stage=fatal/exports）发我。")
    return 0


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    parser = argparse.ArgumentParser()
    parser.add_argument("--diag", action="store_true", help="仅诊断脚本是否成功注册 rpc.exports.decrypt（不做文件处理）")
    parser.add_argument("--proc", type=str, default="QQMusic.exe", help="要 attach 的进程名")
    parser.add_argument("--js", type=str, default="hook_qq_music.js", help="frida 脚本路径")
    parser.add_argument("--wait", type=float, default=3.0, help="等待收集 JS 消息的秒数")
    args = parser.parse_args()

    if args.diag:
        sys.exit(run_diag(process_name=args.proc, js_path=args.js, wait_seconds=args.wait))

    print("本版本仅提供 --diag 诊断模式，不包含文件处理逻辑。")
    print("用法示例：python main.py --diag --wait 5")
    sys.exit(0)
