# -*- coding: utf-8 -*-

import frida
import os
import sys
import hashlib
import argparse
import logging
import shutil
import tempfile
import csv
from datetime import datetime

try:
    from source_finder import guess_song_url
except Exception:
    def guess_song_url(_):
        return None


def list_download_songs():
    download_dir = os.path.join(os.path.expanduser("~"), "Music", "VipSongsDownload")
    if not os.path.exists(download_dir):
        logging.error(f"默认下载目录不存在：{download_dir}")
        return
    logging.info(f"QQ 音乐下载目录：{download_dir}")
    exts = {".mflac", ".mgg", ".ogg", ".flac", ".mp3", ".m4a"}
    count = 0
    for root, _, files in os.walk(download_dir):
        for file in files:
            if os.path.splitext(file)[1].lower() in exts:
                count += 1
                full_path = os.path.join(root, file)
                rel = os.path.relpath(full_path, download_dir)
                print(f"{count:4d}. {rel}")
    logging.info(f"共找到 {count} 个文件")


def append_csv(song_name: str, src_url: str):
    csv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conversion_log.csv")
    exists = os.path.exists(csv_path)
    with open(csv_path, "a", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        if not exists:
            writer.writerow(["转换时间", "歌曲", "来源链接"])
        writer.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), song_name, src_url or ""])


def run_decrypt(input_dir, output_dir):
    if not os.path.exists(input_dir):
        logging.error(f"输入目录不存在: {input_dir}")
        return

    input_dir = os.path.abspath(input_dir)
    output_dir = os.path.abspath(output_dir)

    try:
        session = frida.attach("QQMusic.exe")
    except frida.ProcessNotFoundError:
        logging.error("未找到 QQMusic.exe 进程，请先启动 QQ 音乐")
        return

    try:
        with open("hook_qq_music.js", "r", encoding="utf-8") as f:
            script = session.create_script(f.read())
        script.load()
    except Exception as e:
        logging.error(f"加载 Frida 脚本失败: {e}")
        return

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    temp_dir = tempfile.mkdtemp(prefix="qqmusic_")

    try:
        for root, _, files in os.walk(input_dir):
            for file in files:
                base, ext = os.path.splitext(file)
                if ext.lower() not in [".mflac", ".mgg"]:
                    continue

                logging.info(f"开始解密: {file}")

                new_ext = ext.lower().replace("mflac", "flac").replace("mgg", "ogg")
                output_filename = base + new_ext
                output_file_path = os.path.join(output_dir, output_filename)

                if os.path.exists(output_file_path):
                    logging.info(f"已存在，跳过: {output_file_path}")
                    src_url = guess_song_url(file) or guess_song_url(output_filename)
                    logging.info(f"来源: {src_url or '未找到（可稍后重试）'}")
                    append_csv(output_filename, src_url)
                    continue

                src_abs_path = os.path.abspath(os.path.join(root, file))
                temp_src_path = os.path.join(temp_dir, hashlib.md5(file.encode()).hexdigest() + ext)
                shutil.copyfile(src_abs_path, temp_src_path)

                tmp_output_path = os.path.abspath(
                    os.path.join(temp_dir, hashlib.md5(file.encode()).hexdigest() + new_ext)
                )
                os.makedirs(os.path.dirname(tmp_output_path), exist_ok=True)

                try:
                    # 兼容不同 frida 版本
                    exports = getattr(script, "exports_sync", None) or script.exports
                    exports.decrypt(temp_src_path, tmp_output_path)
                    os.rename(tmp_output_path, output_file_path)
                    logging.info(f"解密成功: {output_file_path}")
                    src_url = guess_song_url(file) or guess_song_url(output_filename)
                    logging.info(f"来源: {src_url or '未找到（可稍后重试）'}")
                    append_csv(output_filename, src_url)
                except Exception as e:
                    logging.error(f"解密失败: {file} -> {e}")
                    try:
                        if os.path.exists(tmp_output_path):
                            os.remove(tmp_output_path)
                    except Exception:
                        pass
                    continue
    finally:
        session.detach()
        shutil.rmtree(temp_dir, ignore_errors=True)
        logging.info("所有任务已完成")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-l", "--list", action="store_true")
    parser.add_argument("-i", "--input", type=str, required=False)
    parser.add_argument("-o", "--output", type=str, required=False)
    args = parser.parse_args()

    if len(sys.argv) == 1:
        print("作者: 唐晓宇\n")
        print("命令用法:")
        print("  列出 QQ 音乐默认下载目录下的歌曲: main.py -l")
        print("  注：默认目录 C:\\Users\\<当前用户名>\\Music\\VipSongsDownload")
        print("  解密转换指定目录下的歌曲（可批量转换）:")
        print("  main.py -i input -o output")
        sys.exit(0)

    if args.list:
        list_download_songs()
        sys.exit(0)

    if not args.input or not args.output:
        parser.error("解密模式需要提供 -i <输入目录> 和 -o <输出目录>；如仅想查看，请使用 -l")
    run_decrypt(args.input, args.output)