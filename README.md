# QQ 音乐音频解密工具

该工具基于 **Frida** 注入 QQMusic.exe，支持将 QQ 音乐缓存的 `.mflac` / `.mgg` 文件解密为标准音频格式（`.flac` / `.ogg`），并可以获取对应的 QQ 音乐歌曲来源链接。

---

## 环境准备

1. 克隆或下载本项目到本地。

2. 安装依赖：
   ```bash
   pip install -r requirements.txt

## 目录结构示例

> ├─ main.py
> ├─ debug.py
> ├─ source_finder.py
> ├─ hook_qq_music.js
> ├─ requirements.txt
> └─ README.md

## 命令用法

### 1. 列出 QQ 音乐默认下载目录下的歌曲

```
python main.py -l
```

- 默认目录：
   `C:\Users\<当前用户名>\Music\VipSongsDownload`
- 功能：仅输出下载目录中的歌曲文件列表，不做解密。

### 2. 解密转换指定目录下的歌曲（可以批量转换）

```
python main.py -i input -o output
```

- `input`：包含 `.mflac` / `.mgg` 文件的目录。
- `output`：解密后音频文件的输出目录。

### 3. 日志与记录

- 所有操作日志实时打印在命令行。
- 每次成功解密后会在项目根目录下生成/追加 `conversion_log.csv`，记录转换信息。

字段：转换时间 歌曲 来源链接

示例：

```
转换时间,歌曲,来源链接
2025-xx-xx xx:xx:xx,郭静 - 爱情讯息.flac,https://y.qq.com/n/ryqq/songDetail/000DOpDe2GfLaq
```

## 4.问题诊断

当出现以下情况时，建议先运行 debug.py：

- 控制台反复提示 `unable to find method 'decrypt'`

- 你怀疑是 `Frida` 版本差异导致 Python 侧调用方式不兼容（例如某些环境没有 `exports_sync`）

- 你想确认 `hook_qq_music.js` 是否真的成功执行并导出了` rpc.exports.decrypt`

```
python debug.py --diag --wait 5
```

## 注意事项

- 请确保 QQ 音乐客户端 **已启动**，否则 Frida 无法附加进程。
- 输出目录可包含中文路径，内部逻辑会自动绕过中文路径兼容问题。
- 来源链接通过 QQ 音乐公开搜索接口获取，部分歌曲可能未能匹配到。
- 默认仅支持 `.mflac` 和 `.mgg` 文件解密，其他格式如 `.mp3/.flac` 会直接列出，但不会做解密。

## 参考原项目
https://github.com/HanZeYu-momo/QQ-Music-Audio-Decryption-Tool 原项目的Frida的兼容性不佳，修改后增强了兼容性。
