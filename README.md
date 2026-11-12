# ChannelGuard / 信道护航

Windows x64 网络信道管理工具：本地代理、应用进程分流、独立浏览器环境和网络诊断。

## 运行

从 Releases 下载 Windows ZIP，完整解压后双击 ChannelGuard.exe。包含运行依赖，不能只复制 EXE。首次启动创建全新的本地配置；需要用户自行识别网络、选择出口并填写自己的代理凭证。系统分流驱动需要管理员权限。

程序运行时读取本机网络以实现管理功能，这些数据保存在使用者本地，不是仓库或发行包内置的样例。

## 开发

Python 3.10+：

```powershell
python -m pip install -r requirements.txt
python -m playwright install chromium
python main.py
```

Mihomo 及原生路由依赖由 vendor 中的固定版本定义，完整发行包保留第三方许可证与对应源码。源码仓库不保存依赖 EXE、DLL 或系统驱动。开发时可从同版本发行包的 _internal/vendor 恢复 vendor 目录；应自行校验依赖来源和哈希。

单元测试：`python -m unittest discover -s tests -v`。
打包：`python build.py`；压缩：`python build.py --archive-only`。

## 虚构示例

[examples/channel.example.json](examples/channel.example.json) 使用文档专用地址 192.0.2.10、虚构名称和占位凭证，仅解释格式，不能作为实际可联网节点。示例不来自任何真实用户、设备或网络。

## 隐私与限制

参见 [PRIVACY.md](PRIVACY.md) 和 [KNOWN_LIMITATIONS.txt](KNOWN_LIMITATIONS.txt)。本公开版不包含真实配置、订阅、代理密码、连接记录、设备识别信息或旧的本机验收报告。应用源码遵循 GPL-3.0；第三方组件保留原许可证。
