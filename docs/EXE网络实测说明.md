# EXE 网络实测

入口：左侧“工具箱” → 查询 EXE 网络。可查询已分配的 EXE，也可选择运行中的程序；查询不会重新分配应用或修改网络路由。

让目标应用执行实际下载、登录或业务操作，观察 30–60 秒以上。按完整路径匹配全部运行实例，可选包含创建时间和父子关系可验证的子进程。程序重启或 PID 复用后重新核验身份。

## 如何判断实际信道

- 系统分流：读取新鲜的辅助进程快照，包含 PID、信道映射、目的地址及实际转发字节；不把“规则已加载”当成流量。TCP 流时间早于当前 PID 创建时间时丢弃。UDP 原始创建时间未知时明确标注。
- Windows 连接表：显示 TCP / UDP、IPv4 / IPv6 的源地址、远端和状态；连接到已知本地代理端口只证明入口，不证明业务请求成功。
- 信道内核：依据完整进程路径，或严格匹配源 IP、源端口、协议以及已知本地代理入口，归属到所选 EXE。仅目的地相同不会被当作唯一归属证据。兼容中继可能隐藏原始源端口，此时宁缺勿推。
- 网卡与候选路由：作为辅助信息，不能覆盖逐应用 VPN 或驱动重定向，因此不能独立证明真实出口。

结果只覆盖观察到的连接。同一 EXE 可以同时经多个出口；没有观察到旁路不等于证明完全没有旁路。系统 DNS 服务、虚拟机、WSL、受保护进程及其他驱动流量可能无法归属。分流活动流最多 400 条；内核每次最多保留 2000 条，达到限制会提示覆盖不足。

## 速度、延迟和稳定性

三个来源的收发速率分别计算，不能相加：它们可能记录同一份流量。计算使用相邻快照、相同流的字节增量和实际经过时间。首次出现的流只建立基线；已经结束或在两次采样之间完成的短连接会漏计，所以这是可见流量的下限。不是网卡总速率，也不是磁盘 I/O。

Windows TCP 可提供已确认 / 接收字节、RTT、RTT 波动、重传和超时。统计不可读或未启用时显示未知。管理员模式下可勾选为目标 TCP 连接补充扩展统计；不会更改路由，也不会关闭其他监测器的统计。RTT 范围必须结合远端看：本地代理 / 中继段的延迟不能代表应用服务器延迟。

近 60 秒吞吐 P50 / P95、峰值、零增量样本和可见流变化用于观察趋势。空闲不等于断网；正常关闭不等于异常断线；TCP 重传也不是精确丢包率。不会生成未经测量的“稳定性评分”。

## 独立参考探测

手动运行时，由诊断进程经选定信道向 Cloudflare / ipify 发出最多各 3 次 HTTPS 请求，记录服务所见 IP、完整请求耗时、请求失败比例和同站耗时差。结果明确属于诊断请求，不能代替所选 EXE 的业务出口 / 延迟证明。小样本不能证明长期稳定性，请求失败比例不是丢包率。

可选额外下载 4 MiB、上传 256 KiB 测试数据，显示有效载荷除以完整请求耗时。此为到单个测试服务的小文件参考吞吐，包含建连和确认；不是线路峰值或目标 EXE 的速度。显式使用本信道认证代理、忽略环境代理，保持 TLS 证书验证，失败不切换直连。

导出的 JSON 含本地路径、PID、连接目的地址和探测 IP；不包含代理密码、认证令牌或应用内容。暂停后是历史快照，应重新开始观察后再判断当前状态。

实现依据：

- [Microsoft：GetPerTcpConnectionEStats](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getpertcpconnectionestats)
- [Microsoft：SetPerTcpConnectionEStats](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-setpertcpconnectionestats)
- [Microsoft：TCP path statistics](https://learn.microsoft.com/en-us/windows/win32/api/tcpestats/ns-tcpestats-tcp_estats_path_rod_v0)
- [Microsoft：Find-NetRoute](https://learn.microsoft.com/powershell/module/nettcpip/find-netroute)
- [Mihomo v1.19.33：连接元数据](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/constant/metadata.go)
- [Mihomo v1.19.33：逐连接计数器](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/tunnel/statistic/tracker.go)
