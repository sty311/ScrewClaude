# 网络检查

默认随主扫描运行；关闭 Online 或 Probes 会跳过浏览器网络采样。第 1、3、6 项分别合并 HTTPS、WebRTC、DNS 的浏览器与 Windows 来源，来源失败自动跳过并保留原因。使用实际 CN 国家字段判定；路径不同、IPv4/IPv6 不同、超时本身不代表 CN 风险。

| 检查 | 端点 |
|---|---|
| 浏览器 DNS | 随机子域名 dns4.browserleaks.net / dns6.browserleaks.net / ipv4.surfsharkdns.com / u.fastly-analytics.com/debug_resolver |
| HTTPS 出口 | api.ipify.org / api6.ipify.org；claude.com/cdn-cgi/trace；claude.ai/cdn-cgi/trace |
| WebRTC | stun.l.google.com:19302（不访问摄像头或麦克风） |
| IP 国家 | ipwho.is，最多 16 个浏览器公网非中继候选，去重并验证响应地址 |

Windows 网络检查还包括系统出口、路由、DNS 配置/缓存、连接与区域可达性；实际端点见 src/NetworkChecks.cs、src/ExtendedChecks.cs、web/network.js。第三方请求不会携带本机报告、私人文件或浏览历史；请求所需出口、解析和连接信息会被对应服务看到。

每次扫描使用独立 ScanId；取消、超时或上一批迟到的数据不会覆盖新一批。浏览器请求受 CORS、DoH、代理、扩展与服务可用性影响。所有有效国家字段非 CN，仅表示本次已取得样本未命中；失败与未知不会伪装成成功。地理坐标由嵌入多边形本地判断，不向第三方发送坐标。

国家归属数据库可能不一致；详情保留国家资料来源与冲突。系统 DNS 配置和实际递归解析器出口含义不同。计分见 [评分规则](SCORING_RULES_2.9.md)。
