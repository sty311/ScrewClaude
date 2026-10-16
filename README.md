<p align="center"><img src="web/logo-avatar.png" alt="ScrewClaude" width="112"></p>

# ScrewClaude

Windows 本机环境风险检测工具：69 项检查、0–100 风险圆环、逐项依据和 HTML / JSON / PNG 导出。用漫画风格展示环境中的中国地区相关特征。免费、MIT 开源。

[![Windows checks](https://github.com/sty311/ScrewClaude/actions/workflows/windows.yml/badge.svg)](https://github.com/sty311/ScrewClaude/actions/workflows/windows.yml)

## 下载与使用

1. 从 [Releases](https://github.com/sty311/ScrewClaude/releases/latest) 下载 **ScrewClaude-2.10.1-windows-portable.zip**，完整解压到任意可访问目录。
2. 双击 **start-web.cmd**（也可以直接打开 ScrewClaude.Web.exe），浏览器会打开本机页面。
3. 点击“开始检测”。默认尝试全部 69 项，无法读取的项目自动跳过；展开卡片查看原因及计分。
4. 通过网页“关于”中的退出操作或系统托盘退出服务。关闭浏览器标签页不会停止服务。

把整个解压目录复制到另一台符合要求的 Windows 电脑即可使用，不依赖原电脑的用户名、桌面目录或安装路径。源码 ZIP 需要先构建；普通用户请下载带 EXE 的便携包。移动前先退出服务。

## 运行条件

| 项目 | 要求 |
|---|---|
| 系统 | Windows 10 / 11，x64 或 x86；ARM64 未验证，macOS / Linux 不支持本机引擎 |
| 运行时 | .NET Framework 4.8 或更新的 4.x（[微软下载](https://dotnet.microsoft.com/en-us/download/dotnet-framework/net48)） |
| 浏览器 | 当前版本 Edge / Chrome / Firefox；浏览器策略会影响 WebRTC、下载和权限 |
| 权限 | 普通用户即可；不要求管理员，不更改代理、DNS、地区设置 |
| 可选能力 | 定位需要系统权限/服务；Wi-Fi、蜂窝需要对应硬件；OCR 需要用户指定 Tesseract |
| 开发 | Windows 自带 .NET Framework C# 编译器；测试另外需要 Node.js 22+ |

运行发行包**不需要 Node、Python、Visual Studio 或 npm install**。不同电脑的硬件、权限、浏览器配置和网络不同，检测结果与跳过数量也会不同。便携不代表每台电脑的 69 项都能读取。

默认地址 http://127.0.0.1:53174/。端口被占用时先退出已有 ScrewClaude；也可运行 start-web.cmd --port 53176。重复双击不会替代已运行的服务；请打开已有页面或退出后重开。不要从 ZIP 预览窗口直接运行 EXE。

## 检测与评分

- 网络出口、IPv6、DNS、WebRTC、时区、语言、输入法、字体、软件及浏览器配置等共 69 项。
- DNS / WebRTC / HTTPS 与主扫描同时执行，结果归入原有检查项。
- 文件和照片分析只处理主动选择的目录，外部账号信息只处理主动导入的记录；缺少输入即跳过。
- 同一证据维度去重，不同维度按 100% / 50% / 25% 递减计分，总分上限 100，显示一位小数。
- ≤30 为低风险，>30 且 ≤60 为中风险，>60 为高风险。跳过不等于安全。

详见 [评分规则](SCORING_RULES_2.9.md) 和 [检测清单](CHECKS.md)。分数表示本工具规则命中程度，不是中国用户概率、国籍鉴定或 Claude 官方封号预测。项目与 Anthropic 无隶属或合作关系。

## 数据与联网

页面仅监听 127.0.0.1，资源和人物图片随 EXE 嵌入，无遥测。打开网页不会自动扫描。开始后默认访问公开网络检测端点，它们会收到连接所需的出口 IP、解析器或请求信息；本机报告、文件内容及浏览历史不会作为报告上传。可在检查范围中关闭联网和路径探测。见 [网络说明](NETWORK_CHECKS.md)。

报告保存在服务进程内，退出后不保留；导出文件由用户自行保存。导入 JSON 保存在 Windows 临时目录的 ScrewClaude-Web-* 子目录，退出后可能仍保留，可按需清理。摘要导出省略原始证据，详细报告可能含个人信息，请检查后再分享。本仓库只含合成测试样例，不含真实扫描报告。

## 从源码构建

~~~bat
build-web.cmd --no-pause
test-risk.cmd --no-pause
test-network.cmd --no-pause
test.cmd --no-pause
powershell -NoProfile -File test-portability.ps1
powershell -NoProfile -File package.ps1
~~~

构建输出 ScrewClaude.Web.exe 和配置文件；便携包输出到 dist/。无 NuGet / npm 运行时依赖。PowerShell 脚本遵守本机执行策略；不要求修改系统执行策略。CI 自动构建并测试，见 [验证范围](PORTABILITY.md)。

源码保留 LocalLens 内部命名和旧报告标识以兼容导入；对外品牌统一为 ScrewClaude。build.cmd / test.cmd 中的 LocalLens.exe 仅供兼容引擎测试，发布入口是 build-web.cmd。

## 许可与致谢

[MIT License](LICENSE)。UI 结构、配色和交互参考 [LinXiaoTao/FuckClaude](https://github.com/LinXiaoTao/FuckClaude)，保留其 MIT 许可；检测使用本项目 69 项 Windows 引擎。当前人物为新生成的虚构漫画角色，提示词在 design/。边界数据来自 Natural Earth 公有领域数据。完整说明见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
