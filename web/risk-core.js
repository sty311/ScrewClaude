/* ScrewClaude full Windows audit risk model, version 3.0.
 * Uses the 69 established ChinaEvidence rules, not the reference UI's 8 probes.
 * Scores are disclosed heuristic contributions, never a population probability
 * or an official Claude decision. No observation is collected by this module.
 */
(function(root,factory){
 'use strict';const api=factory();if(typeof module==='object'&&module.exports)module.exports=api;else root.LocalLensRisk=api;
})(typeof globalThis==='object'?globalThis:this,function(){
 'use strict';
 const SOURCE='ScrewClaude src/ChinaEvidence.cs: the 69 actual audit decisions';
 const METHOD='ScrewClaude（评分规则 3.0）：69 项实测规则，逐项设置基础分。同一观察去重；语言与输入偏好相关组的最强项计 100%，其他项计 35%；服务访问与存储相关组的最强项计 100%，其他项计 50%。其他独立维度全额累计，不按大类排位打折。总分超过 100 时按比例压缩，保留一位小数。分数仅基于本次有效结果；读取不到或没有有效资料的项目已跳过，不按读取数量放大。权重是公开的启发式参数，未用人群数据校准，不是人口概率或平台官方判定。';
 const catalog=[[1,"系统与浏览器 HTTPS 出口","网络出口","分别保留 Windows 系统代理请求和当前浏览器的 HTTPS 出口、端点与国家资料；IPv4、IPv6 或网站分流可能不同，出口不代表操作者的物理所在地。"],[2,"公网 IPv6","网络出口","若系统代理代发请求，IPv6 专用域名不保证客户端实际使用 IPv6。"],[3,"系统与浏览器网络路径核对","网络出口","启用路径检测时比较系统 UDP STUN 与 HTTPS，并自动采样当前浏览器 WebRTC；各来源与时间分别保留。只有有效 CN 国家归属支持中国网络关联，地址差异本身不加分。"],[4,"网络接口","网络出口","虚拟网卡、私网地址和适配器名称不能定位国家。"],[5,"IP 运营商与 ASN","网络出口","使用单一第三方 IP 库；注册地、出口地与物理所在地可能不同。"],[6,"DNS 配置与浏览器递归出口","网络出口","Windows 网卡配置按九个明确公共 DNS 地址核对；当前浏览器递归 DNS 自动向 BrowserLeaks、Surfshark 和 Fastly 采样。两类来源合并到本项，配置不冒充实际递归出口，读取不到的来源跳过。"],[7,"本机路由表","网络出口","本机路由表不是完整互联网路径，也不揭示隧道底层路线。"],[8,"多区域端点耗时","网络出口","三个 AWS 区域服务地址各两次 HTTPS HEAD；耗时含代理、DNS、TLS 和服务器处理，不进行地理三角测距。"],[9,"网络访问与阻断特征","网络出口","只记录三个指定站点的请求响应 / 错误；不能将连接失败直接解释为封锁或设备在中国。"],[10,"持续采样中的中国出口","网络出口","按用户选择观察最多 300 秒，约每 10 秒读取 HTTPS IPv4 出口和接口；短暂变化、其他协议及过去记录可能漏检。"],[11,"Windows 定位配置","位置与无线","本版读取定位权限配置，不请求坐标；权限允许不证明任何程序已采集定位。"],[12,"系统定位 / GNSS 线索","位置与无线","主动请求 Windows 融合定位，或导入浏览器定位；无法保证数据来源为 GNSS，权限拒绝和无结果均不能作为位置结论。"],[13,"附近 Wi-Fi BSSID","位置与无线","仅显示系统返回的无线列表，不查询接入点地理数据库；结果受权限影响。"],[14,"附近 Wi-Fi 名称","位置与无线","中文 SSID 可在任何地方使用，附近名称不证明设备在中国。"],[15,"蜂窝网络注册","位置与无线","只展示系统移动宽带接口信息；不读取 SIM 标识或基站坐标。"],[16,"附近设备与无线环境","位置与无线","只读取已配对 / 已发现蓝牙和打印设备以及邻居缓存；不主动探测其他设备，不查询周边设备位置。"],[17,"Windows 国家 / 地区","地区与语言","用户可修改的设置，不能证明当前位置。"],[18,"显示语言与安装语言","地区与语言","只检查当前用户及系统可读配置，不推断当前物理位置。"],[19,"系统区域与代码页","地区与语言","用于非 Unicode 应用，可能与显示语言、居住地不同。"],[20,"日期、数字与货币格式","地区与语言","使用习惯不是地理位置。"],[21,"用户语言列表","地区与语言","语言偏好不等于所在地或国籍。"],[22,"键盘与输入法","地区与语言","拼音及中文输入法可被海外用户使用；不读取输入内容。"],[23,"时区与自动时区","地区与语言","时区可手动设置，UTC+8 也不只用于中国。"],[24,"其他已加载用户配置","地区与语言","只读取已加载用户配置；不加载其他用户注册表，不读取其私人文件。"],[25,"浏览器语言配置","浏览器","支持 Chrome、Edge、Brave、Vivaldi、Opera、Firefox 的可识别配置目录，每个根目录最多 40 个子目录；配置不等于浏览器运行时值。"],[26,"应用自己的地区","软件与设备","只检查部分常见应用的地区配置，不代表覆盖所有软件。"],[27,"终端与开发环境","软件与设备","只检查选定环境变量及有限镜像配置；不运行 WSL、不枚举容器内部。"],[28,"字体与语言资源","软件与设备","读取实际字体名称，列明简体字体视为弱环境关联；预装字体也可能被观察到，不表示本人身份或当前位置。"],[29,"保存的 Wi-Fi 配置","历史痕迹","只解析 SSID 名称，不读取或显示无线密码；旧网络不能证明当前位置。"],[30,"近期无线连接事件","历史痕迹","最多读取最近 7 天 100 条可访问事件；无事件不等于从未连接。"],[31,"保存的网络档案","历史痕迹","只检查系统保存的网络名称，记录可能过期或来自克隆系统。"],[32,"本机代理与 VPN 配置","网络出口","只读系统代理、WinHTTP 和 VPN 接口线索；不读取订阅密钥或 VPN 私钥。"],[33,"诊断 / 缓存记录","历史痕迹","读取最多 200 条系统 DNS 缓存与 50 条 NRPT 策略；不代表浏览器 DoH、实际递归服务器出口或完整网络历史。"],[34,"浏览器访问与下载历史","浏览器","只读实际 visits 表：每配置最多 4000 次近 90 天 HTTP(S) 访问；单次国内服务访问即保留风险。读取失败、无有效访问和域名展示表不能当成成功访问判定。"],[35,"浏览器网站存储","浏览器","解析实际 IndexedDB / Firefox 存储 origin，国内服务 origin 独立判风险；不要求历史同时可读。不解密 Cookie，不读取 LevelDB 内容，也不证明本人登录。"],[36,"最近使用文件","历史痕迹","读取 Recent 目录最多 200 个快捷方式的名称和目标路径，不打开目标文档；不覆盖 Jump Lists 或应用内部最近记录。"],[37,"系统安装 / 配置日志","历史痕迹","抽样读取标准安装日志尾部最多 2 MiB，匹配语言 / 时区字段；日志可能轮转、截断或遗漏。"],[38,"旧系统与备份","历史痕迹","分析 Windows.old 中相同安装日志；不自动挂载系统镜像、卷影副本或解密备份，不证明旧环境没有其他痕迹。"],[39,"删除后的残留","历史痕迹","读取最多 200 项当前用户回收站元数据；不恢复文件，不读取原始磁盘、MFT、USN 或永久删除的数据。"],[40,"内存 / 休眠 / 转储残留","历史痕迹","对已有 MEMORY.DMP 和最多 10 个应用转储各读取前 2 MiB，可见字符串不等于完整解析；不读取活跃内存、pagefile、hiberfil。"],[41,"已安装软件","软件与设备","有限关键词匹配安装项，不代表软件有恶意，也不定位用户。"],[42,"自启动与软件残留","软件与设备","检查 Run / 启动目录项目名、最多 200 个自动服务及 200 个启用计划任务名称；不能判断是否恶意或覆盖全部持久化方式。"],[43,"开发工具镜像源","软件与设备","只读取白名单配置文件中的源地址行，隐藏凭据与 URL 参数；仅反映开发习惯。"],[44,"企业 / 学校管理配置","软件与设备","只查询计算机域加入状态；不连接域控、不读取企业证书私钥。"],[45,"OEM 与销售版本","软件与设备","制造商和型号没有实时定位能力，不读取产品密钥。"],[46,"设备标识的历史关联","外部关联","可选读取 UUID 和 BIOS 序列号后只保留组合 SHA-256；可与本地基线比较，仍是可关联标识，不连接厂商历史库。"],[47,"外设与驱动地区","软件与设备","查询最多 300 项已安装驱动的设备名称、厂商、版本、签名字段；厂商和设备不能证明使用地区。"],[48,"本机照片的 GPS 元数据","文件元数据","自动查找本机 JPEG/TIFF，或扫描指定目录，最多读取 500 张；不跟随链接和云占位文件。空样本、损坏或达到搜索上限均不能作完整阴性结论；坐标属于文件，不证明此电脑当前位置。"],[49,"图片中的地址 / 地标","文件元数据","自动发现图片后，取前 20 张使用本机 Tesseract OCR；自动查找标准安装目录，仍需已安装引擎与 chi_sim / eng 语言包。识别地名不代表地标识别或拍摄地。"],[50,"私人文档中的地点","文件元数据","自动查找支持格式文本和 DOCX，或使用指定目录；检查明确的联系地址与国家字段，普通地名提及不命中。搜索范围和数量上限见详情，PDF 和加密文档不支持。"],[51,"邮件、聊天与日历","文件元数据","自动查找并分析本机已有的 EML / ICS / VCF 明文导出，也可指定目录；不连接账号，不解码 MIME 附件、编码正文或读取应用聊天数据库。"],[52,"自动填充地址","浏览器","仅读取 Chromium 普通 autofill 表中白名单国家 / 省市字段；不覆盖所有版本地址档案，不读取付款资料、密码或完整街道地址。"],[53,"地图 / 天气位置缓存","文件元数据","有限天气/地图文本缓存的当前定位或收藏/默认地点 countryCode=CN 均保留关联；已保存地区只算偏好，不冒充设备定位。"],[54,"云同步 / 手机备份","文件元数据","读取 OneDrive 根目录配置及 Apple MobileSync 标准目录元数据；不读取云端内容、手机备份数据库或解密备份。"],[55,"文件中的时区偏移","文件元数据","检查已发现文件内的显式命名时区字段；NTFS UTC 时间不能恢复原始时区，任意 UTC+8 偏移不参与中国关联判定。"],[56,"账号历史登录 IP","外部关联","自动查找支持格式的本地平台记录，也可指定文件；不连接后台，不验证真实性，本机管理员权限不会提供服务商历史数据。"],[57,"注册 / 支付地区","外部关联","仅接受用户整理的国家代码和来源说明，不读取支付详情；国家字段与当前位置不同。"],[58,"浏览器运行时环境","浏览器","默认从当前页面自动读取浏览器语言、区域、时区和可见设备字段，也可使用用户选择的浏览器 JSON。值可被修改或伪装，时间与来源分别保留；没有有效数据时跳过。"],[59,"设备历史指纹关联","外部关联","自动查找本机已有的外部历史关联记录，也可指定文件；程序无法获取平台内部指纹识别模型或关联表。"],[60,"跨设备位置关联","外部关联","自动查找本机已有且格式受支持的跨设备记录，不访问其他设备或账号。"],[61,"运营商 / 第三方资料","外部关联","自动查找本机已保存且格式受支持的服务商记录，也可指定文件；不购买或抓取私人数据库。"],[62,"录屏与窗口监控","权限与边界","仅列出有限候选进程名称，不能判定是否正在录屏，也不能排除隐藏、改名或内核级监控；不录制屏幕。"],[63,"键盘与剪贴板监控","权限与边界","仅列出有限自动化 / 剪贴板候选进程名称，不安装输入钩子、不读取剪贴板；无法排除隐蔽监听。"],[64,"摄像头 / 麦克风访问记录","权限与边界","只读可访问的 Windows 隐私记录；记录不完整，也不能证明没有其他采集途径。"],[65,"网络配置变化与基线","权限与边界","完整扫描自动保存配置哈希，下次与历史基线比较，也可指定基线文件；首次扫描没有对比结果。基线未签名，软件升级、权限或采样差异会产生变化，不能认定恶意篡改。"],[66,"诱导授权 / 扩大收集","权限与边界","分析 Chromium / Firefox 安装扩展的权限声明；可选权限不等于授权，安装目录不等于启用；无法认定用户曾被诱导。"],[67,"长期作息与行为推断","权限与边界","统计近 7 天最多 300 条启动 / 停止 / 唤醒类系统事件的本地小时；后台事件不等于有人操作，不推断身份或国家。"],[68,"跨来源中国关联核对","地区与语言","汇总系统配置、本次出口与用户导入的浏览器环境；不同采样时间、不同设备或配置差异不证明伪装或当前位置。"],[69,"隐私保护被当成可疑","权限与边界","关闭定位、使用代理等不是中国位置证据，本版不把它们打成风险分。"]];
 const SUMMARY_METHOD='逐项设权重，重复观察去重；语言相关组余项 35%、服务痕迹余项 50%，其他独立维度全额。';
 const familyDefinitions=Object.freeze([
  {id:'deviceLocation',name:'设备位置',weight:32,description:'本次有效大陆坐标 32 分；带当前定位标志的缓存 10 分。同一位置去重；导入坐标单独降权。'},
  {id:'network',name:'中国网络路径',weight:24,description:'CN 出口 24 分、实际 CN 递归 DNS 18 分、注册 MCC 460 蜂窝网络 22 分，各自全额计分；只配置中国 DNS 为 4 分。重复出口观察去重。'},
  {id:'regional',name:'当前地区偏好',weight:12,description:'国家地区选择 12 分、命名时区 6 分。语言、输入法、浏览器、应用、终端与字体共用相关组：最强项全额，其余 35%，各项保留贡献。'},
  {id:'domesticUsage',name:'国内服务关联',weight:8,description:'访问记录 8 分、网站存储 4 分、解析缓存 0.5 分；相关组最强项全额，其余 50%。网站存储不等于主动访问或拥有账号。'},
  {id:'software',name:'软件与开发生态',weight:5,description:'国内软件安装或启动记录 5 分，同一软件观察去重；开发镜像配置独立计 2 分。软件和镜像不直接定位本人。'},
  {id:'contact',name:'中国联系资料',weight:10,description:'浏览器保存地址 10 分；明确联系字段的文档、消息各 5 分；OCR 为 3 分。相同文档与 OCR 维度取较强项，不把文件自动归属于本人。'},
  {id:'historic',name:'历史地区配置',weight:3,description:'安装记录 3 分、文件命名时区 1.5 分、其他用户配置 1 分、无线名称 0.5 分。不同维度全额计分，不替代当前位置。'},
  {id:'organization',name:'中国组织域',weight:3,description:'已加入且以 .cn 结尾的组织域计 3 分；只支持组织关联。'},
  {id:'external',name:'已保存中国地区记录',weight:8,description:'有来源和时间的 CN 账号地区记录 8 分、登录地区 5 分、历史关联资料 3 分；未验证平台签名和本人归属。'},
  {id:'documentLocation',name:'资料大陆地点',weight:4,description:'照片有效大陆 GPS 4 分、用户导入定位 3 分；反映资料地点，不代表本次设备位置。'}
 ].map(Object.freeze));
 const familiesById=new Map(familyDefinitions.map(f=>[f.id,f]));
 const policy=new Map();
 function group(ids,familyId,evidenceFamily,basePoints){ids.forEach(id=>policy.set(id,{familyId,evidenceFamily,basePoints}));}
 group([1,2,3,5,10],'network','网络出口',24);group([6],'network','中国网络服务',4);group([15],'network','蜂窝网络',22);
 group([12],'deviceLocation','设备位置',32);group([53],'deviceLocation','设备位置',10);
 group([17],'regional','地区偏好',12);group([18,19,25,58],'regional','地区偏好',8);group([20,21,23],'regional','地区偏好',6);group([22],'regional','地区偏好',5);group([26],'regional','地区偏好',4);group([27],'regional','地区偏好',3);group([28],'regional','中文字体环境',1);
 group([24],'historic','其他用户地区配置',1);group([37,38],'historic','历史地区配置',3);group([55],'historic','历史地区配置',1.5);group([14,29,30,31],'historic','无线网络名称',.5);
 group([34],'domesticUsage','持续服务使用',8);group([35],'domesticUsage','持续服务使用',4);group([33],'domesticUsage','国内服务解析',.5);
 group([41,42],'software','软件生态使用',5);group([43],'software','开发服务偏好',2);
 group([44],'organization','组织域关联',3);group([48],'documentLocation','资料地点',4);group([49],'contact','联系资料关联',3);group([50,51],'contact','联系资料关联',5);group([52],'contact','联系资料关联',10);
 group([56],'external','外部记录关联',5);group([57],'external','外部记录关联',8);group([59,60,61],'external','外部记录关联',3);
 // Correlation is explicit and separate from display categories. Parameters
 // are heuristic, not fitted probabilities. Only these groups get discounts.
 const correlationDefinitions=Object.freeze([
  {id:'language-preferences',name:'语言与输入偏好',discount:.35,ids:Object.freeze([18,19,20,21,22,25,26,27,28,58])},
  {id:'service-footprints',name:'国内服务访问与存储',discount:.5,ids:Object.freeze([33,34,35])}
 ].map(Object.freeze));
 const correlationPolicy=new Map();correlationDefinitions.forEach(g=>g.ids.forEach(id=>correlationPolicy.set(id,g)));
 // A dimension describes overlapping measurements, not a claim of statistical
 // independence. Dedupe inside it; corroborate across dimensions of one family.
 const dimensionPolicy=new Map(),dimensionDefinitions=[];
 function dimension(id,name,ids){dimensionDefinitions.push(Object.freeze({id,name,ids:Object.freeze(ids)}));ids.forEach(check=>dimensionPolicy.set(check,{dimensionId:id,dimensionName:name}));}
 dimension('egress','公网出口与重复采样',[1,2,3,5,10]);
 dimension('dns','DNS 配置或实际递归路径',[6]);dimension('cellular','蜂窝注册网络',[15]);
 dimension('location','当前系统位置及位置缓存',[12,53]);
 dimension('country','国家地区选择',[17]);dimension('display-language','显示与安装语言',[18]);dimension('system-locale','系统区域与代码页',[19]);dimension('regional-format','区域格式',[20]);dimension('user-languages','用户语言列表',[21]);
 dimension('input','键盘与输入法',[22]);dimension('timezone','命名时区',[23]);
 dimension('browser-locale','浏览器配置与运行时偏好',[25,58]);dimension('app-locale','应用地区设置',[26]);
 dimension('terminal-locale','终端地区设置',[27]);dimension('fonts','简体字体资源',[28]);
 dimension('other-user','其他已加载用户地区',[24]);dimension('installation','系统安装地区记录',[37,38]);
 dimension('file-timezone','文件内命名时区',[55]);dimension('wireless','无线名称及保存记录',[14,29,30,31]);
 dimension('visits','实际访问记录',[34]);dimension('storage','网站存储 origin',[35]);dimension('dns-cache','国内服务解析缓存',[33]);
 dimension('domestic-apps','国内软件安装与启动记录',[41,42]);dimension('dev-mirror','开发镜像配置',[43]);
 dimension('organization','组织域',[44]);dimension('photo-location','照片地点',[48]);
 dimension('selected-documents','本机文档及图片联系字段',[49,50]);dimension('messages','消息与日历联系字段',[51]);
 dimension('saved-address','浏览器保存地址',[52]);dimension('account-login','导入账号登录地区',[56]);
 dimension('account-region','导入注册或支付地区',[57]);dimension('external-history','导入历史关联资料',[59,60,61]);
 const icon='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="3" width="16" height="18" rx="3"/><path d="m8 10 2 2 5-5M8 16h8"/></svg>';
 const definitions=Object.freeze(catalog.map(([id,name,category,description])=>{
  const p=policy.get(id),f=p&&familiesById.get(p.familyId);
  return Object.freeze({id,name:publicText(name),title:publicText(name),category:publicText(category),description:publicText(description),icon,familyId:f?f.id:null,familyName:f?f.name:(id===68?'跨来源汇总':'不提供地区风险证据'),evidenceFamily:p?p.evidenceFamily:(id===68?'地区偏好':''),weight:p?p.basePoints:0,factor:p?1:0,potentialPoints:p?p.basePoints:0,...dimensionPolicy.get(id),aggregate:id===68});
 }));
 function clean(value){return typeof value==='string'?value.trim():'';}
 const isObject=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
 function riskBand(value){return value<=30?'low':value<=60?'medium':'high';}
 function publicText(value){return clean(value).replace(/发现线索/g,'发现风险').replace(/不是线索/g,'未发现风险').replace(/是线索/g,'发现风险').replace(/中国用户线索/g,'中国地区风险特征').replace(/线索/g,'风险特征');}
 function findingKey(f){return JSON.stringify([f.State,f.SupportedClaim,f.EvidenceFamily,f.MatchingEvidence,f.Reasoning,f.Summary]);}
 function indexFindings(rows){
  const indexed=new Map(),conflicts=new Set();
  for(const f of rows){if(!isObject(f))continue;const id=Number(f.Id);if(!Number.isInteger(id)||id<1||id>69)continue;if(!indexed.has(id))indexed.set(id,f);else if(findingKey(indexed.get(id))!==findingKey(f))conflicts.add(id);}
  return {indexed,conflicts};
 }
 function positiveClaim(f){const claim=clean(f.SupportedClaim);return !!claim&&!/(?:不支持|尚无|缺少|没有|未取得|未完成|未检测)/.test(claim);}
 function signalFor(def,raw,conflict){
  const row={...def,status:'unknown',points:null,value:'尚未检测',reason:'没有完成该项，不能视为通过。',supportedClaim:'',raw:raw||null,duplicate:false,attempted:false};
  if(!raw)return row;
  const state=clean(raw.State),claim=clean(raw.SupportedClaim);
  row.value=publicText(raw.Observation||raw.Summary)||'没有有效观察';row.supportedClaim=publicText(claim);row.reason=publicText(raw.Reasoning||raw.Summary)||row.reason;row.attempted=clean(raw.Summary)!=='尚未执行或未满足所需条件'&&(!!clean(raw.CheckedAt)||!['','未检测'].includes(state));
  if(conflict){row.status='failed';row.reason='同一检测项出现冲突记录，未生成风险结论。';return row;}
  if(state==='读取失败'||state==='缺少依赖'){row.status='failed';const summary=publicText(raw.Summary);if(summary)row.reason=summary+(clean(raw.Reasoning)&&clean(raw.Reasoning)!==clean(raw.Summary)?'；'+publicText(raw.Reasoning):'');return row;}
  if(state==='需外部证据'||state==='需要外部证据'||state==='需外部记录'||state==='需要外部记录'){row.status='external';return row;}
  if(state==='未发现'){
   // Only an explicit completed backend negative is a zero; pending/failed data
   // and generic presence of a value never become a negative here.
   if(raw.IsClue===true){row.reason='结果状态与判断字段冲突，未生成风险结论。';return row;}
   row.status='clear';row.points=0;row.reason=publicText(raw.Reasoning||claim||raw.Summary)||'本次已检查范围未发现支持中国大陆关联的风险特征。';return row;
  }
  if(state==='发现线索'){
   if(raw.ObservationKind==='browser-network'){
    const expected=def.id===6?'网络解析关联':'网络出口';
    if(![1,3,6].includes(def.id)||clean(raw.EvidenceFamily)!==expected||!/(?:country|国家)\s*[:=]\s*CN\b/i.test(clean(raw.MatchingEvidence))){row.reason='浏览器路径缺少明确 CN 国家命中证据，路径差异不能判为中国风险。';return row;}
    if(def.id===6)Object.assign(row,{evidenceFamily:'网络解析关联',weight:18,factor:1,potentialPoints:18});
   }
   // BrowserImport deliberately distinguishes unsigned imported records from
   // real-time local observations. Keep that distinction in family and weight.
   if(def.id===12&&clean(raw.EvidenceFamily)==='导入记录地点'){
    const family=familiesById.get('documentLocation');Object.assign(row,{familyId:family.id,familyName:family.name,evidenceFamily:'导入记录地点',weight:3,factor:1,potentialPoints:3,dimensionId:'imported-location',dimensionName:'用户导入定位记录'});
   }else if(def.id===53&&clean(raw.EvidenceFamily)==='地图地区偏好'){
    const family=familiesById.get('regional');Object.assign(row,{familyId:family.id,familyName:family.name,evidenceFamily:'地图地区偏好',weight:4,factor:1,potentialPoints:4,dimensionId:'saved-map',dimensionName:'地图收藏或默认地区'});
   }else if(def.id===58&&clean(raw.EvidenceFamily)==='导入地区偏好'){
    Object.assign(row,{evidenceFamily:'导入地区偏好',weight:4,factor:1,potentialPoints:4});
   }
   if(raw.IsClue===false||!positiveClaim(raw)||!clean(raw.MatchingEvidence)){
    row.reason='缺少明确的中国关联判断或命中证据，尚不能形成风险结论。';return row;
   }
   if(def.aggregate){
    // Check 68 only restates other real country/locale observations.
    if(clean(raw.EvidenceFamily)!=='地区偏好'){row.reason='汇总记录缺少匹配的证据类型，未独立评分。';return row;}
    row.status='matched';row.points=0;row.duplicate=true;row.scoringReason='本项汇总其他检测的字段，不重复加分。';row.reason=publicText(raw.Reasoning||claim)+'；'+row.scoringReason;return row;
   }
   if(!row.familyId||clean(raw.EvidenceFamily)!==row.evidenceFamily){row.reason='检测记录没有与本项规则匹配的中国关联证据类型，未生成风险结论。';return row;}
   row.status='matched';row.points=0;return row;
  }
  if(def.familyId==='external'&&!['信息','未发现'].includes(state)){row.status='external';}
  return row;
 }
 function asSource(raw,label,observed){
  const source={Source:label,ObservedAt:raw.CheckedAt||observed||'',State:raw.State||'未检测'};
  for(const key of ['Summary','Evidence','Coverage','Observation','SupportedClaim','Reasoning','MatchingEvidence','EvidenceFamily','AlternativeExplanation'])if(raw[key]!==undefined)source[key]=raw[key];
  return source;
 }
 function mergeBrowserFinding(def,local,browser,report){
  const localRow=local||{Id:def.id,State:'未检测',Summary:'本机未取得此项结果'},browserRow={...browser,Id:def.id,ObservationKind:'browser-network'};
  const localSignal=signalFor(def,localRow,false),browserSignal=signalFor(def,browserRow,false),rank=s=>s.status==='matched'?100+s.potentialPoints:s.status==='clear'?50:s.status==='failed'?10:s.status==='external'?5:0;
  if(browserRow.State==='发现线索'&&browserSignal.status!=='matched'){browserRow.State='不可判定';browserRow.IsClue=null;browserRow.Summary=browserSignal.reason;browserRow.Reasoning=browserSignal.reason;}
  const useBrowser=rank(browserSignal)>rank(localSignal),primary=useBrowser?browserRow:localRow;
  const sources=Array.isArray(localRow.Sources)&&localRow.Sources.length?localRow.Sources.map(source=>({...source})): [asSource(localRow,'本次本机检查',localRow.CheckedAt)];
  sources.push(asSource(browserRow,def.id===1?'本次浏览器 HTTPS 出口':def.id===3?'本次浏览器 WebRTC 路径':'本次浏览器递归 DNS',report.FinishedUtc));
  const missed=sources.filter(source=>!['发现线索','未发现'].includes(clean(source.State)));
  const evidence=sources.map(source=>'【'+source.Source+'】'+(source.ObservedAt?' '+source.ObservedAt:'')+'\n状态：'+source.State+'\n'+(source.Summary||'')+'\n'+(source.Evidence||'')).join('\n\n');
  return {...primary,Id:def.id,Title:def.name,Category:def.category,Sources:sources,Evidence:evidence,ObservationKind:useBrowser?'browser-network':primary.ObservationKind,Observation:primary.Observation||primary.Summary||'',Reasoning:(primary.Reasoning||primary.Summary||'')+(missed.length?'；另有 '+missed.length+' 个来源没有有效结果，原因保留在各来源记录中。':''),Coverage:(primary.Coverage||'')+' / 本机与当前浏览器分别保留 '+sources.length+' 个来源'};
 }
 function score(input){
  const state=isObject(input)?input:{},rows=Array.isArray(state.findings)?state.findings:Array.isArray(state.Findings)?state.Findings:[],{indexed,conflicts}=indexFindings(rows);
  const browserNetworkRunning=state.browserNetworkRunning===true||(state.browserNetworkExpected===true&&state.browserNetworkDone!==true),network=!browserNetworkRunning&&(state.browserNetwork||state.BrowserNetwork),networkRows=Array.isArray(network?.Findings)?network.Findings:[],networkIndex=indexFindings(networkRows);
  const signals=definitions.map(def=>{
   const browser=networkIndex.indexed.get(def.id),local=indexed.get(def.id),merged=browser&&[1,3,6].includes(def.id)?mergeBrowserFinding(def,local,networkIndex.conflicts.has(def.id)?{Id:def.id,State:'读取失败',Summary:'浏览器同项结果冲突，已跳过该来源'}:browser,network):local;
   return signalFor(def,merged,conflicts.has(def.id));
  });
  const running=state.running===true,hasReport=state.hasReport===true||Array.isArray(state.Findings),finished=hasReport&&!running&&!browserNetworkRunning,scanCompleted=hasReport&&!running&&state.completed===true,cancelled=state.batchCancelled===true||state.cancelled===true||hasReport&&!running&&state.completed===false;
  const sourceSkippedCount=finished?signals.reduce((sum,s)=>sum+(Array.isArray(s.raw?.Sources)?s.raw.Sources.filter(source=>!['发现线索','未发现'].includes(clean(source.State))).length:0),0):0;
  for(const s of signals){s.originalStatus=s.status;if(finished&&!['matched','clear'].includes(s.status)){s.status='skipped';s.skipReason=s.reason;s.value=publicText(s.raw?.Summary)||'本次没有有效结果';s.points=null;}}
  const rank=(a,b)=>b.potentialPoints-a.potentialPoints||a.id-b.id,contributors=[];
  for(const family of familyDefinitions){
   const groups=new Map();
   for(const s of signals.filter(s=>s.familyId===family.id&&s.status==='matched')){
    if(!groups.has(s.dimensionId))groups.set(s.dimensionId,[]);groups.get(s.dimensionId).push(s);
   }
   const winners=[...groups.values()].map(members=>{
    members.sort(rank);const winner=members[0];
    for(const s of members.slice(1)){s.points=0;s.rawPoints=0;s.discount=0;s.duplicate=true;s.duplicateOf=winner.id;s.scoringReason='与 #'+winner.id+' 同属「'+s.dimensionName+'」维度，重叠观察只计较强项，本项保留风险结果。';s.reason+='；'+s.scoringReason;}
    return winner;
   }).sort(rank);
   contributors.push(...winners);
  }
  const correlationLeaders=new Map();
  for(const s of contributors.slice().sort(rank)){const g=correlationPolicy.get(s.id);if(g&&!correlationLeaders.has(g.id))correlationLeaders.set(g.id,s);}
  for(const s of contributors){
   const g=correlationPolicy.get(s.id),leader=g&&correlationLeaders.get(g.id);
   s.correlationGroup=g?g.id:null;s.correlationName=g?g.name:null;s.correlationLeader=leader?leader.id:null;
   s.discount=g&&leader!==s?g.discount:1;s.rawUnits=Math.round(Math.round(s.potentialPoints*10)*Math.round(s.discount*100)/100);s.rawPoints=s.rawUnits/10;s.duplicate=false;
   const explanation=!g?'独立维度全额':leader===s?'「'+g.name+'」相关组最强项全额':'与 #'+leader.id+' 属「'+g.name+'」相关组，保留 '+(g.discount*100)+'% 贡献';
   s.scoringReason='「'+s.dimensionName+'」基础 '+s.potentialPoints+' 分 × '+(s.discount*100)+'% ＝ '+s.rawPoints+' 分（'+explanation+'）。';
  }
  // Allocate integer tenths, so capping is proportional, order-independent and
  // the displayed row contributions still add to exactly 100 at saturation.
  const rawUnits=contributors.reduce((sum,s)=>sum+s.rawUnits,0),targetUnits=Math.min(1000,rawUnits),scale=rawUnits>1000?1000/rawUnits:1;
  for(const s of contributors){s.finalUnits=Math.floor(s.rawUnits*scale);s.remainder=s.rawUnits*scale-s.finalUnits;}
  const remainderOrder=contributors.slice().sort((a,b)=>b.remainder-a.remainder||a.id-b.id);
  const remaining=targetUnits-contributors.reduce((sum,s)=>sum+s.finalUnits,0);
  for(let index=0;index<remaining;index++)remainderOrder[index].finalUnits++;
  for(const s of contributors){s.points=s.finalUnits/10;if(scale<1)s.scoringReason+=' 原始合计 '+rawUnits/10+' 分，统一压缩至 100，本项计 '+s.points+' 分。';s.reason+='；'+s.scoringReason;delete s.finalUnits;delete s.remainder;delete s.rawUnits;}
  const families=familyDefinitions.map(def=>{
   const members=signals.filter(s=>s.familyId===def.id),positives=members.filter(s=>s.status==='matched'),active=positives.filter(s=>!s.duplicate),points=Math.round(active.reduce((sum,s)=>sum+s.points*10,0))/10;
   return {...def,points,scoreMax:points,dimensionCount:active.length,rawPoints:Math.round(active.reduce((sum,s)=>sum+s.rawPoints*10,0))/10,supportingIds:positives.map(s=>s.id),contributorIds:active.map(s=>s.id),skippedIds:members.filter(s=>s.status==='skipped').map(s=>s.id)};
  });
  const total=targetUnits/10,validCount=signals.filter(s=>s.status==='matched'||s.status==='clear').length,skippedCount=signals.filter(s=>s.status==='skipped').length;
  const failedCount=signals.filter(s=>s.originalStatus==='failed').length,externalCount=signals.filter(s=>s.originalStatus==='external').length,pendingCount=signals.filter(s=>s.status==='unknown').length;
  const progress=Number.isFinite(state.progress)?Math.max(0,Math.min(69,Math.trunc(state.progress))):null,processedCount=progress===null?signals.filter(s=>s.attempted||s.status==='matched'||s.status==='clear').length:progress;
  return {score:total,rawScore:rawUnits/10,normalizationScale:scale,scoringVersion:'3.0',band:riskBand(total),scoreMax:total,complete:finished&&!cancelled,finished,scanCompleted,running:running||browserNetworkRunning,localRunning:running,browserNetworkRunning,cancelled,signals,matchedSignals:signals.filter(s=>s.status==='matched'),families,validCount,completedCount:validCount,totalCount:69,processedCount,failedCount,externalCount,pendingCount,unknownCount:signals.filter(s=>!['matched','clear','skipped'].includes(s.status)).length,skippedCount,sourceSkippedCount,sourcePendingCount:0,sourcePending:[],snapshot:state,method:METHOD,source:SOURCE};
 }
 return Object.freeze({version:'3.0',definitions,dimensions:Object.freeze(dimensionDefinitions),correlations:correlationDefinitions,families:familyDefinitions,familyDefinitions,score,riskBand,publicText,source:SOURCE,method:METHOD,methodSummary:SUMMARY_METHOD});
});
