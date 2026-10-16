using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
namespace LocalLens {
 public sealed class ChinaUserAssessment {
  public bool? IsClue {get;set;} public string Summary {get;set;}
  public string[] EvidenceFamilies {get;set;} public int[] SupportingChecks {get;set;}
  public string Scope="判断中国大陆用户关联，不鉴定国籍或民族；同一组语言设置和重复网络出口不重复当成独立证据。";
  public static ChinaUserAssessment Create(IEnumerable<Finding> items,BrowserNetworkReport network){
   var rows=(items??new Finding[0]).Concat(network==null?(IEnumerable<Finding>)new Finding[0]:network.Findings??new List<Finding>()).ToArray();
   var positive=rows.Where(f=>f.IsClue==true&&f.Id!=68&&!String.IsNullOrWhiteSpace(f.SupportedClaim)).ToArray();
   var families=positive.Select(f=>f.EvidenceFamily).Where(s=>!String.IsNullOrWhiteSpace(s)).Distinct().ToArray();
   return new ChinaUserAssessment{IsClue=positive.Length>0?(bool?)true:rows.Any(f=>f.IsClue.HasValue)?false:(bool?)null,
    Summary=positive.Length>0?"是线索：实际记录支持 "+families.Length+" 类中国大陆关联；逐项查看它支持的判断与其他解释":rows.Any(f=>f.IsClue.HasValue)?"不是线索：已完成项目没有取得支持中国大陆用户关联的证据":"尚无已完成的中国用户关联判定",EvidenceFamilies=families,SupportingChecks=positive.Select(f=>f.Id).Distinct().OrderBy(id=>id).ToArray()};
  }
 }
 public static class ChinaEvidence {
  const string LocaleSource="https://www.rfc-editor.org/rfc/rfc5646";
  const string GeoSource="https://www.naturalearthdata.com/downloads/10m-cultural-vectors/10m-admin-0-details/";
  const string IpSource="https://support.maxmind.com/knowledge-base/articles/maxmind-geolocation-accuracy";
  public static string[] Sources(int id){
   if(new[]{1,2,3,5,6,10}.Contains(id))return new[]{IpSource};
   if(id==12||id==48)return new[]{GeoSource,"https://www.naturalearthdata.com/about/terms-of-use/"};
   if(id==15)return new[]{"https://www.itu.int/dms_pub/itu-t/opb/sp/T-SP-E.212B-2023-PDF-E.pdf"};
   if(id==28)return new[]{"https://learn.microsoft.com/en-us/typography/fonts/windows_11_font_list","https://learn.microsoft.com/windows/deployment/windows-10-missing-fonts"};
   if(id>=17&&id<=27||id==37||id==38||id==55||id==58)return new[]{LocaleSource};
   return new string[0];
  }
  // These rules describe the inferential target, not just whether data exists.
  static readonly string[] rules={"",
   "有效公网 IPv4 的地理查询国家为 CN，支持中国大陆网络出口关联；其他国家不支持。IP/代理出口不等于本人位置。",
   "有效公网 IPv6 的地理查询国家为 CN，支持中国大陆网络出口关联；不能把 IPv4 代答算成 IPv6。",
   "只有被地理归属资料标记为 CN 的实际路径才支持中国关联；IPv4/IPv6、UDP/HTTPS 地址不同本身不支持。",
   "适配器、私网地址、虚拟网卡不含用户国家信息，不支持中国用户关联。",
   "使用本次出口的国家地理字段 CN；运营商品牌、ASN 注册国家或公司名称本身不能替代出口地理归属。",
   "明确配置中国公共解析服务，或实际递归解析器被地理资料标记为 CN，支持中国网络服务关联；不把网卡配置冒充实际 DNS 出口。",
   "未有地理归属的路由跳点与超时不能支持中国关联。",
   "到区域服务器的延迟受代理、拥塞、路由和服务器影响；无地理证据时不支持中国用户关联。",
   "网站可达或不可达有多种网络原因；单靠通断不支持中国用户关联。",
   "持续样本中至少一条有效出口被地理资料标记为 CN，才支持中国网络关联；只改变 IP 或接口不支持。",
   "允许定位是采集权限，不包含任何中国地区证据。",
   "有效定位点落在离线 CN 地域多边形内，且其精度范围远离边界，支持该次设备位置在中国大陆；其他坐标不支持。",
   "BSSID 必须有可信的中国大陆地理映射才支持地域；当前只采集地址，不能据地址存在判定中国用户。",
   "实际 SSID 名称出现 ChinaNet、CMCC、中国电信等明确国内无线服务标识，即保留网络名称关联风险；仅普通汉字不命中，不冒充接入点地理定位。",
   "注册网络明确返回 MCC=460 或 460 开头的 PLMN，支持中国大陆蜂窝网络关联；品牌名及接口存在不足以替代注册字段。",
   "附近设备、打印机和蓝牙配对记录没有用户国家字段，不支持中国用户关联。",
   "当前用户 Geo Name=CN 或 Windows GeoID=45，是明确的中国大陆地区选择；不是物理定位或国籍。",
   "当前界面、首选语言或安装语言存在 CN、中文或简体配置，就命中语言环境关联；分别说明当前偏好与安装痕迹，不要求证明本人所在地。",
   "实际系统区域字段为 CN 地区标签、zh 或 zh-Hans，命中中文地区环境关联；保留原始值，不把简体标签改写为 CN 国家。",
   "实际 LocaleName 为 CN 地区标签、zh 或 zh-Hans，命中中文区域偏好；不使用自定义货币和日期文本冒充语言字段。",
   "实际 LanguageTag 列表出现 CN、zh 或 zh-Hans 即命中；无需是第一语言。显式 SG/HK/TW 地区不自动改写为大陆。",
   "Preload 任一实际键盘项含 0804 都命中中文输入环境；非首选项也保留，不再要求它是第 1 项。",
   "明确的中国命名时区是时区偏好线索；只有 UTC+8 偏移不足以关联中国，同一区域设置不重复计作独立证据。",
   "其他已加载用户实际区域字段出现 CN、zh 或 zh-Hans，命中设备上的中文配置痕迹；不归属为当前本人配置。",
   "浏览器实际语言偏好含 CN、zh 或 zh-Hans 即命中；不要求默认第一语言，不从路径或页面文字猜测。",
   "Office 当前/安装中文语言字段或 Steam 实际 schinese 设置即命中应用中文环境；不把安装语言冒充当前使用语言。",
   "仅从 LANG/LANGUAGE/LC_* 的中文/CN 标签或 TZ 中国命名时区命中；代理 URL、路径和注释不参与。",
   "实际字体清单出现宋体、微软雅黑等列明简体字体，命中可见中文环境风险；即使是预装也保留，说明它不能证明本人身份或位置。",
   "保存的 SSID 名称含列明中国无线服务标识即命中历史网络名称关联；不用普通汉字或任意地点词代替地理归属。",
   "实际无线事件的 SSID 字段出现列明中国无线服务标识即命中；不从中文事件说明判断国家。",
   "系统保存的网络名称含列明中国无线服务标识即命中名称关联；名称可修改，不能据此定位。",
   "代理/VPN 的存在不含中国地区信息，不支持中国用户关联。",
   "实际 DNS 缓存 Entry/RecordName 命中列明国内服务的完整主机边界，即命中国内服务解析痕迹；后台解析也保留，但不声称本人访问。",
   "近 90 天至少一条有效 HTTP(S) 真实 visits 记录命中国内服务主体即命中；不再要求多日、多主体或三次访问。URL 展示表、下载和任意 .cn 字符串不能冒充真实访问。",
   "实际 IndexedDB/Firefox 存储 origin 主机命中国内服务主体即命中；不再要求历史记录同时成功。保留后台/嵌入组件的可能，不声称本人登录。",
   "最近文件的汉字名称和路径没有用户国家字段，不支持中国用户关联。",
   "安装日志中的明确 UILanguage/SystemLocale/UserLocale/InputLocale 等字段带 CN，支持历史大陆配置；孤立中文文字不算。",
   "Windows.old 的明确语言地区配置字段带 CN，只支持旧系统大陆配置历史；不替代当前偏好。",
   "回收站名称和路径中的汉字不支持中国用户关联。",
   "无上下文的内存/转储语言字符串可能来自程序资源；不能证明用户配置或中国用户关联。",
   "实际安装清单或本次运行进程中有一个列明国内软件主体即命中；不再要求两个主体和正在运行同时成立。",
   "实际启用启动项、自动服务或启用任务含一个列明国内软件主体即命中；不再要求扫描瞬间也有进程。",
   "用户配置中有效 URL 的主机名确切属于列明的国内镜像/代码托管服务，支持国内开发生态偏好；注释、字符串相似域名不算。",
   "确实加入的组织域以 .cn 结尾，支持中国组织域关联；工作组名称和未加入的域不算本人组织配置。",
   "制造商、型号和 OEM 品牌没有用户地区记录，不支持中国用户关联。",
   "硬件哈希只能关联设备；必须有该设备的中国使用/销售记录才有地域意义，哈希存在本身不算。",
   "厂商、驱动提供者和签名不等于用户国家，不支持中国用户关联。",
   "照片 GPS 点经离线 CN 多边形校验且远离边界，支持已读取照片的大陆地点关联；东京坐标、无 GPS、仅存在 GPS 标签不命中。照片不自动归属于本人拍摄。",
   "成功 OCR 得到明确的居住/收货/联系地址或 +86 联系字段，才支持中国联系资料关联；旅游说明、百科地名、汉字和孤立城市名不算。",
   "已读取文档有明确居住/收货/账单国家 CN 或带大陆行政区与街路门牌的地址字段，才支持中国联系资料关联；正文提及中国/北京不算。",
   "已读取 EML/ICS/VCF 的地址/居住国家/联系字段明确关联大陆，才支持该资料的中国关联；普通正文、发件品牌和地点提及不算。",
   "真实自动填充国家字段为 CN/China/中国/中国大陆，支持保存的中国地址资料；没有国家的孤立城市词不作为足够证据；不读取付款卡和完整街道。",
   "天气/地图同一缓存对象内的当前位置或收藏/默认地点明确 countryCode=CN 即命中；收藏和默认地点只判地区偏好，不能冒充设备定位。",
   "同步/备份目录存在与用户国家无关，不支持中国用户关联。",
   "文件字段明确记录 Asia/Shanghai、Asia/Chongqing 或 China Standard Time，支持该文件的中国命名时区关联；UTC+8、+0800 和普通时间戳不算。",
   "本人导入的账号历史记录明确 countryCode=CN，支持该记录标注的中国登录历史；保留来源与时间，不把未验证文件称为平台证明。",
   "导入的注册/支付地区字段明确为 CN，支持所提供记录的大陆地区关联；不从货币符号或界面语言猜测。",
   "浏览器实际 language/languages/locale 含 CN、zh 或 zh-Hans，或中国命名 timeZone 即命中；保留中文偏好与明确国家标签的区别。",
   "导入的同设备关联记录明确 countryCode=CN，只支持记录所声称的历史大陆关联；不自动验证身份或平台签名。",
   "导入的跨设备记录明确 countryCode=CN，只支持所提供的大陆关联记录；不从硬件相似性猜测地区。",
   "导入的服务商资料明确 countryCode=CN，只支持来源记录的大陆关联；缺少国家字段不生成否定结论。",
   "录屏/远控软件能力与用户是否为中国用户无关，不算中国用户线索。",
   "键盘/剪贴板工具能力与中国地区无关，不算中国用户线索。",
   "摄像头/麦克风的许可及使用时间没有地区内容，不算中国用户线索。",
   "配置哈希改变只能说明变化，未给出中国归属时不算中国用户线索，也不据此称为恶意修改。",
   "扩展拥有敏感权限是隐私能力事实，不提供中国用户地域证据。",
   "系统后台事件的小时分布既不是明确本人作息也没有中国地域标签，不算中国用户线索。",
   "汇总实际中国网络/地区字段及中文环境关联，不要求每一来源都为 CN；汇总只展示关联，不重复评分。",
   "拒绝定位、代理、防跟踪和权限保护不支持中国用户关联。"
  };
  
  public static string Rule(int id){if(id<1||id>=rules.Length)throw new ArgumentOutOfRangeException("id");return rules[id];}
  static readonly Dictionary<int,string> exclusions=new Dictionary<int,string>{
   {4,"只有接口信息，没有中国国家或地区记录"},{7,"路由/跳点没有经过中国地域归属校验"},{8,"延迟不能区分中国、代理位置和路由差异"},{9,"网站通断不能区分中国网络与普通网络故障"},{11,"定位权限只有允许/拒绝，不含位置国家"},{13,"BSSID 未映射到中国地域数据库"},{16,"设备配对和邻居信息没有国家字段"},{32,"代理工具不能说明用户来自中国"},{36,"汉字文件名不是中国特有的地域记录"},{39,"回收站路径/名称中的汉字不能定位用户国家"},{40,"转储中的孤立语言字符串没有对应的有效用户配置"},{45,"设备品牌不说明购买地或用户地区"},{46,"设备哈希没有与中国历史记录建立关联"},{47,"驱动厂商和签名不说明用户国家"},{54,"备份目录不含中国地区记录"},{62,"录屏能力不说明中国用户关联"},{63,"键盘或剪贴板能力不说明中国用户关联"},{64,"摄像头/麦克风使用记录没有中国地区内容"},{65,"哈希变化没有中国地区语义"},{66,"扩展权限不包含用户国家证据"},{67,"后台事件没有可靠的本人作息与中国地域标签"},{69,"隐私保护选择没有中国地区语义"}
  };
  static void Decide(Finding f,bool hit,string claim,string family,string matches,string why,string alternative){
   f.State=hit?"发现线索":"未发现";f.SupportedClaim=hit?claim:"本项观察不支持中国大陆用户关联";f.EvidenceFamily=hit?family:"";
   f.Summary=hit?claim:why;f.Reasoning=why;f.MatchingEvidence=hit?Rules.TrimEvidence(matches):"";f.AlternativeExplanation=alternative;f.Strength=hit?family:"不支持中国关联";
  }
  static void Pending(Finding f,string reason){f.State="未检测";f.Summary=reason;f.Reasoning=reason;f.SupportedClaim="缺少完成中国关联判断所需的数据";f.MatchingEvidence="";f.EvidenceFamily="";f.Strength="未完成";}
  public static Finding Apply(Finding f){
   f.Observation=f.Summary;f.SupportedClaim="";f.Reasoning="";f.MatchingEvidence="";f.EvidenceFamily="";f.AlternativeExplanation="";
   if(!new[]{"发现线索","未发现","信息"}.Contains(f.State)){f.SupportedClaim="检测状态，尚无中国用户关联结论";return f;}
   string text=f.Evidence??"",reason;bool hit=false;string matches="",family="地区偏好",claim="实际配置存在中文或中国地区环境关联",alternative="地区配置也可由管理员、镜像或本人手动选择；支持地区偏好，不证明国籍或当前所在地。";
   if(exclusions.TryGetValue(f.Id,out reason)){
    if((f.Id==8||f.Id==9)&&!Regex.IsMatch(text,@"HTTP \d{3}")){f.State="读取失败";f.Summary="探测没有返回 HTTP 响应，未生成中国关联判定";return f;}
    Decide(f,false,"","","",reason,"");return f;
   }
   switch(f.Id){
    case 1:case 2:case 3:case 5:case 10:
     matches=MatchLines(text,@"(?i)(?:国家(?:代码)?|country_code|countryCode|出口国家|网络国家)\s*[""']?\s*[:=：]\s*[""']?CN\b");hit=matches.Length>0;
     family="网络出口";claim="实际网络路径具有中国大陆出口归属";reason=hit?"实际请求/采样的国家地理字段为 CN，形成设备的中国网络关联；只使用该字段，不用运营商品牌或地址变化代替。":"所读出口没有 CN 地理归属证据；路径/接口不同本身不指向中国";alternative="代理、远端浏览器和数据库误差可改变出口归属；只说明该路径，不能定位操作者。";break;
    case 6:
     matches=String.Join("\r\n",Values(Marker(text,"DNS_CONFIGURATION"),"addresses").Where(DnsConfigurationAssessment.KnownChinaService).Distinct());hit=matches.Length>0;family="中国网络服务";claim="网卡明确配置了中国公共 DNS 服务";reason=hit?"实际 DNS 地址字段命中所列公共 DNS 服务，支持中国网络服务使用关联；网卡名称不参与，配置与实际递归出口分别判断。":"实际 DNS 配置未命中国公共服务；不据此断言浏览器递归出口";alternative="公共 DNS 可在海外使用，也可由路由器或管理员配置；该条不是本人在中国的定位证据。";break;
    case 12:case 48:
     var positions=Coordinates(text);if(positions.Count==0){if(f.State=="信息"||f.Id==12){Pending(f,"未取得可用于中国地域校验的有效坐标");return f;}reason="成功读取的图片没有有效中国大陆 GPS 点";break;}
     int unknown=0;var located=new List<string>();foreach(var p in positions){if(Double.IsNaN(p[2])){unknown++;continue;}bool? inside=ChinaGeography.IsMainland(p[0],p[1],p[2]);if(!inside.HasValue)unknown++;else if(inside.Value)located.Add(p[0].ToString("F6",CultureInfo.InvariantCulture)+", "+p[1].ToString("F6",CultureInfo.InvariantCulture));}
     if(located.Count==0&&unknown>0){Pending(f,"定位精度范围或 2 km 地图边界余量跨越边界，无法完成大陆地域判定");return f;}
     hit=located.Count>0;matches=String.Join("\r\n",located);family=f.Id==12?"设备位置":"资料地点";claim=f.Id==12?"本次设备定位范围落在中国大陆":"已读取照片记录了中国大陆地点";
     reason=hit?"有效坐标通过离线 CN 多边形校验，距边界大于精度半径及 2 km 保守余量。":"有效坐标未落在大陆地域内；坐标存在本身不支持中国用户";alternative=f.Id==12?"定位由系统融合服务提供，来源可能有误；这是该次设备位置，不证明国籍。":"照片可下载、转发、修改或由他人拍摄；支持资料地点关联，不声称本人拍摄或当前在中国。";break;
    case 14:case 29:case 30:case 31:
     matches=AssociationSignals.WirelessNames(text,f.Id==30);hit=matches.Length>0;family="无线网络名称";claim="实际无线或网络名称含中国服务标识";reason=hit?"实际名称字段命中列明中国无线服务标识；不因名称可修改就抹去关联，也不据此认定地理位置。":"实际名称字段未命中列明中国无线服务标识；普通汉字不单独触发";alternative="名称可自定义、复制或在海外使用；附近网络不等于本人连接，保存名称也不能定位。";break;
    case 28:
     matches=AssociationSignals.Fonts(text);hit=matches.Length>0;family="中文字体环境";claim="设备可见字体包含列明简体中文资源";reason=hit?"实际字体名称命中简体字体清单；预装解释降低证据强度，不抹去可被观察到的中文环境特征。":"实际字体清单没有命中列明简体中文字体";alternative="字体可能由系统或软件预装，也可能用于阅读外语资料；只表示中文环境关联风险，不证明本人身份或位置。";break;
    case 33:
     matches=AssociationSignals.DnsCache(text);hit=matches.Length>0;family="国内服务解析";claim="系统 DNS 缓存出现国内服务的解析痕迹";reason=hit?"实际 Entry/RecordName 字段命中国内服务的完整域名边界；后台解析也保留为设备服务关联。":"实际 DNS 缓存字段未命中列明国内服务";alternative="后台、广告、预取或共享设备可产生解析；缓存不证明本人访问，不等于递归 DNS 出口。";break;
    case 15:
     matches=MatchLines(text,@"(?i)\b(?:MCC\s*[:=]\s*460\b|(?:PLMN|ProviderId)\s*[:=]\s*460[0-9]{2,3}\b)");hit=matches.Length>0;
     if(!hit&&!Regex.IsMatch(text,@"(?i)\b(?:MCC\s*[:=]\s*[0-9]{3}\b|(?:PLMN|ProviderId)\s*[:=]\s*[0-9]{5,6}\b)")){Pending(f,"未返回注册网络 MCC/PLMN；接口或中国运营商品牌不能替代国家字段");return f;}
     family="蜂窝网络";claim="注册网络代码指向中国大陆蜂窝网络";reason=hit?"实际 MCC/PLMN 的国家段为 460，而非从公司名称猜测。":"实际注册网络 MCC/PLMN 未指向 460";alternative="漫游、SIM 归属与当前物理位置可能不同；不从网络代码推断国籍。";break;
    case 17:
     if(!Regex.IsMatch(text,@"(?im)^(Name|Nation)\s*=\s*(?:[A-Z]{2}|\d+)\s*$")){Pending(f,"没有有效用户地区字段");return f;}
     matches=MatchLines(text,@"(?im)^(?:Name\s*=\s*CN|Nation\s*=\s*45)\s*$");hit=matches.Length>0;reason=hit?"当前用户地区字段明确选择 CN/GeoID 45，直接支持大陆地区偏好。":"当前用户有效地区字段未选择中国大陆";break;
    case 18:matches=AssociationSignals.LocaleMatches(MatchLines(text,@"(?im)^(?:UI Culture|PreferredUILanguages)\s*="))+MatchLines(text,@"(?im)^(?:InstallLanguage|Default)\s*=\s*(?:0804|2052)\s*$");hit=matches.Length>0;reason=hit?"界面、用户语言或安装配置命中中文/CN 字段；安装痕迹也保留为环境关联，不要求证明本人当前使用。":"所读界面、用户及安装语言没有命中列明中文/CN 字段";break;
    case 19:case 20:case 21:case 24:case 25:
     if((f.Id==19||f.Id==21)&&!AssociationSignals.HasJsonField(text,f.Id==19?"Name":"LanguageTag")){Pending(f,"未取得可读取的实际语言区域字段");return f;}
     matches=f.Id==19?JsonLocaleFields(text,"Name"):f.Id==21?JsonLocaleFields(text,"LanguageTag"):f.Id==20?NamedLocaleFields(text,@"^LocaleName"):f.Id==24?NamedLocaleFields(text,@"^其他已加载用户配置 \d+ LocaleName"):AssociationSignals.LocaleMatches(MatchLines(text,@"^LANGUAGE_VALUES="));hit=matches.Length>0;family=f.Id==24?"其他用户地区配置":"地区偏好";claim=f.Id==24?"其他已加载用户配置存在中文地区关联":"实际区域或语言字段存在中文地区关联";reason=hit?"实际地区/语言字段命中 CN、zh 或 zh-Hans；保留原始标签，简体偏好不冒充明确国家代码。":"实际地区/语言字段未命中中文/CN 偏好规则";if(f.Id==24)alternative="已排除当前账户及系统服务账户；其他配置可能属于他人，不能据此声称本人曾使用该配置或确定历史时间。";break;
    case 22:matches=MatchLines(text,@"(?im)^\d+\s*=\s*(?:[0-9a-f]{4})?0804\s*$");hit=matches.Length>0;claim="实际键盘配置存在中国大陆中文输入区域";reason=hit?"实际 Preload 项包含 0804；无论首选还是附加项，均保留中文输入环境关联。":"实际键盘配置没有 0804 中文输入项";break;
    case 23:matches=MatchLines(text,@"(?i)^(?:China Standard Time|Asia/(?:Shanghai|Chongqing|Urumqi))$");hit=matches.Length>0;claim="当前使用中国命名时区偏好";reason=hit?"使用明确的中国命名时区，而非把 UTC+8 所有地区都算成中国。":"没有中国命名时区；普通 UTC+8 偏移不支持中国关联";alternative="命名时区可手动选择，Windows China Standard Time 也服务部分共享时区地区；只支持时区偏好，同类配置不重复计证。";break;
    case 26:matches=MatchLines(text,@"(?im)^(?:UILanguage|HelpLanguage|InstallLanguage)\s*=\s*(?:2052|0804)\s*$")+AssociationSignals.LocaleMatches(MatchLines(text,@"(?im)^(?:UILanguage|HelpLanguage|InstallLanguage)\s*="))+MatchLines(text,@"(?im)^Language\s*=\s*schinese\s*$");hit=matches.Length>0;reason=hit?"应用实际语言或安装字段命中中文/CN，包含 Steam schinese；各字段用途保留，不把安装配置称为当前界面。":"所读应用语言字段没有中文/CN 配置";break;
    case 27:matches=AssociationSignals.LocaleMatches(MatchLines(text,@"(?im)^(?:LANG|LANGUAGE|LC_[A-Z_]+)\s*="))+MatchLines(text,@"(?im)^TZ\s*=\s*Asia/(?:Shanghai|Chongqing|Urumqi)\b");hit=matches.Length>0;reason=hit?"白名单语言/时区变量存在中文/CN 或中国命名时区，形成环境偏好关联。":"有效语言/时区变量没有大陆地区标记；代理值和路径不参与判定";break;
    case 34:
     var activity=Marker(text,"DOMESTIC_ACTIVITY");hit=Number(activity,"visits")>=1&&Number(activity,"days")>=1&&Number(activity,"services")>=1&&Values(activity,"families").Any(KnownServiceFamily);matches=hit?"DOMESTIC_ACTIVITY="+new JavaScriptSerializer().Serialize(activity):"";
     family="持续服务使用";claim="浏览器实际访问过国内服务";reason=hit?"近 90 天实际 visits 记录至少有一次国内服务访问；不需要多个主体或跨日期，且不把 URL 展示表或域名字符串当成访问。":"已读取的有效访问记录没有命中国内服务主体";alternative="海外中文用户、旅游者、工作研究和共享浏览器也会产生这些行为；支持使用关联，不能证明所在地或国籍。";break;
    case 35:
     var stored=Values(Marker(text,"DOMESTIC_STORAGE"),"families").Where(KnownServiceFamily).Distinct().ToArray();
     matches=stored.Length>0?"DOMESTIC_STORAGE="+new JavaScriptSerializer().Serialize(new{families=stored}):MatchLines(text,@"^CORROBORATED_DOMESTIC_STORAGE=");hit=matches.Length>0;family="持续服务使用";claim="浏览器存在国内服务的实际网站存储";reason=hit?"实际 origin 目录命中国内服务主机；即使历史缺失也保留关联，不要求先证明持续访问。":"已读取的实际存储 origin 没有命中国内服务；权限声明不冒充网站存储";alternative="存储可能由后台、嵌入组件或共享配置产生；该结果表示设备上存在服务关联，不证明本人访问或登录。";break;
    case 37:case 38:matches=String.Join("\r\n",Regex.Matches(text,@"(?i)\b(?:UILanguage|SystemLocale|UserLocale|InputLocale|InstallLanguage)\b\s*[:=]\s*[""']?([a-z0-9_-]+)").Cast<Match>().Where(m=>SpecificLocaleMatches(m.Groups[1].Value).Length>0||Regex.IsMatch(m.Groups[1].Value,@"^(0804|00000804|2052)$")).Select(m=>m.Value).Distinct());hit=matches.Length>0;family="历史地区配置";claim="安装配置日志明确记录大陆语言区域";reason=hit?"安装字段及其 CN/0804 值同时存在，支持该系统历史配置。":"日志没有明确的字段和值配对；孤立资源字符串不作为用户配置";alternative="出厂镜像、管理员安装和旧用户都可留下该记录；只支持历史配置。";break;
    case 41:case 42:
     var software=Marker(text,"DOMESTIC_SOFTWARE");var installed=Values(software,"installed");var running=Values(software,"running");var enabled=Values(software,"enabled");
     hit=f.Id==41?installed.Concat(running).Any(KnownSoftwareFamily):enabled.Any(KnownSoftwareFamily);matches=hit?"DOMESTIC_SOFTWARE="+new JavaScriptSerializer().Serialize(software):"";family="软件生态使用";claim=f.Id==41?"实际安装或运行记录包含国内软件":"国内软件存在启用的启动、服务或任务配置";
     reason=hit?"实际采集记录命中列明国内软件主体；一个安装/运行主体或一个启用项目即可保留关联，不再要求同时运行或多个厂商。":"实际安装/运行或启用配置未命中列明国内软件主体";alternative="这些软件也服务海外用户和组织；只支持国内软件生态使用，不证明本人所在地。";break;
    case 43:
     matches=String.Join("\r\n",ConfigurationEvidence.ActiveUrls(text).Where(u=>MirrorHost(u.Host)).Select(u=>u.GetLeftPart(UriPartial.Authority)).Distinct());hit=matches.Length>0;family="开发服务偏好";claim="用户开发配置选择国内镜像或代码服务";reason=hit?"有效配置 URL 的完整主机名命中服务域名边界，支持配置偏好。":"没有有效的国内服务主机配置；注释和相似域名不算";alternative="组织模板、CI 配置和海外开发者也会采用国内镜像；只支持服务配置关联。";break;
    case 44:matches=MatchLines(text,@"(?im)^Domain\s*=\s*[^\r\n\s]+\.cn\s*$");hit=matches.Length>0&&Regex.IsMatch(text,@"(?im)^PartOfDomain\s*=\s*True\s*$");family="组织域关联";claim="本机已加入使用 .cn 域的组织";reason=hit?"域成员状态与中国国家域名同时成立，支持中国组织域关联。":"没有同时取得已加入状态与 .cn 组织域";alternative=".cn 域可用于跨国组织；它不是个人国籍或物理位置证明。";break;
    case 49:case 50:case 51:matches=String.Join("\r\n",ContactMatches(text));hit=matches.Length>0;family="联系资料关联";claim="已读取资料存在明确的中国大陆联系/地址字段";reason=hit?"命中的是带归属语义的地址/居住国家/联系字段，排除百科、旅游、孤立城市词和普通汉字。":"所读资料没有明确中国联系或地址字段；普通地名提及不足以关联用户";alternative="资料可属于他人、示例或转发内容；只证明所读资料的联系字段，不自动认定本人地址。";break;
    case 52:matches=MatchLines(text,@"(?i)/\s*(?:country|country_code|countrycode)\s*=\s*(?:CN|China|中国|中国大陆)\s*$");hit=matches.Length>0;family="联系资料关联";claim="浏览器保存了明确标注中国大陆国家的地址资料";reason=hit?"真实自动填充国家白名单字段明确为 CN/China/中国；其他独立保存的外国地址不会抹去该记录。":"自动填充没有明确的中国大陆国家字段；孤立省市词没有足够地区归属依据";alternative="地址可为收件人、公司或代填资料；支持保存资料的中国关联，不冒充当前所在地。";break;
    case 53:
     matches=MatchLines(text,@"^CURRENT_LOCATION_COUNTRY=CN$");bool currentLocation=matches.Length>0;if(!currentLocation)matches=MatchLines(text,@"^SAVED_LOCATION_COUNTRY=CN$");hit=matches.Length>0;family=currentLocation?"设备位置":"地图地区偏好";claim=currentLocation?"本地天气/地图的当前定位记录指向中国大陆":"天气/地图保存了明确的中国大陆地区偏好";reason=hit?(currentLocation?"同一缓存对象含当前定位标志与 CN 国家字段。":"同一缓存对象含收藏/默认位置标志与 CN 国家字段；保留地区偏好风险，不冒充当前定位。"):"没有取得当前或已保存位置的明确 CN 地区记录";alternative="缓存可由默认模板、同步或他人操作留下，也可能陈旧；保存偏好不证明当前所在地。";break;
    case 55:matches=MatchLines(text,@"(?i)(?:TZID|timeZone|timezone|时区)[^\r\n]{0,35}[:=]\s*[""']?(?:Asia/(?:Shanghai|Chongqing|Urumqi)|China Standard Time)");hit=matches.Length>0;family="历史地区配置";claim="已读取文件显式记录中国命名时区";reason=hit?"时区字段包含具体中国命名区域，排除任意 UTC 偏移和 +0800。":"只有 UTC 偏移、时间戳或未注明来源的时区文字，不能指向中国";alternative="时区来自文件生成工具或内容安排；共享时区和模板不能定位本人。";break;
    case 56:case 57:case 59:case 60:case 61:matches=MatchLines(text,@"国家=CN(?:\s*\||$)");hit=f.State=="发现线索";family="外部记录关联";claim="导入记录明确标注中国大陆地区";reason=hit?"解析并验证的记录提供 CN 国家字段、来源和观察时间；支持的是这份记录声称的中国关联，备注内的 CN 不参与判定。":"有效导入记录没有 CN 国家字段";alternative="用户导入文件未经平台签名验证，可陈旧、整理错误或属于其他人/设备，身份与设备归属未经核验；不称为已验证平台证明。";break;
    case 58:matches=RuntimeLocaleMatches(text);hit=matches.Length>0;claim="浏览器运行时存在中文或中国地区偏好";reason=hit?"只使用 language/languages/locale/timeZone 的有效中文/CN/命名时区值；不要求语言必须带 CN，不读取任意 UA 文本代替。":"实际浏览器字段没有命中中文/CN 语言或中国命名时区";break;
    case 68:
     if(!Regex.IsMatch(text,@"(?i)Windows 国家设置\s*[:=：]\s*[A-Z]{2}\b")||!Regex.IsMatch(text,@"(?i)出口国家\s*[:=：]\s*[A-Z]{2}\b")&&RuntimeLocaleMatches(text).Length==0&&!Regex.IsMatch(text,@"""(?:locale|language)""\s*:\s*""[a-z]{2,3}[-_](?:[A-Za-z]{4}[-_])?[A-Z]{2}""")){Pending(f,"缺少可比较的系统国家与其他来源地区字段");return f;}
     matches=MatchLines(text,@"(?i)(?:Windows 国家设置|出口国家)\s*[:=：]\s*CN\b");matches+=RuntimeLocaleMatches(text);hit=matches.Length>0;claim="跨来源实际国家/地区字段存在中国大陆关联";reason=hit?"实际系统、浏览器或网络字段命中 CN 或中文地区偏好，不由任意国家差异猜测。":"国家差异本身不指向中国；当前资料没有明确 CN 国家/地区字段";break;
    default:Pending(f,"本项尚无支持中国用户判断的有效资料");return f;
   }
   Decide(f,hit,claim,family,matches,reason,alternative);return f;
  }
  public static string MatchLines(string text,string pattern){return String.Join("\r\n",(text??"").Replace("\r","").Split('\n').Where(line=>Regex.IsMatch(line,pattern)).Distinct().Take(16));}
  public static string SpecificLocaleMatches(string text){return String.Join(", ",Regex.Matches(text??"",@"(?i)(?<![a-z0-9_-])[a-z]{2,8}(?:[-_][a-z0-9]{1,8})+(?![a-z0-9_-])").Cast<Match>().Select(m=>m.Value).Where(HasChinaRegion).Distinct());}
  static bool HasChinaRegion(string tag){var match=Regex.Match((tag??"").Replace('_','-'),@"^(?:[a-z]{2,3}(?:-[a-z]{3}){0,3}|[a-z]{4}|[a-z]{5,8})(?:-[a-z]{4})?(?:-(?<region>[a-z]{2}|[0-9]{3}))?(?:-(?<variant>[a-z0-9]{5,8}|[0-9][a-z0-9]{3}))*(?:-(?<extension>[0-9a-wy-z])(?:-[a-z0-9]{2,8})+)*(?:-x(?:-[a-z0-9]{1,8})+)?$",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant);if(!match.Success||!match.Groups["region"].Value.Equals("CN",StringComparison.OrdinalIgnoreCase))return false;foreach(string key in new[]{"variant","extension"}){var values=match.Groups[key].Captures.Cast<Capture>().Select(c=>c.Value.ToLowerInvariant()).ToArray();if(values.Distinct().Count()!=values.Length)return false;}return true;}
  static bool ChinaTag(string value){return Regex.IsMatch(value??"",@"(?i)^[a-z]{2,8}(?:[-_][a-z0-9]{1,8})+$")&&HasChinaRegion(value);}
  static string NamedLocaleFields(string text,string fieldPattern){return String.Join("\r\n",Regex.Matches(text??"",@"(?im)"+fieldPattern+@"\s*=\s*([^\s\r\n]+)\s*$").Cast<Match>().Where(m=>AssociationSignals.Locale(m.Groups[1].Value)).Select(m=>m.Value));}
  static string JsonLocaleFields(string text,string key){var result=new List<string>();object value;try{value=new JavaScriptSerializer().DeserializeObject(text);}catch{return "";}LocaleObjects(value,key,result);return String.Join("\r\n",result.Distinct());}
  static void LocaleObjects(object node,string key,List<string> result){var d=node as Dictionary<string,object>;if(d!=null){object raw;if(d.TryGetValue(key,out raw)&&raw is string&&AssociationSignals.Locale((string)raw))result.Add(key+"="+(string)raw);}else{var list=node as IList;if(list!=null)foreach(var item in list)LocaleObjects(item,key,result);}}
  public static string RuntimeLocaleMatches(string text){
   var matches=new List<string>();var serializer=new JavaScriptSerializer();foreach(var line in (text??"").Replace("\r","").Split('\n')){
    string value=line.Trim().TrimStart('\ufeff');if(!value.StartsWith("{"))continue;Dictionary<string,object> d;try{d=serializer.Deserialize<Dictionary<string,object>>(value);}catch(ArgumentException){continue;}catch(InvalidOperationException){continue;}if(d==null)continue;
    foreach(string key in new[]{"language","locale","languages","timeZone"}){object raw;if(!d.TryGetValue(key,out raw))continue;var items=key=="languages"&&raw is IList?((IList)raw).Cast<object>():new[]{raw};foreach(var item in items){var tag=item as string;if(tag==null)continue;bool hit=key=="timeZone"?new[]{"Asia/Shanghai","Asia/Chongqing","Asia/Urumqi"}.Contains(tag):AssociationSignals.Locale(tag);if(hit)matches.Add(key+"="+serializer.Serialize(tag));}}
   }return String.Join("\r\n",matches.Distinct());
  }
  public static List<double[]> Coordinates(string text){
   var result=new List<double[]>();foreach(var line in (text??"").Replace("\r","").Split('\n')){string value=line.Trim().TrimStart('\ufeff');
    if(value.StartsWith("{")){try{var raw=new JavaScriptSerializer().Deserialize<Dictionary<string,object>>(value);var d=raw.ToDictionary(p=>p.Key.ToLowerInvariant(),p=>p.Value);object a,b,c;double lat,lon,accuracy=Double.NaN;if(d.TryGetValue("latitude",out a)&&d.TryGetValue("longitude",out b)&&Numeric(a,out lat)&&Numeric(b,out lon)){
     if(d.TryGetValue("accuracy",out c)||d.TryGetValue("accuracymeters",out c)){double n;if(Numeric(c,out n)&&n>=0)accuracy=n;}result.Add(new[]{lat,lon,accuracy});
    }}catch(ArgumentException){}catch(InvalidOperationException){}}
   }
   foreach(Match m in Regex.Matches(text??"",@"(?im)^GPS_SAMPLE latitude=(-?\d+(?:\.\d+)?) longitude=(-?\d+(?:\.\d+)?)\s*$"))result.Add(new[]{Double.Parse(m.Groups[1].Value,CultureInfo.InvariantCulture),Double.Parse(m.Groups[2].Value,CultureInfo.InvariantCulture),0d});
   return result;
  }
  static bool Numeric(object value,out double n){n=0;return value!=null&&!(value is string)&&!(value is bool)&&Double.TryParse(Convert.ToString(value,CultureInfo.InvariantCulture),NumberStyles.Float,CultureInfo.InvariantCulture,out n)&&!Double.IsNaN(n)&&!Double.IsInfinity(n);}
  public static string[] ContactMatches(string text){return ContactEvidence.Matches(text);}
  public static string[] TimezoneMatches(string text){return Regex.Matches(text??"",@"(?i)(?:TZID|timeZone|timezone|时区)\s*[""']?\s*[:=]\s*[""']?(?:Asia/(?:Shanghai|Chongqing|Urumqi)|China Standard Time)\b").Cast<Match>().Select(m=>m.Value).Distinct().Take(20).ToArray();}
  static bool KnownServiceFamily(string name){return new[]{"百度","腾讯","阿里","京东","哔哩哔哩","新浪","字节","网易"}.Contains(name);}
  static bool KnownSoftwareFamily(string name){return new[]{"腾讯","阿里","百度","搜狗","网易","字节"}.Contains(name);}
  public static string ServiceFamily(string host){
   host=(host??"").ToLowerInvariant();var groups=new[]{new[]{"百度","baidu.com"},new[]{"腾讯","qq.com","weixin.qq.com"},new[]{"阿里","taobao.com","tmall.com","alipay.com","1688.com"},new[]{"京东","jd.com"},new[]{"哔哩哔哩","bilibili.com"},new[]{"新浪","weibo.com","sina.com.cn"},new[]{"字节","douyin.com","toutiao.com"},new[]{"网易","163.com","126.com","netease.com"}};
   foreach(var group in groups)if(group.Skip(1).Any(h=>host==h||host.EndsWith("."+h,StringComparison.Ordinal)))return group[0];return "";
  }
  public static string[] SoftwareFamilies(string text){
   var groups=new[]{new[]{"腾讯",@"(?i)(WeChat|Weixin|微信|Tencent|腾讯|\bQQ\b)"},new[]{"阿里",@"(?i)(DingTalk|钉钉|阿里|Alipay|支付宝)"},new[]{"百度",@"(?i)(Baidu|百度)"},new[]{"搜狗",@"(?i)(Sogou|搜狗)"},new[]{"网易",@"(?i)(NetEase|网易)"},new[]{"字节",@"(?i)(Douyin|抖音|飞书|Feishu)"}};
   return groups.Where(g=>Regex.IsMatch(text??"",g[1])).Select(g=>g[0]).ToArray();
  }
  public static string[] DomainFamilies(string text){return Regex.Matches(text??"",@"(?i)(?<![a-z0-9.-])[a-z0-9][a-z0-9.-]*\.(?:com|cn)(?![a-z0-9.-])").Cast<Match>().Select(m=>ServiceFamily(m.Value)).Where(s=>s.Length>0).Distinct().ToArray();}
  public static string[] CurrentLocationMarkers(string text){return LocationAssociationMarkers(text).Where(s=>s=="CURRENT_LOCATION_COUNTRY=CN").ToArray();}
  public static string[] LocationAssociationMarkers(string text){
   var result=new List<string>();object root;try{root=new JavaScriptSerializer{MaxJsonLength=262144,RecursionLimit=32}.DeserializeObject(text);}catch{return new string[0];}
   FindCurrent(root,result,0);return result.Distinct().ToArray();
  }
  static void FindCurrent(object value,List<string> result,int depth){
   if(depth>16)return;var d=value as Dictionary<string,object>;
   if(d!=null){object current,code;bool isCurrent=d.TryGetValue("isCurrentLocation",out current)&&current is bool&&(bool)current;object kind;if(d.TryGetValue("locationType",out kind)&&kind is string&&(string)kind=="current")isCurrent=true;
    if(d.TryGetValue("countryCode",out code)&&code is string&&((string)code).Equals("CN",StringComparison.OrdinalIgnoreCase)){
     if(isCurrent)result.Add("CURRENT_LOCATION_COUNTRY=CN");
     else {object flag;bool saved=new[]{"isFavorite","isDefault"}.Any(k=>d.TryGetValue(k,out flag)&&flag is bool&&(bool)flag);if(saved)result.Add("SAVED_LOCATION_COUNTRY=CN");}
    }
    foreach(var child in d.Values)FindCurrent(child,result,depth+1);
   }else{var a=value as IList;if(a!=null)foreach(var child in a)FindCurrent(child,result,depth+1);}
  }
  public static Dictionary<string,object> Marker(string text,string name){var m=Regex.Match(text??"",@"(?m)^"+Regex.Escape(name)+@"=(\{[^\r\n]+\})\s*$");if(!m.Success)return new Dictionary<string,object>();try{return new JavaScriptSerializer().Deserialize<Dictionary<string,object>>(m.Groups[1].Value);}catch{return new Dictionary<string,object>();}}
  static int Number(Dictionary<string,object> data,string key){object value;int n;return data.TryGetValue(key,out value)&&Int32.TryParse(Convert.ToString(value,CultureInfo.InvariantCulture),out n)&&n>=0?n:0;}
  static IEnumerable<string> Values(Dictionary<string,object> data,string key){object value;return data.TryGetValue(key,out value)&&value is IList?((IList)value).Cast<object>().Select(v=>Convert.ToString(v,CultureInfo.InvariantCulture)):new string[0];}
  public static IEnumerable<Uri> Urls(string text){foreach(Match m in Regex.Matches(text??"",@"https?://[^\s""'<>]+")){Uri u;if(Uri.TryCreate(m.Value,UriKind.Absolute,out u))yield return u;}}
  static bool MirrorHost(string h){return new[]{"tuna.tsinghua.edu.cn","mirrors.tuna.tsinghua.edu.cn","aliyun.com","npmmirror.com","doubanio.com","gitee.com"}.Any(root=>h.Equals(root,StringComparison.OrdinalIgnoreCase)||h.EndsWith("."+root,StringComparison.OrdinalIgnoreCase));}
 }
}
