using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Script.Serialization;
using LocalLens;
class ClueRuleChecks {
 static int count;
 static void Check(bool ok,string name){if(!ok)throw new Exception(name);count++;Console.WriteLine("PASS: "+name);}
 static Finding Read(int id,string text,string state="信息"){return ChinaEvidence.Apply(new Finding{Id=id,State=state,Summary="collected observation",Evidence=text,Coverage="synthetic source"});}
 static void Yes(int id,string text,string name){var f=Read(id,text);Check(f.IsClue==true&&!String.IsNullOrWhiteSpace(f.SupportedClaim)&&!String.IsNullOrWhiteSpace(f.Reasoning)&&!String.IsNullOrWhiteSpace(f.MatchingEvidence)&&!String.IsNullOrWhiteSpace(f.AlternativeExplanation),name);}
 static void No(int id,string text,string name){var f=Read(id,text);Check(f.IsClue==false&&f.MatchingEvidence==""&&f.EvidenceFamily==""&&!String.IsNullOrWhiteSpace(f.Reasoning),name);}
 static void Throws(Action run,string name){bool failed=false;try{run();}catch{failed=true;}Check(failed,name);}
 static int Main(){try{
  var rows=Catalog.Load();Check(rows.Count==69&&rows.All(f=>f.IsClue==null&&!String.IsNullOrWhiteSpace(f.DecisionRule)),"all 69 checks define a China-association criterion, unrun checks are not cleared");
  Throws(()=>ClueRules.ForId(0),"invalid catalog IDs rejected");Throws(()=>ClueRules.ForId(70),"out-of-range catalog IDs rejected");
  foreach(var state in new[]{"未检测","读取失败","缺少依赖","需外部记录"})Check(Read(17,"Name = CN",state).IsClue==null,"execution status preserved: "+state);
  foreach(int id in new[]{4,7,11,13,16,32,36,39,40,45,46,47,54,62,63,64,65,66,67,69})No(id,"Value = Allow\n中文文件\nSimSun\nTokyo\nBSSID 01:23:45:67:89:ab\nStart = 1234\n国家=CN\nclipboardRead\nTencentService",id+" capabilities/resources/unmapped names never establish China user association");
  No(8,"HTTP 200 20 ms","short region latency does not imply China");No(9,"HTTP 403 10 ms","HTTP blocking does not imply China");Check(Read(8,"request timeout").State=="读取失败","all failed latency probes remain a failed check");
  Yes(1,"国家：CN / China","CN IPv4 geography has an explicit inferential chain");No(1,"国家：JP / Japan","Japanese network geography is not China evidence");
  No(3,"HTTPS v4 出口国家：JP\nHTTPS v6 出口国家：US\nUDP/HTTPS different","different non-CN exits are not a China clue");Yes(3,"UDP 出口国家：CN；来源 ipwho.is","CN UDP geography supports a China path association");
  No(5,"ASN organization = China Mobile\n国家：JP","Chinese ISP branding is not substituted for network geography");Yes(5,"国家：CN\nASN organization = Example","actual country data rather than an ISP name supports the verdict");
  var namedDns=DnsConfigurationAssessment.Evaluate(new[]{"8.8.8.8"},"223.5.5.5 VPN → 8.8.8.8");Check(ChinaEvidence.Apply(namedDns).IsClue==false,"DNS address in adapter name cannot impersonate actual resolver configuration");Check(ChinaEvidence.Apply(DnsConfigurationAssessment.Evaluate(new[]{"2400:3200::1"},"adapter → IPv6 resolver")).IsClue==true,"actual configured China public IPv6 resolver is retained");
  No(10,"interface changed 3 times\n网络国家=JP","interface changes do not imply China");Yes(10,"网络国家=CN | 来源=ipwho.is","monitor requires an actual CN country sample");
  Yes(17,"Name = CN\nNation = 45","explicit Windows home region supports a preference claim");No(17,"Name = JP\nNation = 122","valid Japanese home region is not a mainland preference");Check(Read(17,"Name = [值不存在]").IsClue==null,"missing home region stays incomplete");
  Yes(18,"UI Culture = en-US\nInstallLanguage = 0804","Chinese installation language retains an environment association without claiming current preference");Yes(18,"UI Culture = zh-CN\nInstallLanguage = 0409","actual current UI region supports a mainland-language preference");
  foreach(string tag in new[]{"zh-SG","zh-HK","zh-TW","ja-JP"})No(19,"{\"Name\":\""+tag+"\"}","language/script is not silently converted into CN: "+tag);
  Yes(19,"{\"Name\":\"zh-Hans-CN\"}","explicit script plus CN region is retained");Yes(20,"LocaleName = zh-CN","actual user locale supports regional preference");Yes(21,"[{\"LanguageTag\":\"zh-CN\"}]","language-list country field supports regional preference");
  No(20,"LocaleName = ja-JP\nsCurrency = zh-CN\nsShortDate = zh-CN","custom currency and date strings cannot impersonate actual locale region");No(19,"{\"Name\":\"ja-JP\",\"DisplayName\":\"zh-CN\"}","display text cannot replace the system locale Name field");No(21,"[{\"LanguageTag\":\"ja-JP\",\"Autonym\":\"zh-CN\"}]","language autonym text cannot replace actual LanguageTag");
  foreach(string tag in new[]{"bo-CN","ug-CN","mn-Mong-CN","en-CN","zh-CN-u-nu-hanidec"})Yes(19,"{\"Name\":\""+tag+"\"}","actual CN region is independent of language or script: "+tag);
  foreach(string tag in new[]{"en-US-x-CN","zh-CNfoobar","x-CN"})No(19,"{\"Name\":\""+tag+"\"}","CN outside the actual region slot does not count: "+tag);
  Yes(18,"UI Culture = ug-CN","current minority-language UI with CN is a mainland-region preference");Yes(27,"LANG = bo_CN.UTF-8","POSIX region is independent of Han script");Yes(37,"SystemLocale = ug-CN","typed install language uses actual region grammar");
  const string current="S-1-5-21-111-222-333-1001";
  foreach(string sid in new[]{current,"S-1-5-18","S-1-5-19","S-1-5-20",current+"_Classes",".DEFAULT"})Check(!AuditEngine.OtherUserProfile(sid,current),"current or service hive cannot fabricate other-user evidence: "+sid);
  Check(AuditEngine.OtherUserProfile("S-1-5-21-111-222-333-1002",current),"distinct human user profile remains eligible");
  Yes(22,"1 = 00000409\n2 = 00000804","secondary Chinese input is still an environment association");Yes(22,"1 = 00000804","first Preload entry can establish the input preference");
  No(23,"UTC offset = 08:00:00","UTC+8 is shared and does not establish China");Yes(23,"China Standard Time","named time-zone preference has an explicit non-location boundary");
  Yes(25,"LANGUAGE_VALUES={\"accept_languages\":\"zh-CN,en\"}","browser preference values establish the claim");No(25,"C:\\Users\\zh-CN\\profile：intl 未设置","profile path containing zh-CN does not become browser language evidence");
  Yes(26,"UILanguage = 2052","current Office LCID maps to the mainland locale");Yes(26,"InstallLanguage = 2052\nLanguage = schinese","installation language and Steam simplified preference retain association without claiming a CN country code");
  No(27,"HTTP_PROXY = https://example.com/zh-CN","proxy paths do not become user language evidence");Yes(27,"LANG = zh_CN.UTF-8","actual language environment variable establishes locale preference");
  const string activity="DOMESTIC_ACTIVITY={\"visits\":5,\"days\":2,\"services\":2,\"families\":[\"腾讯\",\"百度\"],\"windowDays\":90}";
  Yes(34,activity,"multi-day actual visits across two service owners support a usage association");No(34,"www.baidu.com\nexample.cn × 100","domain strings and URL-table counts are not actual visit evidence");
  Yes(34,"DOMESTIC_ACTIVITY={\"visits\":99,\"days\":3,\"services\":2,\"families\":[\"腾讯\",\"腾讯\"]}","same-owner visits count as one domestic association without requiring another owner");
  No(35,"baidu.com IndexedDB\nweibo.com advertisement","storage and embedded components alone do not establish personal usage");Yes(35,"CORROBORATED_DOMESTIC_STORAGE=百度","storage needs independently checked visit corroboration and remains the same evidence family");
  Yes(37,"UILanguage = zh-CN","typed installation fields support historical configuration");No(37,"resource contains zh-CN","unbound log strings are not configuration fields");
  No(41,"WeChat\nTencent\n腾讯","one global product or duplicated vendor names are insufficient");Yes(41,"DOMESTIC_SOFTWARE={\"installed\":[\"腾讯\",\"百度\"],\"running\":[]}","installed domestic software remains an association even when not running");
  Yes(41,"DOMESTIC_SOFTWARE={\"installed\":[\"腾讯\",\"百度\"],\"running\":[\"腾讯\"]}","installation across owners plus actual execution supports ecosystem usage");
  No(42,"TencentService","startup name alone is insufficient");Yes(42,"DOMESTIC_SOFTWARE={\"enabled\":[\"腾讯\"],\"running\":[\"腾讯\"]}","enabled startup and execution corroborate a software-owner association");
  Yes(43,"index-url = https://pypi.tuna.tsinghua.edu.cn/simple","exact parsed mirror host supports developer-service preference");No(43,"index-url = https://aliyun.com.evil.example/simple","lookalike host suffix cannot establish a domestic mirror");
  No(43,"index-url = https://pypi.org/simple # example https://pypi.tuna.tsinghua.edu.cn/simple","domestic URL in inline comment cannot impersonate active configuration");
  Yes(44,"Domain = corp.example.cn\nPartOfDomain = True","actual membership plus country domain supports organization association");No(44,"Domain = corp.example.cn\nPartOfDomain = False","workgroup text is not active organization membership");
  Check(ChinaGeography.IsMainland(39.9042,116.4074,25)==true,"offline polygon includes Beijing");Check(ChinaGeography.IsMainland(30.5728,104.0668,25)==true,"offline polygon includes Chengdu");Check(ChinaGeography.IsMainland(19.9,109.6,25)==true,"offline polygon includes Hainan");
  foreach(var p in new[]{new[]{35.6762,139.6503},new[]{25.033,121.5654},new[]{22.28,114.16},new[]{1.3521,103.8198}})Check(ChinaGeography.IsMainland(p[0],p[1],20)==false,"offline polygon excludes a non-mainland point: "+p[0]);
  Check(ChinaGeography.IsMainland(22.1987,113.5439,20)!=true,"Macao is never positively classified as mainland");Check(ChinaGeography.IsMainland(39.9042,116.4074,500000)==null,"large uncertainty cannot be converted into a mainland position");Throws(()=>ChinaGeography.IsMainland(95,116,10),"invalid coordinates rejected");
  Yes(12,"{\"Longitude\":116.4074,\"Latitude\":39.9042,\"Accuracy\":25}","position field order does not affect mainland containment");No(12,"{\"Latitude\":35.6762,\"Longitude\":139.6503,\"Accuracy\":20}","Tokyo GPS exists but is not China evidence");Check(Read(12,"{\"latitude\":39.9042,\"longitude\":116.4074}").IsClue==null,"missing position uncertainty is disclosed, not assumed precise");
  Yes(48,"GPS_SAMPLE latitude=39.904200 longitude=116.407400","photo metadata needs a mainland point, not merely a GPS tag");No(48,"GPS_SAMPLE latitude=35.676200 longitude=139.650300","foreign photo coordinates are not a China clue");
  No(50,"北京是中国的首都。中国旅游攻略。Beijing, Shanghai.","encyclopedic and travel mentions do not establish personal country association");Yes(50,"收货地址：上海市浦东新区世纪大道100号","structured mainland delivery address supports a contact-record association");Yes(51,"residenceCountry: CN","residence country field establishes a China contact-record association");No(50,"country: CN","a generic dataset country field has no user ownership semantics");
  Yes(49,"联系电话：+86 13800138000","explicit mainland mobile contact field supports a contact-record association");
  No(50,"{\"homeCountry\":\"JP\",\"note\":\"China tourism\"}","unrelated China note cannot override an owning Japanese country field");No(50,"home address:12 China Road, London, UK","China street name abroad is not a mainland address");
  Yes(52,"Chrome / country = CN\nChrome / country = JP","independent foreign autofill record does not erase explicit CN record");No(52,"Chrome / city = Beijing\nChrome / country = JP","city text alone cannot override a foreign country record");
  No(53,"Beijing default weather city","default weather city does not prove device position");Check(ChinaEvidence.CurrentLocationMarkers("{\"countryCode\":\"CN\",\"isFavorite\":true}").Length==0,"favorite city is not current device location");Check(ChinaEvidence.CurrentLocationMarkers("{\"countryCode\":\"CN\",\"isCurrentLocation\":true}").Length==1,"current location marker and country must occur in the same object");
  No(55,"2026-10-15T10:00:00+0800\nUTC+8","generic offset is not China evidence");Yes(55,"TZID:Asia/Shanghai","explicit named time-zone field supports file configuration history");
  Yes(58,"{\"language\":\"zh-CN\",\"userAgent\":\"test\"}","browser runtime language carries the actual country tag");No(58,"{\"language\":\"en-US\",\"userAgent\":\"zh-CN China Standard Time\"}","user-agent text cannot impersonate language or time-zone fields");Yes(58,"{\"language\":\"zh-Hans\",\"locale\":\"zh-SG\"}","script-only Chinese preference retains association while Singapore remains its actual region");
  No(58,"{\"timeZone\":\"Asia/Shanghai-old\"}","malformed timezone suffix cannot impersonate an exact runtime timezone");No(58,"{\"language\":\"en-US, zh-CN\"}","a malformed language scalar is not a valid runtime region tag");Yes(58,"{\"languages\":[\"en-US\",\"ug-CN\"]}","actual runtime language array members are checked individually");
  No(58,"{\"language\":\"zh-CN-CN\"}","a second country token is not a well-formed language variant");No(58,"{\"language\":\"zh-CN-u\"}","an extension singleton without a value is not a valid locale");
  No(68,"Windows 国家设置：JP\nHTTPS 出口国家：US","country inconsistency without CN does not imply China");Yes(68,"Windows 国家设置：JP\nHTTPS 出口国家：CN","cross-source assessment uses actual CN fields");Check(Read(68,"Windows 国家设置：CN").IsClue==null,"cross-source check requires another actual country source");
  var a=Read(18,"UI Culture = zh-CN");var b=Read(19,"{\"Name\":\"zh-CN\"}");var cross=Read(68,"Windows 国家设置：CN\nHTTPS 出口国家：JP");var overview=ChinaUserAssessment.Create(new[]{a,b,cross},null);Check(overview.IsClue==true&&overview.EvidenceFamilies.Length==1,"same locale settings and cross-check duplicates never inflate independent evidence types");
  Check(ChinaUserAssessment.Create(new[]{Read(28,"SimSun")},null).IsClue.Value,"actual simplified font produces a weak environment association, not proof of identity");
  foreach(string address in new[]{"127.0.0.1","192.168.1.1","100.64.0.1","::1","::ffff:10.0.0.1","2001:db8::1","https://example.com"})Check(!NetworkCountryLookup.IsPublic(address),"country API rejects private, special or arbitrary-URL input: "+address);
  Check(NetworkCountryLookup.IsPublic("8.8.8.8")&&NetworkCountryLookup.IsPublic("2606:4700:4700::1111"),"public IPv4 and IPv6 accepted by strict country lookup validation");Throws(()=>NetworkCountryLookup.ValidateAddresses(new[]{"8.8.8.8","192.168.1.1"}),"mixed invalid batch is rejected before any outbound lookup");
  var report=new AuditReport{Options=new ScanOptions(),Findings=new List<Finding>{a,b},Completed=true};var summary=Exporter.Prepare(report,false);Check(summary.Findings.All(f=>f.MatchingEvidence.Contains("摘要省略"))&&a.MatchingEvidence.Contains("zh-CN"),"summary strips quoted raw matches without mutating actual evidence");
  var engine=new AuditEngine(new ScanOptions(),f=>{},System.Threading.CancellationToken.None);typeof(AuditEngine).GetMethod("Set",System.Reflection.BindingFlags.Instance|System.Reflection.BindingFlags.NonPublic).Invoke(engine,new object[]{41,"信息","inventory",new String('x',25000)+"\nDOMESTIC_SOFTWARE={\"installed\":[\"腾讯\",\"百度\"],\"running\":[\"腾讯\"]}","bounded inventory"});var actual=(List<Finding>)typeof(AuditEngine).GetField("rows",System.Reflection.BindingFlags.Instance|System.Reflection.BindingFlags.NonPublic).GetValue(engine);Check(actual[40].IsClue==true&&actual[40].Evidence.Length<24500&&actual[40].MatchingEvidence.Contains("腾讯"),"display truncation cannot erase a later corroborated collector marker before decision");
  string json=new JavaScriptSerializer().Serialize(summary),html=Exporter.RenderHtml(report,false);Check(json.Contains("ChinaUserAssessment")&&json.Contains("SupportedClaim")&&json.Contains("Reasoning")&&json.Contains("\"IsClue\":true"),"JSON exports retain binary verdict and inferential chain");Check(html.Contains("支持的判断")&&html.Contains("推断依据")&&html.Contains("其他解释")&&html.Contains("中国用户关联评估"),"HTML exports explain the same inference rather than just list keywords");

  foreach(string tag in new[]{"zh","zh-Hans","zh-CHS"}){Yes(19,"{\"Name\":\""+tag+"\"}","actual Chinese preference retains association: "+tag);Yes(58,"{\"language\":\""+tag+"\"}","runtime Chinese preference retains association: "+tag);}
  Yes(34,"DOMESTIC_ACTIVITY={\"visits\":1,\"days\":1,\"services\":1,\"families\":[\"百度\"]}","one genuine domestic visit is not discarded");
  No(34,"DOMESTIC_ACTIVITY={\"visits\":1,\"days\":1,\"services\":1,\"families\":[\"unknown\"]}","unrecognized service marker cannot fabricate association");
  Yes(35,"DOMESTIC_STORAGE={\"families\":[\"百度\"]}","actual storage origin does not need available history");
  No(35,"DOMESTIC_STORAGE={\"families\":[\"unknown\"]}","unknown storage family remains nonmatching");
  Yes(41,"DOMESTIC_SOFTWARE={\"installed\":[\"腾讯\"],\"running\":[]}","one dormant domestic installation is enough for association");
  Yes(41,"DOMESTIC_SOFTWARE={\"installed\":[],\"running\":[\"腾讯\"]}","actual portable running software need not have uninstall entry");
  Yes(42,"DOMESTIC_SOFTWARE={\"enabled\":[\"腾讯\"],\"running\":[]}","enabled task remains association when process is not currently running");
  No(41,"DOMESTIC_SOFTWARE={\"installed\":[\"UnknownVendor\"]}","unrecognized software marker does not trigger association");
  Yes(28,"Arial\nMicrosoft YaHei\nSimSun","actual listed simplified fonts retain weak risk");No(28,"MS Mincho\nArial\nNoto Sans JP","Japanese or generic fonts are not reclassified as simplified resources");
  foreach(int id in new[]{14,29,31}){Yes(id,"ChinaNet-home","actual network name has a domestic service marker: "+id);No(id,"東京駅\nHome-WiFi","ordinary Han or generic SSIDs remain nonmatching: "+id);}
  Yes(30,"[{\"SSID\":[\"CMCC-home\"]}]","event SSID field retains actual domestic marker");No(30,"[{\"Message\":\"CMCC-home\",\"SSID\":\"Home\"}]","event message cannot impersonate SSID field");
  Yes(33,"[{\"Entry\":\"www.baidu.com\"}]","actual DNS cache record retains domestic service association");No(33,"[{\"Entry\":\"baidu.com.evil.example\",\"Note\":\"www.qq.com\"}]","DNS host boundary and actual field are required");
  Check(Read(19,"not json").IsClue==null&&Read(21,"[]").IsClue==null,"unreadable or missing actual locale fields are skipped rather than cleared");
  Yes(53,"SAVED_LOCATION_COUNTRY=CN","saved Chinese weather preference is retained separately from live location");
  Check(Read(53,"SAVED_LOCATION_COUNTRY=CN").EvidenceFamily=="地图地区偏好","saved location never becomes live-device position evidence");

  No(27,"LANG = https://example.com/zh","URL text in a language field cannot impersonate a locale value");
  No(18,"UI Culture = folder/zh-Hans/data","path text in UI culture is not a locale value");
  No(25,"LANGUAGE_VALUES={\"accept_languages\":\"https://example.com/zh\",\"note\":\"zh-CN\"}","browser language values and keys must be valid");
  Yes(25,"LANGUAGE_VALUES=user_pref(\"intl.accept_languages\", \"en,zh-Hans\");","Firefox actual language preference string retains secondary simplified Chinese");
  Check(Rules.DomesticSoftware("QQ")&&Rules.DomesticSoftware("Feishu"),"collector and judge share the same software family map");
  Console.WriteLine("CHINA EVIDENCE CHECKS PASSED: "+count);return 0;
 }catch(Exception e){Console.Error.WriteLine("FAIL: "+e);return 1;}}
}
