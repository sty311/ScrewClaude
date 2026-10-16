using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
namespace LocalLens {
 public sealed partial class AuditEngine {
  // Parse and validate the whole document before preparing or publishing any finding.
  void ImportBrowser(){
   var data=LocalData.Json(options.BrowserReportPath,1048576);
   if(!Value(data,"app").StartsWith("LocalLens BrowserCheck ",StringComparison.Ordinal))throw new FormatException("不是 LocalLens 浏览器导出文件");
   string exported=ImportTime(data,"time",null), imported=DateTime.UtcNow.ToString("o");
   var env=ImportObject(data,"environment",true);
   var safe=new Dictionary<string,object>();object value;
   foreach(string key in new[]{"language","timeZone","locale","platform","userAgent","screen","webglRenderer","webglVendor"})ImportString(env,safe,key);
   foreach(string key in new[]{"utcOffsetMinutes","devicePixelRatio","logicalCores","deviceMemoryGiB"})if(env.TryGetValue(key,out value)&&value!=null){
    // Some browsers use a human-readable unavailable marker for memory.
    if(key=="deviceMemoryGiB"&&value is string){ImportString(env,safe,key);continue;}
    if(value is string||value is bool)throw new FormatException("environment."+key+" 必须为数字");
    ImportNumber(env,key);safe[key]=value;
   }
   if(env.TryGetValue("secureContext",out value)&&value!=null){if(!(value is bool))throw new FormatException("secureContext 必须为布尔值");safe["secureContext"]=value;}
   if(env.TryGetValue("languages",out value)&&value!=null){var languages=value as IList;if(languages==null||languages.Count>100)throw new FormatException("languages 必须为有限字符串数组");foreach(object language in languages)if(!(language is string)||String.IsNullOrWhiteSpace((string)language))throw new FormatException("languages 包含无效语言");if(languages.Count>0)safe["languages"]=languages;}
   if(safe.Count==0)throw new FormatException("environment 没有可读取的已知字段；空样本不算完成");
   string envTime=ImportTime(data,"environmentObservedAt",exported);
   var rtc=ImportObject(data,"webrtc",false);var loc=ImportObject(data,"location",false);
   Dictionary<string,object> safeRtc=null,safeLoc=null;string rtcState=null,locState=null,rtcTime=null,locTime=null;
   if(rtc!=null){
    rtcState=ImportStatus(rtc,new[]{"not_run","running","completed","error"},"webrtc");
    rtcTime=ImportTime(rtc,"observedAt",exported);safeRtc=new Dictionary<string,object>{{"status",rtcState}};
    foreach(string key in new[]{"error","note"})ImportString(rtc,safeRtc,key);
    if(rtc.TryGetValue("externalStun",out value)){if(!(value is bool))throw new FormatException("externalStun 必须为布尔值");safeRtc["externalStun"]=value;}
    if(rtc.TryGetValue("candidates",out value)){
     var candidates=value as IList;if(candidates==null||candidates.Count>512)throw new FormatException("WebRTC candidates 必须为有限数组");
     var cleaned=new List<Dictionary<string,object>>();foreach(object candidate in candidates){var c=candidate as Dictionary<string,object>;if(c==null)throw new FormatException("WebRTC candidate 必须为对象");var item=new Dictionary<string,object>();foreach(string key in new[]{"candidate","type","address","protocol"})ImportString(c,item,key);if(item.Count==0)throw new FormatException("WebRTC candidate 为空");cleaned.Add(item);}safeRtc["candidates"]=cleaned;
    }else if(rtcState=="completed")throw new FormatException("完成的 WebRTC 记录缺少 candidates");
   }
   if(loc!=null){
    locState=ImportStatus(loc,new[]{"not_run","running","returned","error","unavailable"},"location");
    locTime=ImportTime(loc,"timestamp",ImportTime(loc,"observedAt",exported));safeLoc=new Dictionary<string,object>{{"status",locState}};
    foreach(string key in new[]{"message"})ImportString(loc,safeLoc,key);
    if(locState=="returned"){
     double lat=ImportNumber(loc,"latitude"),lon=ImportNumber(loc,"longitude");if(Math.Abs(lat)>90||Math.Abs(lon)>180)throw new FormatException("浏览器坐标无效");safeLoc["latitude"]=lat;safeLoc["longitude"]=lon;
     if(loc.ContainsKey("accuracyMeters")){double accuracy=ImportNumber(loc,"accuracyMeters");if(accuracy<0)throw new FormatException("定位精度无效");safeLoc["accuracyMeters"]=accuracy;}
    }
   }
   var serializer=new JavaScriptSerializer();
   string note=(options.BrowserReportAutomatic?"本批网页自动采样提交时间：":"导出时间：")+exported+"\r\n用户导入文件未经签名验证，可能过期或来自另一浏览器 / 设备。不同来源时间不可作为同时采样；旧文件未提供分项时间时使用导出时间，实际采样时间未知。";
   var pending=new List<Finding>();
   var regionFields=safe.Where(p=>new[]{"language","languages","locale","timeZone"}.Contains(p.Key)).ToDictionary(p=>p.Key,p=>p.Value);
   bool envHit=ChinaEvidence.RuntimeLocaleMatches(serializer.Serialize(regionFields)).Length>0;
   var environment=new EvidenceSource{Source=options.BrowserReportAutomatic?"本批网页自动采样":"用户导入浏览器环境",ObservedAt=envTime,ImportedAt=imported,State=envHit?"发现线索":regionFields.Count>0?"未发现":"未检测",Summary=envHit?"浏览器运行时字段命中中文/CN 语言或命名时区规则":regionFields.Count>0?"已返回运行时字段未命中中文/CN 语言或命名时区规则":"缺少浏览器语言、区域和时区字段",Evidence=serializer.Serialize(safe)+"\r\n"+note,Coverage=options.BrowserReportAutomatic?"本批网页自动提交 / 来源未签名核验":"用户导入 / 来源未验证"};
   pending.Add(MergeBrowserSource(58,environment));
   string browserLocale=Value(safe,"locale");if(browserLocale.Length==0)browserLocale=Value(safe,"language");
   var region=Regex.Match(browserLocale,@"[-_]([A-Z]{2})(?:$|[-_])");bool comparable=Regex.IsMatch(country??"",@"^[A-Z]{2}$")&&(region.Success||ChinaEvidence.RuntimeLocaleMatches(serializer.Serialize(regionFields)).Length>0);
   pending.Add(MergeBrowserSource(68,new EvidenceSource{Source=environment.Source,ObservedAt=envTime,ImportedAt=imported,State=!comparable?"未检测":country!=region.Groups[1].Value?"发现线索":"未发现",Summary=!comparable?"缺少可比较的系统国家或浏览器区域字段":country!=region.Groups[1].Value?"系统国家与浏览器区域标记不同":"系统国家与浏览器区域标记一致",Evidence="Windows 国家设置："+country+"\r\n"+environment.Evidence,Coverage="系统国家与导入浏览器区域对照 / 采样时间分别保留"}));
   if(rtcState=="completed"||rtcState=="error")pending.Add(MergeBrowserSource(3,new EvidenceSource{Source="用户导入 WebRTC",ObservedAt=rtcTime,ImportedAt=imported,State=rtcState=="error"?"读取失败":"未检测",Summary=rtcState=="error"?"浏览器 WebRTC 采样失败":"导入候选缺少同时采样的浏览器 HTTPS 对照，请使用首页网络检测",Evidence=serializer.Serialize(safeRtc)+"\r\n"+note,Coverage="浏览器单次采样 / 出口对照未完成"}));
   if(locState=="returned"||locState=="error"||locState=="unavailable")pending.Add(MergeBrowserSource(12,new EvidenceSource{Source="用户导入浏览器定位",ObservedAt=locTime,ImportedAt=imported,State=locState=="returned"?"发现线索":"读取失败",Summary=locState=="returned"?"导入记录包含有效经纬度位置数据":"浏览器定位未取得结果",Evidence=serializer.Serialize(safeLoc)+"\r\n"+note,Coverage="用户提供的定位记录 / 来源未验证"}));
   cancel.ThrowIfCancellationRequested();
   foreach(var finding in pending)rows[finding.Id-1]=finding;
   foreach(var finding in pending)update(finding);
  }
  Finding MergeBrowserSource(int id,EvidenceSource source){
   var judged=ChinaEvidence.Apply(new Finding{Id=id,State=source.State,Summary=source.Summary,Evidence=source.Evidence,Coverage=source.Coverage});
   source.State=judged.State;source.Summary=judged.Summary;source.Observation=judged.Observation;source.SupportedClaim=judged.SupportedClaim;source.Reasoning=judged.Reasoning;source.MatchingEvidence=judged.MatchingEvidence;source.EvidenceFamily=judged.EvidenceFamily;source.AlternativeExplanation=judged.AlternativeExplanation;
   if(source.State=="发现线索"){
    if(id==12){source.SupportedClaim="导入的定位记录描述中国大陆地点";source.EvidenceFamily="导入记录地点";}
    if(id==58){source.SupportedClaim=options.BrowserReportAutomatic?"本批网页提交的浏览器偏好含中文或中国地区字段":"导入的浏览器记录描述中文或中国地区偏好";source.EvidenceFamily="导入地区偏好";}
    if(id==68)source.SupportedClaim="本机与浏览器地区字段存在中文或中国地区关联";
    source.Summary=source.SupportedClaim;
   }
   source.Observation=(options.BrowserReportAutomatic?"网页自动提交来源：":"导入来源：")+source.Source+"；记录时间："+source.ObservedAt+"；"+source.Observation;
   if(id==12)source.AlternativeExplanation="坐标及精度取自导入文件，未验证设备、定位方式或原始采样服务；不表示本次设备位置，也不证明操作者国籍。";
   source.Reasoning+=options.BrowserReportAutomatic?" 此判断针对本批网页自动提交的实际字段；未独立核验浏览器或设备归属，不作为本次 Windows 定位结论。":" 此判断只针对用户提供记录中的字段，不表示本次本机或当前浏览器的实时采样。";
   source.AlternativeExplanation+=options.BrowserReportAutomatic?" 网页提交的记录未经签名与设备归属核验；与本次 Windows 检查分别保留，不证明国籍或物理位置。":" 导入文件未经签名或设备归属验证，可来自另一设备、另一用户或过去时间；与本次本机检查分别保留。";
   var serializer=new JavaScriptSerializer{MaxJsonLength=8*1024*1024};var f=serializer.Deserialize<Finding>(serializer.Serialize(F(id)));
   if(f.Sources==null){f.Sources=new List<EvidenceSource>();f.Sources.Add(new EvidenceSource{Source="本次本机检查",ObservedAt=f.CheckedAt,State=f.State,Summary=f.Summary,Evidence=f.Evidence,Coverage=f.Coverage,Observation=f.Observation,SupportedClaim=f.SupportedClaim,Reasoning=f.Reasoning,MatchingEvidence=f.MatchingEvidence,EvidenceFamily=f.EvidenceFamily,AlternativeExplanation=f.AlternativeExplanation});}
   source.Evidence=Rules.TrimEvidence(source.Evidence);f.Sources.Add(source);
   // A supplement never clears an existing detection, failure, or limited observation.
   if((source.State=="发现线索"&&f.State!="发现线索")||f.State=="未检测"||f.State=="信息"||(source.State=="读取失败"&&f.State!="发现线索"&&f.State!="读取失败")){
    f.State=source.State;f.Summary=source.Summary;f.Coverage=source.Coverage;f.CheckedAt=source.ImportedAt;f.Observation=source.Observation;f.SupportedClaim=source.SupportedClaim;f.Reasoning=source.Reasoning;f.MatchingEvidence=source.MatchingEvidence;f.EvidenceFamily=source.EvidenceFamily;f.AlternativeExplanation=source.AlternativeExplanation;f.Strength=String.IsNullOrWhiteSpace(source.EvidenceFamily)?"不支持中国关联":source.EvidenceFamily;
   }
   if(source.State=="读取失败"&&f.State=="发现线索")f.Coverage+=" / 导入来源读取失败";
   // Bound each display block independently so a long original cannot hide the supplement.
   f.Evidence=String.Join("\r\n\r\n",f.Sources.Select(s=>"【"+s.Source+"】观察时间："+(String.IsNullOrEmpty(s.ObservedAt)?"未知":s.ObservedAt)+(String.IsNullOrEmpty(s.ImportedAt)?"":"；导入时间："+s.ImportedAt)+"\r\n状态："+s.State+"；"+s.Coverage+"\r\n"+s.Summary+"\r\n"+(s.Evidence.Length>9000?s.Evidence.Substring(0,9000)+"\r\n[显示已截断，详细 JSON Sources 保留本次来源记录]":s.Evidence)));
   return f;
  }
  static Dictionary<string,object> ImportObject(Dictionary<string,object> parent,string key,bool required){object value;if(!parent.TryGetValue(key,out value)){if(required)throw new FormatException("缺少 "+key);return null;}var d=value as Dictionary<string,object>;if(d==null)throw new FormatException(key+" 必须为对象");return d;}
  static void ImportString(Dictionary<string,object> input,Dictionary<string,object> output,string key){object value;if(!input.TryGetValue(key,out value)||value==null)return;if(!(value is string))throw new FormatException(key+" 必须为字符串");if(!String.IsNullOrWhiteSpace((string)value))output[key]=value;}
  static double ImportNumber(Dictionary<string,object> d,string key){object value;double number;if(!d.TryGetValue(key,out value)||value==null||value is bool||!Double.TryParse(Convert.ToString(value,CultureInfo.InvariantCulture),NumberStyles.Float,CultureInfo.InvariantCulture,out number)||Double.IsNaN(number)||Double.IsInfinity(number))throw new FormatException(key+" 必须为有限数字");return number;}
  static string ImportStatus(Dictionary<string,object> d,string[] allowed,string name){string state=Value(d,"status");if(!allowed.Contains(state))throw new FormatException(name+" 状态为空或无效");return state;}
  static string ImportTime(Dictionary<string,object> d,string key,string fallback){if(!d.ContainsKey(key)&&fallback!=null)return fallback;string value=Value(d,key);DateTimeOffset parsed;if(!Regex.IsMatch(value,@"^\d{4}-\d\d-\d\dT.+(?:Z|[+-]\d\d:\d\d)$")||!DateTimeOffset.TryParse(value,CultureInfo.InvariantCulture,DateTimeStyles.None,out parsed))throw new FormatException(key+" 缺少有效的带时区时间");return value;}
 }
}
