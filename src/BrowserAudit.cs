using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
namespace LocalLens {
 public sealed partial class AuditEngine {
  List<string> profiles; readonly List<string> profileErrors=new List<string>();
  List<string> Profiles(){if(profiles!=null)return profiles;profiles=new List<string>();foreach(var root in new[]{Path.Combine(Local,@"Google\Chrome\User Data"),Path.Combine(Local,@"Microsoft\Edge\User Data"),Path.Combine(Local,@"BraveSoftware\Brave-Browser\User Data"),Path.Combine(Local,@"Vivaldi\User Data"),Path.Combine(Roaming,@"Mozilla\Firefox\Profiles"),Path.Combine(Roaming,@"Opera Software\Opera Stable")}){if(!Directory.Exists(root))continue;try{if(File.Exists(Path.Combine(root,"Preferences")))profiles.Add(root);foreach(var dir in Directory.EnumerateDirectories(root).Take(40))if((File.GetAttributes(dir)&FileAttributes.ReparsePoint)==0&&(File.Exists(Path.Combine(dir,"Preferences"))||File.Exists(Path.Combine(dir,"places.sqlite"))))profiles.Add(dir);}catch(Exception ex){profileErrors.Add(root+": "+ex.Message);}}return profiles.Distinct().ToList();}
  bool Firefox(string p){return File.Exists(Path.Combine(p,"places.sqlite"));}
  string ProfileName(string p){return p.Replace(Local,"%LOCALAPPDATA%").Replace(Roaming,"%APPDATA%");}
  void BrowserHistory(){
   var lines=new List<string>();int urlRows=0,urlFailures=0,validVisits=0,visitTablesRead=0,visitFailures=0;var activity=new List<string[]>();DateTime now=DateTime.UtcNow;
   foreach(var p in Profiles()){
    bool firefox=Firefox(p);string file=Path.Combine(p,firefox?"places.sqlite":"History");if(!File.Exists(file))continue;
    try{using(var db=new SqliteRead(file)){
     try{var urls=db.Query(firefox?"SELECT url FROM moz_places ORDER BY last_visit_date DESC LIMIT 2000":"SELECT url FROM urls ORDER BY last_visit_time DESC LIMIT 2000",2000,cancel);urlRows+=urls.Count;
      lines.Add(ProfileName(p)+"：读取 URL 记录 "+urls.Count+"，仅作域名展示，不计入访问样本");
      lines.AddRange(urls.Select(x=>LocalData.Host(x[0])).Where(h=>h.Length>0).Distinct().Take(80));
     }catch(Exception ex){if(ex is OperationCanceledException)throw;urlFailures++;lines.Add(ProfileName(p)+"：URL 展示查询未完成："+ex.Message);}
     try{var visits=db.Query(firefox?"SELECT p.url,v.visit_date FROM moz_historyvisits v JOIN moz_places p ON p.id=v.place_id ORDER BY v.visit_date DESC LIMIT 4000":"SELECT u.url,v.visit_time FROM visits v JOIN urls u ON u.id=v.url ORDER BY v.visit_time DESC LIMIT 4000",4000,cancel);visitTablesRead++;
      foreach(var row in visits){long micro;string host=LocalData.Host(row[0]);if(host.Length==0||!Int64.TryParse(row[1],out micro))continue;
       try{DateTime time=(firefox?new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc):new DateTime(1601,1,1,0,0,0,DateTimeKind.Utc)).AddTicks(checked(micro*10));if(time>=now.AddDays(-90)&&time<=now.AddMinutes(5)){validVisits++;string service=ChinaEvidence.ServiceFamily(host);if(service.Length>0)activity.Add(new[]{service,time.ToString("yyyy-MM-dd")});}}catch(ArgumentOutOfRangeException){}catch(OverflowException){}
      }
     }catch(Exception ex){if(ex is OperationCanceledException)throw;visitFailures++;lines.Add(ProfileName(p)+"：实际访问表未完成："+ex.Message);}
    }}catch(Exception ex){if(ex is OperationCanceledException)throw;visitFailures++;lines.Add(ProfileName(p)+"：历史数据库未完成："+ex.Message);}
   }
   lines.AddRange(profileErrors);
   lines.Insert(0,"DOMESTIC_ACTIVITY="+new JavaScriptSerializer().Serialize(new{visits=activity.Count,days=activity.Select(x=>x[1]).Distinct().Count(),services=activity.Select(x=>x[0]).Distinct().Count(),families=activity.Select(x=>x[0]).Distinct().ToArray(),windowDays=90}));
   lines.Insert(1,"实际访问表成功 "+visitTablesRead+"；访问查询失败 "+visitFailures+"；有效近 90 天 HTTP(S) 访问 "+validVisits+"；URL 展示记录 "+urlRows+"；URL 展示失败 "+urlFailures+"；配置枚举失败 "+profileErrors.Count);
   lines.Add("只计真实 visits 表近 90 天、最多每配置 4000 次访问；不把 URL 表计数、下载、DNS 缓存或普通 .cn 域名替代实际访问。");
   string coverage="近 90 天 / 实际访问表 / UTC 日期 / 成功访问表 "+visitTablesRead+" / 访问查询失败 "+visitFailures;
   if(visitTablesRead==0&&(visitFailures>0||profileErrors.Count>0)){Set(34,"读取失败","没有成功读取实际访问表，未完成行为判定",String.Join("\r\n",lines),coverage);return;}
   if(validVisits==0){Set(34,"未检测","未取得有效的近 90 天 HTTP(S) 实际访问样本",String.Join("\r\n",lines),coverage);return;}
   Outcome(34,lines,activity.Count,validVisits,visitFailures+urlFailures+profileErrors.Count,"历史访问组合已采集",coverage);
  }
  static string StorageOriginHost(string name,bool firefox){
   var m=Regex.Match(name??"",firefox?@"^(https?)\+\+\+([a-z0-9][a-z0-9.-]*)(?:\+([0-9]{1,5}))?(?:\^[^\r\n]*)?$":@"^(https?)_([a-z0-9][a-z0-9.-]*)_([0-9]{1,5})\.indexeddb\.(?:leveldb|blob)$",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant);
   if(!m.Success)return "";int port=0;if(m.Groups[3].Success&&(!Int32.TryParse(m.Groups[3].Value,out port)||port>65535))return "";
   Uri origin;if(!Uri.TryCreate(m.Groups[1].Value+"://"+m.Groups[2].Value+(port>0?":"+port:""),UriKind.Absolute,out origin)||origin.UserInfo.Length>0||origin.AbsolutePath!="/"||origin.HostNameType!=UriHostNameType.Dns)return "";
   return origin.IdnHost.TrimEnd('.').ToLowerInvariant();
  }
  void BrowserStorage(){
   var lines=new List<string>();int scanned=0,candidates=0,permissionReferences=0,failed=0;var storedFamilies=new HashSet<string>(StringComparer.Ordinal);
   foreach(var p in Profiles()){try{
    bool firefox=Firefox(p);string directory=Path.Combine(p,firefox?@"storage\default":"IndexedDB");
    if(Directory.Exists(directory))foreach(var origin in Directory.EnumerateDirectories(directory).Take(1000)){
     if((File.GetAttributes(origin)&FileAttributes.ReparsePoint)!=0)continue;candidates++;string host=StorageOriginHost(Path.GetFileName(origin),firefox);if(host.Length==0)continue;scanned++;
     string family=ChinaEvidence.ServiceFamily(host);if(family.Length>0)storedFamilies.Add(family);
     if(LocalData.ChinaHost(host))lines.Add(ProfileName(p)+" 实际存储 origin 主机："+host);
    }
    if(!firefox){var file=Path.Combine(p,"Preferences");if(File.Exists(file)){var obj=LocalData.Json(file,8*1024*1024);object profile;if(obj.TryGetValue("profile",out profile)){string text=new JavaScriptSerializer().Serialize(profile);var matches=Regex.Matches(text,@"https?://[a-zA-Z0-9.-]+(?=[:/""\\])");foreach(Match m in matches){string host=LocalData.Host(m.Value);if(LocalData.ChinaHost(host)){permissionReferences++;lines.Add(ProfileName(p)+" 权限 / 站点偏好来源（不计存储证据）："+host);}}}}}
   }catch(Exception ex){if(ex is OperationCanceledException)throw;failed++;lines.Add(ProfileName(p)+"："+ex.Message);}}
   failed+=profileErrors.Count;lines.AddRange(profileErrors);var history=ChinaEvidence.Marker(F(34).Evidence,"DOMESTIC_ACTIVITY");object historyFamilies;var known=history.TryGetValue("families",out historyFamilies)&&historyFamilies is System.Collections.IList?((System.Collections.IList)historyFamilies).Cast<object>().Select(Convert.ToString).ToArray():new string[0];var corroborated=F(34).IsClue==true?storedFamilies.Intersect(known).ToArray():new string[0];
   lines.Insert(0,"DOMESTIC_STORAGE="+new JavaScriptSerializer().Serialize(new{families=storedFamilies.OrderBy(x=>x).ToArray()}));
   if(corroborated.Length>0)lines.Insert(0,"CORROBORATED_DOMESTIC_STORAGE="+String.Join(", ",corroborated));
   lines.Insert(0,"只从实际存储 origin 目录解析 HTTP(S) 主机参与存储佐证；权限 / 站点偏好仅作观察。不解密 Cookie，不解析 LevelDB 内容，不证明存在账号或具体偏好。目录候选 "+candidates+"；有效 origin "+scanned+"；权限 / 偏好引用 "+permissionReferences);
   Outcome(35,lines,storedFamilies.Count,scanned,failed,"实际站点存储命中国内服务主体","实际存储 origin 主机范围；内容不完整");
  }
  void BrowserLanguage(){var lines=new List<string>();int read=0,failed=0;foreach(var p in Profiles()){try{string file=Path.Combine(p,Firefox(p)?"prefs.js":"Preferences");if(!File.Exists(file))continue;string text=LocalData.ReadBounded(file,8*1024*1024);if(Firefox(p)){foreach(Match m in Regex.Matches(text,@"user_pref\(""(?:intl\.(?:accept_languages|locale.requested)|general\.useragent\.locale)"",[^\r\n]+"))lines.Add("LANGUAGE_VALUES="+m.Value);}else{var d=Obj(text);object intl;if(d.TryGetValue("intl",out intl)){var language= intl as Dictionary<string,object>;if(language!=null)lines.Add("LANGUAGE_VALUES="+new JavaScriptSerializer().Serialize(language.Where(k=>new[]{"accept_languages","selected_languages","app_locale"}.Contains(k.Key)).ToDictionary(k=>k.Key,k=>k.Value)));}else lines.Add(ProfileName(p)+"：intl 未设置（可能继承系统）");}read++;}catch(Exception e){failed++;lines.Add(e.Message);}}Outcome(25,lines,lines.Any(Rules.MainlandLocale)?1:0,read,failed,"浏览器配置含大陆中文区域标记","多浏览器 / 多配置目录");}
  void BrowserAutofill(){var lines=new List<string>();int read=0,hit=0,failed=0;foreach(var p in Profiles()){string file=Path.Combine(p,"Web Data");if(!File.Exists(file))continue;try{using(var db=new SqliteRead(file)){var tables=db.Query("SELECT name FROM sqlite_master WHERE type='table'",200,cancel).Select(x=>x[0]).ToArray();if(!tables.Contains("autofill")){lines.Add(ProfileName(p)+"：未支持此版本地址字段结构");failed++;continue;}var fields=db.Query("SELECT name,value FROM autofill WHERE lower(name) IN ('country','country_code','countrycode','address-level1','address-level2','province','state','city') LIMIT 500",500,cancel);read+=fields.Count;foreach(var f in fields){if(LocalData.Place.IsMatch(f[1]))hit++;lines.Add(ProfileName(p)+" / "+f[0]+" = "+f[1]);}lines.Add(ProfileName(p)+"：检查国家 / 省市命名字段 "+fields.Count+"。未读取付款、密码、手机号或完整街道地址。");}}catch(Exception ex){if(ex is OperationCanceledException)throw;failed++;lines.Add(ProfileName(p)+"："+ex.Message);}}Outcome(52,lines,hit,read,failed,"自动填充国家 / 城市字段出现地名线索","仅 Chromium 普通表单白名单字段");}
  void Extensions(){var lines=new List<string>();int read=0,risk=0,failed=0;foreach(var p in Profiles()){try{if(Firefox(p)){string file=Path.Combine(p,"extensions.json");if(!File.Exists(file))continue;var data=LocalData.Json(file,8*1024*1024);object values;if(data.TryGetValue("addons",out values)){foreach(var addon in (System.Collections.IEnumerable)values){var d=addon as Dictionary<string,object>;if(d==null)continue;read++;object perm;string text=d.TryGetValue("userPermissions",out perm)?new JavaScriptSerializer().Serialize(perm):"未提供权限字段";if(SensitivePermission(text))risk++;lines.Add(Value(d,"id")+" active="+Value(d,"active")+" 权限="+text);}}}else{string root=Path.Combine(p,"Extensions");if(!Directory.Exists(root))continue;foreach(string id in Directory.EnumerateDirectories(root).Take(150)){cancel.ThrowIfCancellationRequested();foreach(string v in Directory.EnumerateDirectories(id).Take(10)){string manifest=Path.Combine(v,"manifest.json");if(!File.Exists(manifest))continue;var d=LocalData.Json(manifest,1048576);var perms=new List<string>();foreach(string key in new[]{"permissions","host_permissions","optional_permissions","optional_host_permissions"}){object value;if(d.TryGetValue(key,out value))perms.Add(key+"="+new JavaScriptSerializer().Serialize(value));}string text=String.Join(" ",perms);read++;if(SensitivePermission(text))risk++;lines.Add(Path.GetFileName(id)+" / "+Value(d,"name")+" / "+Value(d,"version")+" "+text);}}}}catch(Exception ex){if(ex is OperationCanceledException)throw;failed++;lines.Add(ProfileName(p)+"："+ex.Message);}}lines.Insert(0,"分析扩展清单 "+read+"；含敏感或广泛权限声明 "+risk+"；错误 "+failed+"。声明权限 / 可选权限不等于已授权，安装文件不等于扩展正在运行。");Outcome(66,lines,risk,read,failed,"扩展声明敏感或广泛权限，需检查授权状态","本地扩展清单；非恶意判定");}
  public static bool SensitivePermission(string s){return Regex.IsMatch(s??"",@"(?i)(clipboardRead|debugger|nativeMessaging|<all_urls>|history|\*://\*/\*|https?://\*/\*)");}
  void Outcome(int id,List<string> lines,int found,int examined,int failed,string yes,string coverage){string status=coverage+" / 有效样本 "+examined+" / 读取失败 "+failed;if(found>0)Set(id,"发现线索",yes,String.Join("\r\n",lines),status);else if(examined==0||(id==10&&examined<2))Set(id,failed>0?"读取失败":"未检测",failed>0?"有效样本不足并有读取失败，未完成判定":"有效样本不足，未执行判定",String.Join("\r\n",lines),status);else Mark(id,String.Join("\r\n",lines),false,yes,"成功读取的样本未命中本项规则",status);}
 }
}
