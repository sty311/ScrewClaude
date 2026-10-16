// Windows-only integration checks against the actual browser collectors.
// Only new synthetic SQLite databases are read. Fixtures are retained, never deleted.
using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;
using LocalLens;

class HistoryEvidenceChecks {
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("winsqlite3",CallingConvention=CallingConvention.StdCall)]
 static extern int sqlite3_open_v2(byte[] path,out IntPtr db,int flags,IntPtr vfs);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("winsqlite3",CallingConvention=CallingConvention.StdCall)]
 static extern int sqlite3_exec(IntPtr db,byte[] sql,IntPtr callback,IntPtr state,out IntPtr error);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("winsqlite3",CallingConvention=CallingConvention.StdCall)]
 static extern int sqlite3_close(IntPtr db);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("winsqlite3",CallingConvention=CallingConvention.StdCall)]
 static extern void sqlite3_free(IntPtr p);

 static readonly BindingFlags Private=BindingFlags.Instance|BindingFlags.NonPublic;
 static readonly JavaScriptSerializer Json=new JavaScriptSerializer();
 static readonly DateTime Today=DateTime.UtcNow.Date;
 const string Baidu="https://private-user:private-password@www.baidu.com/private-history-path?private-history-query=secret#private-history-fragment";
 const string Tencent="https://www.qq.com/private-qq-path?private-qq-query=secret";
 const string Weixin="https://weixin.qq.com/private-weixin-path?private-weixin-query=secret";
 const string Title="PRIVATE_PAGE_TITLE_MUST_NEVER_APPEAR";
 static string root;
 static int passed,failed,cases;
 static List<string> failures=new List<string>();

 sealed class Visit {
  public int Url;
  public string Microseconds;
  public Visit(int url,DateTime time,bool firefox){Url=url;Microseconds=((time.Ticks-(firefox?new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc):new DateTime(1601,1,1,0,0,0,DateTimeKind.Utc)).Ticks)/10).ToString(CultureInfo.InvariantCulture);}
  public Visit(int url,string raw){Url=url;Microseconds=raw;}
 }
 static byte[] Utf8(string value){return Encoding.UTF8.GetBytes(value+"\0");}
 static string Quote(string value){return "'"+value.Replace("'","''")+"'";}
 static void Sql(IntPtr db,string sql){
  IntPtr error;int code=sqlite3_exec(db,Utf8(sql),IntPtr.Zero,IntPtr.Zero,out error);
  string detail=error==IntPtr.Zero?"":Marshal.PtrToStringAnsi(error);
  if(error!=IntPtr.Zero)sqlite3_free(error);
  if(code!=0)throw new Exception("Fixture SQL failed ("+code+"): "+detail);
 }
 static DateTime Day(int offset,int hour){return Today.AddDays(offset).AddHours(hour);}
 static Visit V(int url,int day,bool firefox){return new Visit(url,Day(day,12),firefox);}
 static Visit[] Positive(bool firefox){return new[]{V(1,-3,firefox),V(1,-3,firefox),V(2,-2,firefox),V(2,-2,firefox)};}
 static string Fixture(string name,bool firefox,string[] urls,Visit[] visits,bool omitVisitTable=false){
  string profile=Path.Combine(root,name);Directory.CreateDirectory(profile);
  string file=Path.Combine(profile,firefox?"places.sqlite":"History");IntPtr db;
  int opened=sqlite3_open_v2(Utf8(file),out db,6,IntPtr.Zero);
  if(opened!=0){if(db!=IntPtr.Zero)sqlite3_close(db);throw new Exception("Fixture open failed: "+opened);}
  try{
   Sql(db,firefox?"CREATE TABLE moz_places(id INTEGER PRIMARY KEY,url TEXT,title TEXT,last_visit_date INTEGER,visit_count INTEGER);":"CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT,title TEXT,last_visit_time INTEGER,visit_count INTEGER);");
   string table=firefox?"moz_places":"urls";
   for(int i=0;i<urls.Length;i++)Sql(db,"INSERT INTO "+table+" VALUES("+(i+1)+","+Quote(urls[i])+","+Quote(Title)+","+new Visit(1,Day(-1,12),firefox).Microseconds+",999999);");
   if(!omitVisitTable){
    Sql(db,firefox?"CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY,place_id INTEGER,visit_date INTEGER);":"CREATE TABLE visits(id INTEGER PRIMARY KEY,url INTEGER,visit_time INTEGER);");
    table=firefox?"moz_historyvisits":"visits";
    for(int i=0;i<visits.Length;i++)Sql(db,"INSERT INTO "+table+" VALUES("+(i+1)+","+visits[i].Url+","+Quote(visits[i].Microseconds)+");");
   }
  }finally{sqlite3_close(db);}
  return profile;
 }
 static AuditEngine Engine(params string[] profiles){
  var engine=new AuditEngine(new ScanOptions{BrowserContent=true},f=>{},CancellationToken.None);
  typeof(AuditEngine).GetField("profiles",Private).SetValue(engine,profiles.ToList());return engine;
 }
 static Finding Collect(AuditEngine engine,int id,string method,params object[] arguments){
  Action collect=()=>{try{typeof(AuditEngine).GetMethod(method,Private).Invoke(engine,arguments);}catch(TargetInvocationException error){throw error.InnerException;}};
  typeof(AuditEngine).GetMethod("Run",Private).Invoke(engine,new object[]{id,collect});
  return ((List<Finding>)typeof(AuditEngine).GetField("rows",Private).GetValue(engine))[id-1];
 }
 static Finding History(params string[] profiles){return Collect(Engine(profiles),34,"BrowserHistory");}
 static void Check(bool ok,string name){if(!ok)throw new Exception(name);passed++;Console.WriteLine("PASS: "+name);}
 static void Case(string name,Action run){
  cases++;try{run();}catch(Exception error){failed++;string message=name+": "+error.GetType().Name+": "+error.Message;failures.Add(message);Console.Error.WriteLine("FAIL: "+message);}
 }
 static Dictionary<string,object> Activity(Finding finding){
  var match=Regex.Match(finding.Evidence??"",@"(?m)^DOMESTIC_ACTIVITY=(\{[^\r\n]+\})\s*$");
  if(!match.Success)throw new Exception("Collector omitted DOMESTIC_ACTIVITY: "+finding.Evidence);
  return Json.Deserialize<Dictionary<string,object>>(match.Groups[1].Value);
 }
 static void Counts(Finding finding,int visits,int days,int services,string name){
  var data=Activity(finding);
  Check(Convert.ToInt32(data["visits"])==visits&&Convert.ToInt32(data["days"])==days&&Convert.ToInt32(data["services"])==services&&Convert.ToInt32(data["windowDays"])==90,name+" actual visit/day/company counts and 90-day metadata");
 }
 static string[] Families(Finding finding){return ((IEnumerable)Activity(finding)["families"]).Cast<object>().Select(Convert.ToString).ToArray();}
 static void PositiveFinding(Finding finding,string name){Check(finding.IsClue==true&&!String.IsNullOrWhiteSpace(finding.MatchingEvidence)&&!String.IsNullOrWhiteSpace(finding.Reasoning)&&!String.IsNullOrWhiteSpace(finding.AlternativeExplanation),name);}
 static void NegativeFinding(Finding finding,string name){Check(finding.IsClue==false&&String.IsNullOrEmpty(finding.MatchingEvidence)&&String.IsNullOrEmpty(finding.EvidenceFamily),name);}
 static void PrivateOutput(Finding finding,string name){
  string output=Json.Serialize(finding);
  Check(!output.Contains("https://")&&!output.Contains("private-history-")&&!output.Contains("private-qq-")&&!output.Contains("private-weixin-")&&!output.Contains("private-user")&&!output.Contains("private-password")&&!output.Contains(Title),name+" exposes domains only, without URL paths, queries, credentials or titles");
 }
 static void Storage(string profile,bool firefox,params string[] domains){
  string storage=Path.Combine(profile,firefox?@"storage\default":"IndexedDB");Directory.CreateDirectory(storage);
  foreach(string domain in domains)Directory.CreateDirectory(Path.Combine(storage,(firefox?"https+++":"https_")+domain+(firefox?"":"_0.indexeddb.leveldb")));
 }
 static string[] Corroborated(Finding finding){
  var match=Regex.Match(finding.Evidence??"",@"(?m)^CORROBORATED_DOMESTIC_STORAGE=([^\r\n]+)");
  return match.Success?match.Groups[1].Value.Split(',').Select(s=>s.Trim()).ToArray():new string[0];
 }
 static Finding Weather(string name,string content,string package="Microsoft.BingWeather_test"){
  string packages=Path.Combine(root,name),state=Path.Combine(packages,package,"LocalState");Directory.CreateDirectory(state);
  File.WriteAllText(Path.Combine(state,"weather.json"),content,new UTF8Encoding(false));
  return Collect(Engine(),53,"WeatherCachesAt",packages);
 }

 static int Main(){
  root=Path.Combine(Path.GetTempPath(),"LocalLensHistoryEvidence-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
  Console.WriteLine("SYNTHETIC FIXTURES RETAINED: "+root);
  Console.WriteLine("ASSEMBLY: "+typeof(AuditEngine).Assembly.Location);
  Case("Chromium actual visit join",()=>{
   string p=Fixture("chromium-positive-中文",false,new[]{Baidu,Tencent,"https://www.weibo.com/unvisited-private-path"},Positive(false));
   var f=History(p);Counts(f,4,2,2,"Chromium");PositiveFinding(f,"four visits over two UTC dates and two owners support history");
   Check(Families(f).OrderBy(s=>s).SequenceEqual(new[]{"百度","腾讯"}.OrderBy(s=>s)),"unvisited URL-table row cannot add a third service owner");
   Check(f.Evidence.Contains("www.baidu.com")&&f.Evidence.Contains("www.qq.com"),"Chromium evidence retains host names for inspection");PrivateOutput(f,"Chromium history");
  });
  Case("Firefox actual visit join and Unix epoch",()=>{
   var f=History(Fixture("firefox-positive",true,new[]{Baidu,Tencent},Positive(true)));
   Counts(f,4,2,2,"Firefox");PositiveFinding(f,"Firefox visit_date is decoded from the Unix microsecond epoch");PrivateOutput(f,"Firefox history");
  });
  foreach(bool firefox in new[]{false,true}){bool ff=firefox;Case((ff?"Firefox":"Chromium")+" missing actual visits",()=>{
   var f=History(Fixture((ff?"firefox":"chromium")+"-missing-visits",ff,new[]{Baidu,Tencent},new Visit[0],true));
   Counts(f,0,0,0,ff?"Firefox missing table":"Chromium missing table");
   Check(f.IsClue==null&&f.State=="读取失败"&&f.Evidence.Contains("实际访问表未完成")&&f.Coverage.Contains("访问查询失败 1"),"missing "+(ff?"moz_historyvisits":"visits")+" cannot turn URL summaries into a completed decision and retains its failure");PrivateOutput(f,"missing-table history");
  });}
  Case("Empty actual visit table",()=>{
   var f=History(Fixture("summary-counters-only",false,new[]{Baidu,Tencent},new Visit[0]));Counts(f,0,0,0,"empty visits");Check(f.IsClue==null&&f.State=="未检测","URL visit_count=999999 with recent last_visit_time cannot substitute for missing actual visit samples");
  });
  Case("Empty Firefox actual visits",()=>{
   var f=History(Fixture("firefox-summary-counters-only",true,new[]{Baidu,Tencent},new Visit[0]));Counts(f,0,0,0,"Firefox empty visits");Check(f.IsClue==null&&f.State=="未检测","Firefox URL summary counters without actual visits remain incomplete");
  });
  Case("Two actual visits",()=>{
   var f=History(Fixture("two-visits",false,new[]{Baidu,Tencent},new[]{V(1,-3,false),V(2,-2,false)}));Counts(f,2,2,2,"two visits");PositiveFinding(f,"actual visits retain association without a minimum of three");
  });
  Case("Exact three actual visits",()=>{
   var f=History(Fixture("three-visits",false,new[]{Baidu,Tencent},new[]{V(1,-3,false),V(1,-3,false),V(2,-2,false)}));Counts(f,3,2,2,"three visits");PositiveFinding(f,"exact three actual visits meet the documented boundary");
  });
  Case("One UTC date",()=>{
   var f=History(Fixture("one-utc-date",false,new[]{Baidu,Tencent},new[]{V(1,-3,false),V(1,-3,false),V(2,-3,false),V(2,-3,false)}));Counts(f,4,1,2,"one date");PositiveFinding(f,"one date is enough for actual service association");
  });
  Case("UTC midnight boundary",()=>{
   var f=History(Fixture("utc-midnight",false,new[]{Baidu,Tencent},new[]{new Visit(1,Day(-3,23).AddMinutes(59),false),new Visit(1,Day(-3,23).AddMinutes(59),false),new Visit(2,Day(-2,0).AddMinutes(1),false)}));
   Counts(f,3,2,2,"UTC midnight");PositiveFinding(f,"visits spanning UTC midnight count two UTC dates independently of local Japan date");
  });
  Case("Tencent family deduplication",()=>{
   var f=History(Fixture("qq-plus-weixin",false,new[]{Tencent,Weixin},Positive(false)));Counts(f,4,2,1,"Tencent products");
   Check(Families(f).SequenceEqual(new[]{"腾讯"}),"qq.com and weixin.qq.com form one company family");PositiveFinding(f,"one owner is enough, and remains one owner");
  });
  Case("Unvisited second owner",()=>{
   var f=History(Fixture("unvisited-second-owner",false,new[]{Tencent,Baidu},new[]{V(1,-3,false),V(1,-3,false),V(1,-2,false),V(1,-2,false)}));Counts(f,4,2,1,"unvisited owner");PositiveFinding(f,"Tencent actual visits retain association; unvisited Baidu still cannot add a second owner");
  });
  foreach(bool firefox in new[]{false,true}){bool ff=firefox;Case((ff?"Firefox":"Chromium")+" old and future visits",()=>{
   var f=History(Fixture((ff?"firefox":"chromium")+"-outside-window",ff,new[]{Baidu,Tencent},new[]{V(1,-2,ff),V(1,-2,ff),V(2,-91,ff),V(2,1,ff)}));
   Counts(f,2,1,1,ff?"Firefox exclusions":"Chromium exclusions");PositiveFinding(f,"valid remaining "+(ff?"Firefox":"Chromium")+" visits retain association, excluding old and future records");
  });}
  Case("Inside 90-day window",()=>{
   var f=History(Fixture("inside-90-days",false,new[]{Baidu,Tencent},new[]{V(1,-89,false),V(1,-89,false),V(2,-2,false),V(2,-2,false)}));Counts(f,4,2,2,"89-day-old visits");PositiveFinding(f,"valid actual visits 89 days old remain inside the 90-day window");
  });
  Case("No recent actual visit samples",()=>{
   var f=History(Fixture("no-recent-samples",false,new[]{Baidu,Tencent},new[]{V(1,-91,false),V(1,-91,false),V(2,1,false),V(2,1,false)}));Counts(f,0,0,0,"out-of-window-only visits");Check(f.IsClue==null&&f.State=="未检测","only old or future visits leave the 90-day history check incomplete");
  });
  Case("Only non-HTTP actual records",()=>{
   var f=History(Fixture("non-http-only",false,new[]{"file:///private-history-path/baidu.com","chrome://history"},new[]{V(1,-3,false),V(1,-3,false),V(2,-2,false),V(2,-2,false)}));Counts(f,0,0,0,"non-HTTP visits");Check(f.IsClue==null&&f.State=="未检测","non-HTTP records cannot substitute for actual recent web visit samples");PrivateOutput(f,"non-HTTP history");
  });
  Case("Lookalikes and generic country domains",()=>{
   var f=History(Fixture("host-boundaries",false,new[]{"https://baidu.com.evil.example/private-history-path","https://example.cn/private-history-path","https://example.com/qq.com/baidu.com?cn=CN"},new[]{V(1,-3,false),V(1,-3,false),V(2,-2,false),V(3,-2,false)}));
   Counts(f,0,0,0,"non-service hosts");NegativeFinding(f,"suffix lookalikes, generic .cn domains and domain text in paths are not domestic service visits");PrivateOutput(f,"non-service history");
  });
  Case("Malformed and overflowing visit timestamps",()=>{
   var f=History(Fixture("bad-timestamps",false,new[]{Baidu,Tencent},new[]{V(1,-3,false),V(2,-2,false),new Visit(1,"not-a-number"),new Visit(1,Int64.MaxValue.ToString()),new Visit(2,Int64.MinValue.ToString())}));
   Counts(f,2,2,2,"invalid timestamp exclusions");PositiveFinding(f,"two valid visits retain association while malformed timestamps are excluded");
  });
  Case("Orphan visit references",()=>{
   var f=History(Fixture("orphan-visits",false,new[]{Baidu,Tencent},new[]{V(1,-3,false),V(2,-2,false),V(999,-3,false),V(999,-2,false)}));Counts(f,2,2,2,"joined rows only");PositiveFinding(f,"valid joined visits retain association while orphan records remain excluded");
  });
  Case("Multiple browser profiles",()=>{
   string chrome=Fixture("combined-chromium",false,new[]{Tencent},new[]{V(1,-3,false),V(1,-3,false)});
   string firefox=Fixture("combined-firefox",true,new[]{Baidu},new[]{V(1,-2,true),V(1,-2,true)});
   var f=History(chrome,firefox);Counts(f,4,2,2,"combined Chromium and Firefox");PositiveFinding(f,"actual visits aggregate across supplied profiles with their own time epochs");
  });
  Case("No browser database",()=>{
   string p=Path.Combine(root,"no-database");Directory.CreateDirectory(p);var f=History(p);Counts(f,0,0,0,"no database");Check(f.IsClue==null,"missing browser databases remain an incomplete check");
  });
  Case("Storage without history",()=>{
   string p=Fixture("storage-only",false,new[]{Baidu,Tencent},Positive(false));Storage(p,false,"baidu.com");
   var f=Collect(Engine(p),35,"BrowserStorage");PositiveFinding(f,"actual domestic IndexedDB remains service association without available history");Check(Corroborated(f).Length==0,"unrun history cannot produce a storage corroboration marker");
  });
  Case("Storage with insufficient actual history",()=>{
   string p=Fixture("storage-two-visits",false,new[]{Baidu,Tencent},new[]{V(1,-3,false),V(2,-2,false)});Storage(p,false,"baidu.com");
   var engine=Engine(p);var history=Collect(engine,34,"BrowserHistory");PositiveFinding(history,"actual history is positive without the old three-visit threshold");
   var f=Collect(engine,35,"BrowserStorage");PositiveFinding(f,"actual storage retains association independently of history");Check(Corroborated(f).SequenceEqual(new[]{"百度"}),"actual positive history can corroborate matching storage");
  });
  Case("Permission Preferences without storage",()=>{
   string p=Fixture("preferences-only",false,new[]{Baidu,Tencent},Positive(false));
   File.WriteAllText(Path.Combine(p,"Preferences"),"{\"profile\":{\"content_settings\":{\"exceptions\":{\"notifications\":{\"https://www.baidu.com/private-history-path?private-history-query=secret,*\":{\"setting\":1}}}}}}",new UTF8Encoding(false));
   var engine=Engine(p);PositiveFinding(Collect(engine,34,"BrowserHistory"),"Preferences-only fixture has genuinely positive actual history");var f=Collect(engine,35,"BrowserStorage");
   Check(f.IsClue!=true&&Corroborated(f).Length==0,"permission declarations without actual storage directories cannot corroborate domestic storage");PrivateOutput(f,"permission-only Preferences");
  });
  Case("Matching Chromium storage and Preferences privacy",()=>{
   string p=Fixture("storage-positive",false,new[]{Baidu,Tencent},Positive(false));Storage(p,false,"baidu.com");
   File.WriteAllText(Path.Combine(p,"Preferences"),"{\"profile\":{\"content_settings\":{\"exceptions\":{\"notifications\":{\"https://www.baidu.com/private-history-path?private-history-query=secret,*\":{\"setting\":1}}}}}}",new UTF8Encoding(false));
   var engine=Engine(p);var history=Collect(engine,34,"BrowserHistory");PositiveFinding(history,"matching Chromium storage has positive history first");var f=Collect(engine,35,"BrowserStorage");
   PositiveFinding(f,"IndexedDB and Preferences origins corroborate an already positive history family");Check(Corroborated(f).SequenceEqual(new[]{"百度"}),"only the matching actual history family appears in corroboration");PrivateOutput(f,"Chromium storage Preferences");
   var assessment=ChinaUserAssessment.Create(new[]{history,f},null);Check(assessment.EvidenceFamilies.Length==1&&assessment.SupportingChecks.SequenceEqual(new[]{34,35}),"actual history and corroborated storage retain one evidence family in the combined assessment");
  });
  Case("Unmatched storage family",()=>{
   string p=Fixture("storage-unmatched",false,new[]{Baidu,Tencent},Positive(false));Storage(p,false,"weibo.com");var engine=Engine(p);Collect(engine,34,"BrowserHistory");
   var f=Collect(engine,35,"BrowserStorage");PositiveFinding(f,"Sina actual storage retains its own association even without matching history");Check(Corroborated(f).Length==0,"unmatched storage emits no corroboration marker");
  });
  Case("Mixed matching and unmatched storage families",()=>{
   string p=Fixture("storage-mixed",false,new[]{Baidu,Tencent},Positive(false));Storage(p,false,"baidu.com","weibo.com");var engine=Engine(p);Collect(engine,34,"BrowserHistory");
   var f=Collect(engine,35,"BrowserStorage");PositiveFinding(f,"one matching storage owner can corroborate history");Check(Corroborated(f).SequenceEqual(new[]{"百度"}),"unmatched Sina origin is excluded from the actual corroboration marker");
  });
  Case("Lookalike and malformed storage origins",()=>{
   string p=Fixture("storage-lookalikes",false,new[]{Baidu,Tencent},Positive(false));Storage(p,false,"baidu.com.evil.example","fake-baidu.com");
   Directory.CreateDirectory(Path.Combine(p,"IndexedDB","unrelated_baidu.com_backup"));var engine=Engine(p);Collect(engine,34,"BrowserHistory");
   var f=Collect(engine,35,"BrowserStorage");NegativeFinding(f,"lookalike hosts and domain text in malformed origin directory names cannot corroborate storage");Check(Corroborated(f).Length==0,"storage host extraction excludes suffix lookalikes and arbitrary folder-name substrings");
  });
  Case("Firefox storage matching",()=>{
   string p=Fixture("firefox-storage-positive",true,new[]{Baidu,Tencent},Positive(true));Storage(p,true,"baidu.com");var engine=Engine(p);Collect(engine,34,"BrowserHistory");
   var f=Collect(engine,35,"BrowserStorage");PositiveFinding(f,"Firefox storage/default origin corroborates its positive actual history");Check(Corroborated(f).SequenceEqual(new[]{"百度"}),"Firefox storage corroboration retains the matching owner only");
  });
  Case("Profile path cannot fabricate storage owner",()=>{
   string p=Fixture("baidu.com",false,new[]{Baidu,Tencent},Positive(false));Storage(p,false,"weibo.com");var engine=Engine(p);Collect(engine,34,"BrowserHistory");
   var f=Collect(engine,35,"BrowserStorage");PositiveFinding(f,"Sina actual storage remains association; profile path does not add Baidu");Check(Corroborated(f).Length==0,"storage owners come from origins, excluding local directory names");
  });
  Case("Firefox profile path cannot fabricate storage owner",()=>{
   string p=Fixture(Path.Combine("firefox-path","baidu.com"),true,new[]{Baidu,Tencent},Positive(true));Storage(p,true,"weibo.com");var engine=Engine(p);Collect(engine,34,"BrowserHistory");
   var f=Collect(engine,35,"BrowserStorage");PositiveFinding(f,"Firefox Sina origin retains association without adding profile-path Baidu");Check(Corroborated(f).Length==0,"Firefox stored owners are taken only from origin hosts");
  });
  Case("Weather current-location producer binding",()=>{
   var f=Weather("weather-current","{\"countryCode\":\"CN\",\"isCurrentLocation\":true}");
   PositiveFinding(f,"actual weather collector binds a current-location CN JSON object to check 53");
   Check(Regex.IsMatch(f.Evidence,@"(?m)^CURRENT_LOCATION_COUNTRY=CN\r?$")&&f.Evidence.Contains("weather.json"),"weather output preserves filename and emits the location marker on its own line");
  });
  Case("Nested current Windows Maps record",()=>{
   var f=Weather("maps-current","{\"locations\":[{\"countryCode\":\"JP\",\"isFavorite\":true},{\"countryCode\":\"CN\",\"locationType\":\"current\"}]}","Microsoft.WindowsMaps_test");
   PositiveFinding(f,"actual Windows Maps collector recognizes nested current-location and CN fields in the same object");
  });
  Case("Weather default city",()=>{
   var f=Weather("weather-default","{\"countryCode\":\"CN\",\"city\":\"Beijing\",\"isDefault\":true}");PositiveFinding(f,"default Chinese region retains preference association without claiming current location");
  });
  Case("Weather favorite city",()=>{
   var f=Weather("weather-favorite","{\"countryCode\":\"CN\",\"city\":\"Beijing\",\"isFavorite\":true}");PositiveFinding(f,"favorite Chinese region retains preference association without claiming current location");
  });
  Case("Weather bare city text",()=>{
   var f=Weather("weather-bare","{\"city\":\"Beijing\",\"description\":\"中国 北京\"}");NegativeFinding(f,"bare Chinese city text does not become a device-location marker");
  });
  Case("Weather country and current flag in distinct objects",()=>{
   var f=Weather("weather-separated","{\"countryCode\":\"CN\",\"location\":{\"isCurrentLocation\":true}}");NegativeFinding(f,"CN in a parent object cannot borrow an unrelated current-location flag");
  });
  Case("Weather JP current location plus CN favorite",()=>{
   var f=Weather("weather-jp-current","[{\"countryCode\":\"JP\",\"isCurrentLocation\":true},{\"countryCode\":\"CN\",\"isFavorite\":true}]");PositiveFinding(f,"Chinese favorite remains preference while current Japan location stays separate");
  });
  Case("Weather string current flag",()=>{
   var f=Weather("weather-string-current","{\"countryCode\":\"CN\",\"isCurrentLocation\":\"true\"}");NegativeFinding(f,"a string current flag is not treated as an actual boolean location marker");
  });
  Case("Weather package scope",()=>{
   var f=Weather("weather-unrelated-package","{\"countryCode\":\"CN\",\"isCurrentLocation\":true}","Unrelated.Application_test");Check(f.IsClue==null,"weather collector ignores otherwise matching content in unrelated app packages");
  });
  Console.WriteLine("HISTORY EVIDENCE CHECKS: "+passed+" assertions passed; "+failed+" cases failed; "+cases+" cases total");
  foreach(string failure in failures)Console.WriteLine("FAILED CASE: "+failure);
  return failed==0?0:1;
 }
}
