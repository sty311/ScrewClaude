using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Web.Script.Serialization;
using LocalLens;
class ImportChecks {
 static int count, failed;
 static void Check(bool ok,string name){count++;Console.WriteLine((ok?"PASS: ":"FAIL: ")+name);if(!ok)failed++;}
 static List<Finding> Rows(AuditEngine e){return (List<Finding>)typeof(AuditEngine).GetField("rows",BindingFlags.Instance|BindingFlags.NonPublic).GetValue(e);}
 static string Snapshot(object x){if(x is Finding)x=new[]{(Finding)x};var findings=x as IEnumerable<Finding>;if(findings!=null)x=findings.Select(f=>new object[]{f.Id,f.State,f.Summary,f.Coverage,f.Evidence,f.CheckedAt,f.Sources}).ToArray();return new JavaScriptSerializer().Serialize(x);}
 static AuditEngine Engine(string file,string state){var e=new AuditEngine(new ScanOptions{BrowserReportPath=file},f=>{},CancellationToken.None);foreach(int id in new[]{3,12,68}){var f=Rows(e)[id-1];f.State=state;f.Summary="Original summary";f.Coverage="Original coverage";f.Evidence="Original evidence "+id;f.CheckedAt="2026-10-16T01:00:00Z";}return e;}
 static void Import(AuditEngine e){typeof(AuditEngine).GetMethod("Run",BindingFlags.Instance|BindingFlags.NonPublic).Invoke(e,new object[]{58,(Action)(()=>{try{typeof(AuditEngine).GetMethod("ImportBrowser",BindingFlags.Instance|BindingFlags.NonPublic).Invoke(e,null);}catch(TargetInvocationException ex){throw ex.InnerException;}})});}
 static string Json(string env,string rtc,string loc){return "{\"app\":\"LocalLens BrowserCheck 2.0\",\"time\":\"2026-10-15T00:00:00Z\",\"environment\":"+env+(rtc==null?"":",\"webrtc\":"+rtc)+(loc==null?"":",\"location\":"+loc)+"}";}
 static int Main(string[] args){string dir=Path.GetFullPath(args[0]);Directory.CreateDirectory(dir);string file=Path.Combine(dir,"import.json");
  foreach(string state in new[]{"发现线索","读取失败"}){
   File.WriteAllText(file,Json("{\"language\":\"zh-CN\"}","{\"status\":\"completed\",\"candidates\":[]}","{\"status\":\"returned\",\"latitude\":35,\"longitude\":139}"));
   var e=Engine(file,state);Import(e);var rows=Rows(e);
   Check(rows[57].IsClue==true,"valid zh-CN environment is a definite clue");
   foreach(int id in new[]{3,12,68}){var f=rows[id-1];bool newPositive=false;Check(f.State==(newPositive?"发现线索":state)&&f.Evidence.Contains("Original evidence "+id)&&f.Sources.Any(s=>s.State==state&&s.Summary=="Original summary"),"preserve original source while applying definite verdict for "+id);Check(f.Sources.Any(s=>s.ObservedAt=="2026-10-16T01:00:00Z")&&f.Sources.Any(s=>s.ObservedAt=="2026-10-15T00:00:00Z"),"distinct source times for "+id);}
  }
  foreach(string input in new[]{Json("{\"language\":\"en-US\"}","{\"status\":\"completed\",\"candidates\":[]}","{\"status\":\"returned\",\"latitude\":95,\"longitude\":0}"),Json("{}",null,null),Json("{\"language\":\"en-US\"}","{}",null),Json("{\"language\":{}}",null,null),Json("{\"language\":\"en-US\"}","[]",null),Json("{\"language\":\"en-US\"}",null,"{\"status\":\"returned\",\"latitude\":\"NaN\",\"longitude\":0}"),Json("{\"language\":\"en-US\"}",null,null).Replace("2026-10-15T00:00:00Z","invalid-time")}){
   File.WriteAllText(file,input);var e=Engine(file,"发现线索");string before=Snapshot(new[]{Rows(e)[2],Rows(e)[11],Rows(e)[67]});Import(e);
   Check(Rows(e)[57].State=="读取失败","invalid browser input rejected");string after=Snapshot(new[]{Rows(e)[2],Rows(e)[11],Rows(e)[67]});Check(before==after,"invalid browser input commits no other findings");
  }
  File.WriteAllText(file,Json("{\"language\":\"en-US\"}","{\"status\":\"not_run\"}","{\"status\":\"not_run\"}"));var skipped=Engine(file,"未检测");string rtcBefore=Snapshot(Rows(skipped)[2]);Import(skipped);Check(Snapshot(Rows(skipped)[2])==rtcBefore,"not-run RTC does not become a completed observation");
  File.WriteAllText(file,Json("{\"language\":\"en-US\"}","{\"status\":\"error\",\"error\":\"denied\"}",null));var error=Engine(file,"未检测");Import(error);Check(Rows(error)[2].State=="读取失败"&&Rows(error)[2].Evidence.Contains("denied"),"imported RTC failure remains a failure");
  var report=new AuditReport{Options=new ScanOptions(),Findings=Rows(error)};var detailed=Exporter.Prepare(report,true);var summary=Exporter.Prepare(report,false);Check(Snapshot(detailed).Contains("denied")&&!Snapshot(summary).Contains("denied"),"summary removes all nested imported evidence");
  File.WriteAllText(file,Json("{\"language\":\"ug-CN\"}",null,"{\"status\":\"returned\",\"latitude\":39.9042,\"longitude\":116.4074,\"accuracyMeters\":25}"));var history=Engine(file,"未发现");var local=Rows(history)[11];local.Observation="fresh Tokyo sample";local.SupportedClaim="本次定位不支持中国位置";local.Reasoning="Tokyo outside mainland";Import(history);var merged=Rows(history)[11];
  Check(merged.IsClue==true&&merged.SupportedClaim.Contains("导入")&&!merged.SupportedClaim.Contains("本次设备")&&merged.EvidenceFamily=="导入记录地点","old imported mainland coordinate cannot impersonate current local position");
  Check(merged.Sources.Any(s=>s.Source=="本次本机检查"&&s.State=="未发现"&&s.Observation=="fresh Tokyo sample"&&s.Reasoning.Contains("Tokyo")),"fresh negative source and its inferential metadata survive imported positive supplement");
  Check(Rows(history)[57].IsClue==true&&Rows(history)[57].SupportedClaim.Contains("导入")&&Rows(history)[57].EvidenceFamily=="导入地区偏好","imported minority-language CN preference retains source provenance");
  Console.WriteLine("IMPORT CHECKS: "+(count-failed)+" passed / "+count+" total");return failed==0?0:1;
 }
}
