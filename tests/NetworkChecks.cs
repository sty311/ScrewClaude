using System;
using System.Collections.Generic;
using System.Linq;
using LocalLens;
class NetworkChecks {
 static int count;static void Check(bool ok,string name){if(!ok)throw new Exception("FAIL: "+name);count++;Console.WriteLine("PASS: "+name);}
 static BrowserNetworkReport Sample(){return new BrowserNetworkReport{RuleVersion="ChinaUserEvidence2.4",StartedUtc="2026-10-16T00:00:00Z",FinishedUtc="2026-10-16T00:00:10Z",Browser="SYNTHETIC_BROWSER",Findings=new[]{1,3,6}.Select(id=>new Finding{Id=id,State=id==6?"发现线索":"未发现",Summary="Sample",MatchingEvidence=id==6?"country=CN":"",Evidence="PRIVATE_NETWORK_ADDRESS<script>script</script>",Limit="Sample only"}).ToList()};}
 static void Reject(Action action,string name){bool failed=false;try{action();}catch(FormatException){failed=true;}Check(failed,name);}
 static int Main(){try{
  Check(DnsConfigurationAssessment.Evaluate(new[]{"192.168.1.1"},"router").State=="未发现","router DNS does not match six-address configuration rule");
  Check(DnsConfigurationAssessment.Evaluate(new[]{"202.99.96.214","2408:8000:2009::b3"},"unknown to old list").Summary.Contains("递归出口"),"configuration verdict keeps actual DNS exit separate");
  Check(DnsConfigurationAssessment.Evaluate(new string[0],"").State=="未检测","no DNS configuration is not a negative result");
  Check(DnsConfigurationAssessment.Evaluate(new[]{"223.5.5.5"},"known").State=="发现线索","known configuration signal retained");
  Check(DnsConfigurationAssessment.Evaluate(new[]{"8.8.8.8"},"config").Summary.Contains("递归出口"),"configuration explicitly leaves recursive path unchecked");
  var sample=BrowserNetworkReport.Validate(Sample());Check(sample.Findings.Count==3&&sample.Findings[2].State=="发现线索","browser network observations validated");
  Reject(()=>BrowserNetworkReport.Validate(null),"null observations rejected");
  var legacy=Sample();legacy.RuleVersion=null;Reject(()=>BrowserNetworkReport.Validate(legacy),"legacy mismatch-based network verdicts cannot be imported as China association");var noProof=Sample();noProof.Findings[2].MatchingEvidence="country=JP";Reject(()=>BrowserNetworkReport.Validate(noProof),"positive network verdict requires explicit CN matched evidence");var invalid=Sample();invalid.Findings.RemoveAt(0);Reject(()=>BrowserNetworkReport.Validate(invalid),"incomplete result set rejected");
  invalid=Sample();invalid.Findings[0].Id=6;Reject(()=>BrowserNetworkReport.Validate(invalid),"duplicate result IDs rejected");
  invalid=Sample();invalid.StartedUtc="2026-10-16T00:00:00";Reject(()=>BrowserNetworkReport.Validate(invalid),"timezone-free time rejected");
  invalid=Sample();invalid.FinishedUtc="2026-10-15T00:00:00Z";Reject(()=>BrowserNetworkReport.Validate(invalid),"reversed observation times rejected");
  invalid=Sample();invalid.Findings[0].State="安全";Reject(()=>BrowserNetworkReport.Validate(invalid),"unsupported safe state rejected");
  invalid=Sample();invalid.Findings[0].Evidence=new string('x',30001);Reject(()=>BrowserNetworkReport.Validate(invalid),"oversized evidence rejected");
  var report=new AuditReport{Completed=false,Options=new ScanOptions(),Findings=Catalog.Load(),BrowserNetwork=sample};
  var summary=Exporter.Prepare(report,false);Check(summary.BrowserNetwork.Findings.All(f=>!f.Evidence.Contains("PRIVATE_NETWORK_ADDRESS"))&&!summary.BrowserNetwork.Browser.Contains("SYNTHETIC_BROWSER"),"summary strips network evidence and browser identifier");
  Check(summary.BrowserNetwork.Findings[2].State=="发现线索","summary retains network finding state");
  Check(report.BrowserNetwork.Findings[0].Evidence.Contains("PRIVATE_NETWORK_ADDRESS"),"summary does not mutate original network evidence");
  string html=Exporter.RenderHtml(report,true);Check(html.Contains("浏览器实际网络路径")&&html.Contains("&lt;script&gt;")&&!html.Contains("<script>script"),"HTML includes separately timed network results and escapes source data");
  Console.WriteLine("NETWORK MODEL CHECKS PASSED: "+count);return 0;
 }catch(Exception ex){Console.Error.WriteLine(ex);return 1;}}
}
