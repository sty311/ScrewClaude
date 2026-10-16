// Explicit Windows environment acceptance run; no WebHost or persistent service is started.
using System;
using System.IO;
using System.Linq;
using System.Threading;
using LocalLens;
class LocalScanChecks {
 static int Main(string[] args){try{
  if(args.Length!=2)throw new ArgumentException("Expected private JSON path and summary output directory");
  Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(args[0])));Directory.CreateDirectory(args[1]);
  using(var cancel=new CancellationTokenSource(TimeSpan.FromMinutes(3))){
   int updates=0;var options=new ScanOptions{History=true,BrowserContent=true,Online=false,Wifi=false,RequestLocation=false,DeviceIdentifiers=false};
   var report=new AuditEngine(options,f=>{updates++;if(updates%10==0)Console.WriteLine("Observed updates: "+updates);},cancel.Token).Scan();
   Exporter.SaveJson(args[0],report,true);
   Exporter.SaveJson(Path.Combine(args[1],"LocalLens-2.4-local-scan-summary.json"),report,false);
   Exporter.SaveHtml(Path.Combine(args[1],"LocalLens-2.4-local-scan-summary.html"),report,false);
   if(!report.Completed||report.Findings.Count!=69)throw new Exception("Scan incomplete; inspect the saved report");
   var positive=report.Findings.Where(f=>f.IsClue==true).ToArray();
   if(positive.Any(f=>String.IsNullOrWhiteSpace(f.SupportedClaim)||String.IsNullOrWhiteSpace(f.Reasoning)||String.IsNullOrWhiteSpace(f.MatchingEvidence)||String.IsNullOrWhiteSpace(f.AlternativeExplanation)))throw new Exception("Positive finding missing inferential chain");
   if(report.Findings.Any(f=>new[]{4,7,11,13,14,16,28,29,30,31,32,33,36,39,40,45,46,47,54,62,63,64,65,66,67,69}.Contains(f.Id)&&f.IsClue==true))throw new Exception("Excluded capability was counted as a China clue");
   Console.WriteLine("LOCAL SCAN: complete; all 69 rules present; all positives have source inference and boundary");
   foreach(var g in report.Findings.GroupBy(f=>f.State))Console.WriteLine(g.Key+": "+g.Count());
   foreach(var f in positive)Console.WriteLine("CHECK "+f.Id+": "+f.SupportedClaim+" / "+f.EvidenceFamily);
   Console.WriteLine("Evidence families: "+String.Join(" / ",report.ChinaUserAssessment.EvidenceFamilies));
   Console.WriteLine("Mode: offline, no location request, no identifiers, no selected documents; browser history enabled");
   return 0;
  }
 }catch(Exception ex){Console.Error.WriteLine(ex);return 1;}}
}
