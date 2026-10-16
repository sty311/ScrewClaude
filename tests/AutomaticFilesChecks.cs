// Synthetic local files only; no user data, accounts or network requests.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using LocalLens;
class AutomaticFilesChecks {
 static int count;static BindingFlags flags=BindingFlags.NonPublic|BindingFlags.Instance;
 static void Check(bool ok,string name){if(!ok)throw new Exception(name);count++;Console.WriteLine("PASS: "+name);}
 static void Put(string path,string value){Directory.CreateDirectory(Path.GetDirectoryName(path));File.WriteAllText(path,value);}
 static void Run(AuditEngine engine,string method,params object[] arguments){try{typeof(AuditEngine).GetMethod(method,flags).Invoke(engine,arguments);}catch(TargetInvocationException e){throw e.InnerException;}}
 static Finding Row(AuditEngine e,int id){return ((List<Finding>)typeof(AuditEngine).GetField("rows",flags).GetValue(e))[id-1];}
 static AuditEngine Engine(ScanOptions options,LocalData.WalkResult files){var e=new AuditEngine(options,f=>{},CancellationToken.None);typeof(AuditEngine).GetField("automaticFiles",flags).SetValue(e,files);return e;}
 static int Main(string[] args){try{
  string root=Path.GetFullPath(args[0]);Directory.CreateDirectory(root);
  string docs=Path.Combine(root,"中文 Documents"),pictures=Path.Combine(root,"Pictures"),downloads=Path.Combine(root,"Downloads");
  Put(Path.Combine(docs,"contact.json"),"{\"residenceCountry\":\"CN\"}");
  Put(Path.Combine(docs,"calendar.ics"),"BEGIN:VCALENDAR\nTZID:Asia/Shanghai\nEND:VCALENDAR");
  Put(Path.Combine(docs,"person.vcf"),"BEGIN:VCARD\nADR;TYPE=HOME:;;Example Street;Beijing;;;China\nEND:VCARD");
  Put(Path.Combine(docs,"repo",".git","config"),"synthetic");Put(Path.Combine(docs,"repo","contact.json"),"{\"residenceCountry\":\"CN\"}");
  Put(Path.Combine(docs,"node_modules","contact.json"),"{\"residenceCountry\":\"CN\"}");
  Put(Path.Combine(docs,"app","ScrewClaude.Web.exe"),"not executed");Put(Path.Combine(docs,"app","contact.json"),"{\"residenceCountry\":\"CN\"}");
  Put(Path.Combine(docs,"ScrewClaude-environment-risk-demo.json"),"{\"residenceCountry\":\"CN\"}");
  for(int i=0;i<30;i++)Put(Path.Combine(downloads,i+".exe"),"not executed");
  Directory.CreateDirectory(pictures);using(var image=new Bitmap(20,20))image.Save(Path.Combine(pictures,"photo.jpg"),System.Drawing.Imaging.ImageFormat.Jpeg);
  Put(Path.Combine(downloads,"platform.json"),"{\"format\":\"LocalLens External Evidence 1\",\"records\":[{\"checkId\":56,\"source\":\"Synthetic platform export\",\"observedAt\":\"2026-10-17T00:00:00Z\",\"countryCode\":\"CN\"}]}");
  var roots=new[]{docs,pictures,downloads,docs};var found=AutomaticFiles.Discover(roots,CancellationToken.None);
  Check(new ScanOptions().AutoDiscoverFiles,"automatic discovery is enabled by default");
  Check(found.Files.Count==5,"supported samples from all roots discovered without unrelated executables");
  Check(found.Files.Distinct(StringComparer.OrdinalIgnoreCase).Count()==found.Files.Count,"overlapping or repeated roots do not duplicate samples");
  Check(!found.Files.Any(f=>f.Contains("node_modules")||f.Contains("repo")||f.Contains("environment-risk")),"dependencies repositories and own exports excluded");
  Check(found.Files.Any(f=>f.EndsWith("photo.jpg"))&&found.Files.Any(f=>f.EndsWith("person.vcf")),"separate image and contact file types survive discovery");
  Check(AutomaticFiles.Description(found).Contains("自动查找")&&found.Roots.Count==3,"coverage records actual roots and automatic mode");
  Check(!AutomaticFiles.LocalEntry(FileAttributes.ReparsePoint|FileAttributes.Directory),"junctions and symlink directories are not followed");
  Check(!AutomaticFiles.LocalEntry((FileAttributes)0x1000)&&!AutomaticFiles.LocalEntry((FileAttributes)0x40000)&&!AutomaticFiles.LocalEntry((FileAttributes)0x400000),"offline and cloud recall attributes are excluded");
  var limited=AutomaticFiles.Discover(roots,CancellationToken.None,1);Check(limited.Capped&&limited.Files.Count<=1,"candidate limit is enforced and reported");
  limited=AutomaticFiles.Discover(roots,CancellationToken.None,100,1);Check(limited.Capped&&limited.Directories==1,"directory limit is enforced and reported");
  limited=AutomaticFiles.Discover(roots,CancellationToken.None,100,100,1);Check(limited.Capped&&limited.Entries==1,"entry budget counts unsupported files too");
  limited=AutomaticFiles.Discover(roots,CancellationToken.None,100,100,100,0);Check(limited.Capped&&limited.Files.Count==0,"time budget stops traversal");
  var cancellation=new CancellationTokenSource();cancellation.Cancel();bool stopped=false;try{AutomaticFiles.Discover(roots,cancellation.Token);}catch(OperationCanceledException){stopped=true;}Check(stopped,"cancelled discovery does not enumerate");
  var engine=Engine(new ScanOptions(),found);Run(engine,"RunContent");Check(Row(engine,50).State=="发现线索"&&Row(engine,50).Coverage.Contains("自动发现"),"blank content field automatically analyzes local contact files");
  Check(Row(engine,51).State=="发现线索","automatically found VCF participates in message/contact check");
  Check(Row(engine,55).State=="发现线索","automatically found calendar contributes named timezone evidence");
  Run(engine,"ScanPhotos");Check(Row(engine,48).State=="未发现"&&Row(engine,48).Coverage.Contains("自动发现"),"blank photo field reads actual automatically discovered JPEG");
  Run(engine,"AutomaticExternalRecords");Check(Row(engine,56).State=="发现线索"&&Row(engine,56).Evidence.Contains("Synthetic platform export"),"saved platform records are discovered and retain source provenance");
  Check(Row(engine,57).State=="需外部记录","absent platform fields are not invented");
  var noMessages=new LocalData.WalkResult{Automatic=true,Capped=true};noMessages.Files.Add(Path.Combine(docs,"contact.json"));var cappedEngine=Engine(new ScanOptions(),noMessages);Run(cappedEngine,"RunContent");Check(Row(cappedEngine,51).State=="未检测"&&Row(cappedEngine,51).Summary.Contains("样本")&&Row(cappedEngine,51).Coverage.Contains("上限"),"no message samples remain an explicit skip with search cap disclosed");
  var empty=Path.Combine(root,"Explicit empty");Directory.CreateDirectory(empty);
  engine=Engine(new ScanOptions{ContentFolder=empty,PhotoFolder=empty},found);Run(engine,"RunContent");Run(engine,"ScanPhotos");Check(Row(engine,50).State!="发现线索"&&Row(engine,48).State!="未发现","explicit empty scope overrides automatic samples without a false negative photo result");
  engine=Engine(new ScanOptions{AutoDiscoverFiles=false},found);Run(engine,"ScanPhotos");Check(Row(engine,48).State=="未检测","automatic file checks can be disabled");
  var path=Path.Combine(root,"baseline","baseline.json");var baseline=new Baseline();baseline.Hashes["17"]=LocalData.Hash("first");AutomaticBaseline.Save(path,baseline);Check(Baseline.Load(path).Hashes["17"]==LocalData.Hash("first"),"first local baseline is persisted");
  baseline.Hashes["17"]=LocalData.Hash("second");AutomaticBaseline.Save(path,baseline);Check(Baseline.Load(path).Hashes["17"]==LocalData.Hash("second"),"later complete baseline atomically replaces prior hashes");
  Check(!File.ReadAllText(path).Contains("second"),"automatic baseline stores hashes rather than raw evidence");
  Run(engine,"UserLanguages");Check(Row(engine,21).Evidence.Contains("LanguageTag")&&!Row(engine,21).Evidence.Contains("\"LanguageTag\":null"),"native Windows language collection enumerates list items rather than empty list properties");
  Console.WriteLine("AUTOMATIC FILE CHECKS PASSED: "+count);return 0;
 }catch(Exception ex){Console.Error.WriteLine(ex);return 1;}}
}
