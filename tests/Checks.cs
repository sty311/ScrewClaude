using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using LocalLens;
class Checks {
 static int count;
 static void Assert(bool x,string name){if(!x)throw new Exception("FAIL: "+name);count++;Console.WriteLine("PASS: "+name);}
 static byte[] GPS(){var b=new byte[24];Buffer.BlockCopy(BitConverter.GetBytes((uint)39),0,b,0,4);Buffer.BlockCopy(BitConverter.GetBytes((uint)1),0,b,4,4);Buffer.BlockCopy(BitConverter.GetBytes((uint)54),0,b,8,4);Buffer.BlockCopy(BitConverter.GetBytes((uint)1),0,b,12,4);Buffer.BlockCopy(BitConverter.GetBytes((uint)0),0,b,16,4);Buffer.BlockCopy(BitConverter.GetBytes((uint)1),0,b,20,4);return b;}
 static void Main(){
  Assert(Rules.MainlandLocale("zh-CN"),"mainland locale");Assert(Rules.MainlandLocale("LANG=zh_CN.UTF-8"),"POSIX locale");Assert(!Rules.MainlandLocale("zh-TW"),"Taiwan locale not classified mainland");Assert(!Rules.MainlandLocale("ja-JP"),"Japanese locale not classified mainland");Assert(!Rules.MainlandLocale("UTC+08:00"),"UTC+8 alone not classified mainland");Assert(!Rules.MainlandLocale("zh-Hans"),"simplified script alone not classified mainland");
  Assert(Rules.HasHan("家里WiFi"),"Chinese name recognized");Assert(!Rules.HasHan("Tokyo WiFi"),"Latin name not Chinese");
  var safe=Rules.StripSecrets("https://alice:supersecret@example.com/path?token=secret#id");Assert(!safe.Contains("supersecret")&&!safe.Contains("token=secret"),"URL credentials and query removed");Assert(!Rules.StripSecrets("api_key=abcdef").Contains("abcdef"),"secret key assignment removed");
  var redacted=Rules.Redact(@"C:\Users\Alice\Pictures 192.168.1.3 aa:bb:cc:dd:ee:ff name@example.com 2001:db8::1");Assert(!redacted.Contains("Alice")&&!redacted.Contains("192.168.1.3")&&!redacted.Contains("aa:bb:cc")&&!redacted.Contains("name@example.com")&&!redacted.Contains("2001:db8"),"identifier redaction");
  var catalog=Catalog.Load();Assert(catalog.Count==69&&catalog.Select(x=>x.Id).Distinct().Count()==69,"69 unique source items");Assert(catalog.All(x=>x.State=="未检测"),"initial state is unchecked");Assert(catalog.All(x=>!String.IsNullOrEmpty(x.Limit)),"all checks disclose interpretation limit");
  catalog[0].State="读取失败";catalog[0].Evidence="SECRET_PRIVATE_EVIDENCE<script>alert('x')</script>";catalog[0].Summary="测试";
  var report=new AuditReport {CreatedUtc="2026-10-15T00:00:00Z",Completed=false,Platform="test",Options=new ScanOptions {PhotoFolder=@"C:\Users\Alice\Photos"},Findings=catalog};
  var summary=Exporter.Prepare(report,false);Assert(!summary.Findings[0].Evidence.Contains("SECRET_PRIVATE"),"summary removes raw evidence");Assert(!summary.Options.PhotoFolder.Contains("Alice"),"summary removes selected path");Assert(report.Findings[0].Evidence.Contains("SECRET_PRIVATE"),"summary export does not mutate original");Assert(summary.Findings[0].State=="读取失败"&&!summary.Completed,"failure and interrupted scan retained");
  string dir=Path.Combine(Path.GetTempPath(),"LocalLens-tests-"+Guid.NewGuid());Directory.CreateDirectory(dir);
  Exporter.SaveHtml(Path.Combine(dir,"report.html"),report,true);string html=File.ReadAllText(Path.Combine(dir,"report.html"));Assert(!html.Contains("<script>alert")&&html.Contains("&lt;script&gt;"),"HTML evidence escaped");
  Exporter.SaveJson(Path.Combine(dir,"summary.json"),report,false);Assert(!File.ReadAllText(Path.Combine(dir,"summary.json")).Contains("SECRET_PRIVATE"),"JSON summary excludes raw evidence");Directory.Delete(dir,true);
  Assert(Math.Abs(AuditEngine.Coordinate(GPS(),"N")-39.9)<0.00001,"GPS rationals decoded");Assert(Math.Abs(AuditEngine.Coordinate(GPS(),"S")+39.9)<0.00001,"southern coordinate sign");bool threw=false;try{AuditEngine.Coordinate(new byte[24],"N");}catch(FormatException){threw=true;}Assert(threw,"invalid GPS zero denominator rejected");
  Finding observed=null;var engine=new AuditEngine(new ScanOptions(),x=>observed=x,CancellationToken.None);typeof(AuditEngine).GetMethod("Run",BindingFlags.NonPublic|BindingFlags.Instance).Invoke(engine,new object[]{17,(Action)(()=>{throw new UnauthorizedAccessException("mock denied");})});Assert(observed.State=="读取失败"&&observed.Coverage=="失败","permission failure never reported as clear");
  var cancelled=new CancellationTokenSource();cancelled.Cancel();var interrupted=new AuditEngine(new ScanOptions(),x=>{},cancelled.Token).Scan();Assert(!interrupted.Completed&&interrupted.Findings.All(x=>x.State=="未检测"),"cancel before scan keeps all checks unchecked");
  Console.WriteLine("TOTAL PASSED: "+count);
 }
}
