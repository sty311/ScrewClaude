// Bounded host test. Does not start the GUI or perform a real user scan.
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
using System.Collections.Generic;
using LocalLens;
class PortableChecks {
 static int count;
 static void Check(bool pass,string name){if(!pass)throw new Exception(name);count++;Console.WriteLine("PASS: "+name);}
 static string Read(string url,string token=null){using(var c=new WebClient()){c.Proxy=null;c.Encoding=System.Text.Encoding.UTF8;if(token!=null)c.Headers["X-LocalLens-Token"]=token;return c.DownloadString(url);}}
 static int Main(){try{
  var appRoot=AppDomain.CurrentDomain.BaseDirectory;
  Check(!Directory.Exists(Path.Combine(appRoot,"src"))&&!Directory.Exists(Path.Combine(appRoot,"web")),"no source or web directories beside relocated executable");
  Check(!String.Equals(Path.GetFullPath(Environment.CurrentDirectory).TrimEnd('\\'),appRoot.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase),"working directory differs from executable directory");
  Check(Catalog.Load().Count==69,"all 69 catalog entries loaded from assembly");
  var probe=new TcpListener(IPAddress.Loopback,0);probe.Start();int port=((IPEndPoint)probe.LocalEndpoint).Port;probe.Stop();
  using(var host=new LocalWebHost(port)){
   string html=Read(host.Url);
   Check(html.Contains("ScrewClaude")&&html.Contains("score-number"),"relocated assembly serves branded page");
   string token=Regex.Match(html,"name=\"locallens-token\" content=\"([^\"]+)\"").Groups[1].Value;
   Check(token.Length>=40,"session token generated on this host");
   foreach(var file in new[]{"app.js","styles.css","risk-core.js","network-core.js","network.js","favicon.ico","logo-avatar.png","mascot-doze.png","mascot-scan.png","mascot-result.png","mascot-medium.png","mascot-high.png"}){
    using(var client=new WebClient()){client.Proxy=null;Check(client.DownloadData(host.Url+file).Length>1000,"embedded resource: "+file);}
   }
   var state=new JavaScriptSerializer().Deserialize<Dictionary<string,object>>(Read(host.Url+"api/state",token));
   Check(!(bool)state["running"]&&!(bool)state["hasReport"],"clean process starts idle with no inherited report");
   Check((string)state["version"]=="2.12.1","portable version is 2.12.1");
  }
  Console.WriteLine("PORTABLE CHECKS PASSED: "+count+" ("+(Environment.Is64BitProcess?"x64":"x86")+")");return 0;
 }catch(Exception ex){Console.Error.WriteLine(ex);return 1;}}
}
