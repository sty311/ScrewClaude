using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace LocalLens {
 public static class WebProgram {
  [STAThread] public static void Main(string[] args){
   Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);
   int port=53174;for(int i=0;i<args.Length-1;i++)if(args[i]=="--port")port=int.Parse(args[i+1]);
   try{using(var host=new LocalWebHost(port))using(var context=new WebContext(host)){
    for(int i=0;i<args.Length-1;i++)if(args[i]=="--status-file")File.WriteAllText(args[i+1],new JavaScriptSerializer().Serialize(new{url=host.Url,pid=Process.GetCurrentProcess().Id}),Encoding.UTF8);
    if(!args.Contains("--no-browser"))Process.Start(new ProcessStartInfo(host.Url){UseShellExecute=true});
    Application.Run(context);
   }}catch(Exception ex){MessageBox.Show("本地网页服务未启动："+ex.Message,"ScrewClaude",MessageBoxButtons.OK,MessageBoxIcon.Error);}
  }
 }
 sealed class WebContext:ApplicationContext {
  readonly NotifyIcon tray;readonly System.Windows.Forms.Timer timer;readonly LocalWebHost host;
  public WebContext(LocalWebHost h){host=h;tray=new NotifyIcon{Text="ScrewClaude · 本机网页服务",Visible=true};using(var stream=typeof(WebContext).Assembly.GetManifestResourceStream("app.ico"))tray.Icon=new Icon(stream);var menu=new ContextMenuStrip();menu.Items.Add("打开 ScrewClaude",null,(s,e)=>Process.Start(new ProcessStartInfo(host.Url){UseShellExecute=true}));menu.Items.Add("退出本地服务",null,(s,e)=>ExitThread());tray.ContextMenuStrip=menu;tray.DoubleClick+=(s,e)=>Process.Start(new ProcessStartInfo(host.Url){UseShellExecute=true});timer=new System.Windows.Forms.Timer{Interval=300};timer.Tick+=(s,e)=>{if(host.ShutdownRequested)ExitThread();};timer.Start();}
  protected override void Dispose(bool disposing){if(disposing){timer.Dispose();tray.Visible=false;tray.Dispose();host.Dispose();}base.Dispose(disposing);}
 }
 // A bounded HTTP/1.1 server bound only to IPv4 loopback; no URL ACL or admin rights.
 public sealed class LocalWebHost:IDisposable {
  readonly TcpListener listener;readonly object sync=new object();readonly string token;readonly SemaphoreSlim clients=new SemaphoreSlim(12);readonly string importRoot=Path.Combine(Path.GetTempPath(),"ScrewClaude-Web-"+Guid.NewGuid().ToString("N"));
  readonly HashSet<int> processed=new HashSet<int>();List<Finding> findings=Catalog.Load();ScanOptions options=new ScanOptions{History=true,Online=true,Wifi=true,BrowserContent=true,Probes=true,RequestLocation=true,DeviceIdentifiers=true,Ocr=true,MonitorSeconds=30};AuditReport report;CancellationTokenSource cancellation;Task scanTask;DateTime? started,finished;bool running,disposed;string status="就绪，选择范围后开始检查";
  BrowserNetworkReport browserNetwork;string scanId;bool browserNetworkDone=true,scanCancelled;
  bool BrowserNetworkExpected {get{return scanId!=null&&options.Online&&options.Probes;}}
  bool BrowserNetworkRunning {get{return BrowserNetworkExpected&&!browserNetworkDone&&!scanCancelled;}}
  void EndBrowserNetwork(string reason){if(BrowserNetworkExpected&&browserNetwork==null){string now=DateTime.UtcNow.ToString("o");browserNetwork=BrowserNetworkReport.Validate(new BrowserNetworkReport{RuleVersion="ChinaUserEvidence2.4",StartedUtc=now,FinishedUtc=now,Browser="ScrewClaude / 未取得有效浏览器采样",Findings=new[]{1,3,6}.Select(id=>new Finding{Id=id,State="读取失败",Summary=reason,Evidence="本批浏览器来源未取得有效采样，已跳过；没有作阴性或安全结论。",Coverage="无法读取 / 已跳过",Limit="只按有效国家资料判定，本条没有可用国家资料。"}).ToList()});}browserNetworkDone=true;}
  void ExpireBrowserNetwork(){if(BrowserNetworkRunning&&started.HasValue&&DateTime.UtcNow-started.Value>TimeSpan.FromSeconds(90))EndBrowserNetwork("浏览器网络采样超过本批90秒截止时间，已跳过");}
  public string Url{get;private set;} public bool ShutdownRequested{get;private set;}
  static JavaScriptSerializer Json(){return new JavaScriptSerializer{MaxJsonLength=8*1024*1024,RecursionLimit=64};}
  static T Clone<T>(T value){return Json().Deserialize<T>(Json().Serialize(value));}
  public LocalWebHost(int port){if(port<1024||port>65535)throw new ArgumentOutOfRangeException("port");byte[] entropy=new byte[32];using(var rng=RandomNumberGenerator.Create())rng.GetBytes(entropy);token=Convert.ToBase64String(entropy);listener=new TcpListener(IPAddress.Loopback,port);listener.Start();Url="http://127.0.0.1:"+port+"/";Task.Run((Action)Accept);}
  void Accept(){while(!disposed){try{var client=listener.AcceptTcpClient();if(!clients.Wait(0)){client.Close();continue;}Task.Run(()=>{try{Serve(client);}finally{client.Close();clients.Release();}});}catch(SocketException){if(!disposed)Thread.Sleep(100);}catch(ObjectDisposedException){break;}}}
  sealed class Request {public string Method,Path,Query;public Dictionary<string,string> Headers=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);public byte[] Body;}
  Request Read(NetworkStream stream){var header=new List<byte>();int matched=0;while(header.Count<16384){int b=stream.ReadByte();if(b<0)throw new IOException("Incomplete HTTP headers");header.Add((byte)b);matched=b==new byte[]{13,10,13,10}[matched]?matched+1:b==13?1:0;if(matched==4)break;}if(matched!=4)throw new FormatException("Headers too large");var lines=Encoding.ASCII.GetString(header.ToArray()).Split(new[]{"\r\n"},StringSplitOptions.None);var first=lines[0].Split(' ');if(first.Length!=3||!first[1].StartsWith("/")||first[1].StartsWith("//"))throw new FormatException("Invalid request");var r=new Request{Method=first[0],Path=first[1].Split('?')[0],Query=first[1].Contains("?")?first[1].Substring(first[1].IndexOf('?')+1):""};foreach(string line in lines.Skip(1)){if(line.Length==0)break;int colon=line.IndexOf(':');if(colon<=0)throw new FormatException("Invalid header");string name=line.Substring(0,colon).Trim();if(r.Headers.ContainsKey(name))throw new FormatException("Duplicate header");r.Headers[name]=line.Substring(colon+1).Trim();}if(r.Headers.ContainsKey("Transfer-Encoding"))throw new FormatException("Chunked requests unsupported");int length=0;if(r.Headers.ContainsKey("Content-Length")&&(!int.TryParse(r.Headers["Content-Length"],out length)||length<0||length>1048576))throw new FormatException("Body exceeds 1 MiB");r.Body=new byte[length];int offset=0;while(offset<length){int n=stream.Read(r.Body,offset,length-offset);if(n==0)throw new IOException("Incomplete body");offset+=n;}return r;}
  void Serve(TcpClient client){try{client.ReceiveTimeout=10000;client.SendTimeout=10000;using(var stream=client.GetStream()){
   Request r;try{r=Read(stream);}catch(Exception){Reply(stream,400,"application/json",Encoding.UTF8.GetBytes("{\"error\":\"无效请求或文件过大\"}"),null);return;}
   string host,origin;if(!r.Headers.TryGetValue("Host",out host)||host!=new Uri(Url).Authority||(r.Headers.TryGetValue("Origin",out origin)&&origin!=Url.TrimEnd('/'))){Error(stream,403,"拒绝外部来源");return;}
   if(r.Method!="GET"&&r.Method!="POST"){Error(stream,405,"不支持此请求方法");return;}
   if(r.Path.StartsWith("/api/",StringComparison.Ordinal)){
    string supplied;if(!r.Headers.TryGetValue("X-LocalLens-Token",out supplied)||supplied!=token){Error(stream,403,"本地会话已失效，请刷新页面");return;}
    try{Api(stream,r);}catch(Exception ex){Error(stream,400,Rules.StripSecrets(ex.Message));}return;
   }
   if(r.Method!="GET"){Error(stream,405,"只接受读取");return;}
   string resource=r.Path=="/"?"web.index.html":r.Path=="/app.js"?"web.app.js":r.Path=="/risk-core.js"?"web.risk-core.js":r.Path=="/network-core.js"?"web.network-core.js":r.Path=="/network.js"?"web.network.js":r.Path=="/styles.css"?"web.styles.css":r.Path=="/favicon.ico"?"app.ico":r.Path=="/logo-avatar.png"?"web.logo-avatar.png":r.Path=="/mascot-doze.png"?"web.mascot-doze.png":r.Path=="/mascot-scan.png"?"web.mascot-scan.png":r.Path=="/mascot-result.png"?"web.mascot-result.png":r.Path=="/mascot-medium.png"?"web.mascot-medium.png":r.Path=="/mascot-high.png"?"web.mascot-high.png":null;
   if(resource==null){Error(stream,404,"页面不存在");return;}
   byte[] bytes;using(var input=typeof(LocalWebHost).Assembly.GetManifestResourceStream(resource)){if(input==null)throw new IOException("缺少网页资源，请运行 build-web.cmd");using(var memory=new MemoryStream()){input.CopyTo(memory);bytes=memory.ToArray();}}
   if(r.Path=="/")bytes=Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(bytes).Replace("__LOCALLENS_TOKEN__",token));
   Reply(stream,200,r.Path.EndsWith(".js",StringComparison.Ordinal)?"application/javascript; charset=utf-8":r.Path=="/styles.css"?"text/css; charset=utf-8":r.Path=="/favicon.ico"?"image/x-icon":r.Path.EndsWith(".png",StringComparison.Ordinal)?"image/png":"text/html; charset=utf-8",bytes,null);
  }}catch(IOException){}catch(SocketException){}catch(ObjectDisposedException){}}
  static string Parameter(Request r,string name){foreach(var pair in r.Query.Split('&')){var p=pair.Split(new[]{'='},2);if(p[0]==name)return p.Length==2?Uri.UnescapeDataString(p[1]):"";}return "";}
  void Api(NetworkStream stream,Request r){
   if(r.Path=="/api/state"&&r.Method=="GET"){lock(sync){ExpireBrowserNetwork();Send(stream,new{version="2.10.1",scanId=scanId,cancelled=scanCancelled,browserNetworkRunning=BrowserNetworkRunning,browserNetworkDone=browserNetworkDone,browserNetworkExpected=BrowserNetworkExpected,browserNetwork=browserNetwork,running=running,hasReport=report!=null,completed=report!=null&&report.Completed,status=status,startedAt=started.HasValue?started.Value.ToString("o"):null,finishedAt=finished.HasValue?finished.Value.ToString("o"):null,elapsedSeconds=started.HasValue?(int)((finished??DateTime.UtcNow)-started.Value).TotalSeconds:0,progress=processed.Count,findings=findings,options=options,chinaAssessment=ChinaUserAssessment.Create(findings,browserNetwork)});}return;}
   if(r.Path=="/api/scan"&&r.Method=="POST"){
    var selected=Json().Deserialize<ScanOptions>(Encoding.UTF8.GetString(r.Body));if(selected==null)throw new FormatException("缺少检查范围");selected.MonitorSeconds=Math.Min(300,Math.Max(0,selected.MonitorSeconds));
    lock(sync){if(running){Error(stream,409,"检查正在进行中");return;}options=selected;scanId=Guid.NewGuid().ToString("N");scanCancelled=false;browserNetwork=null;browserNetworkDone=!(selected.Online&&selected.Probes);report=null;findings=Catalog.Load();processed.Clear();running=true;started=DateTime.UtcNow;finished=null;status="正在准备本机检查…";cancellation=new CancellationTokenSource();scanTask=Task.Run(()=>Scan(selected,cancellation.Token));}Send(stream,new{ok=true,scanId=scanId});return;
   }
   if(r.Path=="/api/cancel"&&r.Method=="POST"){lock(sync){scanCancelled=true;EndBrowserNetwork("本批浏览器来源已停止，未读取部分已跳过");if(running){cancellation.Cancel();status="正在停止检查，已完成的结果会保留…";}}Send(stream,new{ok=true});return;}
   if(r.Path=="/api/export"&&r.Method=="GET"){AuditReport current;lock(sync){string expected;if(r.Headers.TryGetValue("X-LocalLens-Scan-Id",out expected)&&expected!=scanId){Error(stream,409,"检测批次已更新，请重新导出");return;}ExpireBrowserNetwork();if(report==null||running||BrowserNetworkRunning)throw new InvalidOperationException("请先等待统一检测结束或停止检测");current=Clone(report);current.BrowserNetwork=Clone(browserNetwork);}bool detailed=Parameter(r,"detailed")=="true",html=Parameter(r,"format")=="html";string content=html?Exporter.RenderHtml(current,detailed):Json().Serialize(Exporter.Prepare(current,detailed));Reply(stream,200,html?"text/html; charset=utf-8":"application/json; charset=utf-8",Encoding.UTF8.GetBytes(content),"ScrewClaude-"+DateTime.Now.ToString("yyyyMMdd-HHmmss")+(detailed?"-detailed":"-summary")+(html?".html":".json"));return;}
   if(r.Path=="/api/baseline"&&r.Method=="GET"){lock(sync){if(report==null||!report.Completed||running)throw new InvalidOperationException("完整检查结束后才能保存基线");Reply(stream,200,"application/json; charset=utf-8",Encoding.UTF8.GetBytes(Json().Serialize(report.Snapshot)),"ScrewClaude-baseline-"+DateTime.Now.ToString("yyyyMMdd-HHmmss")+".json");}return;}
   if(r.Path=="/api/import"&&r.Method=="POST"){string kind=Parameter(r,"kind");if(!new[]{"browser","external","baseline"}.Contains(kind))throw new FormatException("未知导入类型");var parsed=Json().DeserializeObject(Encoding.UTF8.GetString(r.Body)) as Dictionary<string,object>;if(parsed==null)throw new FormatException("JSON 顶层必须为对象");Directory.CreateDirectory(importRoot);string path=Path.Combine(importRoot,kind+"-"+Guid.NewGuid().ToString("N")+".json");File.WriteAllBytes(path,r.Body);Send(stream,new{path=path});return;}
   if(r.Path=="/api/pick"&&r.Method=="POST"){lock(sync){if(running)throw new InvalidOperationException("扫描期间不能更改范围");}string kind=Parameter(r,"kind"),path=null;Exception failure=null;var thread=new Thread(()=>{try{if(kind=="folder"){using(var d=new FolderBrowserDialog{ShowNewFolderButton=false,Description="选择仅由 ScrewClaude 本机读取的目录"})if(d.ShowDialog()==DialogResult.OK)path=d.SelectedPath;}else if(kind=="ocr"){using(var d=new OpenFileDialog{Filter="Tesseract 程序|tesseract.exe",CheckFileExists=true})if(d.ShowDialog()==DialogResult.OK)path=d.FileName;}else throw new FormatException("未知选择类型");}catch(Exception ex){failure=ex;}});thread.SetApartmentState(ApartmentState.STA);thread.Start();thread.Join();if(failure!=null)throw failure;Send(stream,new{path=path});return;}
   if(r.Path=="/api/network-countries"&&r.Method=="POST"){var addresses=Json().Deserialize<string[]>(Encoding.UTF8.GetString(r.Body));Send(stream,NetworkCountryLookup.LookupMany(addresses));return;}
   if((r.Path=="/api/browser-network"||r.Path=="/api/browser-network/skip")&&r.Method=="POST"){lock(sync){ExpireBrowserNetwork();string expected;if(scanId!=null&&(!r.Headers.TryGetValue("X-LocalLens-Scan-Id",out expected)||expected!=scanId||scanCancelled)){Error(stream,409,"检测批次已结束或更新，已忽略过期网络结果");return;}if(r.Path=="/api/browser-network/skip"){EndBrowserNetwork("本批浏览器来源无法取得有效结果，已跳过");}else{if(BrowserNetworkExpected&&browserNetworkDone){Error(stream,409,"本批网络检测已结束，已忽略迟到结果");return;}var observation=BrowserNetworkReport.Validate(Json().Deserialize<BrowserNetworkReport>(Encoding.UTF8.GetString(r.Body)));browserNetwork=observation;browserNetworkDone=true;}}Send(stream,new{ok=true});return;}
   if(r.Path=="/api/shutdown"&&r.Method=="POST"){Send(stream,new{ok=true});ShutdownRequested=true;return;}
   Error(stream,404,"接口不存在");
  }
  void Scan(ScanOptions selected,CancellationToken ct){try{
   var result=new AuditEngine(selected,f=>{var copy=Clone(f);lock(sync){findings[f.Id-1]=copy;if(f.Summary!="尚未执行或未满足所需条件"){processed.Add(f.Id);if(!ct.IsCancellationRequested)status="正在检查："+f.Title;}}},ct).Scan();
   lock(sync){result.ScanId=scanId;report=result;findings=result.Findings;status=result.Completed?"本次检查已完成，结果仅反映可读取的范围":"检查已取消，未完成项不能视为通过";}
  }catch(Exception ex){lock(sync){status="检查未完成："+Rules.StripSecrets(ex.Message);}}
  finally{lock(sync){running=false;finished=DateTime.UtcNow;cancellation.Dispose();cancellation=null;}}}
  static void Send(NetworkStream stream,object value){Reply(stream,200,"application/json; charset=utf-8",Encoding.UTF8.GetBytes(Json().Serialize(value)),null);}
  static void Error(NetworkStream stream,int code,string message){Reply(stream,code,"application/json; charset=utf-8",Encoding.UTF8.GetBytes(Json().Serialize(new{error=message})),null);}
  static void Reply(NetworkStream stream,int code,string type,byte[] bytes,string file){string reason=code==200?"OK":code==403?"Forbidden":code==404?"Not Found":code==409?"Conflict":code==405?"Method Not Allowed":"Bad Request";string headers="HTTP/1.1 "+code+" "+reason+"\r\nContent-Type: "+type+"\r\nContent-Length: "+bytes.Length+"\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' https://api.ipify.org https://api6.ipify.org https://claude.com https://claude.ai https://*.dns4.browserleaks.net https://*.dns6.browserleaks.net https://*.ipv4.surfsharkdns.com https://*.u.fastly-analytics.com; frame-ancestors 'none'; base-uri 'none'; form-action 'none'\r\n"+(file==null?"":"Content-Disposition: attachment; filename=\""+file+"\"\r\n")+"\r\n";byte[] head=Encoding.ASCII.GetBytes(headers);stream.Write(head,0,head.Length);stream.Write(bytes,0,bytes.Length);stream.Flush();}
  public void Dispose(){if(disposed)return;disposed=true;lock(sync){if(cancellation!=null)cancellation.Cancel();}listener.Stop();try{if(scanTask!=null)scanTask.Wait(3000);}catch{} }
 }
}
