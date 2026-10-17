using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
namespace LocalLens {
 public static class Stun {
  static int U16(byte[] b,int i){return (b[i]<<8)|b[i+1];}
  public static string Parse(byte[] b,byte[] request){
   if(b==null||request==null||request.Length!=20||b.Length<20||U16(b,0)!=0x0101||U16(b,2)+20!=b.Length||(U16(b,2)%4)!=0)throw new FormatException("STUN 响应头无效");
   for(int i=4;i<20;i++)if(b[i]!=request[i])throw new FormatException("STUN magic / transaction 不匹配");
   string mapped=null;
   for(int p=20;p<b.Length;){if(p+4>b.Length)throw new FormatException("STUN 属性截断");int type=U16(b,p),len=U16(b,p+2),a=p+4;if(a+len>b.Length)throw new FormatException("STUN 属性越界");if(type==0x0020||type==0x0001){if(len<4)throw new FormatException("STUN 地址过短");int n=b[a+1]==1?4:b[a+1]==2?16:0;if(n==0||len!=n+4||b[a]!=0)throw new FormatException("STUN 地址格式无效");var addr=new byte[n];for(int j=0;j<n;j++)addr[j]=(byte)(b[a+4+j]^(type==0x0020?request[4+j]:0));mapped=new IPAddress(addr).ToString();if(type==0x0020)return mapped;}p=a+((len+3)&~3);}
   if(mapped==null)throw new FormatException("STUN 未提供映射地址");return mapped;
  }
 }
 public sealed partial class AuditEngine {
  string UdpExit(){var task=Dns.GetHostAddressesAsync("stun.l.google.com");if(!task.Wait(4000,cancel))throw new TimeoutException("STUN DNS 超时");var address=task.Result.FirstOrDefault(a=>a.AddressFamily==AddressFamily.InterNetwork);if(address==null)throw new IOException("STUN 没有 IPv4 服务器地址");byte[] request=new byte[20];request[1]=1;request[4]=0x21;request[5]=0x12;request[6]=0xa4;request[7]=0x42;var tx=new byte[12];using(var rng=RandomNumberGenerator.Create())rng.GetBytes(tx);Buffer.BlockCopy(tx,0,request,8,12);using(var udp=new UdpClient(AddressFamily.InterNetwork)){udp.Client.ReceiveTimeout=4000;udp.Connect(address,19302);using(cancel.Register(()=>udp.Close())){udp.Send(request,request.Length);IPEndPoint remote=null;byte[] result=udp.Receive(ref remote);return Stun.Parse(result,request);}}}
  string Probe(string host){cancel.ThrowIfCancellationRequested();var req=(HttpWebRequest)WebRequest.Create("https://"+host+"/");req.Method="HEAD";req.Timeout=5000;req.ReadWriteTimeout=5000;req.AllowAutoRedirect=false;req.UserAgent="ScrewClaude/2.12.2";var timer=Stopwatch.StartNew();using(cancel.Register(()=>req.Abort())){try{using(var r=(HttpWebResponse)req.GetResponse())return host+" HTTP "+(int)r.StatusCode+" "+timer.ElapsedMilliseconds+" ms";}catch(WebException ex){cancel.ThrowIfCancellationRequested();var r=ex.Response as HttpWebResponse;if(r!=null){using(r)return host+" HTTP "+(int)r.StatusCode+" "+timer.ElapsedMilliseconds+" ms（服务器已响应）";}return host+" 请求失败 / "+ex.Status+" "+timer.ElapsedMilliseconds+" ms";}}}
  void NetworkProbes(){
   if(!options.Online||!options.Probes){foreach(int id in new[]{8,9})Skip(id,"需同时启用联网查询和网络路径探测");return;}
   Run(3,()=>{
    var lines=new List<string>();foreach(var p in geo)lines.Add("HTTPS "+p.Key+" 出口国家："+Value(p.Value,"country_code"));
    bool incomplete=false;try{string udp=UdpExit();lines.Add("UDP STUN 地址："+udp);var g=NetworkCountryLookup.Lookup(udp);if(String.IsNullOrWhiteSpace(g.Country)){incomplete=true;lines.Add("UDP 国家查询失败："+g.Error);}else lines.Add("UDP 出口国家："+g.Country+"；来源 "+g.Source);if(ip.ContainsKey("v4"))lines.Add("UDP/HTTPS IPv4 路径差异="+(ip["v4"]!=udp));}
    catch(Exception ex){if(ex is OperationCanceledException)throw;incomplete=true;lines.Add("UDP 检测失败："+ex.Message);}
    bool cn=lines.Any(line=>System.Text.RegularExpressions.Regex.IsMatch(line,@"出口国家：CN\b"));
    if(incomplete&&!cn)Set(3,"读取失败","部分路径没有国家地理资料，未完成中国关联检查",String.Join("\r\n",lines),"部分路径查询失败");
    else Mark(3,String.Join("\r\n",lines),cn,"实际路径存在 CN 地理归属","实际有效路径没有 CN 地理归属",incomplete?"有 CN 证据 / 部分路径未完成":"已查询各有效路径的国家资料");
   });
   Run(8,()=>{var lines=new List<string>();foreach(var region in new[]{"ap-northeast-1","eu-west-1","us-east-1"})for(int n=0;n<2;n++)lines.Add(Probe("ec2."+region+".amazonaws.com"));Info(8,String.Join("\r\n",lines)+"\r\n仅测到相应 AWS 服务地址的请求耗时，受代理、DNS、TLS 与服务器影响；不能反推出国家。","已测量三个区域服务端点，各两次");});
   Run(9,()=>{var lines=new List<string>();foreach(var host in new[]{"www.baidu.com","www.wikipedia.org","www.google.com"})lines.Add(Probe(host));Info(9,String.Join("\r\n",lines)+"\r\n失败可能来自本地策略、DNS、代理、服务故障或网络限制，不能单独证明审查或所在地。","已记录所列站点的可达性");});
   Run(7,()=>Info(7,F(7).Evidence+"\r\n可选路径探测：\r\n"+Command(Path.Combine(Environment.SystemDirectory,"tracert.exe"),"-d -h 10 -w 500 1.1.1.1",false,22000),"已读取路由表并采样最多 10 跳；超时跳不代表国界"));
  }
  void Monitor(){
   if(!options.Online||options.MonitorSeconds<=0){Skip(10,"未启用持续出口采样");return;}
   int seconds=Math.Min(300,Math.Max(15,options.MonitorSeconds));var watch=Stopwatch.StartNew();var lines=new List<string>();int success=0,failed=0,cn=0;
   do{cancel.ThrowIfCancellationRequested();try{var d=Obj(JsonGet("https://api.ipify.org?format=json"));IPAddress address;if(!IPAddress.TryParse(Value(d,"ip"),out address))throw new FormatException("无效出口 IP");var g=NetworkCountryLookup.Lookup(address.ToString());if(String.IsNullOrWhiteSpace(g.Country))throw new IOException("出口国家查询失败："+g.Error);success++;if(g.Country=="CN")cn++;lines.Add(DateTime.UtcNow.ToString("o")+" 地址="+address+" | 网络国家="+g.Country+" | 来源="+g.Source);}
    catch(Exception ex){if(ex is OperationCanceledException)throw;failed++;lines.Add(DateTime.UtcNow.ToString("o")+" 采样失败："+ex.Message);}
    Set(10,cn>0?"发现线索":"未检测","持续出口采样中 "+(int)watch.Elapsed.TotalSeconds+" / "+seconds+" 秒",String.Join("\r\n",lines),"采样尚未结束");
    if(watch.Elapsed.TotalSeconds>=seconds)break;cancel.WaitHandle.WaitOne(Math.Min(10000,Math.Max(1,(seconds-(int)watch.Elapsed.TotalSeconds)*1000)));
   }while(watch.Elapsed.TotalSeconds<=seconds+1);
   lines.Insert(0,"有效国家样本 "+success+"；失败 "+failed+"；CN 样本 "+cn+"。IP/接口变化不是中国关联条件。");
   Outcome(10,lines,cn,success,failed,"持续采样出现中国大陆出口国家资料","最多 5 分钟 / 每约 10 秒 / IP 国家资料缓存");
  }
 }
}
