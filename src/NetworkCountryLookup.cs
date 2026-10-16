using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
namespace LocalLens {
 public sealed class CountryObservation {public string Ip {get;set;} public string Country {get;set;} public string Source {get;set;} public string Error {get;set;}}
 public static class NetworkCountryLookup {
  static readonly object sync=new object();static readonly Dictionary<string,CountryObservation> cache=new Dictionary<string,CountryObservation>();static readonly SemaphoreSlim slots=new SemaphoreSlim(4);
  public static bool IsPublic(string value){IPAddress a;if(!IPAddress.TryParse(value,out a))return false;if(a.IsIPv4MappedToIPv6)return IsPublic(a.MapToIPv4().ToString());var b=a.GetAddressBytes();
   if(a.AddressFamily==AddressFamily.InterNetworkV6)return (b[0]&0xe0)==0x20&&!(b[0]==0x20&&b[1]==1&&b[2]==0x0d&&b[3]==0xb8);
   if(a.AddressFamily!=AddressFamily.InterNetwork)return false;
   return b[0]>0&&b[0]<224&&b[0]!=10&&b[0]!=127&&!(b[0]==169&&b[1]==254)&&!(b[0]==172&&b[1]>=16&&b[1]<=31)&&!(b[0]==192&&b[1]==168)&&!(b[0]==100&&b[1]>=64&&b[1]<=127)&&!(b[0]==198&&(b[1]==18||b[1]==19))&&!(b[0]==192&&b[1]==0&&(b[2]==0||b[2]==2))&&!(b[0]==198&&b[1]==51&&b[2]==100)&&!(b[0]==203&&b[1]==0&&b[2]==113);
  }
  public static string[] ValidateAddresses(string[] values){if(values==null||values.Length<1||values.Length>16||values.Any(v=>!IsPublic(v)))throw new FormatException("国家查询仅接受 1–16 个有效公网 IP；私网、测试地址和任意 URL 不允许");return values.Select(v=>IPAddress.Parse(v).ToString()).Distinct().ToArray();}
  public static CountryObservation[] LookupMany(string[] values){var ips=ValidateAddresses(values);return Task.WhenAll(ips.Select(ip=>Task.Run(()=>Lookup(ip)))).GetAwaiter().GetResult();}
  public static CountryObservation Lookup(string ip){ip=ValidateAddresses(new[]{ip})[0];lock(sync){CountryObservation previous;if(cache.TryGetValue(ip,out previous))return previous;if(cache.Count>=128)return new CountryObservation{Ip=ip,Source="ipwho.is",Error="本次服务的公网归属查询已达到 128 个地址上限"};}
   slots.Wait();try{
    var request=(HttpWebRequest)WebRequest.Create("https://ipwho.is/"+Uri.EscapeDataString(ip));request.Timeout=5000;request.ReadWriteTimeout=5000;request.AllowAutoRedirect=false;request.UserAgent="ScrewClaude/2.12.0 country-evidence";ServicePointManager.SecurityProtocol|=SecurityProtocolType.Tls12;
    using(var response=(HttpWebResponse)request.GetResponse())using(var reader=new StreamReader(response.GetResponseStream(),Encoding.UTF8)){
     var body=new StringBuilder();var buffer=new char[2048];int n;while((n=reader.Read(buffer,0,buffer.Length))>0){body.Append(buffer,0,n);if(body.Length>32768)throw new IOException("地理资料响应超过上限");}
     var d=new JavaScriptSerializer().Deserialize<Dictionary<string,object>>(body.ToString());object cc,returned,success;IPAddress address;
     if(d==null||!d.TryGetValue("country_code",out cc)||!System.Text.RegularExpressions.Regex.IsMatch(Convert.ToString(cc),"^(?!(?:ZZ|XX)$)[A-Z]{2}$",System.Text.RegularExpressions.RegexOptions.IgnoreCase)||!d.TryGetValue("ip",out returned)||!IPAddress.TryParse(Convert.ToString(returned),out address)||!address.Equals(IPAddress.Parse(ip))||d.TryGetValue("success",out success)&&success is bool&&!(bool)success)throw new IOException("地理资料未返回与请求地址一致的有效国家字段");
     var observation=new CountryObservation{Ip=ip,Country=Convert.ToString(cc).ToUpperInvariant(),Source="ipwho.is"};lock(sync){if(cache.Count<128)cache[ip]=observation;}return observation;
    }
   }catch(Exception ex){return new CountryObservation{Ip=ip,Source="ipwho.is",Error=Rules.StripSecrets(ex.Message)};}finally{slots.Release();}
  }
 }
}
