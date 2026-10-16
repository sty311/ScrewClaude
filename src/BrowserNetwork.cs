using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;

namespace LocalLens {
 public sealed class BrowserNetworkReport {
  public string RuleVersion {get;set;}
  public string StartedUtc {get;set;}
  public string FinishedUtc {get;set;}
  public string Browser {get;set;}
  public List<Finding> Findings {get;set;}
  public static BrowserNetworkReport Validate(BrowserNetworkReport report) {
   if(report==null||report.RuleVersion!="ChinaUserEvidence2.4"||report.Findings==null||report.Findings.Count!=3||!report.Findings.Select(f=>f==null?0:f.Id).OrderBy(x=>x).SequenceEqual(new[]{1,3,6}))throw new FormatException("网络结果必须使用 2.4 中国关联规则并包含 HTTPS、WebRTC 与 DNS 三项；旧版路径差异结果请重新检测");
   DateTimeOffset start=Time(report.StartedUtc),end=Time(report.FinishedUtc);if(end<start||end-start>TimeSpan.FromMinutes(5))throw new FormatException("网络结果时间范围无效");
   if(String.IsNullOrWhiteSpace(report.Browser)||report.Browser.Length>1000)throw new FormatException("浏览器标识无效");
   foreach(var f in report.Findings){
    if(!new[]{"发现线索","未发现","读取失败","不可判定"}.Contains(f.State)||String.IsNullOrWhiteSpace(f.Summary)||f.Summary.Length>1000||f.Evidence==null||f.Evidence.Length>30000||String.IsNullOrWhiteSpace(f.Limit)||f.Limit.Length>2000||(f.Coverage!=null&&f.Coverage.Length>1000))throw new FormatException("网络结果字段无效");
    if(new[]{f.Observation,f.Reasoning,f.MatchingEvidence,f.SupportedClaim,f.AlternativeExplanation}.Any(s=>s!=null&&s.Length>4000))throw new FormatException("网络推断字段超出上限");
    if(f.State=="发现线索"&&(String.IsNullOrWhiteSpace(f.MatchingEvidence)||!Regex.IsMatch(f.MatchingEvidence,@"(?i)(?:country|国家)\s*[:=]\s*CN\b")))throw new FormatException("肯定的中国网络线索必须保留明确的 CN 国家证据");
    f.Title=f.Id==6?"浏览器递归 DNS 出口":f.Id==3?"浏览器 WebRTC 路径":"浏览器 HTTPS / 网站出口";
    f.Category="浏览器实际网络路径";f.Strength="规则判定";if(String.IsNullOrWhiteSpace(f.Coverage))f.Coverage="当前浏览器 / 独立采样时间";f.CheckedAt=report.FinishedUtc;f.Sources=null;
    f.EvidenceFamily=f.State=="发现线索"?(f.Id==6?"网络解析关联":"网络出口"):"";f.SupportedClaim=f.State=="发现线索"?(f.Id==6?"本次浏览器递归解析链存在中国大陆解析器":"本次浏览器实际网络路径存在中国大陆出口"):(f.State=="未发现"?"本次有效网络资料不支持中国关联":"中国网络关联检测尚未完成");
    f.AlternativeExplanation="第三方地理资料可能有误；解析器/代理出口不等于设备或操作者的物理位置，也不证明国籍。";
   }
   return report;
  }
  static DateTimeOffset Time(string value){DateTimeOffset result;if(value==null||!Regex.IsMatch(value,@"(?:Z|[+-]\d\d:\d\d)$")||!DateTimeOffset.TryParse(value,CultureInfo.InvariantCulture,DateTimeStyles.None,out result))throw new FormatException("网络结果时间必须带时区");return result;}
 }
 public static class DnsConfigurationAssessment {
  public static bool KnownChinaService(string address){System.Net.IPAddress ip;if(!System.Net.IPAddress.TryParse(address,out ip))return false;return new[]{"223.5.5.5","223.6.6.6","114.114.114.114","114.114.115.115","119.29.29.29","180.76.76.76","2400:3200::1","2400:3200:baba::1","2402:4e00::"}.Contains(ip.ToString());}
  public static Finding Evaluate(IEnumerable<string> addresses,string evidence){
   var values=addresses.ToArray();bool hit=values.Any(KnownChinaService);
   return new Finding{Id=6,State=hit?"发现线索":values.Length==0?"未检测":"未发现",Summary=hit?"网卡配置命中所列国内公共 DNS 清单":values.Length==0?"未取得网卡 DNS 配置，未执行判定":"网卡配置未命中所列公共 DNS 地址；递归出口见浏览器检测",Evidence="DNS_CONFIGURATION="+new System.Web.Script.Serialization.JavaScriptSerializer().Serialize(new{addresses=values})+"\r\n"+evidence+"\r\n本项只判定实际 DNS 地址是否命中所列九个 IPv4/IPv6 公共服务地址；递归解析器由浏览器 DNS 卡片独立采样和判定。",Coverage="网卡 DNS 实际地址字段 / 九地址规则"};
  }
 }
}
