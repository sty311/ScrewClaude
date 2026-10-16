using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

namespace LocalLens {
  public sealed class EvidenceSource {
    public string Source { get; set; }
    public string ObservedAt { get; set; }
    public string ImportedAt { get; set; }
    public string State { get; set; }
    public string Summary { get; set; }
    public string Evidence { get; set; }
    public string Coverage { get; set; }
    public string Observation { get; set; }
    public string SupportedClaim { get; set; }
    public string Reasoning { get; set; }
    public string MatchingEvidence { get; set; }
    public string EvidenceFamily { get; set; }
    public string AlternativeExplanation { get; set; }
  }
  public sealed class Finding {
    public int Id { get; set; }
    public string Category { get; set; }
    public string Title { get; set; }
    public string State { get; set; }
    public bool? IsClue { get { return State=="发现线索"?(bool?)true:State=="未发现"?(bool?)false:null; } }
    public string DecisionRule { get { return Category=="浏览器实际网络路径"?Limit:ClueRules.ForId(Id); } }
    public string Coverage { get; set; }
    public string Strength { get; set; }
    public string Summary { get; set; }
    public string Evidence { get; set; }
    public string Limit { get; set; }
    public string CheckedAt { get; set; }
    public string Observation { get; set; }
    public string SupportedClaim { get; set; }
    public string Reasoning { get; set; }
    public string MatchingEvidence { get; set; }
    public string EvidenceFamily { get; set; }
    public string AlternativeExplanation { get; set; }
    public string[] RuleSources { get { return ChinaEvidence.Sources(Id); } }
    public List<EvidenceSource> Sources { get; set; }
  }
  public sealed class ScanOptions {
    public ScanOptions(){AutoDiscoverFiles=true;}
    public bool AutoDiscoverFiles { get; set; }
    public bool Online { get; set; }
    public bool Wifi { get; set; }
    public bool History { get; set; }
    public string PhotoFolder { get; set; }
    public bool BrowserContent { get; set; }
    public bool Probes { get; set; }
    public bool RequestLocation { get; set; }
    public bool DeviceIdentifiers { get; set; }
    public bool Ocr { get; set; }
    public string OcrExecutable { get; set; }
    public int MonitorSeconds { get; set; }
    public string ContentFolder { get; set; }
    public string BrowserReportPath { get; set; }
    public bool BrowserReportAutomatic { get; set; }
    public string BaselinePath { get; set; }
    public string ExternalEvidencePath { get; set; }
  }
  public sealed class AuditReport {
    public string App = "ScrewClaude 2.11.0";
    public string ScanId;
    public string CreatedUtc;
    public bool Completed;
    public string Platform;
    public ScanOptions Options;
    public string Interpretation = "判定目标：本项实际证据是否支持用户与中国大陆存在地区、偏好或使用关联。肯定结论必须说明中国关联、命中证据与推断链；采集能力、汉字、默认字体和普通出口差异不算中国用户线索。地区关联不是国籍证明，网络出口不是本人位置；不输出未经校准的概率。未执行、失败和缺少数据单列检测状态。";
    public ChinaUserAssessment ChinaUserAssessment { get { return LocalLens.ChinaUserAssessment.Create(Findings,BrowserNetwork); } }
    public List<Finding> Findings;
    public Baseline Snapshot;
    public BrowserNetworkReport BrowserNetwork;
  }
  public static class Rules {
    public static string ResultLabel(string state) { return state=="发现线索"?"是线索":state=="未发现"?"不是线索":state=="信息"?"未执行判定":state=="不可判定"?"检测未完成":state; }
    public static bool HasHan(string s) { return Regex.IsMatch(s ?? "", "[\\u3400-\\u9fff]"); }
    public static bool MainlandLocale(string s) {
      return Regex.IsMatch(s ?? "", @"(?i)(\bzh[-_]CN\b|\bzh[-_]Hans[-_]CN\b|\b0804\b|\b00000804\b|\bChina Standard Time\b|\bAsia/Shanghai\b|\bAsia/Chongqing\b)");
    }
    public static bool DomesticSoftware(string s) {
      return ChinaEvidence.SoftwareFamilies(s).Length>0;
    }
    public static bool DomesticMirror(string s) {
      return Regex.IsMatch(s ?? "", @"(?i)(tuna\.tsinghua\.edu\.cn|mirrors\.[a-z0-9.-]+\.cn|aliyun\.com|npmmirror\.com|doubanio\.com|gitee\.com)");
    }
    public static string StripSecrets(string s) {
      s = Regex.Replace(s ?? "", @"(?i)(https?|socks5h?|socks4)://[^\s/@]+@", "$1://[凭据已隐藏]@");
      s = Regex.Replace(s, @"(?i)(https?|socks5h?|socks4)://[^\s]+", delegate(Match m) {
        string v=m.Value; int p=v.IndexOfAny(new char[]{'?','#'}); return p<0?v:v.Substring(0,p)+"[参数已隐藏]";
      });
      s = Regex.Replace(s, @"(?im)^([^\r\n]*(?:password|passwd|token|secret|apikey|api_key|_auth)[^=:\r\n]*[=:]).*$", "$1 [敏感值已隐藏]");
      return s;
    }
    public static string Redact(string s) {
      s = StripSecrets(s);
      s = Regex.Replace(s, @"(?i)[A-Z]:\\Users\\[^\\\s\r\n]+", @"C:\Users\[用户]");
      s = Regex.Replace(s, @"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[IPv4]");
      s = Regex.Replace(s, @"(?i)(?<![a-z0-9])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![a-z0-9])", "[MAC]");
      s = Regex.Replace(s, @"(?i)(?<![a-z0-9:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?:%\d+)?(?![a-z0-9:])", "[IPv6]");
      s = Regex.Replace(s, @"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[邮箱]");
      return s;
    }
    public static string Html(string s) { return System.Net.WebUtility.HtmlEncode(s ?? ""); }
    public static string TrimEvidence(string s) { s = StripSecrets(s); return s.Length > 24000 ? s.Substring(0,24000)+"\r\n[已截断展示]" : s; }
  }
  public static class Catalog {
    public static List<Finding> Load() {
      using (Stream stream = typeof(Catalog).Assembly.GetManifestResourceStream("catalog.json"))
      using (StreamReader reader = new StreamReader(stream, Encoding.UTF8)) {
        var list = new JavaScriptSerializer().Deserialize<List<Finding>>(reader.ReadToEnd());
        foreach (var f in list) { f.State="未检测"; f.Coverage="未执行"; f.Summary="尚未开始扫描"; f.Evidence=""; f.CheckedAt=""; }
        return list;
      }
    }
  }
  public static class Exporter {
    public static AuditReport Prepare(AuditReport input, bool detailed) {
      var serializer = new JavaScriptSerializer { MaxJsonLength=8*1024*1024 };
      var clone = serializer.Deserialize<AuditReport>(serializer.Serialize(input));
      if (!detailed) {
        clone.Options.PhotoFolder = String.IsNullOrEmpty(clone.Options.PhotoFolder)?"":"[用户选择的目录]";
        clone.Snapshot=null;
        clone.Options.OcrExecutable=String.IsNullOrEmpty(clone.Options.OcrExecutable)?"":"[用户选择的程序]";
        clone.Options.ContentFolder=String.IsNullOrEmpty(clone.Options.ContentFolder)?"":"[用户选择的目录]";
        clone.Options.BrowserReportPath=String.IsNullOrEmpty(clone.Options.BrowserReportPath)?"":"[用户选择的文件]";
        clone.Options.BaselinePath=String.IsNullOrEmpty(clone.Options.BaselinePath)?"":"[用户选择的文件]";
        clone.Options.ExternalEvidencePath=String.IsNullOrEmpty(clone.Options.ExternalEvidencePath)?"":"[用户选择的文件]";
        if(clone.BrowserNetwork!=null)clone.BrowserNetwork.Browser="[摘要省略浏览器标识]";
        foreach (var f in clone.Findings.Concat(clone.BrowserNetwork==null?new List<Finding>():clone.BrowserNetwork.Findings)) {
          f.Evidence="[摘要导出不包含原始证据；可在程序内查看]";
          f.Sources=null;
          f.Summary=Rules.Redact(f.Summary);
          f.Observation=Rules.Redact(f.Observation);
          f.MatchingEvidence=clone.BrowserNetwork!=null&&clone.BrowserNetwork.Findings.Contains(f)&&f.State=="发现线索"?"country=CN（摘要已省略IP与来源原文）":"[摘要省略命中原文；请在本机查看]";
        }
      }
      return clone;
    }
    public static void SaveJson(string path, AuditReport report, bool detailed) {
      File.WriteAllText(path,new JavaScriptSerializer { MaxJsonLength=8*1024*1024 }.Serialize(Prepare(report,detailed)),new UTF8Encoding(true));
    }
    public static void SaveHtml(string path, AuditReport report, bool detailed) {
      File.WriteAllText(path,RenderHtml(report,detailed),new UTF8Encoding(true));
    }
    public static string RenderHtml(AuditReport report, bool detailed) {
      var r=Prepare(report,detailed); var b=new StringBuilder();
      b.Append("<!doctype html><html lang='zh-CN'><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>ScrewClaude 本地环境自查报告</title><style>body{font:15px/1.7 system-ui,'Microsoft YaHei',sans-serif;color:#182b41;background:#f3f6fa;margin:0}main{max-width:1050px;margin:40px auto;padding:28px}h1{font-size:32px}article{background:white;border:1px solid #dde4ee;border-radius:12px;margin:14px 0;padding:20px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f7fb;padding:14px}small{color:#586a80}.tag{padding:4px 9px;border-radius:5px;background:#eaf0fa;margin-right:8px}.found{background:#fff1d6}.err{background:#ffe7e7}</style><main><small>SCREWCLAUDE / READ-ONLY AUDIT</small><h1>Windows 本地环境自查</h1>");
      b.Append("<p>生成时间（UTC）："+Rules.Html(r.CreatedUtc)+" · "+(r.Completed?"扫描完成":"扫描中断 / 未完成")+" · "+(detailed?"详细报告，含本地标识":"摘要报告，原始证据已省略")+"</p><p>"+Rules.Html(r.Interpretation)+"</p>");
      b.Append("<article><h2>中国用户关联评估</h2><p>"+Rules.Html(r.ChinaUserAssessment.Summary)+"</p><p>证据类型："+Rules.Html(String.Join(" / ",r.ChinaUserAssessment.EvidenceFamilies))+"</p><p>"+Rules.Html(r.ChinaUserAssessment.Scope)+"</p></article>");
      if(r.BrowserNetwork!=null){b.Append("<h2>浏览器实际网络路径（独立检测）</h2><p>开始："+Rules.Html(r.BrowserNetwork.StartedUtc)+"；结束："+Rules.Html(r.BrowserNetwork.FinishedUtc)+"</p><p>"+Rules.Html(r.BrowserNetwork.Browser)+"</p>");foreach(var f in r.BrowserNetwork.Findings)AppendFinding(b,f);}
      b.Append("<h2>Windows 本机检查</h2>");
      foreach(var f in r.Findings)AppendFinding(b,f);
      b.Append("</main></html>"); return b.ToString();
    }
    private static void AppendFinding(StringBuilder b,Finding f) {
        b.Append("<article><small>"+f.Id.ToString("00")+" / "+Rules.Html(f.Category)+" / 检测状态："+Rules.Html(f.Coverage)+"</small><h2>"+Rules.Html(f.Title)+"</h2><p><span class='tag "+(f.State=="发现线索"?"found":f.State=="读取失败"?"err":"")+"'>"+Rules.Html(Rules.ResultLabel(f.State))+"</span><span class='tag'>"+Rules.Html(f.Strength)+"</span>"+Rules.Html(f.Summary)+"</p><pre>"+Rules.Html(f.Evidence)+"</pre><p>实际观察："+Rules.Html(f.Observation)+"</p><p>支持的判断："+Rules.Html(f.SupportedClaim)+"</p><p>推断依据："+Rules.Html(f.Reasoning)+"</p><pre>"+Rules.Html(f.MatchingEvidence)+"</pre><p>其他解释："+Rules.Html(f.AlternativeExplanation)+"</p><p>判定规则："+Rules.Html(f.DecisionRule)+"</p><details><summary>采样范围</summary>"+Rules.Html(f.Limit)+"</details></article>");
    }
  }
}
