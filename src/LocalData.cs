using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;
using System.Xml;

namespace LocalLens {
 public static class LocalData {
  public static readonly Regex Place = new Regex(@"(?i)(\b(?:China|Beijing|Shanghai|Guangzhou|Shenzhen|CN)\b|中国|北京|上海|广东|深圳|浙江|江苏|四川|湖北|福建|山东|河南|湖南|河北|陕西|重庆|天津|辽宁|黑龙江|吉林|云南|贵州|广西|海南|甘肃|青海|宁夏|新疆|西藏|内蒙古)");
  public static string Hash(string s) { using(var h=SHA256.Create()) return BitConverter.ToString(h.ComputeHash(Encoding.UTF8.GetBytes(s??""))).Replace("-","").ToLowerInvariant(); }
  public static string Canonical(string s) {return String.Join("\n",(s??"").Replace("\r","").Split('\n').Select(x=>x.Trim()).Where(x=>x.Length>0).OrderBy(x=>x,StringComparer.Ordinal));}
  public static string Host(string s) {Uri u;return Uri.TryCreate(s,UriKind.Absolute,out u)&&(u.Scheme=="http"||u.Scheme=="https")?u.IdnHost.ToLowerInvariant():"";}
  public static bool ChinaHost(string h) {return h.EndsWith(".cn",StringComparison.OrdinalIgnoreCase)||new[]{"baidu.com","qq.com","weixin.qq.com","weibo.com","taobao.com","jd.com","bilibili.com","douyin.com"}.Any(x=>h==x||h.EndsWith("."+x,StringComparison.OrdinalIgnoreCase));}
  public static string ReadBounded(string path,int max=2097152) {if(new FileInfo(path).Length>max)throw new IOException("文件超过读取上限 "+max+" 字节");using(var s=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete))using(var r=new StreamReader(s,true)){var b=new char[max+1];int total=0,n;while(total<=max&&(n=r.Read(b,total,b.Length-total))>0)total+=n;if(total>max)throw new IOException("内容超过上限");return new string(b,0,total);}}
  public static Dictionary<string,object> Json(string path,int max=2097152) {var d=new JavaScriptSerializer{MaxJsonLength=max,RecursionLimit=64}.Deserialize<Dictionary<string,object>>(ReadBounded(path,max));if(d==null)throw new FormatException("JSON 顶层必须为对象");return d;}
  public static string DocumentText(string path) {
   if(Path.GetExtension(path).ToLowerInvariant()!=".docx")return ReadBounded(path);
   if(new FileInfo(path).Length>20*1024*1024)throw new IOException("DOCX 超过 20 MiB 上限");
   using(var f=File.OpenRead(path))using(var zip=new ZipArchive(f,ZipArchiveMode.Read)){
    var e=zip.GetEntry("word/document.xml");if(e==null)throw new FormatException("缺少 document.xml");if(e.Length>2097152)throw new IOException("文档解压内容超过 2 MiB");
    using(var s=e.Open())using(var reader=XmlReader.Create(s,new XmlReaderSettings{DtdProcessing=DtdProcessing.Prohibit,XmlResolver=null,MaxCharactersInDocument=2097152})) {var b=new StringBuilder();while(reader.Read())if(reader.NodeType==XmlNodeType.Text)b.Append(reader.Value).Append(' ');return b.ToString();}
   }
  }
  public sealed class WalkResult {public List<string> Files=new List<string>();public List<string> Errors=new List<string>();public List<string> Roots=new List<string>();public bool Capped;public bool Automatic;public int Directories,Entries,Excluded;}
  public static WalkResult Walk(string root,int maxFiles,int maxDirs,CancellationToken token) {
   var r=new WalkResult();if(!Directory.Exists(root))throw new DirectoryNotFoundException("目录不存在或不可访问");if((File.GetAttributes(root)&FileAttributes.ReparsePoint)!=0)throw new IOException("不跟随重解析目录");r.Roots.Add(root);var q=new Queue<string>();q.Enqueue(root);int dirs=0;
   while(q.Count>0&&dirs<maxDirs){token.ThrowIfCancellationRequested();var dir=q.Dequeue();dirs++;try{foreach(var f in Directory.EnumerateFiles(dir)){token.ThrowIfCancellationRequested();if((File.GetAttributes(f)&FileAttributes.ReparsePoint)!=0)continue;if(r.Files.Count>=maxFiles){r.Capped=true;return r;}r.Files.Add(f);}foreach(var d in Directory.EnumerateDirectories(dir)){if((File.GetAttributes(d)&FileAttributes.ReparsePoint)!=0)continue;if(dirs+q.Count<maxDirs)q.Enqueue(d);else r.Capped=true;}}catch(UnauthorizedAccessException e){r.Errors.Add(e.Message);}catch(IOException e){r.Errors.Add(e.Message);}}
   r.Directories=dirs;r.Entries=r.Files.Count;if(q.Count>0)r.Capped=true;return r;
  }
 }
 public sealed class Baseline {
  public string Format="LocalLens Baseline 2";
  public string CreatedUtc=DateTime.UtcNow.ToString("o");
  public Dictionary<string,string> Hashes=new Dictionary<string,string>();
  public static Baseline Create(IEnumerable<Finding> rows){var b=new Baseline();var ids=new[]{6,11,17,18,19,20,21,22,23,24,25,26,27,28,31,32,41,42,43,44,45,46,47,66};foreach(var f in rows)if(ids.Contains(f.Id)&&f.State!="未检测"&&f.State!="读取失败"&&f.State!="不可判定")b.Hashes[f.Id.ToString()]=LocalData.Hash(LocalData.Canonical(f.Evidence));return b;}
  public static Baseline Load(string path){var b=new JavaScriptSerializer{MaxJsonLength=262144}.Deserialize<Baseline>(LocalData.ReadBounded(path,262144));if(b==null||b.Format!="LocalLens Baseline 2"||b.Hashes==null||b.Hashes.Count>69)throw new FormatException("不是有效的 LocalLens v2 基线");foreach(var pair in b.Hashes){int id;if(!int.TryParse(pair.Key,out id)||id<1||id>69||!Regex.IsMatch(pair.Value??"","^[a-f0-9]{64}$"))throw new FormatException("基线字段无效");}return b;}
 }
}
