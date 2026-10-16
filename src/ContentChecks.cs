using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
namespace LocalLens {
 public sealed partial class AuditEngine {
  void RunContent(){LocalData.WalkResult walk=null;Run(50,()=>{walk=LocalData.Walk(options.ContentFolder,500,100,cancel);ContentGroup(50,walk,f=>Regex.IsMatch(Path.GetExtension(f),@"(?i)^\.(txt|md|csv|tsv|json|xml|ini|log|docx)$"),false);});if(walk==null){foreach(int id in new[]{49,51,55})Skip(id,"内容目录枚举失败");return;}
   Run(51,()=>ContentGroup(51,walk,f=>Regex.IsMatch(Path.GetExtension(f),@"(?i)^\.(eml|ics|vcf)$"),false));Run(55,()=>ContentGroup(55,walk,f=>Regex.IsMatch(Path.GetExtension(f),@"(?i)^\.(txt|md|csv|json|xml|log|eml|ics|docx)$"),true));
   if(options.Ocr)Run(49,()=>OcrImages(walk));else Skip(49,"高级选项未启用图片 OCR；需要本机 Tesseract 与识别语言包");
  }

  void OcrImages(LocalData.WalkResult walk){
   var images=walk.Files.Where(f=>Regex.IsMatch(Path.GetExtension(f),@"(?i)^\.(png|jpe?g|bmp|tiff?)$")).Take(20).ToArray();
   if(images.Length==0){Skip(49,"所选范围内没有支持的 OCR 图片样本");return;}
   string exe=options.OcrExecutable;
   if(String.IsNullOrWhiteSpace(exe))exe=new[]{Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),@"Tesseract-OCR\tesseract.exe"),Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),@"Tesseract-OCR\tesseract.exe")}.FirstOrDefault(File.Exists);
   if(String.IsNullOrWhiteSpace(exe)||!File.Exists(exe)){Set(49,"缺少依赖","请在高级选项选择已安装的 Tesseract 程序","图片 OCR 需要本机 tesseract.exe 和 chi_sim / eng 语言包。程序不自动下载或安装软件。","依赖未满足");return;}
   if(!Path.GetFileName(exe).Equals("tesseract.exe",StringComparison.OrdinalIgnoreCase))throw new FormatException("只接受 tesseract.exe");
   string available=Command(exe,"--list-langs",true,8000);var languages=new[]{"chi_sim","eng"}.Where(l=>Regex.IsMatch(available,@"(?m)^\s*"+l+@"\s*$")).ToArray();if(languages.Length==0)throw new IOException("Tesseract 未安装 chi_sim 或 eng 语言包");
   var lines=new List<string>{"OCR 引擎："+exe+"；语言："+String.Join("+",languages)};int read=0,hit=0,failed=0;
   foreach(var file in images){cancel.ThrowIfCancellationRequested();try{if(new FileInfo(file).Length>20*1024*1024)throw new IOException("图片超过 20 MiB");string text=Command(exe,"\""+Path.GetFullPath(file)+"\" stdout -l "+String.Join("+",languages)+" --psm 3",true,20000);read++;var hits=ChinaEvidence.ContactMatches(text);if(hits.Length>0){hit++;lines.Add("来源文件："+Path.GetFileName(file));lines.AddRange(hits);}}catch(Exception ex){if(ex is OperationCanceledException)throw;failed++;lines.Add(Path.GetFileName(file)+": "+ex.Message);}}
   lines.Add("仅本机 OCR，最多 20 张；误识别 / 漏字可能发生，图片内容地名不等于拍摄地。仅安装 eng 时不覆盖中文识别。");Outcome(49,lines,hit,read,failed,"图片识别文本包含地名关键词","选定图片 + 本机 OCR 语言范围");
  }
  void ContentGroup(int id,LocalData.WalkResult walk,Func<string,bool> filter,bool timezone){
   var lines=new List<string>();int scanned=0,hit=0,failed=walk.Errors.Count;
   foreach(var file in walk.Files.Where(filter)){cancel.ThrowIfCancellationRequested();try{
    string text=LocalData.DocumentText(file);scanned++;var matches=timezone?ChinaEvidence.TimezoneMatches(text):ChinaEvidence.ContactMatches(text);
    if(matches.Length>0){hit++;lines.Add("来源文件："+Path.GetFileName(file));lines.AddRange(matches);}
   }catch(Exception ex){if(ex is OperationCanceledException)throw;failed++;lines.Add(Path.GetFileName(file)+"："+ex.Message);}}
   lines.Insert(0,"候选文件 "+walk.Files.Count+"；成功读取 "+scanned+"；错误 "+failed+"；达到枚举上限="+walk.Capped+"。只保留中国联系字段或明确命名时区片段，普通地名和任意 UTC 偏移不参与判定。");
   lines.AddRange(walk.Errors.Take(10));
   if(id==51)lines.Add("仅分析选定 EML / ICS / VCF 明文；不解密附件或聊天数据库，不连接账号。");
   if(id==50)lines.Add("仅支持 TXT / MD / CSV / TSV / JSON / XML / INI / LOG / DOCX；字段可能是示例或他人资料，不自动视为本人地址。");
   Outcome(id,lines,hit,scanned,failed+(walk.Capped?1:0),timezone?"中国命名时区字段已提取":"明确中国联系字段已提取","用户选定文件 / 字段语义检查");
  }
 }
}
