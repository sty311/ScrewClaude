using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using Microsoft.Win32;

namespace LocalLens {
 // Local candidate discovery only. Never opens accounts or hydrates cloud placeholders.
 public static class AutomaticFiles {
  static readonly HashSet<string> ExcludedNames=new HashSet<string>(new[]{"AppData",".git",".svn","node_modules",".venv","venv","__pycache__",".cache",".codex",".agents","Codex","$RECYCLE.BIN","System Volume Information"},StringComparer.OrdinalIgnoreCase);
  static readonly HashSet<string> Documents=new HashSet<string>(new[]{".txt",".md",".csv",".tsv",".json",".xml",".ini",".log",".docx"},StringComparer.OrdinalIgnoreCase);
  static readonly HashSet<string> Messages=new HashSet<string>(new[]{".eml",".ics",".vcf"},StringComparer.OrdinalIgnoreCase);
  static readonly HashSet<string> Photos=new HashSet<string>(new[]{".jpg",".jpeg",".tif",".tiff"},StringComparer.OrdinalIgnoreCase);
  static readonly HashSet<string> Images=new HashSet<string>(new[]{".png",".jpg",".jpeg",".bmp",".tif",".tiff"},StringComparer.OrdinalIgnoreCase);
  public static List<string> Roots(){
   var roots=new List<string>();
   foreach(var folder in new[]{Environment.SpecialFolder.DesktopDirectory,Environment.SpecialFolder.MyDocuments,Environment.SpecialFolder.MyPictures,Environment.SpecialFolder.MyVideos,Environment.SpecialFolder.MyMusic})AddRoot(roots,Environment.GetFolderPath(folder));
   using(var key=Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",false))if(key!=null)AddRoot(roots,Environment.ExpandEnvironmentVariables(Convert.ToString(key.GetValue("{374DE290-123F-4565-9164-39C4925E467B}"))));
   string user=Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);AddRoot(roots,Path.Combine(user,"Downloads"));
   foreach(string variable in new[]{"OneDrive","OneDriveConsumer","OneDriveCommercial"})AddRoot(roots,Environment.GetEnvironmentVariable(variable));
   AddRoot(roots,user);return roots;
  }
  static void AddRoot(List<string> roots,string value){if(String.IsNullOrWhiteSpace(value))return;try{string path=Path.GetFullPath(value).TrimEnd(Path.DirectorySeparatorChar);if(Directory.Exists(path)&&!roots.Contains(path,StringComparer.OrdinalIgnoreCase))roots.Add(path);}catch(ArgumentException){}catch(NotSupportedException){}}
  public static bool LocalEntry(FileAttributes attributes){const int cloudUnavailable=0x1000|0x40000|0x400000;return (attributes&FileAttributes.ReparsePoint)==0&&((int)attributes&cloudUnavailable)==0;}
  static bool ExcludedDirectory(string path){return ExcludedNames.Contains(Path.GetFileName(path))||Directory.Exists(Path.Combine(path,".git"))||File.Exists(Path.Combine(path,"ScrewClaude.Web.exe"))||File.Exists(Path.Combine(path,"LocalLens.Web.exe"))||(File.Exists(Path.Combine(path,"build-web.cmd"))&&File.Exists(Path.Combine(path,"src","catalog.json")));}
  public static bool Candidate(string path){string ext=Path.GetExtension(path),name=Path.GetFileName(path);return (Documents.Contains(ext)||Messages.Contains(ext)||Images.Contains(ext))&&!name.StartsWith("ScrewClaude-environment-risk-",StringComparison.OrdinalIgnoreCase)&&!name.StartsWith("LocalLens-environment-risk-",StringComparison.OrdinalIgnoreCase)&&!name.EndsWith(".private.json",StringComparison.OrdinalIgnoreCase)&&!name.Equals("desktop.ini",StringComparison.OrdinalIgnoreCase);}
  public static LocalData.WalkResult Discover(IEnumerable<string> roots,CancellationToken token,int maxFiles=1400,int maxDirs=1000,int maxEntries=30000,int maxMilliseconds=8000){
   var result=new LocalData.WalkResult();result.Automatic=true;var queue=new Queue<string>();var seenDirs=new HashSet<string>(StringComparer.OrdinalIgnoreCase);var seenFiles=new HashSet<string>(StringComparer.OrdinalIgnoreCase);var timer=Stopwatch.StartNew();int documents=0,messages=0,photos=0,images=0;
   foreach(string value in roots){token.ThrowIfCancellationRequested();try{string root=Path.GetFullPath(value);if(seenDirs.Add(root)){queue.Enqueue(root);result.Roots.Add(root);}}catch(Exception e){if(e is OperationCanceledException)throw;result.Errors.Add("搜索根目录不可用："+e.Message);}}
   while(queue.Count>0){
    token.ThrowIfCancellationRequested();if(result.Directories>=maxDirs||result.Entries>=maxEntries||timer.ElapsedMilliseconds>=maxMilliseconds||result.Files.Count>=maxFiles){result.Capped=true;break;}
    string dir=queue.Dequeue();result.Directories++;
    try{
     if(!LocalEntry(File.GetAttributes(dir))||ExcludedDirectory(dir)){result.Excluded++;continue;}
     int entriesHere=0;var files=new List<FileInfo>();
     foreach(string entry in Directory.EnumerateFileSystemEntries(dir)){
      token.ThrowIfCancellationRequested();if(result.Entries>=maxEntries||timer.ElapsedMilliseconds>=maxMilliseconds||entriesHere>=2000){result.Capped=true;break;}result.Entries++;entriesHere++;
      try{var attributes=File.GetAttributes(entry);if(!LocalEntry(attributes)){result.Excluded++;continue;}
       if((attributes&FileAttributes.Directory)!=0){if(!ExcludedDirectory(entry)&&seenDirs.Add(Path.GetFullPath(entry))){if(queue.Count+result.Directories<maxDirs)queue.Enqueue(entry);else result.Capped=true;}else result.Excluded++;continue;}
       if(Candidate(entry)&&seenFiles.Add(Path.GetFullPath(entry)))files.Add(new FileInfo(entry));
      }catch(UnauthorizedAccessException e){result.Errors.Add(e.Message);}catch(IOException e){result.Errors.Add(e.Message);}
     }
     foreach(var file in files.OrderByDescending(f=>f.LastWriteTimeUtc)){
      token.ThrowIfCancellationRequested();string ext=file.Extension;long maxBytes=ext.Equals(".docx",StringComparison.OrdinalIgnoreCase)?20L*1024*1024:Images.Contains(ext)?30L*1024*1024:2L*1024*1024;
      if(file.Length>maxBytes){result.Excluded++;continue;}
      bool document=Documents.Contains(ext),message=Messages.Contains(ext),photo=Photos.Contains(ext),image=Images.Contains(ext);
      if((document&&documents>=500)||(message&&messages>=200)||(photo&&photos>=500)||(image&&!photo&&images>=200)||result.Files.Count>=maxFiles){result.Capped=true;continue;}
      result.Files.Add(file.FullName);if(document)documents++;if(message)messages++;if(photo)photos++;if(image&&!photo)images++;
     }
    }catch(UnauthorizedAccessException e){result.Errors.Add(e.Message);}catch(IOException e){result.Errors.Add(e.Message);}
   }
   return result;
  }
  public static string Description(LocalData.WalkResult result){return (result.Automatic?"自动查找":"指定目录")+"：搜索根目录 "+result.Roots.Count+"；已检查目录 "+result.Directories+"；目录条目 "+result.Entries+"；候选文件 "+result.Files.Count+"；排除链接、云占位、开发目录或超限文件 "+result.Excluded+"；枚举错误 "+result.Errors.Count+"；达到上限="+result.Capped+"\r\n"+String.Join("\r\n",result.Roots);}
 }

 public static class AutomaticBaseline {
  public static string DefaultPath {get{return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"ScrewClaude","baseline.json");}}
  public static void Save(string path,Baseline baseline){
   Directory.CreateDirectory(Path.GetDirectoryName(path));string temp=path+"."+Guid.NewGuid().ToString("N")+".tmp";
   File.WriteAllText(temp,new System.Web.Script.Serialization.JavaScriptSerializer().Serialize(baseline),new System.Text.UTF8Encoding(false));
   if(File.Exists(path))File.Replace(temp,path,null);else File.Move(temp,path);
  }
 }
 public sealed partial class AuditEngine {
  LocalData.WalkResult automaticFiles;
  LocalData.WalkResult FindAutomaticFiles(){return automaticFiles??(automaticFiles=AutomaticFiles.Discover(AutomaticFiles.Roots(),cancel));}
  LocalData.WalkResult ContentFiles(){if(!String.IsNullOrWhiteSpace(options.ContentFolder))return LocalData.Walk(options.ContentFolder,500,100,cancel);return FindAutomaticFiles();}
  void ScanPhotos(){if(!String.IsNullOrWhiteSpace(options.PhotoFolder))PhotoMetadata(options.PhotoFolder);else if(options.AutoDiscoverFiles)PhotoFiles(FindAutomaticFiles());else Skip(48,"已关闭自动查找文件，且未指定照片目录");}
  void AutomaticExternalRecords(){
   try{ReadAutomaticExternalRecords();}catch(OperationCanceledException){throw;}catch(Exception ex){foreach(int id in new[]{56,57,59,60,61})Set(id,"读取失败","自动查找平台记录失败",Rules.StripSecrets(ex.Message),"自动查找 / 未完成");}
  }
  void ReadAutomaticExternalRecords(){
   var files=FindAutomaticFiles();var matches=new List<string>();int failed=0;
   foreach(string file in files.Files.Where(f=>Path.GetExtension(f).Equals(".json",StringComparison.OrdinalIgnoreCase)).Take(200)){
    cancel.ThrowIfCancellationRequested();try{if(!AutomaticFiles.LocalEntry(File.GetAttributes(file)))continue;var data=LocalData.Json(file,1048576);if(Value(data,"format")=="LocalLens External Evidence 1")matches.Add(file);}catch(Exception ex){if(ex is OperationCanceledException)throw;failed++;}
   }
   if(matches.Count==0){foreach(int id in new[]{56,57,59,60,61})Set(id,"需外部记录","自动搜索未找到可解析的已保存平台记录",AutomaticFiles.Description(files)+"\r\n没有发现 LocalLens External Evidence 1 格式的本地记录；其他 JSON 解析失败/超过大小限制 "+failed+"。本机搜索无法取得平台后台尚未导出的数据。","自动查找本地 JSON / 外部平台记录不存在");return;}
   foreach(int id in new[]{56,57,59,60,61}){
    var collected=new List<Finding>();string original=options.ExternalEvidencePath;
    try{foreach(string file in matches.Take(20)){options.ExternalEvidencePath=file;Run(id,()=>ImportExternal(id));var snapshot=new System.Web.Script.Serialization.JavaScriptSerializer().Deserialize<Finding>(new System.Web.Script.Serialization.JavaScriptSerializer().Serialize(F(id)));snapshot.Evidence="自动发现记录："+file+"\r\n"+snapshot.Evidence;collected.Add(snapshot);}}
    finally{options.ExternalEvidencePath=original;}
    var best=collected.OrderByDescending(f=>f.State=="发现线索"?3:f.State=="读取失败"||f.State=="未检测"?2:f.State=="未发现"?1:0).First();
    Set(id,best.State,best.Summary,String.Join("\r\n\r\n",collected.Select(f=>f.Evidence)),"自动查找本地平台记录 / 已解析 "+collected.Count+" 个文件 / 未验证平台来源真实性");
   }
  }
  void SaveAutomaticBaseline(){
   if(!options.AutoDiscoverFiles||F(65).State=="读取失败")return;
   try{AutomaticBaseline.Save(AutomaticBaseline.DefaultPath,Baseline.Create(rows));if(String.IsNullOrWhiteSpace(options.BaselinePath)&&!baselineExisted)Skip(65,"首次完整扫描已自动保存配置基线，下次扫描自动比较");}
   catch(Exception e){Set(65,"读取失败","本次自动基线保存失败",Rules.StripSecrets(e.Message),"仅保存配置哈希 / 未保存成功");}
  }
  bool baselineExisted;
 }
}
