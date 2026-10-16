// Windows-only native ABI and synthetic-file checks. No network requests.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using LocalLens;
class WindowsChecks {
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)] [DllImport("winsqlite3",CallingConvention=CallingConvention.StdCall)] static extern int sqlite3_open_v2(byte[] path,out IntPtr db,int flags,IntPtr vfs);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)] [DllImport("winsqlite3",CallingConvention=CallingConvention.StdCall)] static extern int sqlite3_exec(IntPtr db,byte[] sql,IntPtr callback,IntPtr state,out IntPtr error);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)] [DllImport("winsqlite3",CallingConvention=CallingConvention.StdCall)] static extern int sqlite3_close(IntPtr db);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)] [DllImport("winsqlite3",CallingConvention=CallingConvention.StdCall)] static extern void sqlite3_free(IntPtr p);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern IntPtr GetModuleHandle(string name);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern int GetModuleFileName(IntPtr module,StringBuilder file,int size);
 static int count;static BindingFlags Private=BindingFlags.Instance|BindingFlags.NonPublic;
 static void Check(bool ok,string name){if(!ok)throw new Exception("FAIL: "+name);count++;Console.WriteLine("PASS: "+name);}
 static void Throws(Action a,string name){bool threw=false;try{a();}catch{threw=true;}Check(threw,name);}
 static byte[] Bytes(string path){using(var f=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete))using(var m=new MemoryStream()){f.CopyTo(m);return m.ToArray();}}
 static byte[] Utf8(string s){return Encoding.UTF8.GetBytes(s+"\0");}
 static void Sql(IntPtr db,string sql){IntPtr error;int c=sqlite3_exec(db,Utf8(sql),IntPtr.Zero,IntPtr.Zero,out error);if(error!=IntPtr.Zero)sqlite3_free(error);if(c!=0)throw new Exception("Fixture SQLite exec failed: "+c);}
 static Finding Collector(int id,string name,ScanOptions options,List<string> profiles,params object[] args){var engine=new AuditEngine(options,f=>{},CancellationToken.None);if(profiles!=null)typeof(AuditEngine).GetField("profiles",Private).SetValue(engine,profiles);typeof(AuditEngine).GetMethod("Run",Private).Invoke(engine,new object[]{id,(Action)(()=>{try{typeof(AuditEngine).GetMethod(name,Private).Invoke(engine,args);}catch(TargetInvocationException ex){throw ex.InnerException;}})});return ((List<Finding>)typeof(AuditEngine).GetField("rows",Private).GetValue(engine))[id-1];}
 static int Main(string[] args){try{string root=Path.GetFullPath(args[0]);Directory.CreateDirectory(root);string profile=Path.Combine(root,"中文配置");Directory.CreateDirectory(profile);string path=Path.Combine(profile,"History");IntPtr writer;Check(sqlite3_open_v2(Utf8(path),out writer,6,IntPtr.Zero)==0,"native writer fixture opens Chinese path");try{
  Sql(writer,"PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS urls(url TEXT,last_visit_time INTEGER); DELETE FROM urls; INSERT INTO urls VALUES('https://www.baidu.com/synthetic?private=secret',1); CREATE TABLE IF NOT EXISTS downloads_url_chains(url TEXT,id INTEGER);");
  byte[] before=Bytes(path),wal=Bytes(path+"-wal");using(var db=new SqliteRead(path)){Check(db.Query("SELECT url FROM urls",10,CancellationToken.None).Count==1,"read committed WAL while writer remains open");Sql(writer,"BEGIN IMMEDIATE; INSERT INTO urls VALUES('https://example.com/pending',2);");Check(db.Query("SELECT url FROM urls",10,CancellationToken.None).Count==1,"reader excludes uncommitted writer changes");Sql(writer,"ROLLBACK;");Throws(()=>db.Query("SELECT missing FROM urls",10,CancellationToken.None),"unsupported schema is an explicit failure");}Check(before.SequenceEqual(Bytes(path))&&wal.SequenceEqual(Bytes(path+"-wal")),"reader leaves main database and WAL bytes unchanged");
  Sql(writer,"ALTER TABLE urls ADD COLUMN id INTEGER; UPDATE urls SET id=1; CREATE TABLE visits(url INTEGER,visit_time INTEGER); INSERT INTO visits VALUES(1,"+((DateTime.UtcNow-new DateTime(1601,1,1,0,0,0,DateTimeKind.Utc)).Ticks/10).ToString(System.Globalization.CultureInfo.InvariantCulture)+");");
  var other=Path.Combine(root,"第二配置");Directory.CreateDirectory(other);File.Copy(Path.Combine(args[1],"profile","History"),Path.Combine(other,"History"),true);var history=Collector(34,"BrowserHistory",new ScanOptions{BrowserContent=true},new List<string>{profile,other});Check(history.State=="发现线索"&&history.Evidence.Contains("URL 展示记录")&&history.Evidence.Contains(profile)&&history.Evidence.Contains(other)&&!history.Evidence.Contains("private=secret"),"two Chinese profiles read domain-only evidence");
  Sql(writer,"PRAGMA journal_mode=DELETE; BEGIN EXCLUSIVE;");Throws(()=>{using(var db=new SqliteRead(path))db.Query("SELECT url FROM urls",10,CancellationToken.None);},"exclusive database lock is reported");Sql(writer,"ROLLBACK;");
 }finally{sqlite3_close(writer);}
 var module=new StringBuilder(1024);GetModuleFileName(GetModuleHandle("winsqlite3.dll"),module,module.Capacity);Check(module.ToString().StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows),StringComparison.OrdinalIgnoreCase),"SQLite module loaded from Windows system installation");Console.WriteLine("ABI "+(Environment.Is64BitProcess?"x64":"x86")+" module="+module);
 Throws(()=>{using(var db=new SqliteRead(Path.Combine(root,"missing"))){}},"missing database is rejected");
 var empty=Path.Combine(root,"empty");Directory.CreateDirectory(empty);var missing=Collector(34,"BrowserHistory",new ScanOptions(),new List<string>{empty});Check(missing.State!="未发现","missing browser database is not a negative finding");
 var photo=Collector(48,"PhotoMetadata",new ScanOptions(),null,empty);Check(photo.State!="未发现","empty photo directory is not a negative finding");
 string photos=Path.Combine(root,"photos");Directory.CreateDirectory(photos);using(var bmp=new Bitmap(20,20))bmp.Save(Path.Combine(photos,"no-gps.jpg"),System.Drawing.Imaging.ImageFormat.Jpeg);photo=Collector(48,"PhotoMetadata",new ScanOptions(),null,photos);Check(photo.State=="未发现","valid JPEG without GPS is read");File.WriteAllText(Path.Combine(photos,"broken.jpg"),"broken image");photo=Collector(48,"PhotoMetadata",new ScanOptions(),null,photos);Check(photo.IsClue==null&&photo.Evidence.Contains("错误 1"),"damaged image retains limitation");
 var ocr=Collector(49,"RunContent",new ScanOptions{ContentFolder=photos,Ocr=true,OcrExecutable=Path.Combine(root,"missing","tesseract.exe")},null);Check(ocr.State=="缺少依赖","missing OCR dependency is explicit");
 if(args.Length>2){Throws(()=>LocalData.Walk(args[2],10,10,CancellationToken.None),"content rejects reparse root");photo=Collector(48,"PhotoMetadata",new ScanOptions(),null,args[2]);Check(photo.State=="读取失败","photo scan rejects reparse root");}
 Console.WriteLine("WINDOWS CHECKS PASSED: "+count);return 0;
 }catch(Exception ex){Console.Error.WriteLine(ex);return 1;}}
}
