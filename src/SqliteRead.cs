using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
namespace LocalLens {
 // Windows 10+ system SQLite; the database is always opened SQLITE_OPEN_READONLY.
 public sealed class SqliteRead:IDisposable {
  IntPtr db;
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
  [DllImport("winsqlite3",CallingConvention=CallingConvention.StdCall)] static extern int sqlite3_open_v2(byte[] path,out IntPtr db,int flags,IntPtr vfs);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
  [DllImport("winsqlite3",CallingConvention=CallingConvention.StdCall)] static extern int sqlite3_close(IntPtr db);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
  [DllImport("winsqlite3",CallingConvention=CallingConvention.StdCall)] static extern int sqlite3_busy_timeout(IntPtr db,int ms);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
  [DllImport("winsqlite3",CallingConvention=CallingConvention.StdCall)] static extern int sqlite3_prepare_v2(IntPtr db,byte[] sql,int len,out IntPtr statement,IntPtr tail);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
  [DllImport("winsqlite3",CallingConvention=CallingConvention.StdCall)] static extern int sqlite3_stmt_readonly(IntPtr statement);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
  [DllImport("winsqlite3",CallingConvention=CallingConvention.StdCall)] static extern int sqlite3_step(IntPtr statement);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
  [DllImport("winsqlite3",CallingConvention=CallingConvention.StdCall)] static extern int sqlite3_finalize(IntPtr statement);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
  [DllImport("winsqlite3",CallingConvention=CallingConvention.StdCall)] static extern int sqlite3_column_count(IntPtr statement);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
  [DllImport("winsqlite3",CallingConvention=CallingConvention.StdCall)] static extern IntPtr sqlite3_column_text(IntPtr statement,int index);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
  [DllImport("winsqlite3",CallingConvention=CallingConvention.StdCall)] static extern int sqlite3_column_bytes(IntPtr statement,int index);
  static byte[] Utf8(string s){return Encoding.UTF8.GetBytes(s+"\0");}
  public SqliteRead(string path){if(!File.Exists(path))throw new FileNotFoundException("数据库不存在",path);int c=sqlite3_open_v2(Utf8(path),out db,1,IntPtr.Zero);if(c!=0){Dispose();throw new IOException("SQLite 只读打开失败，代码 "+c);}sqlite3_busy_timeout(db,700);}
  public List<string[]> Query(string sql,int max,CancellationToken token){if(!sql.TrimStart().StartsWith("SELECT ",StringComparison.OrdinalIgnoreCase)||sql.Contains(";"))throw new ArgumentException("只接受单条 SELECT");IntPtr s;var result=new List<string[]>();int c=sqlite3_prepare_v2(db,Utf8(sql),-1,out s,IntPtr.Zero);if(c!=0)throw new IOException("SQLite 查询准备失败（结构可能不支持），代码 "+c);try{if(sqlite3_stmt_readonly(s)==0)throw new InvalidOperationException("拒绝写入查询");while(result.Count<max){token.ThrowIfCancellationRequested();c=sqlite3_step(s);if(c==101)break;if(c!=100)throw new IOException("SQLite 读取失败（数据库可能正在使用），代码 "+c);int n=sqlite3_column_count(s);var row=new string[n];for(int i=0;i<n;i++){int bytes=sqlite3_column_bytes(s,i);if(bytes>32768)throw new IOException("SQLite 字段超过安全读取上限");var data=new byte[bytes];if(bytes>0)Marshal.Copy(sqlite3_column_text(s,i),data,0,bytes);row[i]=Encoding.UTF8.GetString(data);}result.Add(row);}return result;}finally{sqlite3_finalize(s);}}
  public void Dispose(){if(db!=IntPtr.Zero){sqlite3_close(db);db=IntPtr.Zero;}}
 }
}
