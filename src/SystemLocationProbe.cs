using System;
using System.Device.Location;
using System.Diagnostics;
using System.Threading;
using System.Web.Script.Serialization;
namespace LocalLens {
 public sealed class LocationSample {
  public string Permission {get;set;} public string Status {get;set;}
  public double Latitude {get;set;} public double Longitude {get;set;} public double Accuracy {get;set;}
  public DateTimeOffset Timestamp {get;set;} public bool IsUnknown {get;set;}
 }
 public sealed class LocationResult {
  public bool Success {get;set;} public string Reason {get;set;} public string Permission {get;set;} public string Status {get;set;}
  public double? Latitude {get;set;} public double? Longitude {get;set;} public double? Accuracy {get;set;}
  public string Timestamp {get;set;} public int Attempts {get;set;} public long WaitMilliseconds {get;set;}
 }
 public interface ILocationProvider:IDisposable {void Start();LocationSample Read();}
 public interface ILocationClock {long Milliseconds {get;} DateTimeOffset UtcNow {get;} void Delay(int milliseconds,CancellationToken cancel);}
 public static class SystemLocationProbe {
  sealed class Provider:ILocationProvider {
   readonly GeoCoordinateWatcher watcher=new GeoCoordinateWatcher();
   public void Start(){watcher.Start(false);}
   public LocationSample Read(){var p=watcher.Position;var c=p.Location;return new LocationSample{Permission=watcher.Permission.ToString(),Status=watcher.Status.ToString(),IsUnknown=c.IsUnknown,Latitude=c.Latitude,Longitude=c.Longitude,Accuracy=c.HorizontalAccuracy,Timestamp=p.Timestamp};}
   public void Dispose(){watcher.Dispose();}
  }
  sealed class Clock:ILocationClock {
   readonly Stopwatch watch=Stopwatch.StartNew();public long Milliseconds {get{return watch.ElapsedMilliseconds;}}
   public DateTimeOffset UtcNow {get{return DateTimeOffset.UtcNow;}}
   public void Delay(int milliseconds,CancellationToken cancel){if(cancel.WaitHandle.WaitOne(milliseconds))cancel.ThrowIfCancellationRequested();}
  }
  public static string CaptureJson(){
   LocationResult result;
   try{result=Acquire(()=>new Provider(),new Clock(),CancellationToken.None,45000,15000);}
   catch(Exception e){result=new LocationResult{Success=false,Reason="系统定位接口未完成："+e.GetType().Name+" / "+Rules.StripSecrets(e.Message)};}
   return new JavaScriptSerializer().Serialize(result);
  }
  static bool Finite(double n){return !Double.IsNaN(n)&&!Double.IsInfinity(n);}
  public static LocationResult Acquire(Func<ILocationProvider> factory,ILocationClock clock,CancellationToken cancel,int timeoutMilliseconds,int retryAfterMilliseconds){
   if(timeoutMilliseconds<=0||retryAfterMilliseconds<=0||retryAfterMilliseconds>=timeoutMilliseconds)throw new ArgumentOutOfRangeException("timeoutMilliseconds");
   ILocationProvider provider=null;LocationSample sample=null;int attempts=0;long began=clock.Milliseconds;
   try {
    while(clock.Milliseconds-began<timeoutMilliseconds){
     cancel.ThrowIfCancellationRequested();
     if(provider==null){provider=factory();attempts++;provider.Start();}
     sample=provider.Read();
     if(sample!=null){
      if(sample.Permission=="Denied")return Failure("系统定位权限被拒绝，已跳过；未重复请求权限",sample,attempts,clock.Milliseconds-began);
      var age=clock.UtcNow-sample.Timestamp;
      if(sample.Status=="Ready"&&!sample.IsUnknown&&Finite(sample.Latitude)&&Finite(sample.Longitude)&&Finite(sample.Accuracy)&&Math.Abs(sample.Latitude)<=90&&Math.Abs(sample.Longitude)<=180&&sample.Accuracy>=0&&age>=TimeSpan.FromMinutes(-1)&&age<=TimeSpan.FromMinutes(5))return new LocationResult{Success=true,Latitude=sample.Latitude,Longitude=sample.Longitude,Accuracy=sample.Accuracy,Timestamp=sample.Timestamp.ToUniversalTime().ToString("o"),Permission=sample.Permission,Status=sample.Status,Attempts=attempts,WaitMilliseconds=clock.Milliseconds-began,Reason="已取得本次有效系统定位；启动无数据时在同批等待并自动重试"};
      if(sample.Status=="Disabled"&&clock.Milliseconds-began>=3000)return Failure("系统定位服务不可用，已跳过",sample,attempts,clock.Milliseconds-began);
     }
     // NoData and Initializing are transient. Restart once inside the same
     // bounded acquisition instead of making the user run the whole scan twice.
     if(attempts==1&&clock.Milliseconds-began>=retryAfterMilliseconds){provider.Dispose();provider=null;continue;}
     int remaining=timeoutMilliseconds-(int)(clock.Milliseconds-began);if(remaining>0)clock.Delay(Math.Min(200,remaining),cancel);
    }
    return Failure("系统定位在 "+(timeoutMilliseconds/1000)+" 秒内未取得有效的新坐标，已自动尝试 "+attempts+" 次并跳过",sample,attempts,clock.Milliseconds-began);
   }finally{if(provider!=null)provider.Dispose();}
  }
  static LocationResult Failure(string reason,LocationSample sample,int attempts,long elapsed){return new LocationResult{Success=false,Reason=reason,Permission=sample==null?"Unknown":sample.Permission,Status=sample==null?"Unknown":sample.Status,Attempts=attempts,WaitMilliseconds=elapsed};}
 }
 public sealed partial class AuditEngine {
  void SystemLocation(){
   string assembly=typeof(SystemLocationProbe).Assembly.Location.Replace("'","''");
   string output=PS("[void][Reflection.Assembly]::LoadFrom('"+assembly+"'); [LocalLens.SystemLocationProbe]::CaptureJson()",55000);
   var result=new JavaScriptSerializer().Deserialize<LocationResult>(output.Trim().TrimStart('\ufeff'));
   if(result==null)throw new FormatException("系统定位未返回有效结果对象");
   string coverage="系统融合定位 / 同批尝试 "+result.Attempts+" 次 / 等待 "+result.WaitMilliseconds+" 毫秒";
   if(!result.Success){Set(12,"读取失败",result.Reason,output,coverage);return;}
   Set(12,"信息","已取得系统融合定位；坐标仅在本机展示",output+"\r\nWindows 融合定位，不保证来自 GNSS/GPS；保留实际时间、精度和本批尝试次数。",coverage);
  }
 }
}
