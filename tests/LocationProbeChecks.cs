using System;
using System.Linq;
using System.Collections.Generic;
using System.Threading;
using LocalLens;
class LocationProbeChecks {
 static int count;static void Check(bool ok,string name){if(!ok)throw new Exception(name);count++;Console.WriteLine("PASS: "+name);}
 sealed class Clock:ILocationClock {public long Time;public Action Tick;public long Milliseconds{get{return Time;}}public DateTimeOffset UtcNow{get{return new DateTimeOffset(2026,10,16,12,0,0,TimeSpan.Zero).AddMilliseconds(Time);}}public void Delay(int ms,CancellationToken cancel){Time+=ms;if(Tick!=null)Tick();cancel.ThrowIfCancellationRequested();}}
 sealed class Provider:ILocationProvider {public Func<LocationSample> Next;public int Started,Disposed,Reads;public void Start(){Started++;}public LocationSample Read(){Reads++;return Next();}public void Dispose(){Disposed++;}}
 static LocationSample Ready(Clock clock){return new LocationSample{Permission="Granted",Status="Ready",Latitude=39.9,Longitude=116.4,Accuracy=25,Timestamp=clock.UtcNow};}
 static LocationSample Waiting(string status="NoData",string permission="Granted"){return new LocationSample{Permission=permission,Status=status,IsUnknown=true,Latitude=Double.NaN,Longitude=Double.NaN,Accuracy=Double.NaN};}
 static int Main(string[] args){try{
  if(args.Length>0&&args[0]=="--live-engine"){
   Finding observed=null;var engine=new AuditEngine(new ScanOptions(),f=>{if(f.Id==12)observed=f;},CancellationToken.None);
   typeof(AuditEngine).GetMethod("SystemLocation",System.Reflection.BindingFlags.Instance|System.Reflection.BindingFlags.NonPublic).Invoke(engine,null);
   Console.WriteLine(new System.Web.Script.Serialization.JavaScriptSerializer().Serialize(new{observed.State,observed.Summary,observed.Coverage,HasValidVerdict=observed.IsClue.HasValue,HasActualCoordinates=ChinaEvidence.Coordinates(observed.Evidence).Count>0}));return observed.IsClue.HasValue?0:2;
  }
  if(args.Length>0&&args[0]=="--live"){
   string json=SystemLocationProbe.CaptureJson();var result=new System.Web.Script.Serialization.JavaScriptSerializer().Deserialize<LocationResult>(json);
   Console.WriteLine(new System.Web.Script.Serialization.JavaScriptSerializer().Serialize(new{result.Success,result.Reason,result.Status,result.Permission,result.Attempts,result.WaitMilliseconds,HasCoordinates=result.Latitude.HasValue&&result.Longitude.HasValue,HasTimestamp=!String.IsNullOrEmpty(result.Timestamp)}));return result.Success?0:2;
  }
  var clock=new Clock();var one=new Provider{Next=()=>Ready(clock)};var r=SystemLocationProbe.Acquire(()=>one,clock,CancellationToken.None,45000,15000);Check(r.Success&&r.Attempts==1&&r.WaitMilliseconds==0,"ready coordinates return on first acquisition");Check(one.Disposed==1,"successful provider always disposed");
  clock=new Clock();one=new Provider{Next=()=>clock.Time<12000?Waiting():Ready(clock)};r=SystemLocationProbe.Acquire(()=>one,clock,CancellationToken.None,45000,15000);Check(r.Success&&r.Attempts==1&&r.WaitMilliseconds==12000,"NoData is allowed to become Ready without ending the scan");
  clock=new Clock();var first=new Provider{Next=()=>Waiting()};var second=new Provider{Next=()=>Ready(clock)};int made=0;r=SystemLocationProbe.Acquire(()=>made++==0?first:second,clock,CancellationToken.None,45000,15000);Check(r.Success&&r.Attempts==2&&r.WaitMilliseconds==15000,"first NoData and second Ready recover within one call");Check(first.Disposed==1&&second.Disposed==1,"retry disposes both providers exactly once");
  clock=new Clock();var providers=new List<Provider>();r=SystemLocationProbe.Acquire(()=>{var p=new Provider{Next=()=>Waiting()};providers.Add(p);return p;},clock,CancellationToken.None,45000,15000);Check(!r.Success&&r.Attempts==2&&r.WaitMilliseconds==45000,"persistent NoData is bounded to two attempts and 45 seconds");Check(!r.Latitude.HasValue&&!r.Longitude.HasValue&&providers.All(p=>p.Disposed==1),"failed attempts have no fabricated coordinates and release all providers");
  clock=new Clock();one=new Provider{Next=()=>Waiting("Disabled","Denied")};r=SystemLocationProbe.Acquire(()=>one,clock,CancellationToken.None,45000,15000);Check(!r.Success&&r.Attempts==1&&r.WaitMilliseconds==0&&r.Reason.Contains("权限被拒绝"),"denied permission exits immediately without retrying permission");
  clock=new Clock();one=new Provider{Next=()=>Waiting("Disabled")};r=SystemLocationProbe.Acquire(()=>one,clock,CancellationToken.None,45000,15000);Check(!r.Success&&r.Attempts==1&&r.WaitMilliseconds==3000,"persistent Disabled status gets only an initialization grace period");
  clock=new Clock();one=new Provider{Next=()=>clock.Time<2000?Waiting("Disabled","Unknown"):Ready(clock)};r=SystemLocationProbe.Acquire(()=>one,clock,CancellationToken.None,45000,15000);Check(r.Success&&r.WaitMilliseconds==2000,"transient Disabled during startup is not mistaken for permanent denial");
  clock=new Clock();one=new Provider{Next=()=>{var p=Ready(clock);p.Timestamp=p.Timestamp.AddMinutes(-10);return p;}};r=SystemLocationProbe.Acquire(()=>one,clock,CancellationToken.None,1000,400);Check(!r.Success&&!r.Latitude.HasValue,"old cached coordinates do not masquerade as a fresh sample");
  clock=new Clock();one=new Provider{Next=()=>{var p=Ready(clock);p.Accuracy=Double.NaN;return p;}};r=SystemLocationProbe.Acquire(()=>one,clock,CancellationToken.None,1000,400);Check(!r.Success,"coordinates without finite accuracy are not used for mainland classification");
  clock=new Clock();one=new Provider{Next=()=>{var p=Ready(clock);p.Latitude=91;return p;}};r=SystemLocationProbe.Acquire(()=>one,clock,CancellationToken.None,1000,400);Check(!r.Success,"invalid coordinate bounds remain unavailable");
  clock=new Clock();one=new Provider{Next=()=>{var p=Ready(clock);p.Status="Initializing";return p;}};r=SystemLocationProbe.Acquire(()=>one,clock,CancellationToken.None,1000,400);Check(!r.Success,"cached Position during initialization is not ready data");
  clock=new Clock();one=new Provider{Next=()=>Waiting()};var cancel=new CancellationTokenSource();clock.Tick=()=>cancel.Cancel();bool cancelled=false;try{SystemLocationProbe.Acquire(()=>one,clock,cancel.Token,45000,15000);}catch(OperationCanceledException){cancelled=true;}Check(cancelled&&one.Disposed==1&&clock.Time==200,"cancellation stops waits and disposes the active watcher");
  clock=new Clock();one=new Provider{Next=()=>{throw new InvalidOperationException("provider failure");}};bool failed=false;try{SystemLocationProbe.Acquire(()=>one,clock,CancellationToken.None,45000,15000);}catch(InvalidOperationException){failed=true;}Check(failed&&one.Disposed==1,"provider exceptions still release the watcher");
  Console.WriteLine("LOCATION CHECKS PASSED: "+count);return 0;
 }catch(Exception e){Console.Error.WriteLine(e);return 1;}}
}
