// Native WinForms harness. Synthetic lifecycle tests are separate from --live.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;
using LocalLens;
class GuiSmoke {
 [DllImport("user32.dll")] static extern bool SetProcessDPIAware();
 static int count;static string output;
 static readonly BindingFlags Private=BindingFlags.Instance|BindingFlags.NonPublic;
 static T Get<T>(object o,string name){return (T)o.GetType().GetField(name,Private).GetValue(o);}
 static void Put(object o,string name,object value){o.GetType().GetField(name,Private).SetValue(o,value);}
 static void Check(bool ok,string name){if(!ok)throw new Exception("FAIL: "+name);count++;Console.WriteLine("PASS: "+name);}
 static IEnumerable<Control> Walk(Control c){foreach(Control x in c.Controls){yield return x;foreach(var y in Walk(x))yield return y;}}
 static void Pump(Func<bool> until,int seconds){var deadline=DateTime.UtcNow.AddSeconds(seconds);do{Application.DoEvents();if(until())return;Thread.Sleep(15);}while(DateTime.UtcNow<deadline);throw new TimeoutException("GUI wait exceeded "+seconds+" seconds");}
 static void Show(Form f){f.ShowInTaskbar=false;f.StartPosition=FormStartPosition.Manual;f.Location=new Point(-30000,-30000);f.Show();Application.DoEvents();}
 static void Capture(Form f,string name){using(var b=new Bitmap(f.Width,f.Height)){f.DrawToBitmap(b,new Rectangle(Point.Empty,f.Size));b.Save(Path.Combine(output,name+".png"));}}
 static void Ready(MainForm f,bool export,bool baseline,bool admin){Check(Get<Button>(f,"start").Enabled&&!Get<Button>(f,"stop").Enabled&&Get<Button>(f,"advanced").Enabled&&Get<Button>(f,"browse").Enabled,"scan controls restored");Check(Get<Button>(f,"export").Enabled==export&&Get<Button>(f,"saveBaseline").Enabled==baseline,"report and baseline readiness");Check(Get<Button>(f,"admin").Enabled==admin,"administrator button follows current mode");}
 static AuditReport Synthetic(ScanOptions o,bool completed){return new AuditReport{Options=o,Completed=completed,CreatedUtc=DateTime.UtcNow.ToString("o"),Findings=Catalog.Load(),Snapshot=new Baseline()};}
 static void Start(MainForm f){Get<Button>(f,"start").PerformClick();}
 static void Lifecycle(){using(var f=new MainForm(false)){Show(f);bool admin=Get<Button>(f,"admin").Enabled;int errors=0;Put(f,"scanError",(Action<Exception>)(ex=>{errors++;Console.WriteLine("Expected injected error: "+ex.Message);}));
  foreach(string mode in new[]{"complete","cancel","error","complete"}){
   var gate=new ManualResetEventSlim(false);
   Put(f,"scanRunner",(Func<ScanOptions,Action<Finding>,CancellationToken,AuditReport>)((o,cb,token)=>{gate.Wait();if(mode=="error")throw new IOException("synthetic scan failure");if(mode=="cancel"){token.WaitHandle.WaitOne(5000);return Synthetic(o,false);}return Synthetic(o,true);}));
   Start(f);Check(Get<bool>(f,"running")&&!Get<Button>(f,"admin").Enabled&&!Get<Button>(f,"export").Enabled&&!Get<Button>(f,"saveBaseline").Enabled&&Get<Button>(f,"stop").Enabled,"running state disables unsafe actions: "+mode);
   if(mode=="cancel")Get<Button>(f,"stop").PerformClick();gate.Set();Pump(()=>!Get<bool>(f,"running"),15);Ready(f,mode!="error",mode=="complete",admin);gate.Dispose();
  }
  Check(errors==1,"exception path was actually executed");
  Put(f,"elevated",true);Put(f,"scanRunner",(Func<ScanOptions,Action<Finding>,CancellationToken,AuditReport>)((o,cb,t)=>Synthetic(o,true)));Start(f);Pump(()=>!Get<bool>(f,"running"),15);Ready(f,true,true,false);f.Close();
 }}
 static void Demo(){using(var f=new MainForm(true)){Show(f);var grid=Get<DataGridView>(f,"grid");Check(grid.Rows.Count==69,"demo contains 69 stable rows");var filter=Get<ComboBox>(f,"states");filter.SelectedItem="发现线索";Check(grid.Rows.Count==6,"state filter");filter.SelectedIndex=0;var cats=Get<ListBox>(f,"categories");cats.SelectedItem="网络出口";Check(grid.Rows.Count==11,"category filter");cats.SelectedIndex=0;var search=Get<TextBox>(f,"search");search.Text="浏览器指纹";Check(grid.Rows.Count==1&&((int)grid.Rows[0].Tag)==58,"search filter");grid.CurrentCell=grid.Rows[0].Cells[2];Check(Get<TextBox>(f,"evidence").Text.Contains("解释边界"),"selected row details");search.Clear();Ready(f,false,false,false);Check(Get<Label>(f,"summary").Height<=Get<Label>(f,"summary").Parent.ClientSize.Height,"summary label fits toolbar without clipping");Capture(f,"demo-main");f.Size=f.MinimumSize;Application.DoEvents();Capture(f,"demo-minimum");Check(Get<Button>(f,"start").Visible&&grid.Height>100,"minimum window layout");f.Close();}
  var options=new ScanOptions();using(var a=new AdvancedForm(options)){Show(a);Get<CheckBox>(a,"browser").Checked=true;Capture(a,"advanced");Walk(a).OfType<Button>().Single(b=>b.Text=="取消").PerformClick();a.Close();}Check(!options.BrowserContent,"advanced cancel leaves options unchanged");
  using(var a=new AdvancedForm(options)){Show(a);Get<CheckBox>(a,"browser").Checked=true;Get<NumericUpDown>(a,"monitor").Value=30;Walk(a).OfType<Button>().Single(b=>b.Text=="应用范围").PerformClick();a.Close();}Check(options.BrowserContent&&options.MonitorSeconds==30,"advanced apply saves options");
 }
 static void Live(){using(var f=new MainForm(false)){Show(f);bool admin=Get<Button>(f,"admin").Enabled;Check(!Get<CheckBox>(f,"online").Checked&&!Get<CheckBox>(f,"wifi").Checked&&Get<CheckBox>(f,"history").Checked,"actual default scan is offline with history");Start(f);Pump(()=>!Get<bool>(f,"running"),240);var report=Get<AuditReport>(f,"report");Check(report!=null&&report.Completed&&report.Findings.Count==69,"actual native offline scan completes");Ready(f,true,true,admin);Exporter.SaveJson(Path.Combine(output,"offline-detailed.private.json"),report,true);Exporter.SaveJson(Path.Combine(output,"offline-summary.json"),report,false);Exporter.SaveHtml(Path.Combine(output,"offline-summary.html"),report,false);File.WriteAllText(Path.Combine(output,"baseline.private.json"),new System.Web.Script.Serialization.JavaScriptSerializer().Serialize(report.Snapshot));Check(Baseline.Load(Path.Combine(output,"baseline.private.json")).Hashes.Count==report.Snapshot.Hashes.Count,"actual baseline save/load");foreach(var group in report.Findings.GroupBy(x=>x.State))Console.WriteLine("STATE "+group.Key+" "+group.Count());foreach(var failed in report.Findings.Where(x=>x.State=="读取失败"))Console.WriteLine("FAILED CHECK "+failed.Id+" "+failed.Title);Capture(f,"offline-main.private");Start(f);Get<Button>(f,"stop").PerformClick();Pump(()=>!Get<bool>(f,"running"),30);Check(!Get<AuditReport>(f,"report").Completed,"actual rescan cancellation");Ready(f,true,false,admin);f.Close();}}
 [STAThread]static int Main(string[] args){int result=0;output=Path.GetFullPath(args.Length==0?"work\\gui":args[0]);Directory.CreateDirectory(output);SetProcessDPIAware();Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);using(var driver=new Form{ShowInTaskbar=false,StartPosition=FormStartPosition.Manual,Location=new Point(-30000,-30000)}){driver.Shown+=(s,e)=>driver.BeginInvoke((Action)(()=>{try{if(args.Contains("--live"))Live();else{Demo();Lifecycle();}Console.WriteLine("GUI CHECKS PASSED: "+count);}catch(Exception ex){Console.Error.WriteLine(ex);result=1;}finally{driver.Close();}}));Application.Run(driver);}return result;}
}
