using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace LocalLens {
  internal static class Program {
    [DllImport("user32.dll")] private static extern bool SetProcessDPIAware();
    [STAThread] private static void Main(string[] args) {
      if(Environment.OSVersion.Platform!=PlatformID.Win32NT && !args.Contains("--demo")){Console.WriteLine("ScrewClaude is a Windows desktop application.");return;}
      try {if(Environment.OSVersion.Platform==PlatformID.Win32NT)SetProcessDPIAware();}catch{}
      Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);
      Application.ThreadException+=(s,e)=>MessageBox.Show("界面发生错误："+e.Exception.Message,"ScrewClaude",MessageBoxButtons.OK,MessageBoxIcon.Error);
      Application.Run(new MainForm(args.Contains("--demo")));
    }
  }
  public sealed class MainForm:Form {
    readonly Color ink=Color.FromArgb(27,44,65), muted=Color.FromArgb(91,108,130), accent=Color.FromArgb(38,92,210), bg=Color.FromArgb(242,246,251);
    List<Finding> findings=Catalog.Load(); AuditReport report; CancellationTokenSource cancellation; bool running=false;
    ScanOptions advancedOptions=new ScanOptions(); Button advanced,saveBaseline;
    readonly bool demo; bool elevated; DataGridView grid; ListBox categories; ComboBox states; TextBox search,evidence,photoPath;
    internal Func<ScanOptions,Action<Finding>,CancellationToken,AuditReport> scanRunner=(o,callback,token)=>new AuditEngine(o,callback,token).Scan();
    internal Action<Exception> scanError;
    Label summary,status,detailTitle; CheckBox online,wifi,history,detailed; Button start,stop,export,browse,admin;
    ProgressBar progress;
    public MainForm(bool demoMode) {
      demo=demoMode; Text="ScrewClaude 2.12.1 · Windows 环境自查"; Size=new Size(1240,850);MinimumSize=new Size(1040,720);StartPosition=FormStartPosition.CenterScreen;
      scanError=ex=>MessageBox.Show(this,ex.Message,"扫描错误",MessageBoxButtons.OK,MessageBoxIcon.Warning);
      AutoScaleMode=AutoScaleMode.Font;Font=new Font("Microsoft YaHei UI",9F);BackColor=bg;ForeColor=ink;
      try{Icon=new Icon(Assembly.GetExecutingAssembly().GetManifestResourceStream("app.ico"));}catch{}
      Build(); RefreshRows();
      FormClosing+=(s,e)=>{if(running){cancellation.Cancel();e.Cancel=true;status.Text="正在停止查询，请稍后关闭窗口。";}};
      if(demo)Shown+=(s,e)=>LoadDemo();
    }
    Button Button(string text,int width,EventHandler action,bool primary=false) {
      var b=new Button {Text=text,Width=width,Height=36,FlatStyle=FlatStyle.Flat,BackColor=primary?accent:Color.White,ForeColor=primary?Color.White:ink,Cursor=Cursors.Hand,Margin=new Padding(0,0,8,0)};
      b.FlatAppearance.BorderColor=primary?accent:Color.FromArgb(211,222,235);b.Click+=action;return b;
    }
    Label Label(string text,float size,Color color,bool bold=false) {return new Label {Text=text,AutoSize=false,Dock=DockStyle.Fill,ForeColor=color,Font=new Font("Microsoft YaHei UI",size,bold?FontStyle.Bold:FontStyle.Regular),TextAlign=ContentAlignment.MiddleLeft};}
    void Build() {
      var layout=new TableLayoutPanel {Dock=DockStyle.Fill,ColumnCount=1,RowCount=5,Padding=new Padding(22)};
      layout.RowStyles.Add(new RowStyle(SizeType.Absolute,93));layout.RowStyles.Add(new RowStyle(SizeType.Absolute,101));layout.RowStyles.Add(new RowStyle(SizeType.Absolute,42));layout.RowStyles.Add(new RowStyle(SizeType.Percent,100));layout.RowStyles.Add(new RowStyle(SizeType.Absolute,65));Controls.Add(layout);
      var header=new TableLayoutPanel {Dock=DockStyle.Fill,ColumnCount=2,RowCount=2,Margin=Padding.Empty};header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));header.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,220));header.RowStyles.Add(new RowStyle(SizeType.Absolute,48));header.RowStyles.Add(new RowStyle(SizeType.Percent,100));
      header.Controls.Add(Label("ScrewClaude 2.12.1 /  本地环境自查",23,ink,true),0,0);header.Controls.Add(Label("逐项查看可见线索，明确检测范围。发现关联 ≠ 确定位置。",10,muted),0,1);
      try{elevated=new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);}catch{}
      var mode=Label(demo?"演示数据 · 非真实检测":elevated?"管理员模式 · 只读":"普通用户模式 · 只读",10,accent,true);mode.TextAlign=ContentAlignment.MiddleRight;header.Controls.Add(mode,1,0);
      admin=Button("以管理员身份重新打开",210,Elevate);admin.Enabled=!elevated&&!demo;admin.Anchor=AnchorStyles.Right;header.Controls.Add(admin,1,1);layout.Controls.Add(header,0,0);
      var opts=new TableLayoutPanel {Dock=DockStyle.Fill,BackColor=Color.White,Padding=new Padding(13,7,13,7),ColumnCount=1,RowCount=2,Margin=new Padding(0,3,0,9)};opts.RowStyles.Add(new RowStyle(SizeType.Absolute,33));opts.RowStyles.Add(new RowStyle(SizeType.Percent,100));
      var checks=new FlowLayoutPanel {Dock=DockStyle.Fill,WrapContents=false};online=new CheckBox {Text="允许联网查询 IP",AutoSize=true,Margin=new Padding(0,5,22,0)};wifi=new CheckBox {Text="无线 / 蜂窝列表",AutoSize=true,Margin=new Padding(0,5,22,0)};history=new CheckBox {Text="历史痕迹（有限范围）",Checked=true,AutoSize=true,Margin=new Padding(0,5,22,0)};
      checks.Controls.AddRange(new Control[]{online,wifi,history});
      advanced=Button("高级范围 / 导入",150,(s,e)=>{if(running)return;using(var d=new AdvancedForm(advancedOptions))d.ShowDialog(this);});advanced.Height=28;checks.Controls.Add(advanced);
      saveBaseline=Button("保存基线",100,SaveBaseline);saveBaseline.Height=28;saveBaseline.Enabled=false;checks.Controls.Add(saveBaseline);var tip=new ToolTip {AutoPopDelay=25000};tip.SetToolTip(online,"仅当勾选并开始检查时访问 api.ipify.org、api6.ipify.org、ipwho.is。第三方将看到请求出口 IP；归属地查询包含查询 IP。不发送文件或扫描结果。不强制直连，不修改代理。");tip.SetToolTip(wifi,"调用系统无线列表接口，可能需要 Windows 定位权限；程序不自动修改权限，不查询 BSSID 地理库。");opts.Controls.Add(checks,0,0);
      var folder=new TableLayoutPanel {Dock=DockStyle.Fill,ColumnCount=4,Margin=Padding.Empty};folder.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,115));folder.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));folder.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,115));folder.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,65));folder.Controls.Add(Label("照片 GPS（可选）",9,muted),0,0);
      photoPath=new TextBox {ReadOnly=true,Dock=DockStyle.Fill,BackColor=bg,Margin=new Padding(0,6,8,0)};folder.Controls.Add(photoPath,1,0);browse=Button("选择照片目录",110,ChooseFolder);browse.Height=29;folder.Controls.Add(browse,2,0);var clear=Button("清空",60,(s,e)=>{if(!running)photoPath.Text="";});clear.Height=29;folder.Controls.Add(clear,3,0);opts.Controls.Add(folder,0,1);layout.Controls.Add(opts,0,1);
      var toolbar=new TableLayoutPanel {Dock=DockStyle.Fill,ColumnCount=2,RowCount=1,Margin=Padding.Empty};toolbar.RowStyles.Add(new RowStyle(SizeType.Percent,100));toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,490));summary=Label("69 项覆盖说明 · 尚未扫描",10,muted,true);toolbar.Controls.Add(summary,0,0);
      var filters=new FlowLayoutPanel {Dock=DockStyle.Fill,FlowDirection=FlowDirection.RightToLeft,WrapContents=false};search=new TextBox {Width=260,Margin=new Padding(8,5,0,0)};search.TextChanged+=(s,e)=>RefreshRows();states=new ComboBox {DropDownStyle=ComboBoxStyle.DropDownList,Width=170,Margin=new Padding(0,4,0,0)};states.Items.AddRange(new object[]{"全部状态","是线索","读取失败","未检测","不是线索","未执行判定","需外部记录","检测未完成","缺少依赖"});states.SelectedIndex=0;states.SelectedIndexChanged+=(s,e)=>RefreshRows();filters.Controls.Add(search);filters.Controls.Add(states);tip.SetToolTip(search,"按检查项名称、摘要或类别筛选");toolbar.Controls.Add(filters,1,0);layout.Controls.Add(toolbar,0,2);
      var main=new TableLayoutPanel {Dock=DockStyle.Fill,ColumnCount=2,Margin=Padding.Empty};main.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,168));main.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));categories=new ListBox {Dock=DockStyle.Fill,BorderStyle=BorderStyle.None,BackColor=bg,Font=new Font("Microsoft YaHei UI",10),ItemHeight=34,IntegralHeight=false,Margin=new Padding(0,8,12,0)};categories.Items.Add("全部检查");foreach(var c in findings.Select(f=>f.Category).Distinct())categories.Items.Add(c);categories.SelectedIndex=0;categories.SelectedIndexChanged+=(s,e)=>RefreshRows();main.Controls.Add(categories,0,0);
      var right=new SplitContainer {Dock=DockStyle.Fill,Orientation=Orientation.Horizontal,BackColor=bg,SplitterWidth=8,Margin=Padding.Empty};right.Size=new Size(950,500);right.SplitterDistance=280;right.Panel1MinSize=100;right.Panel2MinSize=145;
      grid=new DataGridView {Dock=DockStyle.Fill,BackgroundColor=Color.White,BorderStyle=BorderStyle.None,ReadOnly=true,AllowUserToAddRows=false,AllowUserToDeleteRows=false,AllowUserToResizeRows=false,RowHeadersVisible=false,SelectionMode=DataGridViewSelectionMode.FullRowSelect,MultiSelect=false,AutoGenerateColumns=false,EnableHeadersVisualStyles=false,CellBorderStyle=DataGridViewCellBorderStyle.SingleHorizontal,GridColor=bg};grid.ColumnHeadersDefaultCellStyle.BackColor=Color.FromArgb(229,237,247);grid.ColumnHeadersDefaultCellStyle.ForeColor=muted;grid.ColumnHeadersDefaultCellStyle.Font=new Font(Font,FontStyle.Bold);grid.ColumnHeadersHeight=36;grid.RowTemplate.Height=36;grid.DefaultCellStyle.SelectionBackColor=Color.FromArgb(224,235,255);grid.DefaultCellStyle.SelectionForeColor=ink;grid.DefaultCellStyle.Padding=new Padding(4,0,3,0);grid.DefaultCellStyle.Font=new Font("Microsoft YaHei UI",9);
      grid.Columns.Add(new DataGridViewTextBoxColumn {Name="id",HeaderText="#",Width=42});grid.Columns.Add(new DataGridViewTextBoxColumn {Name="state",HeaderText="状态",Width=87});grid.Columns.Add(new DataGridViewTextBoxColumn {Name="title",HeaderText="检查项",Width=210});grid.Columns.Add(new DataGridViewTextBoxColumn {Name="summary",HeaderText="本次结果",AutoSizeMode=DataGridViewAutoSizeColumnMode.Fill,MinimumWidth=180});grid.Columns.Add(new DataGridViewTextBoxColumn {Name="coverage",HeaderText="覆盖",Width=115});grid.SelectionChanged+=(s,e)=>ShowFinding();right.Panel1.Controls.Add(grid);
      var details=new TableLayoutPanel {Dock=DockStyle.Fill,ColumnCount=1,RowCount=2,BackColor=Color.White,Padding=new Padding(12,4,12,8)};details.RowStyles.Add(new RowStyle(SizeType.Absolute,31));details.RowStyles.Add(new RowStyle(SizeType.Percent,100));detailTitle=Label("选择一项查看证据与解释",10,accent,true);details.Controls.Add(detailTitle,0,0);evidence=new TextBox {Dock=DockStyle.Fill,Multiline=true,ReadOnly=true,ScrollBars=ScrollBars.Vertical,BorderStyle=BorderStyle.None,BackColor=Color.White,ForeColor=ink,Font=new Font("Microsoft YaHei UI",9),WordWrap=true};details.Controls.Add(evidence,0,1);right.Panel2.Controls.Add(details);main.Controls.Add(right,1,0);layout.Controls.Add(main,0,3);
      var footer=new TableLayoutPanel {Dock=DockStyle.Fill,ColumnCount=2,RowCount=2,Margin=new Padding(0,10,0,0)};footer.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));footer.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,660));footer.RowStyles.Add(new RowStyle(SizeType.Absolute,36));footer.RowStyles.Add(new RowStyle(SizeType.Percent,100));status=Label("就绪 · 默认离线，不修改系统设置",9,muted);footer.Controls.Add(status,0,0);
      var actions=new FlowLayoutPanel {Dock=DockStyle.Fill,FlowDirection=FlowDirection.RightToLeft,WrapContents=false};start=Button("开始检查",108,StartScan,true);stop=Button("取消",63,(s,e)=>{if(cancellation!=null){cancellation.Cancel();status.Text="正在停止（外部查询可能需要数秒）…";}});stop.Enabled=false;export=Button("导出报告",96,SaveReport);export.Enabled=false;var browser=Button("浏览器检查",105,OpenBrowser);detailed=new CheckBox {Text="导出详细证据",AutoSize=true,Margin=new Padding(0,9,10,0)};actions.Controls.AddRange(new Control[]{start,stop,export,browser,detailed});footer.Controls.Add(actions,1,0);progress=new ProgressBar {Dock=DockStyle.Fill,Height=5,Style=ProgressBarStyle.Blocks,Margin=new Padding(0,9,0,0)};footer.Controls.Add(progress,0,1);footer.SetColumnSpan(progress,2);layout.Controls.Add(footer,0,4);
    }
    void ChooseFolder(object s,EventArgs e){using(var dialog=new FolderBrowserDialog {Description="仅检查此目录及子目录内 JPEG / TIFF 的 GPS 元数据（最多 500 张），不上传照片",ShowNewFolderButton=false})if(dialog.ShowDialog(this)==DialogResult.OK)photoPath.Text=dialog.SelectedPath;}
    void Elevate(object s,EventArgs e){if(running)return;try{System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(Application.ExecutablePath) {UseShellExecute=true,Verb="runas"});Close();}catch(Exception ex){MessageBox.Show(this,"未重新启动："+ex.Message,"ScrewClaude");}}
    async void StartScan(object sender,EventArgs e){
      if(running)return;if(demo){LoadDemo();return;}
      running=true;report=null;export.Enabled=false;start.Enabled=false;stop.Enabled=true;browse.Enabled=false;admin.Enabled=false;online.Enabled=wifi.Enabled=history.Enabled=false;
      cancellation=new CancellationTokenSource();findings=Catalog.Load();RefreshRows();progress.Style=ProgressBarStyle.Marquee;progress.MarqueeAnimationSpeed=25;status.Text="正在读取所选范围…";
      advanced.Enabled=false;saveBaseline.Enabled=false;
      try {
        var options=new System.Web.Script.Serialization.JavaScriptSerializer().Deserialize<ScanOptions>(new System.Web.Script.Serialization.JavaScriptSerializer().Serialize(advancedOptions));
        options.Online=online.Checked;options.Wifi=wifi.Checked;options.History=history.Checked;options.PhotoFolder=photoPath.Text;
        report=await Task.Run(()=>scanRunner(options,f=>{
          if(IsDisposed||!IsHandleCreated)return;
          BeginInvoke((Action)(()=>{findings[f.Id-1]=f;RefreshRows();if(f.State!="未检测")status.Text="正在检查："+f.Title;}));
        },cancellation.Token));
        findings=report.Findings;RefreshRows();status.Text=report.Completed?"扫描完成 · 报告只反映本次可读范围":"扫描已取消 · 未完成项目不能视为通过";export.Enabled=true;
      }catch(Exception ex){status.Text="扫描未完成："+ex.Message;scanError(ex);}
      finally{advanced.Enabled=true;saveBaseline.Enabled=report!=null&&report.Completed;running=false;start.Enabled=true;stop.Enabled=false;browse.Enabled=true;admin.Enabled=!elevated&&!demo;online.Enabled=wifi.Enabled=history.Enabled=true;progress.Style=ProgressBarStyle.Blocks;progress.Value=0;cancellation.Dispose();cancellation=null;}
    }
    void RefreshRows(){if(grid==null||categories==null||states==null)return;int selected=grid.SelectedRows.Count>0?(int)grid.SelectedRows[0].Tag:-1;string category=Convert.ToString(categories.SelectedItem),state=Convert.ToString(states.SelectedItem),q=search.Text.Trim();grid.SuspendLayout();grid.Rows.Clear();foreach(var f in findings){if(category!="全部检查"&&f.Category!=category)continue;if(state!="全部状态"&&Rules.ResultLabel(f.State)!=state)continue;if(q.Length>0&&(f.Title+f.Summary+f.Category).IndexOf(q,StringComparison.OrdinalIgnoreCase)<0)continue;int i=grid.Rows.Add(f.Id.ToString("00"),Rules.ResultLabel(f.State),f.Title,f.Summary,f.Coverage);var row=grid.Rows[i];row.Tag=f.Id;if(f.State=="发现线索")row.Cells[1].Style.ForeColor=Color.FromArgb(158,92,10);else if(f.State=="读取失败")row.Cells[1].Style.ForeColor=Color.FromArgb(188,51,60);else if(f.State=="未检测")row.Cells[1].Style.ForeColor=muted;if(f.Id==selected)row.Selected=true;}grid.ResumeLayout();if(selected>0)foreach(DataGridViewRow row in grid.Rows)if((int)row.Tag==selected){grid.CurrentCell=row.Cells[2];break;}summary.Text=String.Format("{0} 项线索  ·  {1} 项读取失败  ·  {2} 项未检测",findings.Count(f=>f.State=="发现线索"),findings.Count(f=>f.State=="读取失败"),findings.Count(f=>f.State=="未检测"));ShowFinding();}
    void ShowFinding(){if(grid==null||evidence==null||grid.SelectedRows.Count==0){return;}var tag=grid.SelectedRows[0].Tag;if(tag==null)return;var f=findings[(int)tag-1];detailTitle.Text=f.Id.ToString("00")+"  "+f.Title+"  /  "+f.Strength;evidence.Text="【判定规则】\r\n"+f.DecisionRule+"\r\n【采样范围】\r\n"+f.Limit+"\r\n\r\n【结果】"+Rules.ResultLabel(f.State)+" · "+f.Coverage+"\r\n"+f.Summary+"\r\n\r\n【本地证据】\r\n"+f.Evidence;}
    void SaveReport(object s,EventArgs e){if(report==null)return;using(var dialog=new SaveFileDialog {Title="保存本次自查报告",FileName="ScrewClaude-"+DateTime.Now.ToString("yyyyMMdd-HHmm")+".html",Filter="可阅读报告 (*.html)|*.html|结构化报告 (*.json)|*.json",AddExtension=true})if(dialog.ShowDialog(this)==DialogResult.OK){try{if(dialog.FilterIndex==2)Exporter.SaveJson(dialog.FileName,report,detailed.Checked);else Exporter.SaveHtml(dialog.FileName,report,detailed.Checked);status.Text="已保存"+(detailed.Checked?"详细报告（包含证据中的本地标识）":"摘要报告（省略原始证据）");}catch(Exception ex){MessageBox.Show(this,"保存失败："+ex.Message,"ScrewClaude");}}}
    void SaveBaseline(object s,EventArgs e){if(report==null||report.Snapshot==null)return;using(var d=new SaveFileDialog{Filter="基线 JSON|*.json",FileName="ScrewClaude-baseline-"+DateTime.Now.ToString("yyyyMMdd-HHmm")+".json"})if(d.ShowDialog(this)==DialogResult.OK)try{File.WriteAllText(d.FileName,new System.Web.Script.Serialization.JavaScriptSerializer().Serialize(report.Snapshot),new System.Text.UTF8Encoding(true));status.Text="基线已保存；仅包含选定配置哈希，下次在高级选项导入比较";}catch(Exception ex){MessageBox.Show(this,ex.Message,"保存失败");}}
    void OpenBrowser(object s,EventArgs e){try{string root=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"LocalLens");Directory.CreateDirectory(root);string path=Path.Combine(root,"BrowserCheck.html");using(var input=Assembly.GetExecutingAssembly().GetManifestResourceStream("BrowserCheck.html"))using(var output=File.Create(path))input.CopyTo(output);System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(path) {UseShellExecute=true});}catch(Exception ex){MessageBox.Show(this,"无法打开浏览器检查页："+ex.Message,"ScrewClaude");}}
    void LoadDemo(){findings=Catalog.Load();foreach(var f in findings){f.State="未检测";f.Summary="演示模式：未读取真实设备";f.Coverage="未执行";}foreach(int i in new[]{17,18,20,21,23,28}){var f=findings[i-1];f.State="发现线索";f.Summary="示例：发现地区相关配置，不证明物理位置";f.Evidence="演示数据 / 非真实检测\r\n此面板展示检测范围、原始证据和解释边界。";f.Coverage="演示";}foreach(int i in new[]{4,6,7,11,32,41,64}){findings[i-1].State="未发现";findings[i-1].Summary="演示样本未命中本项规则";findings[i-1].Coverage="演示";}RefreshRows();status.Text="演示模式：所有内容为界面样例";}
  }
}
