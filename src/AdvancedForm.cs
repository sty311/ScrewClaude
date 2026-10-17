using System;
using System.Drawing;
using System.IO;
using System.Windows.Forms;
namespace LocalLens {
 public sealed class AdvancedForm:Form {
  public ScanOptions Options;
  CheckBox browser,probes,location,device,ocr; NumericUpDown monitor;
  TextBox content,browserReport,baseline,external,ocrExe;
  public AdvancedForm(ScanOptions o){Options=o;Text="ScrewClaude 2.12.2 · 高级检查范围";Size=new Size(850,760);MinimumSize=Size;StartPosition=FormStartPosition.CenterParent;Font=new Font("Microsoft YaHei UI",9);BackColor=Color.White;var panel=new TableLayoutPanel{Dock=DockStyle.Fill,Padding=new Padding(20),ColumnCount=1,RowCount=14};Controls.Add(panel);
   panel.Controls.Add(new Label{Text="明确选择读取范围与网络请求",AutoSize=true,Font=new Font(Font,FontStyle.Bold)});
   browser=Check(panel,"浏览器内容：历史 / 下载域名、站点来源、自动填充国家与城市字段",o.BrowserContent);
   probes=Check(panel,"网络路径：UDP STUN、区域耗时、站点可达性、最多 10 跳 tracert（需主界面联网）",o.Probes);
   location=Check(panel,"请求 Windows 系统定位（受系统权限控制，系统可能联系定位服务）",o.RequestLocation);
   device=Check(panel,"生成硬件标识哈希，供历史基线比较（不输出明文序列号）",o.DeviceIdentifiers);
   ocr=Check(panel,"对所选内容目录前 20 张图片进行本地 OCR（需本机 Tesseract / 语言包）",o.Ocr);
   var mp=new FlowLayoutPanel{Dock=DockStyle.Fill,Height=35};mp.Controls.Add(new Label{Text="出口持续采样秒数（0 关闭，最多 300；需联网）",AutoSize=true,Margin=new Padding(0,6,10,0)});monitor=new NumericUpDown{Minimum=0,Maximum=300,Increment=15,Value=Math.Min(300,Math.Max(0,o.MonitorSeconds)),Width=80};mp.Controls.Add(monitor);panel.Controls.Add(mp);
   ocrExe=PathRow(panel,"Tesseract 程序",o.OcrExecutable,false,true);
   content=PathRow(panel,"内容目录",o.ContentFolder,true);
   browserReport=PathRow(panel,"浏览器结果 JSON",o.BrowserReportPath,false);
   baseline=PathRow(panel,"历史基线 JSON",o.BaselinePath,false);
   external=PathRow(panel,"外部证据 JSON",o.ExternalEvidencePath,false);
   panel.Controls.Add(new Label{Text="网络路径选项请求：stun.l.google.com:19302（UDP）、ec2.{ap-northeast-1,eu-west-1,us-east-1}.amazonaws.com、www.baidu.com、www.wikipedia.org、www.google.com；tracert 目的为 1.1.1.1。UDP 使用系统路由，可能不同于 HTTP 代理。\n内容目录：最多 500 个文件 / 100 个目录；文本、DOCX、EML、ICS、VCF 与 OCR 图片。各项超时、权限失败和范围限制会列入结果。",Dock=DockStyle.Fill,AutoSize=true,MaximumSize=new Size(780,0),ForeColor=Color.DimGray});
   var buttons=new FlowLayoutPanel{Dock=DockStyle.Fill,FlowDirection=FlowDirection.RightToLeft};var save=new Button{Text="应用范围",AutoSize=true,Height=34};save.Click+=(s,e)=>{Options.BrowserContent=browser.Checked;Options.Probes=probes.Checked;Options.RequestLocation=location.Checked;Options.DeviceIdentifiers=device.Checked;Options.Ocr=ocr.Checked;Options.MonitorSeconds=(int)monitor.Value;Options.OcrExecutable=ocrExe.Text;Options.ContentFolder=content.Text;Options.BrowserReportPath=browserReport.Text;Options.BaselinePath=baseline.Text;Options.ExternalEvidencePath=external.Text;DialogResult=DialogResult.OK;};buttons.Controls.Add(save);buttons.Controls.Add(new Button{Text="取消",DialogResult=DialogResult.Cancel,Height=34});panel.Controls.Add(buttons);AcceptButton=save;
   for(int i=0;i<panel.RowCount;i++)panel.RowStyles.Add(new RowStyle(SizeType.Absolute,i==12?100:i==0?32:i==13?44:38));
  }
  CheckBox Check(TableLayoutPanel p,string label,bool value){var c=new CheckBox{Text=label,Checked=value,AutoSize=true,Dock=DockStyle.Fill};p.Controls.Add(c);return c;}
  TextBox PathRow(TableLayoutPanel parent,string title,string path,bool directory,bool executable=false){var row=new TableLayoutPanel{ColumnCount=4,Dock=DockStyle.Fill};row.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,135));row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));row.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,65));row.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,55));row.Controls.Add(new Label{Text=title,Dock=DockStyle.Fill,TextAlign=ContentAlignment.MiddleLeft});var t=new TextBox{Text=path??"",ReadOnly=true,Dock=DockStyle.Fill};row.Controls.Add(t);var choose=new Button{Text="选择",Dock=DockStyle.Fill};choose.Click+=(s,e)=>{if(directory){using(var d=new FolderBrowserDialog{ShowNewFolderButton=false,Description="选择仅在本机分析的文件目录"})if(d.ShowDialog(this)==DialogResult.OK)t.Text=d.SelectedPath;}else using(var d=new OpenFileDialog{Filter=executable?"Tesseract 程序|tesseract.exe":"JSON 文件|*.json",CheckFileExists=true})if(d.ShowDialog(this)==DialogResult.OK)t.Text=d.FileName;};row.Controls.Add(choose);var clear=new Button{Text="清空",Dock=DockStyle.Fill};clear.Click+=(s,e)=>t.Text="";row.Controls.Add(clear);parent.Controls.Add(row);return t;}
 }
}
