using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;
using System.Xml;
using Microsoft.Win32;

namespace LocalLens {
  public sealed partial class AuditEngine {
    private List<Finding> rows; private ScanOptions options; private Action<Finding> update; private CancellationToken cancel;
    private readonly Dictionary<string,Dictionary<string,object>> geo = new Dictionary<string,Dictionary<string,object>>();
    private readonly Dictionary<string,string> ip = new Dictionary<string,string>();
    private string wifiText="", country="";
    private string Local { get {return Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);} }
    private string Roaming {get {return Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);} }
    private string User {get {return Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);} }
    private string SystemDrive {get {return Path.GetPathRoot(Environment.SystemDirectory);} }
    [DllImport("kernel32.dll")] private static extern uint GetOEMCP();
    public AuditEngine(ScanOptions o, Action<Finding> callback, CancellationToken token) {options=o;update=callback;cancel=token;rows=Catalog.Load();}
    private Finding F(int id) {return rows[id-1];}
    private void Set(int id,string state,string summary,string evidence,string coverage) {
      var f=F(id);f.State=state;f.Summary=summary;f.Evidence=evidence??"";f.Coverage=coverage;f.CheckedAt=DateTime.UtcNow.ToString("o");ChinaEvidence.Apply(f);f.Evidence=Rules.TrimEvidence(f.Evidence);update(f);
    }
    private void Run(int id, Action action) {
      cancel.ThrowIfCancellationRequested();
      try {action();} catch(OperationCanceledException) {throw;} catch(Exception e) {
        cancel.ThrowIfCancellationRequested();
        Set(id,"读取失败","该项未完成，不能视为通过",e.GetType().Name+": "+Rules.StripSecrets(e.Message),"失败");
      }
    }
    private void Info(int id,string text,string summary="缺少有效样本") {Set(id,"信息",summary,text,"本机读取结果 / 逐项中国关联审查");}
    private void Mark(int id,string text,bool found,string yes,string no,string coverage="已检查所列范围") {
      Set(id,found?"发现线索":"未发现",found?yes:no,text,coverage);
    }
    private void Skip(int id,string reason) {Set(id,"未检测",reason,"没有对此项给出通过结论。","未执行");}
    private string Reg(RegistryKey root,string key,string name) {
      using(var k=root.OpenSubKey(key,false)) {if(k==null)return "[键不存在]";object v=k.GetValue(name,null,RegistryValueOptions.DoNotExpandEnvironmentNames);if(v==null)return "[值不存在]";var a=v as string[];return a!=null?String.Join(", ",a):Convert.ToString(v,CultureInfo.InvariantCulture);}
    }
    private string RegValues(RegistryKey root,string key,params string[] names) {return String.Join("\r\n",names.Select(n=>n+" = "+Reg(root,key,n)));}
    private string Command(string exe,string arguments,bool utf8=false,int timeout=12000) {
      cancel.ThrowIfCancellationRequested();
      var b=new StringBuilder(); var err=new StringBuilder();
      var si=new ProcessStartInfo(exe,arguments) {UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
      si.StandardOutputEncoding=utf8?new UTF8Encoding(false):Encoding.GetEncoding((int)GetOEMCP());si.StandardErrorEncoding=si.StandardOutputEncoding;
      using(var p=new Process {StartInfo=si}) {
        p.OutputDataReceived+=(s,e)=>{if(e.Data!=null)lock(b){if(b.Length<64000)b.AppendLine(e.Data);else if(b.Length<64100)b.AppendLine("[输出达到上限，后续省略]");}};
        p.ErrorDataReceived+=(s,e)=>{if(e.Data!=null)lock(err){if(err.Length<4000)err.AppendLine(e.Data);}};
        p.Start();p.BeginOutputReadLine();p.BeginErrorReadLine();var watch=Stopwatch.StartNew();
        while(!p.WaitForExit(100)) {if(cancel.IsCancellationRequested||watch.ElapsedMilliseconds>timeout){try{p.Kill();}catch{}cancel.ThrowIfCancellationRequested();throw new TimeoutException("系统查询超过 "+timeout/1000+" 秒，已停止该查询。");}}
        p.WaitForExit(); if(p.ExitCode!=0)throw new IOException("系统查询退出码 "+p.ExitCode+"\r\n"+err+"\r\n"+b);
        return b.ToString();
      }
    }
    private string PS(string body,int timeout=12000) {
      string script="$ErrorActionPreference='Stop';[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false);"+body;
      string exe=Path.Combine(Environment.SystemDirectory,@"WindowsPowerShell\v1.0\powershell.exe");
      return Command(exe,"-NoLogo -NoProfile -NonInteractive -EncodedCommand "+Convert.ToBase64String(Encoding.Unicode.GetBytes(script)),true,timeout);
    }
    private string JsonGet(string url) {
      cancel.ThrowIfCancellationRequested(); ServicePointManager.SecurityProtocol|=SecurityProtocolType.Tls12;
      var req=(HttpWebRequest)WebRequest.Create(url); req.Timeout=8000;req.ReadWriteTimeout=8000;req.UserAgent="ScrewClaude/2.11.0 (user-initiated-environment-check)";req.AllowAutoRedirect=false;
      // Preserve .NET's system-proxy routing. Never force a direct connection.
      using(cancel.Register(()=>req.Abort()))
      using(var response=(HttpWebResponse)req.GetResponse())
      using(var reader=new StreamReader(response.GetResponseStream(),Encoding.UTF8)) {
        var b=new StringBuilder();var buffer=new char[4096];int n;
        while((n=reader.Read(buffer,0,buffer.Length))>0){b.Append(buffer,0,n);if(b.Length>131072)throw new IOException("接口响应过大");}
        return b.ToString();
      }
    }
    private Dictionary<string,object> Obj(string json) {return new JavaScriptSerializer {MaxJsonLength=16*1024*1024}.Deserialize<Dictionary<string,object>>(json);}
    private static string Value(Dictionary<string,object> d,string key) {return d!=null&&d.ContainsKey(key)?Convert.ToString(d[key],CultureInfo.InvariantCulture):"";}
    private void PublicIp(int id,string key,string endpoint) {
      var d=Obj(JsonGet(endpoint));IPAddress addr;
      if(!IPAddress.TryParse(Value(d,"ip"),out addr))throw new IOException("IP 服务未返回有效地址");
      if(key=="v6"&&addr.AddressFamily!=AddressFamily.InterNetworkV6)throw new IOException("IPv6 端点返回 IPv4，IPv6 检测未完成");
      ip[key]=addr.ToString();
      var g=Obj(JsonGet("https://ipwho.is/"+Uri.EscapeDataString(addr.ToString())));
      if(Value(g,"success").Equals("False",StringComparison.OrdinalIgnoreCase)||String.IsNullOrEmpty(Value(g,"country_code")))throw new IOException("已取得 IP，但归属地查询失败。IP = "+addr+"\r\n"+Value(g,"message"));
      geo[key]=g;string cc=Value(g,"country_code").ToUpperInvariant();
      string note=key=="v6"&&addr.AddressFamily!=AddressFamily.InterNetworkV6?"\r\n注意：该端点返回 IPv4，不能据此声称本机 IPv6 已通过检查。":"";
      Mark(id,"请求端点："+endpoint+"\r\n路径：.NET 系统代理设置\r\nIP："+addr+"\r\n国家："+cc+" / "+Value(g,"country")+"\r\n地区："+Value(g,"region")+" / "+Value(g,"city")+note,cc=="CN","该请求的出口被数据库标记为中国大陆","该请求的出口未被数据库标记为中国大陆","单路径 / 单一地理数据库");
    }
    private string[] BrowserRoots() {return new[]{Path.Combine(Local,@"Google\Chrome\User Data\Default"),Path.Combine(Local,@"Microsoft\Edge\User Data\Default")};}
    private string Existing(params string[] paths) {return String.Join("\r\n",paths.Select(p=>p+" → "+(File.Exists(p)||Directory.Exists(p)?"存在":"未在此路径发现（未验证权限）")));}
    private bool IsLocale(string s) {return Rules.MainlandLocale(s);}
    public AuditReport Scan() {
      bool complete=false;
      try {
        foreach(var f in rows)Skip(f.Id,"尚未执行或未满足所需条件");
        if(options.Online) {
          Run(1,()=>PublicIp(1,"v4","https://api.ipify.org?format=json"));
          Run(2,()=>PublicIp(2,"v6","https://api6.ipify.org?format=json"));
          Run(3,()=>{if(geo.Count<2){Skip(3,"出口样本不足，无法比较");return;}string a=Value(geo["v4"],"country_code"),b=Value(geo["v6"],"country_code");Mark(3,"HTTPS IPv4 端点国家："+a+"\r\nHTTPS IPv6 端点国家："+b+"\r\n未检查 UDP、递归 DNS 或浏览器请求。",a!=b,"两个查询结果的出口国家不同","本次两个 HTTPS 结果的国家一致","仅比较两次 HTTPS 查询");});
          Run(5,()=>{if(geo.Count==0){Skip(5,"没有可用归属地结果");return;}Mark(5,String.Join("\r\n\r\n",geo.Select(k=>k.Key+"\r\n国家："+Value(k.Value,"country_code")+"\r\n"+new JavaScriptSerializer().Serialize(k.Value.ContainsKey("connection")?k.Value["connection"]:null))),geo.Values.Any(g=>Value(g,"country_code")=="CN"),"运营商资料对应的出口国家为 CN","运营商资料对应的出口国家未命中 CN 规则","本次查询的出口运营商与国家字段");});
        } else {foreach(int id in new[]{1,2,3,5})Skip(id,"联网检测未启用");}
        Run(4,()=>{var lines=new List<string>();foreach(var n in NetworkInterface.GetAllNetworkInterfaces()) {cancel.ThrowIfCancellationRequested();try{var p=n.GetIPProperties();lines.Add(n.Name+" | "+n.NetworkInterfaceType+" | "+n.OperationalStatus+"\r\n"+n.Description+"\r\n地址："+String.Join(", ",p.UnicastAddresses.Select(x=>x.Address.ToString()))+"\r\n网关："+String.Join(", ",p.GatewayAddresses.Select(x=>x.Address.ToString())));}catch(Exception e){lines.Add(n.Name+"：读取受限 "+e.Message);}}Info(4,String.Join("\r\n\r\n",lines));});
        Run(6,()=>{var lines=new List<string>();var addresses=new List<string>();foreach(var n in NetworkInterface.GetAllNetworkInterfaces()){if(n.OperationalStatus!=OperationalStatus.Up)continue;foreach(var d in n.GetIPProperties().DnsAddresses){addresses.Add(d.ToString());lines.Add(n.Name+" → "+d);}}var result=DnsConfigurationAssessment.Evaluate(addresses,String.Join("\r\n",lines));Set(6,result.State,result.Summary,result.Evidence,result.Coverage);});
        Run(7,()=>Info(7,Command(Path.Combine(Environment.SystemDirectory,"route.exe"),"print"),"已读取当前路由表，未运行跨境路径探测"));
        Run(11,()=>Info(11,RegValues(Registry.CurrentUser,@"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location","Value")+"\r\n设备级：\r\n"+RegValues(Registry.LocalMachine,@"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location","Value"),"已读取定位权限配置；未请求位置"));
        if(options.Wifi) {
          Run(13,()=>{wifiText=Command(Path.Combine(Environment.SystemDirectory,"netsh.exe"),"wlan show networks mode=bssid");if(Regex.IsMatch(wifiText,@"(?i)(access is denied|access denied|拒绝访问|location permission|位置权限)"))throw new UnauthorizedAccessException(wifiText);Info(13,wifiText,"已查询无线列表；未查询 BSSID 地理库");});
          Run(14,()=>{if(F(13).State=="读取失败"){Skip(14,"无线列表读取失败");return;}var names=Regex.Matches(wifiText,@"(?m)^\s*SSID\s+\d+\s*:\s*(.+)$").Cast<Match>().Select(m=>m.Groups[1].Value.Trim()).ToArray();if(names.Length==0){Skip(14,"未取得可分析的 SSID，无线设备或格式条件未满足");return;}Mark(14,String.Join("\r\n",names),names.Any(Rules.HasHan),"附近 SSID 中有中文名称","已返回的 SSID 未见中文名称");});
          Run(15,()=>Info(15,Command(Path.Combine(Environment.SystemDirectory,"netsh.exe"),"mbn show interfaces"),"仅查看移动宽带接口信息"));
        } else {foreach(int id in new[]{13,14,15})Skip(id,"无线 / 蜂窝检查未启用");}
        Run(17,()=>{string name=Reg(Registry.CurrentUser,@"Control Panel\International\Geo","Name"),nation=Reg(Registry.CurrentUser,@"Control Panel\International\Geo","Nation");country=name;if(name=="[键不存在]"||name=="[值不存在]"){if(nation=="[键不存在]"||nation=="[值不存在]"){Skip(17,"两个地区字段均未找到");return;}}Mark(17,"Name = "+name+"\r\nNation = "+nation,name=="CN"||nation=="45","国家 / 地区设置为中国","当前可读国家设置未标记为中国");});
        Run(18,()=>{string s="UI Culture = "+CultureInfo.CurrentUICulture.Name+"\r\n"+RegValues(Registry.LocalMachine,@"SYSTEM\CurrentControlSet\Control\Nls\Language","InstallLanguage","Default")+"\r\n"+RegValues(Registry.CurrentUser,@"Control Panel\Desktop","PreferredUILanguages");Mark(18,s,IsLocale(s),"显示或安装语言配置存在大陆中文标记","未见所列大陆中文语言标记");});
        Run(19,()=>{string s=PS("Get-WinSystemLocale | Select-Object Name,DisplayName | ConvertTo-Json -Compress");Mark(19,s,IsLocale(s),"系统区域含大陆中文标记","系统区域未见大陆中文标记");});
        Run(20,()=>{string s=RegValues(Registry.CurrentUser,@"Control Panel\International","LocaleName","sLanguage","sCountry","sCurrency","sShortDate","sTimeFormat","sDecimal","iCalendarType");Mark(20,s,IsLocale(s),"区域格式含大陆中文标记","所列区域格式未见大陆中文标记");});
        Run(21,UserLanguages);
        Run(22,()=>{using(var k=Registry.CurrentUser.OpenSubKey(@"Keyboard Layout\Preload",false)){if(k==null){Skip(22,"未找到可读取的首选键盘配置");return;}string s=String.Join("\r\n",k.GetValueNames().Select(n=>n+" = "+Convert.ToString(k.GetValue(n))));Mark(22,s,s.Contains("0804"),"发现简体中文键盘标记","所查键盘配置未发现 0804 标记","仅 Keyboard Layout / Preload");}});
        Run(23,()=>{string s=TimeZoneInfo.Local.Id+"\r\n"+TimeZoneInfo.Local.DisplayName+"\r\nUTC offset = "+TimeZoneInfo.Local.GetUtcOffset(DateTime.Now)+"\r\n自动时区服务 Start = "+Reg(Registry.LocalMachine,@"SYSTEM\CurrentControlSet\Services\tzautoupdate","Start");Mark(23,s,IsLocale(s),"当前使用中国标准时区设置","当前时区不是 China Standard Time");});
        Run(24,()=>{var list=new List<string>();int inaccessible=0;string currentSid;using(var identity=System.Security.Principal.WindowsIdentity.GetCurrent())currentSid=identity.User.Value;foreach(string sid in Registry.Users.GetSubKeyNames()){if(!OtherUserProfile(sid,currentSid))continue;try{using(var k=Registry.Users.OpenSubKey(sid+@"\Control Panel\International",false)){string locale=k==null?"":Convert.ToString(k.GetValue("LocaleName"));if(!String.IsNullOrWhiteSpace(locale))list.Add("其他已加载用户配置 "+(list.Count+1)+" LocaleName="+locale);}}catch{inaccessible++;}}if(list.Count==0){Skip(24,"没有其他已加载且可读的用户区域配置；当前用户及系统服务账户不重复统计");return;}string s=String.Join("\r\n",list);if(inaccessible>0)s+="\r\n不可读取的配置数："+inaccessible;Mark(24,s,IsLocale(s),"其他用户配置有大陆地区标记","其他可读用户配置未见大陆地区标记","仅其他已加载用户；不代表过去时间，不能确定归属于本人；不可读取 "+inaccessible);});
        Run(26,()=>{string s="Office：\r\n"+RegValues(Registry.CurrentUser,@"Software\Microsoft\Office\16.0\Common\LanguageResources","UILanguage","HelpLanguage","InstallLanguage")+"\r\nSteam：\r\n"+RegValues(Registry.CurrentUser,@"Software\Valve\Steam","Language");Info(26,s,"已检查部分常见应用配置");});
        Run(27,()=>{var names=new[]{"LANG","LANGUAGE","LC_ALL","LC_CTYPE","TZ","HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","NO_PROXY"};string s=String.Join("\r\n",names.Select(n=>n+" = "+Rules.StripSecrets(Environment.GetEnvironmentVariable(n)??"[未设置]")));Mark(27,s,IsLocale(s),"选定环境变量含大陆中文 / 时区标记","选定环境变量未见大陆中文 / 时区标记","仅当前进程继承的白名单环境变量");});
        Run(28,()=>{using(var fonts=new System.Drawing.Text.InstalledFontCollection()){var names=fonts.Families.Select(f=>f.Name).Where(s=>Rules.HasHan(s)||Regex.IsMatch(s,@"(?i)(SimSun|SimHei|Microsoft YaHei|DengXian|FangSong|KaiTi)")).ToArray();Mark(28,String.Join("\r\n",names),names.Length>0,"发现中文相关字体","有限字体清单未命中","有限字体名称匹配");}});
        if(options.History) {
          Run(29,()=>{string root=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),@"Microsoft\Wlansvc\Profiles\Interfaces");var list=new List<string>();if(!Directory.Exists(root)){Skip(29,"无线配置目录不存在或不可枚举");return;}foreach(string file in Directory.EnumerateFiles(root,"*.xml",SearchOption.AllDirectories).Take(200)){cancel.ThrowIfCancellationRequested();var settings=new XmlReaderSettings {DtdProcessing=DtdProcessing.Prohibit,XmlResolver=null};using(var reader=XmlReader.Create(file,settings)){var doc=new XmlDocument {XmlResolver=null};doc.Load(reader);var node=doc.SelectSingleNode("//*[local-name()='SSID']/*[local-name()='name']");if(node!=null)list.Add(node.InnerText);}}Mark(29,String.Join("\r\n",list),list.Any(Rules.HasHan),"保存的 SSID 有中文名称","读取到的 SSID 未见中文名称","最多 200 个配置；仅名称");});
          Run(30,()=>{string s=PS("$log=Get-WinEvent -ListLog 'Microsoft-Windows-WLAN-AutoConfig/Operational'; if(-not $log.IsEnabled){throw 'WLAN event log is disabled'}; if($log.RecordCount -eq 0){'[]'} else {@(Get-WinEvent -LogName $log.LogName -MaxEvents 100 | Where-Object {$_.TimeCreated -gt (Get-Date).AddDays(-7)} | ForEach-Object {$eventXml=[xml]$_.ToXml(); $ssid=@($eventXml.Event.EventData.Data | Where-Object {$_.Name -eq 'SSID'} | ForEach-Object {$_.'#text'}); if($ssid.Count -gt 0){[pscustomobject]@{TimeCreated=$_.TimeCreated;SSID=$ssid}}}) | ConvertTo-Json -Depth 4 -Compress}",18000);Info(30,s,"已检查最近 7 天最多 100 条事件的 SSID 字段");});
          Run(31,()=>{var names=new List<string>();using(var k=Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles",false)){if(k==null){Skip(31,"网络档案键不存在");return;}foreach(var name in k.GetSubKeyNames()){using(var child=k.OpenSubKey(name,false)){names.Add(Convert.ToString(child.GetValue("ProfileName")));}}}Mark(31,String.Join("\r\n",names),names.Any(Rules.HasHan),"网络档案中有中文名称","可读网络档案未见中文名称");});
        } else {foreach(int id in new[]{29,30,31,34,35,36,37,38,40})Skip(id,"历史痕迹检查未启用");}
        Run(32,()=>{string s=RegValues(Registry.CurrentUser,@"Software\Microsoft\Windows\CurrentVersion\Internet Settings","ProxyEnable","ProxyServer","AutoConfigURL")+"\r\nWinHTTP：\r\n"+Command(Path.Combine(Environment.SystemDirectory,"netsh.exe"),"winhttp show proxy")+"\r\n疑似虚拟接口（名称匹配，可能误判）：\r\n"+String.Join("\r\n",NetworkInterface.GetAllNetworkInterfaces().Where(n=>Regex.IsMatch(n.Description+" "+n.Name,@"(?i)(TUN|TAP|WireGuard|VPN|Clash|Mihomo|Wintun)")).Select(n=>n.Name+" / "+n.Description));Info(32,s,"发现与否均不据此判断国家");});
        Run(41,()=>{var names=new List<string>();foreach(var root in new[]{Registry.CurrentUser,Registry.LocalMachine})foreach(var path in new[]{@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",@"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"})using(var key=root.OpenSubKey(path,false)){if(key==null)continue;foreach(var sub in key.GetSubKeyNames())using(var k=key.OpenSubKey(sub,false)){string name=Convert.ToString(k.GetValue("DisplayName"));if(Rules.DomesticSoftware(name))names.Add(name);}}Mark(41,String.Join("\r\n",names.Distinct())+"\r\n"+SoftwareMarker(String.Join("\n",names),""),names.Count>0,"安装项命中国内常见软件名称","所查安装项未命中有限软件清单","传统卸载注册表；不包括所有商店应用 / 便携软件");});
        Run(42,()=>{var lines=new List<string>();foreach(var root in new[]{Registry.CurrentUser,Registry.LocalMachine})using(var k=root.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",false)){if(k!=null)foreach(var n in k.GetValueNames())lines.Add(root.Name+" / "+n+"（只展示项目名，不导出启动命令）");}foreach(var dir in new[]{Environment.GetFolderPath(Environment.SpecialFolder.Startup),Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)})if(Directory.Exists(dir))lines.AddRange(Directory.EnumerateFiles(dir).Take(100).Select(Path.GetFileName));Info(42,String.Join("\r\n",lines),"已列出常见自启动项目名称，未进行恶意判定");});
        Run(43,()=>{var paths=new[]{Path.Combine(User,".npmrc"),Path.Combine(User,".gitconfig"),Path.Combine(Roaming,@"pip\pip.ini"),Path.Combine(User,@"pip\pip.ini"),Path.Combine(User,".condarc")};var lines=new List<string>();foreach(var path in paths){if(!File.Exists(path))continue;if(new FileInfo(path).Length>256*1024){lines.Add(path+"：过大，跳过");continue;}foreach(var line in File.ReadLines(path).Take(2000)){
         if(Regex.IsMatch(line,@"^\s*[#;]"))continue;
         if(Regex.IsMatch(line,@"(?i)(password|token|secret|_auth|credential)")){lines.Add(path+"：__omitted__ = [敏感配置未采集]");continue;}
         if(Regex.IsMatch(line,@"(?i)(https?://|^\s*\[|^\s*(?:registry|(?:--)?(?:extra-)?index-url|channel_alias|channels|default_channels|custom_channels|insteadOf|pushInsteadOf|url)\s*[:=])"))lines.Add(path+"："+Rules.StripSecrets(line));
         else{var boundary=Regex.Match(line,@"^(\s*[A-Za-z_][A-Za-z0-9_.-]*\s*)[:=]");if(boundary.Success)lines.Add(path+"："+boundary.Groups[1].Value+"= [无关配置值未采集]");}
        }}string s=String.Join("\r\n",lines);Info(43,s,"白名单配置文件 / 活动 URL 解析 / 注释与配置边界隔离");});
        Run(44,()=>Info(44,Wmi("SELECT Domain,PartOfDomain FROM Win32_ComputerSystem",new[]{"Domain","PartOfDomain"}),"只查询本机域加入信息"));
        Run(45,()=>Info(45,Wmi("SELECT Manufacturer,Model FROM Win32_ComputerSystem",new[]{"Manufacturer","Model"}),"只显示制造商与型号，不推断销售国家"));
        Run(48,ScanPhotos);
        Run(64,()=>{var lines=new List<string>();foreach(var device in new[]{"webcam","microphone"}){string root=@"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\"+device;lines.Add(device+"："+Reg(Registry.CurrentUser,root,"Value"));using(var k=Registry.CurrentUser.OpenSubKey(root+@"\NonPackaged",false)){if(k==null)continue;foreach(var sub in k.GetSubKeyNames().Take(80))using(var app=k.OpenSubKey(sub,false)){lines.Add(sub.Replace('#','\\')+" | Start = "+Convert.ToString(app.GetValue("LastUsedTimeStart"))+" | Stop = "+Convert.ToString(app.GetValue("LastUsedTimeStop")));}}}Info(64,String.Join("\r\n",lines),"已读取部分系统权限 / 使用记录，不能判断有无偷拍监听");});
        Run(68,()=>{var s=new StringBuilder("Windows 国家设置："+country+"\r\nWindows 时区："+TimeZoneInfo.Local.Id+"\r\n");bool mismatch=false;foreach(var pair in geo){string code=Value(pair.Value,"country_code");s.AppendLine(pair.Key+" 查询出口国家："+code);if(Regex.IsMatch(country??"","^[A-Z]{2}$")&&country!=code)mismatch=true;}s.AppendLine("浏览器运行时值需在附带检查页另行查看。时区未自动映射为国家。");if(geo.Count==0||!Regex.IsMatch(country??"","^[A-Z]{2}$")){Info(68,s.ToString(),"缺少有效系统国家或网络出口对照样本");return;}Mark(68,s.ToString(),mismatch,"国家设置与至少一个查询出口国家不同","可比较的国家设置与出口结果一致","仅配置与本次出口比较");});
        ExtendedScan();
        cancel.ThrowIfCancellationRequested();
        complete=true;SaveAutomaticBaseline();
      } catch(OperationCanceledException) {} 
      return new AuditReport {CreatedUtc=DateTime.UtcNow.ToString("o"),Completed=complete,Platform=Environment.OSVersion.ToString(),Options=options,Findings=rows,Snapshot=Baseline.Create(rows)};
    }
    private void UserLanguages(){string s=PS("@(foreach($item in (Get-WinUserLanguageList)){[pscustomobject]@{LanguageTag=$item.LanguageTag;Autonym=$item.Autonym;InputMethodTips=@($item.InputMethodTips)}}) | ConvertTo-Json -Depth 4 -Compress");Mark(21,s,IsLocale(s),"语言列表含大陆中文标记","语言列表未见大陆中文标记");}
    public static bool OtherUserProfile(string sid,string currentSid){return !String.Equals(sid,currentSid,StringComparison.OrdinalIgnoreCase)&&Regex.IsMatch(sid??"",@"^S-1-(?:5-21-\d+-\d+-\d+-\d+|12-1-\d+-\d+-\d+-\d+)$");}
    private string Wmi(string query,string[] fields) {
      var b=new StringBuilder();using(var search=new ManagementObjectSearcher(new ManagementScope(@"\\.\root\cimv2"),new ObjectQuery(query),new System.Management.EnumerationOptions {Timeout=TimeSpan.FromSeconds(8)}))using(var objects=search.Get()){foreach(ManagementObject item in objects){using(item){foreach(var f in fields)b.AppendLine(f+" = "+Convert.ToString(item[f]));}}}return b.ToString();
    }
    private static double Rational(byte[] b,int offset) {uint den=BitConverter.ToUInt32(b,offset+4);if(den==0)throw new FormatException("GPS 分母为零");return (double)BitConverter.ToUInt32(b,offset)/den;}
    public static double Coordinate(byte[] b,string reference) {if(b.Length<24)throw new FormatException("GPS 数据长度错误");double v=Rational(b,0)+Rational(b,8)/60+Rational(b,16)/3600;return reference=="S"||reference=="W"?-v:v;}
    private void PhotoMetadata(string root) {PhotoFiles(LocalData.Walk(root,10000,1000,cancel));}
    private void PhotoFiles(LocalData.WalkResult walk) {
      var files=walk.Files.Where(file=>Regex.IsMatch(Path.GetExtension(file),@"(?i)^\.(jpe?g|tiff?)$")).Take(501).ToArray();
      int count=0,failed=walk.Errors.Count,found=0,skipped=0;bool capped=walk.Capped||files.Length>500;
      var lines=new List<string>{AutomaticFiles.Description(walk)};
      foreach(string file in files.Take(500)){
        cancel.ThrowIfCancellationRequested();count++;
        try{
          if(!AutomaticFiles.LocalEntry(File.GetAttributes(file))||new FileInfo(file).Length>30*1024*1024){skipped++;continue;}
          using(var stream=new FileStream(file,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete))using(var img=Image.FromStream(stream,false,false)){
            if(!img.PropertyIdList.Contains(2)||!img.PropertyIdList.Contains(4))continue;
            string latRef=Encoding.ASCII.GetString(img.GetPropertyItem(1).Value).Trim('\0'),lonRef=Encoding.ASCII.GetString(img.GetPropertyItem(3).Value).Trim('\0');
            if((latRef!="N"&&latRef!="S")||(lonRef!="E"&&lonRef!="W"))throw new FormatException("GPS 方向错误");
            double lat=Coordinate(img.GetPropertyItem(2).Value,latRef),lon=Coordinate(img.GetPropertyItem(4).Value,lonRef);
            if(Math.Abs(lat)>90||Math.Abs(lon)>180)throw new FormatException("GPS 坐标越界");found++;
            lines.Add(Path.GetFileName(file)+"\r\nGPS_SAMPLE latitude="+lat.ToString("F6",CultureInfo.InvariantCulture)+" longitude="+lon.ToString("F6",CultureInfo.InvariantCulture));
          }
        }catch(Exception e){if(e is OperationCanceledException)throw;failed++;lines.Add(Path.GetFileName(file)+"："+e.Message);}
      }
      lines.Insert(0,"候选图片 "+count+"；发现 GPS "+found+"；错误 "+failed+"；大文件或链接跳过 "+skipped+"；达到上限 "+capped+"\r\n坐标只在本地展示；使用内置 Natural Earth 1:10m CN 多边形及至少 2 km 边界余量进行离线地域校验。");
      if(count==0)Info(48,String.Join("\r\n",lines),"自动或指定范围没有可分析的 JPEG / TIFF 样本");
      else if(found==0&&(failed>0||skipped>0||capped))Info(48,String.Join("\r\n",lines),"未取得 GPS，但扫描有受限 / 跳过项目");
      else Mark(48,String.Join("\r\n",lines),found>0,"已发现图片中取得 GPS 元数据","已读取图片未发现 GPS 元数据",(walk.Automatic?"自动发现图片":"指定目录图片")+(capped?" / 有上限 / 部分覆盖":" / JPEG / TIFF"));
    }
  }
}
