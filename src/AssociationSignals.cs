using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
namespace LocalLens {
 // Association risk is distinct from proof of identity or current location.
 // Read only the field type collected by the check, never arbitrary UI text.
 public static class AssociationSignals {
  public static bool Locale(string tag) {
   return !String.IsNullOrWhiteSpace(tag) && (ChinaEvidence.SpecificLocaleMatches(tag)==tag || Regex.IsMatch(tag,@"^(?:zh|zh-Hans|zh-CHS)$",RegexOptions.IgnoreCase));
  }
  public static string LocaleMatches(string text) {
   var result=new List<string>();
   foreach(var line in (text??"").Replace("\r","").Split('\n')) {
    var pair=Regex.Match(line,@"^([^=]+)\s*=\s*(.*)$");if(!pair.Success)continue;
    string key=pair.Groups[1].Value.Trim(),value=pair.Groups[2].Value.Trim();var values=new List<string>();
    if(key=="LANGUAGE_VALUES") {
     try {
      if(value.StartsWith("{")){var d=new JavaScriptSerializer().Deserialize<Dictionary<string,object>>(value);foreach(var p in d)if(new[]{"accept_languages","selected_languages","app_locale"}.Contains(p.Key)&&p.Value is string)values.Add((string)p.Value);}
      else {var m=Regex.Match(value,@"^user_pref\(""(?:intl\.(?:accept_languages|locale.requested)|general\.useragent\.locale)"",\s*(""(?:[^""\\]|\\.)*"")\s*\);?$");if(m.Success)values.Add(new JavaScriptSerializer().Deserialize<string>(m.Groups[1].Value));}
     }catch(ArgumentException){}catch(InvalidOperationException){}
    }else if(Regex.IsMatch(key,@"^(?:UI Culture|PreferredUILanguages|UILanguage|HelpLanguage|InstallLanguage|LANG|LANGUAGE|LC_[A-Z_]+)$"))values.Add(value);
    foreach(var raw in values.SelectMany(v=>v.Split(new[]{',',':'},StringSplitOptions.RemoveEmptyEntries))){var tag=raw.Trim();if(Regex.IsMatch(key,@"^(?:LANG|LANGUAGE|LC_[A-Z_]+)$"))tag=Regex.Replace(tag,@"\.[A-Za-z0-9-]+(?:@[A-Za-z0-9_-]+)?$","");if(Locale(tag))result.Add(key+"="+tag);}
   }
   return String.Join("\r\n",result.Distinct());
  }
  public static string Fonts(string text) {
   return String.Join("\r\n",(text??"").Replace("\r","").Split('\n').Select(s=>s.Trim()).Where(s=>Regex.IsMatch(s,@"^(?:SimSun(?:-Ext[BG])?|NSimSun|SimHei|Microsoft YaHei(?: UI)?|DengXian(?: Light)?|FangSong|KaiTi|PingFang SC|Noto Sans SC|Source Han Sans SC|微软雅黑|宋体|新宋体|黑体|等线|仿宋|楷体)$",RegexOptions.IgnoreCase)).Distinct());
  }
  public static string WirelessNames(string text,bool events) {
   var names=events?JsonFields(text,new[]{"SSID"}):(text??"").Replace("\r","").Split('\n');
   return String.Join("\r\n",names.Where(s=>Regex.IsMatch(s??"",@"(?i)(?:^(?:ChinaNet|CMCC|ChinaUnicom|CUCC)(?:[-_@ ]|$)|中国(?:移动|联通|电信)|天翼)" )).Distinct());
  }
  public static string DnsCache(string text) {
   return String.Join("\r\n",JsonFields(text,new[]{"Entry","RecordName"}).Select(s=>s.TrimEnd('.').ToLowerInvariant()).Where(s=>ChinaEvidence.ServiceFamily(s).Length>0).Distinct());
  }
  public static bool HasJsonField(string text,string key) { return JsonFields(text,new[]{key}).Any(s=>!String.IsNullOrWhiteSpace(s)); }
  static IEnumerable<string> JsonFields(string text,string[] keys) {
   var output=new List<string>();
   foreach(var line in (text??"").Replace("\r","").Split('\n')) {
    var trimmed=line.Trim().TrimStart('\ufeff');if(!trimmed.StartsWith("{")&&!trimmed.StartsWith("["))continue;
    try { Fields(new JavaScriptSerializer().DeserializeObject(trimmed),keys,output); } catch(ArgumentException){} catch(InvalidOperationException){}
   }
   return output;
  }
  static void Fields(object node,string[] keys,List<string> output) {
   var d=node as Dictionary<string,object>;
   if(d!=null){foreach(var pair in d){if(keys.Contains(pair.Key)){var value=pair.Value as string;if(value!=null)output.Add(value);else{var list=pair.Value as IList;if(list!=null)output.AddRange(list.Cast<object>().OfType<string>());}}}}
   else{var array=node as IList;if(array!=null)foreach(var child in array)Fields(child,keys,output);}
  }
 }
}
