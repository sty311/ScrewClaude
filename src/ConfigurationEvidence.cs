using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace LocalLens {
 public static class ConfigurationEvidence {
  const int MaxEvidenceChars=2*1024*1024,MaxLines=10000,MaxLineChars=8192,MaxUrls=128,MaxSources=32;
  static readonly Regex Assignment=new Regex(@"^\s*(?<key>(?:--)?(?:@[A-Za-z0-9._-]+:)?[A-Za-z][A-Za-z0-9_.-]*)\s*(?:=|:)\s*(?<value>.*)$",RegexOptions.CultureInvariant);
  static readonly Regex Section=new Regex(@"^\[\s*(?<name>[A-Za-z][A-Za-z0-9.-]*)(?:\s+(?<sub>.*?))?\s*\]$",RegexOptions.CultureInvariant);
  sealed class Context {
   public string Format="",SectionName="",SectionKey="",ListKey="";public int ListIndent;public bool CustomChannels,Invalid;public Uri GitTarget;
   public readonly Dictionary<string,List<Uri>> Active=new Dictionary<string,List<Uri>>(StringComparer.OrdinalIgnoreCase);
   public void EndList(){ListKey="";CustomChannels=false;}
   public void Set(string key,IEnumerable<Uri> values){Active[key]=values.Where(v=>v!=null).Take(MaxUrls).ToList();}
   public void Append(Uri uri){if(uri!=null&&Active.ContainsKey(ListKey)&&Active[ListKey].Count<MaxUrls)Active[ListKey].Add(uri);}
  }

  // A bounded parser for the npm/pip/Conda/Git forms collected by check 43.
  // It reads URL values, never URLs appearing in prose, comments or Git aliases.
  // Each collector-prefixed source retains its own section/list context.
  public static IEnumerable<Uri> ActiveUrls(string evidence){
   var empty=new Uri[0];if(String.IsNullOrEmpty(evidence)||evidence.Length>MaxEvidenceChars)return empty;
   var sources=new Dictionary<string,Context>(StringComparer.OrdinalIgnoreCase);
   using(var reader=new StringReader(evidence)){
    string raw;int lineCount=0;
    while((raw=reader.ReadLine())!=null){
     if(++lineCount>MaxLines||raw.Length>MaxLineChars)return empty;
     string source="";string line=RemoveCollectorPrefix(raw,out source);
     Context context;if(!sources.TryGetValue(source,out context)){if(sources.Count>=MaxSources)return empty;context=new Context{Format=SourceFormat(source)};sources[source]=context;}
     if(context.Invalid)continue;line=WithoutComments(line);if(line==null){context.Active.Clear();context.Invalid=true;continue;}if(String.IsNullOrWhiteSpace(line))continue;
     int indent=line.TakeWhile(c=>c==' '||c=='\t').Count();string text=line.Trim();
     if(text.StartsWith("[",StringComparison.Ordinal)){
      context.EndList();context.GitTarget=null;context.SectionName="";context.SectionKey=text;
      Match section=Section.Match(text);if(!section.Success)continue;
      context.SectionName=section.Groups["name"].Value.ToLowerInvariant();
      if(context.Format==""&&(context.SectionName=="url"||context.SectionName=="remote"||context.SectionName=="submodule"||context.SectionName=="user"))context.Format="git";
      if(context.SectionName=="url"&&context.Format=="git"){
       string sub=section.Groups["sub"].Value.Trim();
       if(sub.StartsWith("\"",StringComparison.Ordinal))context.GitTarget=Url(sub);
      }
      continue;
     }
     if(context.ListKey.Length>0){
      if(!context.CustomChannels&&indent>=context.ListIndent&&text.StartsWith("-",StringComparison.Ordinal)&&text.Length>1&&Char.IsWhiteSpace(text[1])){context.Append(Url(text.Substring(1)));continue;}
      Match nested=Assignment.Match(line);
      if(context.CustomChannels&&indent>context.ListIndent&&nested.Success){context.Append(Url(nested.Groups["value"].Value));continue;}
      context.EndList();
     }
     Match assignment=Assignment.Match(line);if(!assignment.Success)continue;
     string key=assignment.Groups["key"].Value.ToLowerInvariant();if(key.StartsWith("--",StringComparison.Ordinal))key=key.Substring(2);
     string value=assignment.Groups["value"].Value.Trim();
     if(key=="insteadof"||key=="pushinsteadof"){
      // The alias is a match prefix, not an address the user will contact.
      string alias=Scalar(value);if(context.Format=="git"&&context.SectionName=="url"&&context.GitTarget!=null&&!String.IsNullOrEmpty(alias))context.Set(context.SectionKey+"|"+key+"|"+alias,new[]{context.GitTarget});
      continue;
     }
     if(context.SectionName=="url")continue;
     if(key=="channels"||key=="default_channels"||key=="custom_channels"){
      if(context.Format!=""&&context.Format!="conda")continue;
      string listKey=context.SectionKey+"|"+key;context.Set(listKey,new Uri[0]);
      if(value.Length==0){context.ListKey=listKey;context.ListIndent=indent;context.CustomChannels=key=="custom_channels";}
      else if(key!="custom_channels")context.Set(listKey,InlineList(value));
      continue;
     }
     bool generic=context.Format=="",active=(generic||context.Format=="pip")&&(key=="index-url"||key=="extra-index-url");
     active|=(generic||context.Format=="npm")&&(key=="registry"||key.EndsWith(":registry",StringComparison.Ordinal));
     active|=(generic||context.Format=="conda")&&key=="channel_alias";
     if(key=="url")active=generic&&context.SectionName==""||(generic||context.Format=="git")&&(context.SectionName=="remote"||context.SectionName=="submodule");
     if(active)context.Set(context.SectionKey+"|"+key,new[]{Url(value)});
    }
   }
   return sources.Values.SelectMany(c=>c.Active.Values).SelectMany(v=>v).GroupBy(u=>u.AbsoluteUri,StringComparer.Ordinal).Select(g=>g.First()).Take(MaxUrls).ToArray();
  }

  static string SourceFormat(string source){
   string path=source.Replace('\\','/').ToLowerInvariant();
   if(path.EndsWith(".gitconfig",StringComparison.Ordinal)||path.EndsWith("/.git/config",StringComparison.Ordinal))return "git";
   if(path.EndsWith(".npmrc",StringComparison.Ordinal))return "npm";
   if(path.EndsWith("pip.ini",StringComparison.Ordinal))return "pip";
   if(path.EndsWith(".condarc",StringComparison.Ordinal))return "conda";
   return "";
  }

  static string RemoveCollectorPrefix(string line,out string source){
   source="";int colon=line.IndexOf('：');if(colon<0)return line.TrimStart('\ufeff');
   string path=line.Substring(0,colon).Trim().TrimStart('\ufeff');
   bool absolute=path.StartsWith("/",StringComparison.Ordinal)||path.StartsWith(@"\\",StringComparison.Ordinal)||(path.Length>=3&&Char.IsLetter(path[0])&&path[1]==':'&&(path[2]=='\\'||path[2]=='/'));
   bool known=path==".npmrc"||path==".gitconfig"||path==".condarc"||String.Equals(path,"pip.ini",StringComparison.OrdinalIgnoreCase);
   if(!absolute&&!known)return line.TrimStart('\ufeff');source=path;return line.Substring(colon+1);
  }

  static string WithoutComments(string line){
   char quote='\0';bool escaped=false;
   for(int i=0;i<line.Length;i++){
    char c=line[i];
    if(quote!='\0'){
     if(escaped){escaped=false;continue;}if(c=='\\'&&quote=='"'){escaped=true;continue;}
     if(c==quote){if(quote=='\''&&i+1<line.Length&&line[i+1]=='\''){i++;continue;}quote='\0';}
    }else if(c=='#'||c==';')return line.Substring(0,i);
    else if(c=='"'||c=='\'')quote=c;
   }
   return quote=='\0'?line:null;
  }

  static string Scalar(string value){
   value=value.Trim();if(value.Length==0)return "";
   char quote=value[0];if(quote!='"'&&quote!='\'')return value;
   if(value.Length<2||value[value.Length-1]!=quote)return null;
   var result=new StringBuilder();
   for(int i=1;i<value.Length-1;i++){
    char c=value[i];
    if(c==quote){if(quote=='\''&&i+1<value.Length-1&&value[i+1]=='\''){result.Append(c);i++;continue;}return null;}
    if(c=='\\'&&quote=='"'){
     if(++i>=value.Length-1)return null;c=value[i];if(c!='\\'&&c!='"')return null;
    }
    result.Append(c);
   }
   return result.ToString();
  }

  static Uri Url(string value){
   value=Scalar(value);if(String.IsNullOrEmpty(value)||value.Length>4096||value.Any(Char.IsWhiteSpace))return null;
   Uri uri;if(!Uri.TryCreate(value,UriKind.Absolute,out uri)||(uri.Scheme!=Uri.UriSchemeHttps&&uri.Scheme!=Uri.UriSchemeHttp)||String.IsNullOrEmpty(uri.Host)||uri.UserInfo.Length>0||!uri.IsWellFormedOriginalString())return null;
   return uri;
  }

  static IEnumerable<Uri> InlineList(string value){
   var result=new List<Uri>();if(value.Length<2||value[0]!='['||value[value.Length-1]!=']')return result;
   int start=1;char quote='\0';bool escaped=false;
   for(int i=1;i<value.Length;i++){
    char c=value[i];
    if(quote!='\0'){if(escaped){escaped=false;continue;}if(c=='\\'&&quote=='"'){escaped=true;continue;}if(c==quote)quote='\0';}
    else if(c=='"'||c=='\'')quote=c;
    else if(c==','||i==value.Length-1){Uri uri=Url(value.Substring(start,i-start));if(uri!=null&&result.Count<MaxUrls)result.Add(uri);start=i+1;}
   }
   return result;
  }
 }
}
