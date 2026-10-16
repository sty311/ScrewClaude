using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

namespace LocalLens {
 public static class ContactEvidence {
  const int MaxMatches=20,MaxScalar=512,MaxInput=2097152;
  sealed class Field {public string Name,Value,Role,Kind;}
  sealed class Country {public string Role,Value;}
  static readonly Regex address=new Regex(@"^\s*(?:(?:中华人民共和国|中国大陆|中国|PRC|CN)[\s,，]*)?(?:北京市?|上海市?|天津市?|重庆市?|(?:河北|山西|辽宁|吉林|黑龙江|江苏|浙江|安徽|福建|江西|山东|河南|湖北|湖南|广东|海南|四川|贵州|云南|陕西|甘肃|青海)省?|(?:内蒙古|广西|西藏|宁夏|新疆)(?:自治区)?)[^\r\n;；<>:{}""']{1,100}(?:街|路|巷|道|胡同|弄)[^\r\n;；<>:{}""']{0,30}[0-9０-９一二三四五六七八九十百零〇]{1,8}号[^\r\n;；<>:{}""']{0,40}\s*$",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant);
  static readonly Regex foreignAddress=new Regex(@"(?:^\s*(?:香港|澳门|澳門|台湾|臺灣|Hong Kong\b|Macau\b|Macao\b|Taiwan\b)|(?:^|[,，\s])(?:JP|JPN|Japan|日本|US|USA|United States|美国|UK|GB|United Kingdom|英国|SG|Singapore|新加坡|TW|Taiwan|台湾|臺灣|HK|Hong Kong|香港|MO|Macau|Macao|澳门|澳門|CA|Canada|加拿大|AU|Australia|澳大利亚|NZ|New Zealand|FR|France|法国|DE|Germany|德国|KR|Korea|韩国)\s*$)",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant);
  static readonly Regex mobile=new Regex(@"^\+86[ \t-]*1[3-9](?:[ \t-]*[0-9]){9}$",RegexOptions.CultureInvariant);
  static string Key(string field){return Regex.Replace(field??"",@"[\s_-]","").ToLowerInvariant();}
  static string AddressRole(string name){
   switch(Key(name)){
    case "homeaddress":case "residenceaddress":case "residentialaddress":case "居住地址":case "家庭住址":case "家庭地址":case "住宅地址":return "home";
    case "shippingaddress":case "deliveryaddress":case "收货地址":case "送货地址":return "shipping";
    case "billingaddress":case "账单地址":case "帐单地址":return "billing";
    case "contactaddress":case "postaladdress":case "联系地址":case "通讯地址":case "通信地址":return "contact";
    default:return "";
   }
  }
  static string ContainerRole(string name){
   string role=AddressRole(name);if(role.Length>0)return role;
   switch(Key(name)){case "home":case "residence":case "residential":return "home";case "shipping":case "delivery":return "shipping";case "billing":return "billing";case "contact":return "contact";default:return "";}
  }
  static bool GenericCountry(string name){return new[]{"country","countrycode","国家","国家代码"}.Contains(Key(name));}
  static string CountryRole(string name,string context){
   switch(Key(name)){
    case "residencecountry":case "countryofresidence":case "residentialcountry":case "homecountry":case "居住国家":case "居住地区":case "家庭国家":return "home";
    case "shippingcountry":case "deliverycountry":case "收货国家":case "收货地区":return "shipping";
    case "billingcountry":case "账单国家":case "帐单国家":return "billing";
    case "addresscountry":return "address";
    case "contactcountry":case "postalcountry":case "联系国家":return "contact";
   }
   if(GenericCountry(name))return context.Length>0?context:"*";
   int dot=(name??"").IndexOf('.');if(dot>0&&name.IndexOf('.',dot+1)<0){string role=ContainerRole(name.Substring(0,dot));if(role.Length>0&&GenericCountry(name.Substring(dot+1)))return role;}
   return "";
  }
  static bool PhoneField(string name){return new[]{"phone","telephone","tel","mobile","mobilenumber","phonenumber","电话","手机","联系电话","手机号码","电话号码"}.Contains(Key(name));}
  static bool ChinaCountry(string value){string v=(value??"").Trim();return v.Equals("CN",StringComparison.OrdinalIgnoreCase)||v.Equals("China",StringComparison.OrdinalIgnoreCase)||v.Equals("PRC",StringComparison.OrdinalIgnoreCase)||v=="中国"||v=="中国大陆";}
  static bool Related(string first,string second){return first=="*"||second=="*"||first==second||first=="address"||second=="address";}
  static bool Conflict(IEnumerable<Country> countries,string role){return countries.Any(c=>Related(c.Role,role)&&!String.IsNullOrWhiteSpace(c.Value)&&!ChinaCountry(c.Value));}
  static void Add(List<string> result,string name,string value){
   if(result.Count>=MaxMatches||name.Length>160||value.Length>MaxScalar)return;
   string evidence=name+": "+new JavaScriptSerializer().Serialize(value);if(evidence.Length<=1400&&!result.Contains(evidence))result.Add(evidence);
  }
  static Field ContactField(string name,string value,string context,string contextName){
   if(name.Length>80||value==null||value.Length>MaxScalar)return null;
   string role=CountryRole(name,context);if(role.Length>0)return new Field{Name=GenericCountry(name)&&context.Length>0?contextName+"."+name:name,Value=value,Role=role,Kind="country"};
   role=AddressRole(name);if(role.Length>0)return new Field{Name=name,Value=value,Role=role,Kind="address"};
   return PhoneField(name)?new Field{Name=name,Value=value,Role="contact",Kind="phone"}:null;
  }
  static void Judge(IEnumerable<Field> fields,List<Country> countries,List<string> result){
   foreach(var field in fields){if(result.Count>=MaxMatches)return;
    if(field.Kind=="phone"){string phone=field.Value.Trim();if(Regex.IsMatch(field.Name,@"^(?:[a-z0-9-]+\.)?TEL(?:;|$)",RegexOptions.IgnoreCase)&&phone.StartsWith("tel:",StringComparison.OrdinalIgnoreCase))phone=phone.Substring(4);if(mobile.IsMatch(phone))Add(result,field.Name,field.Value);continue;}
    if(field.Kind=="adr"){
     var parts=VcardParts(field.Value);if(parts.Count!=7||Conflict(countries,field.Role))continue;
     if(ChinaCountry(parts[6])||(String.IsNullOrWhiteSpace(parts[6])&&address.IsMatch(parts[4]+parts[3]+parts[2])&&!foreignAddress.IsMatch(parts[4]+parts[3]+parts[2])))Add(result,field.Name,field.Value);
    }else if(!Conflict(countries,field.Role)&&((field.Kind=="country"&&field.Role!="*"&&ChinaCountry(field.Value))||(field.Kind=="address"&&address.IsMatch(field.Value)&&!foreignAddress.IsMatch(field.Value))))Add(result,field.Name,field.Value);
   }
  }
  static void Declare(Field field,List<Country> countries){
   if(field.Kind=="country")countries.Add(new Country{Role=field.Role,Value=field.Value});
   else if(field.Kind=="address"&&foreignAddress.IsMatch(field.Value))countries.Add(new Country{Role=field.Role,Value="[explicit non-mainland address]"});
   else if(field.Kind=="adr"){var parts=VcardParts(field.Value);if(parts.Count==7&&!String.IsNullOrWhiteSpace(parts[6]))countries.Add(new Country{Role=field.Role,Value=parts[6]});}
  }
  static void JsonDeclarations(Dictionary<string,object> data,string context,string contextName,List<Country> countries,int depth){
   if(depth>16)return;
   foreach(var pair in data){var scalar=pair.Value as string;if(scalar!=null){var field=ContactField(pair.Key,scalar,context,contextName);if(field!=null)Declare(field,countries);}
    else{string role=ContainerRole(pair.Key);var child=pair.Value as Dictionary<string,object>;if(role.Length>0&&child!=null)JsonDeclarations(child,role,pair.Key,countries,depth+1);}}
  }
  static void JsonRecords(object node,string context,string contextName,List<Country> inherited,List<string> result,int depth){
   if(depth>16||result.Count>=MaxMatches)return;
   var data=node as Dictionary<string,object>;if(data!=null){var countries=new List<Country>(inherited);JsonDeclarations(data,context,contextName,countries,depth);var fields=new List<Field>();
    foreach(var pair in data){var value=pair.Value as string;if(value!=null){var field=ContactField(pair.Key,value,context,contextName);if(field!=null)fields.Add(field);}}
    Judge(fields,countries,result);
    foreach(var pair in data){if(pair.Value is string)continue;string role=ContainerRole(pair.Key);JsonRecords(pair.Value,role,role.Length>0?pair.Key:"",role.Length>0?countries:new List<Country>(),result,depth+1);}
   }else{var list=node as IList;if(list!=null)foreach(var item in list)JsonRecords(item,context,contextName,inherited,result,depth+1);}
  }
  static bool Scalar(string text,out string value){
   value="";string s=(text??"").Trim();if(s.Length==0)return true;
   if(s[0]=='"'||s[0]=='\''){char quote=s[0];var b=new StringBuilder();bool closed=false;int i=1;
    for(;i<s.Length;i++){char c=s[i];if(c==quote){closed=true;i++;break;}if(c=='\\'){if(++i>=s.Length)return false;char next=s[i];if(next==quote||next=='\\')b.Append(next);else if(next=='n'||next=='r')return false;else{b.Append('\\');b.Append(next);}}else b.Append(c);if(b.Length>MaxScalar)return false;}
    if(!closed)return false;string tail=s.Substring(i).TrimStart();if(tail.Length>0&&!tail.StartsWith("#")&&!tail.StartsWith(";")&&!tail.StartsWith("；")&&!tail.StartsWith("//"))return false;value=b.ToString();return true;
   }
   int end=s.Length;foreach(string marker in new[]{"#",";","；","//"}){int at=s.IndexOf(marker,StringComparison.Ordinal);if(at>=0)end=Math.Min(end,at);}value=s.Substring(0,end).Trim();return value.Length<=MaxScalar&&!Regex.IsMatch(value,@"[{}""\r\n]|[,，]\s*[^,，:：=]{1,50}[:：=]");
  }
  static List<string> VcardParts(string value){
   var result=new List<string>();var b=new StringBuilder();bool escaped=false;foreach(char c in value){if(escaped){if(c=='n'||c=='N')b.Append(' ');else b.Append(c);escaped=false;}else if(c=='\\')escaped=true;else if(c==';'){result.Add(b.ToString().Trim());b.Clear();}else b.Append(c);}if(escaped)b.Append('\\');result.Add(b.ToString().Trim());return result;
  }
  static Field PlainField(string line){
   var vcard=Regex.Match(line,@"^\s*((?:(?:[a-z0-9-]+)\.)?(ADR|TEL)((?:;[^:\r\n]*)?)):(.*)$",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant);
   if(vcard.Success){string raw=vcard.Groups[4].Value.Trim();if(raw.Length>MaxScalar)return null;string value;if(raw.StartsWith("\"")||raw.StartsWith("'")){if(!Scalar(raw,out value))return null;}else value=raw;
    string kind=vcard.Groups[2].Value.ToUpperInvariant();if(kind=="TEL")return new Field{Name=vcard.Groups[1].Value,Value=value,Role="contact",Kind="phone"};
    return new Field{Name=vcard.Groups[1].Value,Value=value,Role=Regex.IsMatch(vcard.Groups[3].Value,@"(?i)(?:[=,;])HOME(?:[,;]|$)")?"home":"address",Kind="adr"};
   }
   var m=Regex.Match(line,@"^\s*([^:=：\r\n]{1,160})\s*[:=：]\s*(.*)$");if(!m.Success)return null;string scalar;if(!Scalar(m.Groups[2].Value,out scalar))return null;return ContactField(m.Groups[1].Value.Trim(),scalar,"","");
  }
  static void PlainRecords(string text,List<string> result){
   var fields=new List<Field>();string pending=null;
   Action flush=()=>{var countries=new List<Country>();foreach(var field in fields)Declare(field,countries);Judge(fields,countries,result);fields.Clear();};
   foreach(string raw in text.Replace("\r","").Split('\n')){
    if((raw.StartsWith(" ")||raw.StartsWith("\t"))&&pending!=null){pending+=raw.Substring(1);if(pending.Length>MaxScalar+200)pending="";continue;}
    if(pending!=null){var field=PlainField(pending);if(field!=null)fields.Add(field);pending=null;}
    if(String.IsNullOrWhiteSpace(raw)||raw.Trim().Equals("BEGIN:VCARD",StringComparison.OrdinalIgnoreCase)||raw.Trim().Equals("END:VCARD",StringComparison.OrdinalIgnoreCase)){flush();continue;}
    if(Regex.IsMatch(raw,@"^\s*(?:[a-z0-9-]+\.)?(?:ADR|TEL)(?:;|:)",RegexOptions.IgnoreCase))pending=raw;else{var field=PlainField(raw);if(field!=null)fields.Add(field);}
    if(result.Count>=MaxMatches)return;
   }
   if(pending!=null){var field=PlainField(pending);if(field!=null)fields.Add(field);}flush();
  }
  public static string[] Matches(string text){
   if(String.IsNullOrWhiteSpace(text)||text.Length>MaxInput)return new string[0];var result=new List<string>();string trimmed=text.TrimStart('\ufeff',' ','\t','\r','\n');
   if(trimmed.StartsWith("{")||trimmed.StartsWith("[")){
    object data;try{data=new JavaScriptSerializer{MaxJsonLength=MaxInput,RecursionLimit=64}.DeserializeObject(trimmed);}catch(ArgumentException){return new string[0];}catch(InvalidOperationException){return new string[0];}
    JsonRecords(data,"","",new List<Country>(),result,0);
   }else PlainRecords(text,result);
   return result.Take(MaxMatches).ToArray();
  }
 }
}
