using System;
using System.Linq;
using LocalLens;

class ContactEvidenceChecks {
 static int count;
 static void Check(bool ok,string name){if(!ok)throw new Exception(name);count++;Console.WriteLine("PASS: "+name);}
 static void Yes(string text,string name){Check(ContactEvidence.Matches(text).Length>0,name);}
 static void No(string text,string name){Check(ContactEvidence.Matches(text).Length==0,name);}
 static int Main(){try{
  No("{\"homeCountry\":\"JP\",\"note\":\"China tourism\"}","JSON country evidence cannot borrow China from a note");
  No("home address: 12 China Road, London, UK","China street names overseas do not establish mainland addresses");
  No("country: CN","generic dataset country is not an ownership field");
  No("{\"country\":\"CN\",\"note\":\"homeCountry: China\"}","JSON note contents are not reinterpreted as fields");
  No("{\"homeCountry\":\"JP\",\"China\":true}","unrelated JSON keys cannot change the owned country");
  No("{\"homeCountry\":\"CN\",\"country\":\"JP\"}","contradictory country in the same record prevents a China country claim");
  No("{\"homeCountry\":\"JP\",\"home address\":\"上海市浦东新区世纪大道100号\"}","a foreign home country conflicts with the same home address");
  No("{\"homeCountry\":\"CN\",\"homeAddress\":{\"country\":\"JP\"}}","nested owned address country also contradicts its home record");
  No("{\"homeCountry\":\"China tourism\"}","country values must be exact scalars");
  No("{\"homeCountry\":\"CN\"}, homeCountry: CN","malformed JSON is not salvaged using plaintext scanning");
  No("北京是中国的首都。中国旅游攻略。Beijing, Shanghai.","unowned prose and place mentions are excluded");
  No("homeCountry: JP # China\nhome address: 12 China Road, London, UK","plaintext comments do not alter the owning country");
  No("homeCountry: 'JP', note: 'China tourism'","quoted scalar cannot swallow a following field");
  No("home address: 上海市浦东新区世纪大道100号, homeCountry: JP","unquoted address cannot swallow a following country field");
  No("myhomeCountry: CN","ownership field names match exactly");
  No("ADR:;;China Road;London;;;UK","VCF uses the final country component, not China in the street");
  No("ADR:;;上海市浦东新区世纪大道100号;Tokyo;;;JP","VCF foreign country overrides a Chinese-looking street");
  No("ADR:;;CN;London;;;UK","VCF CN in a non-country component is not accepted");
  No("联系电话：+86 12800138000","invalid mainland mobile prefix is excluded");
  No("phone: +86 138001380001","extra phone digits cannot pass a prefix match");
  No("phone: +86 13800138000 ext 5","phone field must contain an exact mobile value");
  No("note: phone: +86 13800138000","phone text inside an unrelated field is excluded");
  foreach(string country in new[]{"CN","China","中国","中国大陆","PRC"})Yes("{\"residenceCountry\":\""+country+"\"}","exact owned country accepted: "+country);
  Yes("homeCountry = 'CN' # manually entered","single-quoted scalar with trailing comment is parsed exactly");
  Yes("billingCountry: \"China\"; note: imported","double-quoted scalar with trailing comment is parsed exactly");
  Yes("收货地址：上海市浦东新区世纪大道100号","mainland delivery address has municipality, street and door number");
  Yes("家庭住址：安徽省合肥市蜀山区长江西路100号","mainland province address includes provinces missing from the old list");
  Yes("{\"shippingAddress\":{\"country\":\"CN\",\"note\":\"Japan tourism\"}}","country inside an owned address object preserves its ownership");
  Yes("{\"homeCountry\":\"JP\",\"shippingCountry\":\"CN\"}","distinct home and shipping roles do not erase valid shipping evidence");
  Yes("{\"country\":\"JP\",\"contacts\":[{\"homeCountry\":\"CN\"}]}","dataset metadata does not contradict a separate nested contact record");
  Yes("ADR;TYPE=HOME:;;1 Example Road;Shanghai;;;CN","VCF final CN country component is accepted");
  Yes("ADR;TYPE=HOME:;;1 Example\\; Road;Shanghai;;;China","escaped VCF separators do not change the final country component");
  Yes("联系电话：+86 13800138000","explicit mainland mobile contact field is accepted");
  Yes("TEL;TYPE=CELL;VALUE=uri:tel:+8613800138000","VCF telephone URI is interpreted as a phone field");
  string phoneEvidence=ContactEvidence.Matches("item1.TEL;VALUE=uri:tel:+8613800138000").Single();Check(phoneEvidence=="item1.TEL;VALUE=uri: \"tel:+8613800138000\"","phone evidence preserves grouped field and exact URI value");Yes(phoneEvidence,"canonical VCF telephone evidence round-trips");
  Yes("BEGIN:VCARD\nADR;TYPE=HOME:;;1 Example Road;Shanghai;;;\n CN\nEND:VCARD","folded VCF country component is reconstructed");
  string evidence=ContactEvidence.Matches("{\"shippingAddress\":{\"country\":\"CN\"}}").Single();Check(evidence=="shippingAddress.country: \"CN\"","evidence preserves the exact owned field and scalar value");
  Yes(evidence,"canonical evidence round-trips as an exact owned field");
  string addressEvidence=ContactEvidence.Matches("收货地址：上海市浦东新区世纪大道100号").Single();Yes(addressEvidence,"canonical address evidence round-trips without broad prefix parsing");
  No("source.txt → homeCountry: CN","arbitrary filename prefixes do not become owning fields");
  No("homeCountry: \"CN\" trailing unrelated text","quoted value must end before a valid comment or end of line");
  No("{\"homeCountry\":\"CN\",\"home address\":\"Hong Kong\"}","explicit non-mainland home address contradicts generic China country");
  string many="["+String.Join(",",Enumerable.Range(0,40).Select(i=>"{\"homeCountry\":\"CN\",\"phone\":\"+8613800138"+i.ToString("000")+"\"}"))+"]";var bounded=ContactEvidence.Matches(many);Check(bounded.Length<=20&&bounded.All(s=>s.Length<=1400),"returned evidence is bounded by count and length");
  Console.WriteLine("CONTACT EVIDENCE CHECKS PASSED: "+count);return 0;
 }catch(Exception ex){Console.Error.WriteLine("FAIL: "+ex);return 1;}}
}
