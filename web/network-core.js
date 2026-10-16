(function(root){
 'use strict';
 function ip(value){
  if(typeof value!=='string'||value.length>64)return null;
  if(/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)){const parts=value.split('.');return parts.every(x=>Number(x)<=255&&String(Number(x))===x)?parts.join('.'):null;}
  if(!value.includes(':')||!/^[a-fA-F0-9:.]+$/.test(value))return null;
  try{return new URL('http://['+value+']/').hostname.slice(1,-1).toLowerCase();}catch{return null;}
 }
 function publicIp(value){
  const address=ip(value);if(!address)return false;
  if(address.includes(':')){
   if(address.startsWith('::ffff:')){const words=address.slice(7).split(':');if(words.length!==2)return false;const a=parseInt(words[0],16),b=parseInt(words[1],16);return publicIp([a>>8,a&255,b>>8,b&255].join('.'));}
   // Match the local country service: global unicast 2000::/3, excluding documentation.
   const first=parseInt(address.split(':')[0],16);return first>=0x2000&&first<=0x3fff&&!address.startsWith('2001:db8:');
  }
  const [a,b,c]=address.split('.').map(Number);
  return a!==0&&a!==10&&a!==127&&a<224&&!(a===169&&b===254)&&!(a===172&&b>=16&&b<=31)&&!(a===192&&b===168)&&!(a===100&&b>=64&&b<=127)&&!(a===198&&(b===18||b===19))&&!(a===192&&b===0&&(c===0||c===2))&&!(a===198&&b===51&&c===100)&&!(a===203&&b===0&&c===113);
 }
 function country(value){const cc=typeof value==='string'&&/^[a-z]{2}$/i.test(value)?value.toUpperCase():'';return cc==='ZZ'||cc==='XX'?'':cc;}
 function parseDns(provider,body){
  if(!body||typeof body!=='object'||Array.isArray(body))throw Error('DNS 服务返回格式无效');
  const rows=[];
  function add(address,cc,place,isp){const normalized=ip(address);if(!normalized)throw Error('DNS 服务返回无效 IP');rows.push({ip:normalized,country:country(cc),place:String(place||'').slice(0,180),isp:String(isp||'').slice(0,180),source:provider});}
  if(provider==='Fastly'){
   const row=body.dns_resolver_info;if(!row||typeof row!=='object')throw Error('缺少 DNS 解析器记录');add(row.ip,row.cc,row.cc,row.as_name);
  }else{
   const entries=Object.entries(body);if(entries.length>100)throw Error('DNS 记录数量异常');
   for(const [address,row]of entries){
    if(provider==='BrowserLeaks IPv4'||provider==='BrowserLeaks IPv6'){if(!Array.isArray(row)||row.length<2)throw Error('BrowserLeaks 格式变化');add(address,row[0],row[1],row[2]);}
    else if(provider==='Surfshark'){if(!row||typeof row!=='object'||Array.isArray(row))throw Error('Surfshark 格式变化');add(address,row.CountryCode,[row.Country,row.City].filter(Boolean).join(', '),row.ISP);}
    else throw Error('未知 DNS 来源');
   }
  }
  if(!rows.length)throw Error('未取得解析器记录');return rows;
 }
 function finding(id,title,state,summary,evidence,limit,coverage){const bounded=evidence.length>24000?evidence.slice(0,24000)+'\n[证据展示达到上限；结论基于本次全部有效样本]':evidence;return {Id:id,Category:'浏览器实际网络路径',Title:title,State:state,IsClue:state==='发现线索'?true:state==='未发现'?false:null,Summary:summary,Evidence:bounded,Coverage:coverage||'当前浏览器 / 本次主动采样',Strength:'规则判定',Limit:limit,CheckedAt:new Date().toISOString(),Sources:null};}
 function dnsFinding(results){
  const samples=results.flatMap(r=>r.rows||[]).map(r=>({...r,country:country(r.country)})),unique=new Map();
  for(const row of samples){const key=row.ip+'|'+row.source+'|'+row.country;if(!unique.has(key))unique.set(key,row);}
  const rows=[...unique.values()],addresses=new Set(rows.map(r=>r.ip)),cn=new Set(rows.filter(r=>r.country==='CN').map(r=>r.ip));
  const failures=results.filter(r=>!r.rows?.length),unknown=rows.filter(r=>!r.country),conflicts=[...addresses].filter(a=>new Set(rows.filter(r=>r.ip===a&&r.country).map(r=>r.country)).size>1);
  let state='未发现',summary=`${addresses.size} 个 DNS 地址均未命中 CN 规则`;
  if(!addresses.size){state='读取失败';summary='没有有效 DNS 响应，未执行判定';}
  else if(cn.size){state='发现线索';summary=`${cn.size} 个 DNS 地址命中 CN 规则`;}
  else if(unknown.length){state='不可判定';summary=`${new Set(unknown.map(r=>r.ip)).size} 个 DNS 地址缺少国家标记，判定未完成`;}
  const coverage=`有效请求 ${results.length-failures.length}/${results.length}；失败 ${failures.length}；归属未知 ${new Set(unknown.map(r=>r.ip)).size}；归属冲突 ${conflicts.length}`;
  const evidence=[`请求 ${results.length}；有记录 ${results.length-failures.length}；无有效记录 ${failures.length}；独立解析器 ${addresses.size}`,...rows.map(r=>`${r.ip} | ${r.country||'归属未知'} | ${r.country==='CN'?'是线索':r.country?'不是线索':'归属查询未完成'} | ${r.place} | ${r.isp} | 来源 ${r.source}`),...failures.map(r=>`${r.source}：${r.error||'无结果'}`)].join('\n');
  return decorate(finding(6,'浏览器递归 DNS 出口',state,summary,evidence,'判定规则：本次有效响应中，任一解析器的国家标记为 CN → 是线索；全部已知且无 CN → 不是线索。来源冲突时保留 CN 命中；未知归属和请求失败单列检测状态。',coverage),'实际递归请求取得 '+addresses.size+' 个解析器地址','本次浏览器递归解析链存在中国大陆解析器','解析器明确 CN 地理标记支持中国网络解析关联；缓存域名和 Windows 网卡配置不替代实际递归结果。',rows.filter(r=>r.country==='CN').map(r=>r.ip+' | country=CN | source='+r.source).join('\n'),'网络解析关联');
 }
 function countryEvidence(row,fallback){
  const entries=[],seen=new Set();
  function add(cc,source){cc=country(cc);if(!cc)return;source=String(source||fallback||'国家字段');const key=cc+'|'+source;if(!seen.has(key)){seen.add(key);entries.push({country:cc,source});}}
  for(const s of row.countrySources||[])add(s.country||s.Country,s.source||s.Source);
  add(row.country||row.Country,row.countrySource||row.Source||row.source||fallback);return entries;
 }
 function mergeCountryEvidence(entries){const unique=new Map();for(const entry of entries)unique.set(entry.country+'|'+entry.source,entry);return [...unique.values()];}
 function countries(entries){return [...new Set(entries.map(s=>s.country))];}
 function describeCountries(entries){return entries.map(s=>s.source+':'+s.country).join(', ')||'无有效国家来源';}
 function decorate(f,observation,claim,why,matches,family){return Object.assign(f,{Observation:observation,SupportedClaim:f.IsClue?claim:f.IsClue===false?'本次有效资料不支持中国用户关联':'中国关联检测尚未完成',Reasoning:why,MatchingEvidence:matches,EvidenceFamily:f.IsClue?family:'',AlternativeExplanation:'国家资料描述网络出口/解析器，代理、共享网络和资料误差均可产生不同归属；不证明操作者位置或国籍。'});}
 function httpsFinding(results){
  const byAddress=new Map();
  for(const row of results){const address=ip(row.ip);if(!publicIp(address))continue;byAddress.set(address,mergeCountryEvidence([...(byAddress.get(address)||[]),...countryEvidence(row,row.name+' 端点国家字段')]));}
  const valid=results.filter(r=>publicIp(r.ip)).map(r=>({...r,ip:ip(r.ip),countries:byAddress.get(ip(r.ip))})),fail=results.length-valid.length,cn=valid.filter(r=>countries(r.countries).includes('CN')),unknown=valid.filter(r=>!r.countries.length);
  const conflicts=[...byAddress.values()].filter(s=>countries(s).length>1).length,groups=[valid.filter(r=>!r.ip.includes(':')),valid.filter(r=>r.ip.includes(':'))],split=groups.some(g=>new Set(g.map(r=>r.ip)).size>1);
  let state='未发现',summary='有效 HTTPS 国家资料没有中国大陆归属';
  if(!valid.length){state='读取失败';summary='未取得有效 HTTPS 出口，未生成中国关联判定';}
  else if(cn.length){state='发现线索';summary=new Set(cn.map(r=>r.ip)).size+' 个 HTTPS 出口有 CN 国家归属证据';}
  else if(unknown.length){state='不可判定';summary=unknown.length+' 个出口缺少国家资料，尚不能完成中国关联判断';}
  const evidence=results.map(r=>{const sources=byAddress.get(ip(r.ip))||[];return r.name+'：'+(ip(r.ip)||r.error||'无结果')+(ip(r.ip)&&!publicIp(r.ip)?' | 非有效公网出口':'')+' | country='+(countries(sources).join('/')||'未知')+' | 来源='+describeCountries(sources)+(r.countryError?' | '+r.countryError:'');}).join('\n');
  return decorate(finding(1,'浏览器 HTTPS / 网站出口',state,summary,evidence,'中国用户关联规则：实际公网出口的国家地理字段为 CN 才是线索；任意两个地址不同不指向中国。国家资料冲突保留 CN 并披露；缺失和失败单列状态。','有效请求 '+valid.length+'/'+results.length+'；请求失败 '+fail+'；国家未知 '+unknown.length+'；归属冲突 '+conflicts),split?'观察到同协议出口不同，这是路径差异事实':'已记录各 HTTPS 请求的实际出口','本次浏览器 HTTPS 路径存在中国大陆出口','以明确 CN 国家资料支持中国网络关联；路径不同只作为观察，不参与中国判断。',[...byAddress].filter(([,sources])=>countries(sources).includes('CN')).map(([address,sources])=>address+' | country=CN | 来源='+sources.filter(s=>s.country==='CN').map(s=>s.source).join(', ')).join('\n'),'网络出口');
 }
 function rtcFinding(rtc,https){
  const candidates=(rtc.candidates||[]).map(c=>({...c,address:ip(c.address)})),publics=[...new Set(candidates.filter(c=>c.type!=='relay'&&publicIp(c.address)).map(c=>c.address))];
  const observed=publics.map(address=>{const rows=(rtc.geography||[]).filter(g=>ip(g.Ip||g.ip)===address);return {address,sources:mergeCountryEvidence(rows.flatMap(g=>countryEvidence(g,'国家查询'))),errors:rows.map(g=>g.Error||g.error).filter(Boolean)};});
  const cn=observed.filter(c=>countries(c.sources).includes('CN')),unknown=observed.filter(c=>!c.sources.length),conflicts=observed.filter(c=>countries(c.sources).length>1);
  const baseline=https.map(r=>ip(r.ip)).filter(Boolean),diff=publics.filter(a=>baseline.some(b=>a.includes(':')===b.includes(':'))&&!baseline.includes(a));
  let state='未发现',summary=publics.length?'有效 WebRTC 公网国家资料没有中国大陆归属':'ICE 完成且没有非中继公网候选，未取得中国出口线索';
  if(cn.length){state='发现线索';summary=cn.length+' 个 WebRTC 公网候选有 CN 国家归属证据';}
  else if(rtc.error||!rtc.completed){state='读取失败';summary='ICE 尚未完成，没有生成否定结论';}
  else if(unknown.length){state='不可判定';summary=unknown.length+' 个公网候选缺少国家资料，尚未完成中国关联判断';}
  const evidence=[rtc.error?'采样失败：'+rtc.error:'STUN：stun.l.google.com:19302',...observed.map(c=>c.address+' | country='+(countries(c.sources).join('/')||'未知')+' | source='+describeCountries(c.sources)+(c.errors.length?' | '+c.errors.join('; '):'')),...candidates.filter(c=>!publicIp(c.address)||c.type==='relay').map(c=>(c.address||c.rawAddress||'隐藏地址')+' | '+c.type+' | 非有效直接公网地域证据'),'同次 HTTPS 地址：'+baseline.join(', '),'同协议路径差异数='+diff.length+'；路径差异本身不指向中国大陆'].join('\n');
  return decorate(finding(3,'浏览器 WebRTC 路径',state,summary,evidence,'中国用户关联规则：非中继公网候选必须有 CN 地理资料才是线索；与 HTTPS 出口不同只说明路径不同，不证明中国。归属冲突保留 CN 并披露；私网、mDNS、TURN 不作用户地域证据。','ICE '+(rtc.completed&&!rtc.error?'完成':'未完成')+'；公网候选 '+publics.length+'；国家未知 '+unknown.length+'；归属冲突 '+conflicts.length+'；路径差异 '+diff.length),diff.length?'存在 WebRTC/HTTPS 路径差异；该差异本身不指向中国大陆':'已记录 WebRTC 实际候选；未观察到可比较的同协议路径差异','本次浏览器 WebRTC 路径存在中国大陆出口','以非中继公网地址的 CN 国家资料支持中国关联；不把任意泄漏/差异解释成中国用户。',cn.map(c=>c.address+' | country=CN | source='+c.sources.filter(s=>s.country==='CN').map(s=>s.source).join(', ')).join('\n'),'网络出口');
 }
 const api={ip,publicIp,country,parseDns,dnsFinding,httpsFinding,rtcFinding};if(typeof module==='object'&&module.exports)module.exports=api;else root.LocalLensNetwork=api;
})(typeof window==='object'?window:this);
