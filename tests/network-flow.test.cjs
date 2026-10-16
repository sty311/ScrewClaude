'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const {webcrypto}=require('node:crypto');
const core=require('../web/network-core.js');
const source=fs.readFileSync(require.resolve('../web/network.js'),'utf8');
const candidate=(address,type='srflx')=>({address,type,protocol:'udp'});
let count=0;async function check(name,run){await run();count++;console.log('PASS: '+name);}
function deferred(){let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};}

function harness(options={}){
 const urls=[],countryCalls=[],saveCalls=[],progress=[];
 let failSave=options.failSave??true,saved,serial=0,rtcClosed=0;
 class SyntheticRtc{
  createDataChannel(){}async createOffer(){return {};}
  async setLocalDescription(){for(const c of options.candidates||[candidate('1.1.1.1')])this.onicecandidate({candidate:{...c,candidate:'candidate:1 1 udp 1 '+c.address+' 12345 typ '+c.type}});this.onicecandidate({candidate:null});}
  close(){rtcClosed++;}
 }
 // Deliberately no DOM, consent dialog, optional-panel button or toast exists.
 // This module must operate exclusively as a component of the main scan.
 const context=vm.createContext({LocalLensNetwork:core,crypto:webcrypto,AbortController,RTCPeerConnection:options.rtcClass||SyntheticRtc,setTimeout,clearTimeout,Uint8Array,Date,navigator:{userAgent:'synthetic-test'},
  fetch:async(url,init)=>{
   // All traffic is synthetic; no external requests or local server are used.
   urls.push(url);assert.equal(init.credentials,'omit');assert.equal(init.referrerPolicy,'no-referrer');assert.ok(init.signal);
   if(options.fetch)return options.fetch(url,init);
   let data;
   if(url.includes('.browserleaks.net')){
    if(!/^https:\/\/[0-9a-f]{10}\.dns[46]\.browserleaks\.net\/$/.test(url))throw Error('Failed to fetch');
    data=url.includes('.dns6.')?{'2408:8000:2009::b3':['CN','China','Synthetic ISP']}:{'202.99.96.214':['CN','China','Synthetic ISP']};
   }else if(url.includes('surfsharkdns'))data={'8.8.8.8':{CountryCode:'US',Country:'US',ISP:'Synthetic'}};
   else if(url.includes('fastly-analytics'))data={dns_resolver_info:{ip:'8.8.4.4',cc:'US'}};
   else if(url.includes('/trace'))return {ok:true,text:async()=> 'ip=1.1.1.1\nloc='+(options.traceCountry??'US')};
   else data={ip:url.includes('api6.')?'2606:4700:4700::1111':'1.1.1.1'};
   return {ok:true,text:async()=>JSON.stringify(data)};
  },request:async(path,init)=>{
   if(path==='/api/network-countries'){
    const ips=JSON.parse(init.body);assert.ok(ips.length>0&&ips.length<=16&&ips.every(core.publicIp));assert.ok(init.signal&&typeof init.signal.addEventListener==='function');countryCalls.push({ips,signal:init.signal});
    return options.countryLookup?options.countryLookup(ips,init):ips.map(Ip=>({Ip,Country:'US',Source:'synthetic country source'}));
   }
   assert.equal(path,'/api/browser-network');saved=JSON.parse(init.body);saveCalls.push({report:saved,init});assert.equal(saved.RuleVersion,'ChinaUserEvidence2.4');
   assert.ok(init.headers['X-LocalLens-Scan-Id']);assert.ok(init.signal);
   if(options.saveResult)return options.saveResult(saved,init);
   if(failSave)throw Error('synthetic service failure');
   return {ok:true};
  }
 });
 vm.runInContext(source,context);
 return {urls,countryCalls,saveCalls,progress,context,get saved(){return saved;},get rtcClosed(){return rtcClosed;},set failSave(value){failSave=value;},
  run:(runOptions={})=>context.runBrowserNetworkScan({scanId:'scan-'+(++serial),onProgress:value=>progress.push(value),...runOptions}),
  reset:scanId=>context.resetBrowserNetworkReport(scanId),cancel:()=>context.cancelBrowserNetworkScan(),report:scanId=>context.getBrowserNetworkReport(scanId),
  enrich:async(https,rtc)=>context.enrichCountryEvidence(https,rtc,new AbortController().signal)};
}

(async()=>{
 await check('loading the integrated module requires no DOM and starts no external request',async()=>{
  const h=harness();assert.equal(h.urls.length,0);assert.equal(h.countryCalls.length,0);assert.equal(h.saveCalls.length,0);assert.equal(h.report(''),null);
 });
 await check('a scan ID is required before any network observation starts',async()=>{
  const h=harness();await assert.rejects(h.run({scanId:''}),/有效主扫描批次/);assert.equal(h.urls.length,0);
 });
 const h=harness();let first;
 await check('provider-compatible random URLs retain IPv4 and IPv6 CN samples through the main workflow',async()=>{
  first=await h.run({scanId:'main-1'});const dns=h.saved.Findings.find(f=>f.Id===6);
  assert.equal(h.urls.filter(url=>url.includes('.browserleaks.net')).length,6);
  assert.match(dns.Evidence,/请求 12；有记录 12；无有效记录 0/);
  assert.equal(new Set(h.urls.filter(url=>/browserleaks|surfsharkdns|fastly-analytics/.test(url))).size,12);
  assert.equal(dns.State,'发现线索');assert.match(dns.Evidence,/2408:8000:2009::b3/);assert.match(dns.MatchingEvidence,/country=CN/);
  assert.deepEqual(h.progress.map(p=>p.completed),[0,1,2,3]);assert.ok(h.progress.every(p=>p.scanId==='main-1'&&p.total===3));
 });
 await check('the save carries the same main scan ID header without changing the strict evidence payload',async()=>{
  assert.equal(h.countryCalls.length,1);assert.equal(h.countryCalls[0].signal.aborted,false);
  assert.equal(h.saveCalls[0].init.headers['X-LocalLens-Scan-Id'],'main-1');assert.equal(h.saved.ScanId,undefined);assert.equal(first.ScanId,'main-1');
  for(const id of [1,3]){const f=h.saved.Findings.find(f=>f.Id===id);assert.equal(f.IsClue,false);assert.ok(f.Observation&&f.Reasoning&&f.AlternativeExplanation);assert.equal(f.MatchingEvidence,'');}
 });
 await check('ordinary save failure returns actual results for the main report and local export',async()=>{
  assert.equal(first.Saved,false);assert.match(first.SaveError,/synthetic service failure/);assert.equal(h.report('main-1'),first);assert.equal(h.report('another-main'),null);
 });
 await check('a new main scan clears old reports before its network observations complete',async()=>{
  const before=h.urls.length;h.reset('main-2');assert.equal(h.report('main-1'),null);assert.equal(h.report('main-2'),null);assert.equal(h.urls.length,before);
 });
 await check('a later successful save releases the previous unsaved-report guard',async()=>{
  h.failSave=false;const report=await h.run({scanId:'main-3'});assert.equal(report.Saved,true);assert.equal(report.SaveError,'');assert.equal(h.report('main-3'),report);assert.equal(h.report('main-1'),null);
 });
 await check('canonical HTTPS addresses share endpoint attribution with WebRTC after a lookup failure',async()=>{
  const h=harness({countryLookup:ips=>ips.map(Ip=>({Ip,Source:'synthetic lookup',Error:'synthetic lookup unavailable'}))});
  const https=[{name:'IPv6 ipify',ip:'2606:4700:4700:0:0:0:0:1111'},{name:'claude.com',ip:'2606:4700:4700::1111',country:'JP'}],rtc={completed:true,candidates:[candidate('2606:4700:4700::1111')]};
  await h.enrich(https,rtc);assert.equal(h.countryCalls[0].ips.length,1);
  assert.equal(https[0].countrySources.length,1);assert.equal(https[0].countrySources[0].source,'claude.com 端点国家字段');
  const web=core.httpsFinding(https),ice=core.rtcFinding(rtc,https);assert.equal(web.IsClue,false);assert.equal(ice.IsClue,false);assert.match(web.Coverage,/国家未知 0/);assert.match(web.Evidence,/synthetic lookup unavailable/);assert.match(ice.Evidence,/claude\.com 端点国家字段:JP/);
 });
 await check('CN endpoint evidence survives foreign lookup conflict for HTTPS and same-path WebRTC',async()=>{
  const h=harness(),https=[{name:'ipify',ip:'1.1.1.1'},{name:'claude.ai',ip:'1.1.1.1',country:'cn'}],rtc={completed:true,candidates:[candidate('1.1.1.1')]};
  await h.enrich(https,rtc);
  for(const result of [core.httpsFinding(https),core.rtcFinding(rtc,https)]){assert.equal(result.IsClue,true);assert.match(result.Coverage,/归属冲突 1/);assert.match(result.Evidence,/synthetic country source:US/);assert.match(result.MatchingEvidence,/country=CN.*claude\.ai 端点国家字段/);assert.doesNotMatch(result.MatchingEvidence,/synthetic country source/);}
 });
 await check('unknown placeholder country values remain unclassified observations for main-scan skipping',async()=>{
  const h=harness({countryLookup:ips=>ips.map(Ip=>({Ip,Country:'XX',Source:'synthetic lookup'}))}),https=[{name:'trace',ip:'1.1.1.1',country:'ZZ'}],rtc={completed:true,candidates:[candidate('1.1.1.1')]};
  await h.enrich(https,rtc);assert.equal(core.httpsFinding(https).IsClue,null);assert.equal(core.rtcFinding(rtc,https).IsClue,null);assert.match(core.httpsFinding(https).Evidence,/国家字段无效或未知/);
 });
 await check('failed country lookup retains raw addresses and actual failure reasons',async()=>{
  const h=harness({countryLookup:()=>{throw Error('synthetic country service failure');}}),https=[{name:'ipify',ip:'8.8.8.8'}],rtc={completed:true,candidates:[candidate('1.1.1.1')]};
  await h.enrich(https,rtc);for(const result of [core.httpsFinding(https),core.rtcFinding(rtc,https)]){assert.equal(result.IsClue,null);assert.match(result.Evidence,/synthetic country service failure/);}
 });
 await check('country enrichment sends only deduplicated eligible public non-relay addresses',async()=>{
  const h=harness(),https=[{name:'public',ip:'8.8.8.8'},{name:'private',ip:'192.0.0.9',country:'CN'},{name:'special-v6',ip:'300::1'}],rtc={completed:true,candidates:[candidate('8.8.8.8'),candidate('192.168.1.1'),candidate('::2'),candidate('1.1.1.1','relay')]};
  await h.enrich(https,rtc);assert.deepEqual(h.countryCalls[0].ips,['8.8.8.8']);assert.equal(https[1].countrySources.length,0);assert.equal(core.rtcFinding(rtc,https).IsClue,false);
 });
 await check('country lookup address cap leaves unsampled countries unclassified',async()=>{
  const h=harness(),https=Array.from({length:20},(_,i)=>({name:'endpoint '+i,ip:'8.8.8.'+(i+1)})),rtc={completed:true,candidates:[]};
  await h.enrich(https,rtc);assert.equal(h.countryCalls[0].ips.length,16);const result=core.httpsFinding(https);assert.equal(result.IsClue,null);assert.match(result.Coverage,/国家未知 4/);
 });
 await check('malformed country response is retained as a disclosed failed observation',async()=>{
  const h=harness({countryLookup:()=>({unexpected:true})}),https=[{name:'a',ip:'8.8.8.8'}],rtc={completed:true,candidates:[]};
  await h.enrich(https,rtc);const result=core.httpsFinding(https);assert.equal(result.IsClue,null);assert.match(result.Evidence,/本机国家查询返回格式无效/);
 });
 await check('main cancellation aborts in-flight country lookup and cannot save a partial cancelled report',async()=>{
  const started=deferred(),controller=new AbortController();
  const h=harness({traceCountry:'',failSave:false,countryLookup:(_ips,init)=>new Promise((_resolve,reject)=>{init.signal.addEventListener('abort',()=>{const error=Error('synthetic abort');error.name='AbortError';reject(error);},{once:true});started.resolve();})});
  const running=h.run({scanId:'cancelled-main',signal:controller.signal});await started.promise;controller.abort();assert.equal(await running,null);
  assert.equal(h.countryCalls[0].signal.aborted,true);assert.equal(h.saveCalls.length,0);assert.equal(h.report('cancelled-main'),null);assert.equal(h.progress.some(p=>p.completed===3),false);assert.equal(h.rtcClosed,1);
 });
 await check('explicit cancel function invalidates the current run even when an old provider ignores abort',async()=>{
  const started=deferred(),late=deferred();const h=harness({countryLookup:()=>{started.resolve();return late.promise;}});
  const running=h.run({scanId:'cancel-method'});await started.promise;h.cancel();late.resolve([]);assert.equal(await running,null);assert.equal(h.saveCalls.length,0);assert.equal(h.report('cancel-method'),null);
 });
 await check('late observations from a replaced main scan cannot overwrite or save into a new batch',async()=>{
  const started=deferred(),late=deferred();let lookupCount=0;
  const h=harness({failSave:false,countryLookup:ips=>{if(++lookupCount===1){started.resolve();return late.promise;}return ips.map(Ip=>({Ip,Country:'US',Source:'new-main'}));}});
  const old=h.run({scanId:'old-main'});await started.promise;const next=await h.run({scanId:'new-main'});const progressCount=h.progress.length;late.resolve([{Ip:'1.1.1.1',Country:'CN',Source:'late-old-main'}]);assert.equal(await old,null);
  assert.equal(h.saveCalls.length,1);assert.equal(h.saveCalls[0].init.headers['X-LocalLens-Scan-Id'],'new-main');assert.equal(h.report('new-main'),next);assert.equal(h.report('old-main'),null);assert.equal(h.progress.length,progressCount);
 });
 await check('server HTTP 409 rejects stale results instead of retaining an unsaved fallback',async()=>{
  const h=harness({saveResult:()=>{const error=Error('批次已更新');error.status=409;throw error;}});assert.equal(await h.run({scanId:'stale-main'}),null);assert.equal(h.report('stale-main'),null);assert.equal(h.progress.some(p=>p.completed===3),false);
 });
 await check('cancellation while the save is unresolved cannot adopt its late successful response',async()=>{
  const started=deferred(),late=deferred(),controller=new AbortController();const h=harness({saveResult:()=>{started.resolve();return late.promise;}});
  const running=h.run({scanId:'saving-main',signal:controller.signal});await started.promise;controller.abort();late.resolve({ok:true});assert.equal(await running,null);assert.equal(h.report('saving-main'),null);assert.equal(h.progress.some(p=>p.completed===3),false);
 });
 await check('an already cancelled main scan produces no external traffic',async()=>{
  const h=harness(),controller=new AbortController();controller.abort();assert.equal(await h.run({signal:controller.signal}),null);assert.equal(h.urls.length,0);assert.equal(h.saveCalls.length,0);assert.equal(h.progress.length,0);
 });
 await check('main cancellation also releases a stalled RTC negotiation and closes the peer',async()=>{
  const started=deferred(),controller=new AbortController();let closed=0;
  class StalledRtc{createDataChannel(){}createOffer(){started.resolve();return new Promise(()=>{});}close(){closed++;}}
  const h=harness({rtcClass:StalledRtc,failSave:false}),running=h.run({scanId:'stalled-rtc',signal:controller.signal});await started.promise;controller.abort();assert.equal(await running,null);assert.equal(closed,1);assert.equal(h.saveCalls.length,0);
 });
 await check('the overall deadline releases a country lookup that ignores abort and rejects its late data',async()=>{
  const started=deferred(),late=deferred();const h=harness({failSave:false,countryLookup:()=>{started.resolve();return late.promise;}});
  const running=h.run({scanId:'country-deadline',timeoutMs:20});await started.promise;assert.equal(await running,null);
  assert.equal(h.countryCalls[0].signal.aborted,true);assert.equal(h.saveCalls.length,0);assert.equal(h.report('country-deadline'),null);const progressCount=h.progress.length;
  late.resolve([{Ip:'1.1.1.1',Country:'CN',Source:'late-timeout-sample'}]);await new Promise(resolve=>setTimeout(resolve,0));
  assert.equal(h.saveCalls.length,0);assert.equal(h.progress.length,progressCount);assert.equal(h.report('country-deadline'),null);
 });
 await check('all three unreadable network checks still return disclosed evidence for unified skipping',async()=>{
  class FailedRtc{constructor(){throw Error('synthetic RTC unavailable');}}
  const h=harness({rtcClass:FailedRtc,failSave:false,fetch:()=>{throw Error('synthetic endpoint unavailable');}}),report=await h.run({scanId:'all-unreadable'});
  assert.equal(report.Saved,true);assert.equal(report.Findings.length,3);assert.deepEqual(Array.from(report.Findings,f=>f.Id),[6,3,1]);
  for(const finding of report.Findings){assert.equal(finding.IsClue,null);assert.ok(['读取失败','不可判定'].includes(finding.State));assert.match(finding.Evidence,/synthetic/);}
 });
 console.log('Network flow checks: '+count+' passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
