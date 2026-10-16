'use strict';
// LocalLens 2.7: these three observations belong to the current main scan.
// The controller in app.js owns all UI, progress, options and cancellation.
let browserNetworkReport=null,unsavedNetworkReport=null,networkBusy=false,networkAbort=null,currentNetworkRun=null,networkScanId='';
function readableError(error){return error.name==='AbortError'?'请求取消或超时':error.message==='Failed to fetch'?'浏览器无法读取响应（网络、CORS 或拦截）':String(error.message||error).slice(0,250);}
async function probeFetch(url,json=true,signal){
 const controller=new AbortController(),abort=()=>controller.abort();signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)controller.abort();
 const timer=setTimeout(abort,7000);
 try{const response=await fetch(url,{cache:'no-store',credentials:'omit',referrerPolicy:'no-referrer',signal:controller.signal});if(!response.ok)throw Error(`HTTP ${response.status}`);const text=await response.text();if(text.length>131072)throw Error('响应过大');return json?JSON.parse(text):text;}
 finally{clearTimeout(timer);signal?.removeEventListener('abort',abort);}
}
async function collectHttps(signal){
 const endpoints=[['IPv4 · ipify','https://api.ipify.org?format=json'],['IPv6 · ipify','https://api6.ipify.org?format=json'],['claude.com','https://claude.com/cdn-cgi/trace'],['claude.ai','https://claude.ai/cdn-cgi/trace']];
 return Promise.all(endpoints.map(async([name,url])=>{try{const value=await probeFetch(url,!url.includes('/trace'),signal);const fields=typeof value==='string'?Object.fromEntries(value.trim().split('\n').map(line=>line.split(/=(.*)/s).slice(0,2))):value;const address=LocalLensNetwork.ip(fields.ip);if(!address)throw Error('端点未返回有效 IP');if(name.startsWith('IPv6')&&!address.includes(':'))throw Error('IPv6 端点返回 IPv4，IPv6 未完成');return {name,ip:address,country:fields.loc||''};}catch(error){return {name,error:readableError(error)};}}));
}
async function collectDns(signal){
 const providers=[['BrowserLeaks IPv4','dns4.browserleaks.net','/'],['BrowserLeaks IPv6','dns6.browserleaks.net','/'],['Surfshark','ipv4.surfsharkdns.com','/'],['Fastly','u.fastly-analytics.com','/debug_resolver']];
 const jobs=[];
 // BrowserLeaks accepts a ten-hex-digit label; longer labels can fail during TLS.
 for(const [source,domain,path]of providers)for(let i=0;i<3;i++)jobs.push((async()=>{const random=Array.from(crypto.getRandomValues(new Uint8Array(source.startsWith('BrowserLeaks')?5:16)),b=>b.toString(16).padStart(2,'0')).join('');try{return {source,rows:LocalLensNetwork.parseDns(source,await probeFetch(`https://${random}.${domain}${path}`,true,signal))};}catch(error){return {source,error:readableError(error)};}})());
 return Promise.all(jobs);
}
async function collectRtc(signal){
 const result={completed:false,candidates:[]};let pc,timer,finish;
 try{
  if(typeof RTCPeerConnection==='undefined')throw Error('浏览器未开放 RTCPeerConnection');
  pc=new RTCPeerConnection({iceServers:[{urls:'stun:stun.l.google.com:19302'}]});pc.createDataChannel('locallens-check');
  const gathered=new Promise(resolve=>{finish=()=>{clearTimeout(timer);resolve();};timer=setTimeout(()=>{result.error='ICE 收集超过 10 秒，保留部分候选';finish();},10000);pc.onicecandidate=event=>{if(!event.candidate){result.completed=true;finish();return;}const c=event.candidate,parts=c.candidate.split(/\s+/);if(result.candidates.length<128)result.candidates.push({address:c.address||parts[4],rawAddress:c.address||parts[4],type:c.type||parts[parts.indexOf('typ')+1],protocol:c.protocol||parts[2]});};pc.onicegatheringstatechange=()=>{if(pc.iceGatheringState==='complete'){result.completed=true;finish();}};});
  const abort=()=>{result.error='用户取消';finish();};signal?.addEventListener('abort',abort,{once:true});
  // Bound negotiation too: a stalled createOffer/setLocalDescription must not
  // keep the unified scan open after the ICE timeout or a user's cancellation.
  try{if(signal?.aborted)throw Error('用户取消');await Promise.race([(async()=>{await pc.setLocalDescription(await pc.createOffer());await gathered;})(),gathered]);}finally{signal?.removeEventListener('abort',abort);}
 }catch(error){result.error=readableError(error);}finally{clearTimeout(timer);pc?.close();}
 return result;
}
async function enrichCountryEvidence(https,rtc,signal){
 const addresses=[...new Set([...https.map(r=>r.ip),...rtc.candidates.filter(c=>c.type!=='relay').map(c=>c.address)].filter(a=>LocalLensNetwork.publicIp(a)).map(a=>LocalLensNetwork.ip(a)))].slice(0,16);
 if(!addresses.length){rtc.geography=[];return;}
 let geography;try{geography=await request('/api/network-countries',{method:'POST',body:JSON.stringify(addresses),signal});if(!Array.isArray(geography))throw Error('本机国家查询返回格式无效');}catch(error){geography=addresses.map(Ip=>({Ip,Source:'ipwho.is',Error:readableError(error)}));}
 const sourcesByIp=new Map(addresses.map(address=>[address,[]])),errorsByIp=new Map();
 function add(address,cc,source){address=LocalLensNetwork.ip(address);cc=LocalLensNetwork.country(cc);const sources=sourcesByIp.get(address);if(cc&&sources&&!sources.some(s=>s.country===cc&&s.source===source))sources.push({country:cc,source});}
 // Country fields describe an address. Share them across simultaneous endpoints for
 // that canonical address, while retaining the name of the endpoint that supplied them.
 for(const row of https)add(row.ip,row.country,row.name+' 端点国家字段');
 for(const g of geography){const address=LocalLensNetwork.ip(g.Ip);add(address,g.Country,g.Source||'ipwho.is');if(sourcesByIp.has(address)&&(g.Error||!LocalLensNetwork.country(g.Country)))errorsByIp.set(address,g.Error||'国家字段无效或未知');}
 for(const row of https){const address=LocalLensNetwork.ip(row.ip);row.countrySources=(sourcesByIp.get(address)||[]).map(s=>({...s}));if(errorsByIp.has(address))row.countryError=errorsByIp.get(address);}
 rtc.geography=addresses.map(Ip=>{const sources=sourcesByIp.get(Ip),chosen=sources.find(s=>s.country==='CN')||sources[0];return {Ip,Country:chosen?.country,Source:chosen?.source,Error:errorsByIp.get(Ip),countrySources:sources.map(s=>({...s}))};});
}
function cancelBrowserNetworkScan(){
 const run=currentNetworkRun;if(run)run.controller.abort();
 currentNetworkRun=null;networkAbort=null;networkBusy=false;
}
function resetBrowserNetworkReport(scanId=''){
 cancelBrowserNetworkScan();networkScanId=String(scanId||'');
 browserNetworkReport=null;unsavedNetworkReport=null;
}
function getBrowserNetworkReport(scanId){
 return String(scanId||'')===networkScanId?(unsavedNetworkReport||browserNetworkReport):null;
}
async function runBrowserNetworkScan(options={}){
 const scanId=String(options.scanId||options.scanBatchId||'');
 if(!scanId||scanId.length>128)throw Error('浏览器网络检测缺少有效主扫描批次');
 resetBrowserNetworkReport(scanId);
 const run={scanId,controller:new AbortController()};
 currentNetworkRun=run;networkAbort=run.controller;networkBusy=true;
 const signal=run.controller.signal,abort=()=>run.controller.abort();
 options.signal?.addEventListener('abort',abort,{once:true});if(options.signal?.aborted)abort();
 const current=()=>currentNetworkRun===run&&networkScanId===scanId&&!signal.aborted;
 const progress=(completed,stage,message)=>{if(current()&&typeof options.onProgress==='function')options.onProgress({scanId,completed,total:3,stage,message});};
 const started=new Date().toISOString();
 const work=async()=>{
  if(!current())return null;
  progress(0,'collect','正在检测 DNS、WebRTC 和 HTTPS 实际网络路径');
  const [dns,https,rtc]=await Promise.all([collectDns(signal),collectHttps(signal),collectRtc(signal)]);
  if(!current())return null;
  progress(1,'countries','已取得网络样本，正在核对公网地址的国家归属');
  await enrichCountryEvidence(https,rtc,signal);
  if(!current())return null;
  progress(2,'save','网络规则判定完成，正在合并到本批主检测');
  // The 2.4 identifier is the existing server's strict evidence wire format,
  // not a separate UI mode. Do not send client-only lifecycle fields in it.
  const payload={RuleVersion:'ChinaUserEvidence2.4',StartedUtc:started,FinishedUtc:new Date().toISOString(),Browser:navigator.userAgent,Findings:[LocalLensNetwork.dnsFinding(dns),LocalLensNetwork.rtcFinding(rtc,https),LocalLensNetwork.httpsFinding(https)]};
  const report={...payload,ScanId:scanId,Saved:false,SaveError:''};
  try{
   await request('/api/browser-network',{method:'POST',headers:{'X-LocalLens-Scan-Id':scanId},body:JSON.stringify(payload),signal});
   if(!current())return null;
   report.Saved=true;unsavedNetworkReport=null;
  }catch(error){
   if(!current()||error.status===409)return null;
   report.SaveError=readableError(error);unsavedNetworkReport=report;
  }
  if(!current())return null;
  browserNetworkReport=report;
  progress(3,'complete',report.Saved?'网络检测已并入本批主结果':'网络检测已在本页保留，服务保存未完成');
  return report;
 };
 // Local requests can stall too. The main scan must finish even when a
 // provider/transport ignores AbortSignal; late work remains invalid above.
 const requestedTimeout=Number(options.timeoutMs),timeoutMs=Number.isFinite(requestedTimeout)&&requestedTimeout>0?Math.min(requestedTimeout,75000):75000;
 let interrupted;
 const stopped=new Promise(resolve=>{interrupted=()=>resolve(null);signal.addEventListener('abort',interrupted,{once:true});if(signal.aborted)interrupted();});
 const deadlineTimer=setTimeout(abort,timeoutMs);
 try{return await Promise.race([work(),stopped]);}finally{
  clearTimeout(deadlineTimer);signal.removeEventListener('abort',interrupted);
  options.signal?.removeEventListener('abort',abort);
  if(currentNetworkRun===run){currentNetworkRun=null;networkAbort=null;networkBusy=false;}
 }
}
