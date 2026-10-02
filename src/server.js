import express from 'express';
import helmet from 'helmet';
import http from 'node:http';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import * as cheerio from 'cheerio';
import pLimit from 'p-limit';
import { ProxyPool } from './pool.js';
import { validatePublicTarget } from './security.js';
import { requestViaProxy, openProxyStream } from './proxy.js';
import { scanWebsite } from './scanner.js';
import { saveScanResult } from './database.js';
import { regionForCountry } from './regions.js';
import { initThreatIntel, refreshThreatIntel, status as threatIntelStatus } from './threat-intel.js';
import { startProxyGateways } from './gateway.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');
const int = (name, fallback) => Number.parseInt(process.env[name] || String(fallback), 10);
const bool = (name, fallback = false) => String(process.env[name] ?? String(fallback)).toLowerCase() === 'true';
const displayNames = (() => { try { return new Intl.DisplayNames(['en'], { type:'region' }); } catch { return null; } })();
const normalizeCountry = code => String(code || 'XX').toUpperCase() === 'UK' ? 'GB' : String(code || 'XX').toUpperCase();
const countryName = code => { const c=normalizeCountry(code); if(c==='XX')return 'Unknown'; try{return displayNames?.of(c)||c;}catch{return c;} };

const config = {
  port:int('PORT',3210), adminToken:process.env.ADMIN_TOKEN||'', sourceRefreshMs:int('SOURCE_REFRESH_MS',300000), healthIntervalMs:int('HEALTHCHECK_INTERVAL_MS',60000),
  healthTimeoutMs:int('HEALTHCHECK_TIMEOUT_MS',7000), healthBatchSize:int('HEALTHCHECK_BATCH_SIZE',80), maxProxies:int('MAX_PROXIES',5000), healthcheckUrl:process.env.HEALTHCHECK_URL||'https://api.ipify.org?format=json',
  exposeAddresses:bool('EXPOSE_NODE_ADDRESSES'), maxTestBytes:int('MAX_TEST_RESPONSE_BYTES',262144), testTimeoutMs:int('TEST_TIMEOUT_MS',10000),
  matrixMaxNodes:Math.max(1,Math.min(30,int('TEST_MATRIX_MAX_NODES',20))), matrixConcurrency:Math.max(1,Math.min(10,int('TEST_MATRIX_CONCURRENCY',4))),
  previewSessionTtlMs:Math.max(60000,int('PREVIEW_SESSION_TTL_MS',900000)), previewTimeoutMs:Math.max(5000,int('PREVIEW_TIMEOUT_MS',45000)), previewMaxHtmlBytes:Math.max(65536,int('PREVIEW_MAX_HTML_BYTES',2097152)),
  previewMaxResourceBytes:Math.max(65536,int('PREVIEW_MAX_RESOURCE_BYTES',16777216)), previewMaxDownloadBytes:Math.max(1048576,int('PREVIEW_MAX_DOWNLOAD_BYTES',33554432)), previewMaxStreamBytes:Math.max(1048576,int('PREVIEW_MAX_STREAM_BYTES',536870912)),
  previewUserAgent:process.env.PREVIEW_USER_AGENT||'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0',
  publicRateLimitWindowMs:Math.max(10000,int('PUBLIC_RATE_LIMIT_WINDOW_MS',60000)), publicRateLimitMax:Math.max(5,int('PUBLIC_RATE_LIMIT_MAX',60)), scanRateLimitMax:Math.max(1,int('SCAN_RATE_LIMIT_MAX',12)),
  scanTimeoutMs:Math.max(3000,int('SCAN_TIMEOUT_MS',12000)), scanMaxBytes:Math.max(65536,int('SCAN_MAX_BYTES',1048576)),
  virusTotalApiKey:process.env.VIRUSTOTAL_API_KEY||'', googleWebRiskApiKey:process.env.GOOGLE_WEB_RISK_API_KEY||'', storeScanHistory:bool('STORE_SCAN_HISTORY'),
  openPhishEnabled:bool('OPENPHISH_ENABLED',true), openPhishFeedUrl:process.env.OPENPHISH_FEED_URL||'https://openphish.com/feed.txt',
  threatFeedRefreshMs:Math.max(60*60*1000,int('THREAT_FEED_REFRESH_MS',12*60*60*1000)), threatFeedCachePath:process.env.THREAT_FEED_CACHE_PATH||'/app/data/openphish-cache.json',
  clamavHost:process.env.CLAMAV_HOST||'', clamavPort:int('CLAMAV_PORT',3310),
  browserTicketTtlMs:Math.max(15000,Math.min(300000,int('BROWSER_TICKET_TTL_MS',90000)))
};

const pool = new ProxyPool(config);
await pool.loadState();
await initThreatIntel(config).catch(error => console.error('[threat-intel] init:', error.message));

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', bool('TRUST_PROXY') ? 1 : false);
app.use(helmet({ contentSecurityPolicy:false, crossOriginEmbedderPolicy:false }));
app.use(express.json({ limit:'64kb' }));
app.use((req,res,next)=>{
  const frontendAsset=/\.(?:html|js|css)$/i.test(req.path)||['/','/tester','/preview','/browser','/scanner','/api','/api/docs'].includes(req.path);
  if(frontendAsset){res.set('Cache-Control','no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0');res.set('Pragma','no-cache');res.set('Expires','0');res.set('Surrogate-Control','no-store');}
  next();
});
app.use(express.static(path.join(root,'public'),{maxAge:0,etag:false,lastModified:false}));

const nodeRef=node=>createHash('sha256').update(node.id).digest('hex').slice(0,24);
const findNodeByRef=ref=>[...pool.nodes.values()].find(node=>nodeRef(node)===ref)||null;
const safeNode=node=>({
  ref:nodeRef(node),protocol:node.protocol,country:normalizeCountry(node.country),countryName:countryName(node.country),city:node.city,region:node.region,
  anonymity:node.anonymity,status:node.status,latencyMs:node.latencyMs,lastCheck:node.lastCheck,lastSuccess:node.lastSuccess,
  address:config.exposeAddresses?`${node.ip}:${node.port}`:'hidden',
  network:{connectionType:node.connectionType||null,isVpn:node.isVpn??null,isProxy:node.isProxy??null,isTor:node.isTor??null,isHostingProvider:node.isHostingProvider??null,isNonResidential:node.isNonResidential??null,isHomeResidential:node.isHomeResidential??null,asn:node.ipAsn??null,org:node.ipOrg||null,confidence:node.ipConfidence||null,detectionSource:node.ipDetectionSource||null,detectionReason:node.ipDetectionReason||null,lookupAt:node.ipLookupAt||null},
  reliability:(node.successes||0)+(node.failures||0)?Math.round((node.successes||0)/((node.successes||0)+(node.failures||0))*100):null
});
const selector=body=>({country:body?.country?normalizeCountry(body.country):undefined,region:body?.region?String(body.region):undefined,protocol:body?.protocol?String(body.protocol).toLowerCase():undefined,networkType:body?.networkType?String(body.networkType).toLowerCase():undefined});

const buckets=new Map();
const rateLimit=max=>(req,res,next)=>{max||=config.publicRateLimitMax;const now=Date.now(),key=`${req.ip||req.socket.remoteAddress||'unknown'}:${req.path}`;let b=buckets.get(key);if(!b||b.resetAt<=now)b={count:0,resetAt:now+config.publicRateLimitWindowMs};b.count++;buckets.set(key,b);res.set('x-ratelimit-limit',String(max));res.set('x-ratelimit-remaining',String(Math.max(0,max-b.count)));if(b.count>max)return res.status(429).json({error:'Public rate limit exceeded. Try again shortly.'});next();};
setInterval(()=>{const now=Date.now();for(const[k,b]of buckets)if(b.resetAt<=now)buckets.delete(k);},60000).unref();
const requireAdmin=(req,res,next)=>!config.adminToken||req.get('x-admin-token')!==config.adminToken?res.status(401).json({error:'Admin token required'}):next();

const statsHandler=(_req,res)=>res.json(pool.stats());
const configHandler=(_req,res)=>res.json({
  exposeNodeAddresses:config.exposeAddresses,matrixMaxNodes:config.matrixMaxNodes,previewSessionTtlMs:config.previewSessionTtlMs,previewTimeoutMs:config.previewTimeoutMs,publicTools:true,previewAllowsAllPublicDomains:true,
  scannerProviders:{localHeuristics:true,openPhish:threatIntelStatus(),clamAV:{configured:Boolean(config.clamavHost)},virusTotal:Boolean(config.virusTotalApiKey),googleWebRisk:Boolean(config.googleWebRiskApiKey)},
  storeScanHistory:config.storeScanHistory,apiVersion:'v1',browserBridge:{supported:true,ticketTtlMs:config.browserTicketTtlMs,extensionDownload:'/downloads/nekoroute-firefox-bridge.zip'},
  disclaimer:'NekoRoute is provided for regional availability, moderation, compatibility and defensive security analysis. Users are responsible for their use of the service and for complying with applicable laws and site terms.',
  privacyNotice:'Target website traffic is fetched through the selected proxy. NekoRoute does not guarantee anonymity or zero trace at the host, proxy, network-provider, or third-party reputation-provider layer.'
});
const filtersFromQuery=req=>({country:req.query.country?normalizeCountry(req.query.country):undefined,region:req.query.region?String(req.query.region):undefined,protocol:req.query.protocol?.toLowerCase(),status:req.query.status?.toLowerCase(),networkType:req.query.networkType?.toLowerCase()});
const proxiesHandler=(req,res)=>{const rows=pool.list(filtersFromQuery(req));const limit=Math.max(1,Math.min(500,Number(req.query.limit||100)));const offset=Math.max(0,Number(req.query.offset||0));res.set({'x-total-count':String(rows.length),'x-offset':String(offset),'x-limit':String(limit)}).json(rows.slice(offset,offset+limit).map(safeNode));};
const nodesV1Handler=(req,res)=>{const rows=pool.list(filtersFromQuery(req));const pageSize=Math.max(1,Math.min(200,Number(req.query.pageSize||req.query.limit||50)));const pages=Math.max(1,Math.ceil(rows.length/pageSize));const page=Math.max(1,Math.min(pages,Number(req.query.page||1)));const offset=(page-1)*pageSize;res.json({items:rows.slice(offset,offset+pageSize).map(safeNode),total:rows.length,page,pageSize,pages,hasPrevious:page>1,hasNext:page<pages});};
const regionsHandler=(_req,res)=>{const by=pool.stats().byRegion||{};res.json(Object.entries(by).sort((a,b)=>b[1]-a[1]).map(([region,count])=>({region,count})));};
const countriesHandler=(req,res)=>{const by=pool.stats().byCountry||{};const wanted=req.query.region?String(req.query.region):null;const rows=Object.entries(by).map(([code,count])=>{const c=normalizeCountry(code);return{code:c,name:countryName(c),region:regionForCountry(c),count};}).filter(x=>!wanted||x.region===wanted).sort((a,b)=>a.name.localeCompare(b.name));res.json(rows);};

app.get(['/api/health','/api/v1/health'],(_req,res)=>res.json({ok:true,service:'NekoRoute',version:'0.5.7',nodes:pool.nodes.size}));
app.get(['/api/stats','/api/v1/stats'],statsHandler);
app.get(['/api/config','/api/v1/config'],configHandler);
app.get(['/api/proxies','/api/v1/proxies'],proxiesHandler);
app.get('/api/v1/nodes',nodesV1Handler);
app.get('/api/v1/regions',regionsHandler);
app.get('/api/v1/countries',countriesHandler);
app.get('/api/v1/threat-intel',(_req,res)=>res.json(threatIntelStatus()));
app.get('/api/v1',(_req,res)=>res.json({
  service:'NekoRoute',version:'0.5.7',docs:'/api/docs',openapi:'/api/openapi.json',endpoints:{
    health:'GET /api/v1/health',stats:'GET /api/v1/stats',regions:'GET /api/v1/regions',countries:'GET /api/v1/countries?region=Europe',nodes:'GET /api/v1/nodes?status=online&country=FR',
    test:'POST /api/v1/test',matrix:'POST /api/v1/test-matrix',scan:'POST /api/v1/scan',previewSession:'POST /api/v1/preview/session',previewResources:'GET /api/v1/preview/session/:id/resources',browserTicket:'POST /api/v1/browser-ticket',threatIntel:'GET /api/v1/threat-intel'
  }
}));
app.get('/api/openapi.json',(_req,res)=>res.json({openapi:'3.1.0',info:{title:'NekoRoute Public API',version:'0.5.7',description:'Regional availability diagnostics, defensive scanning, proxy-pool metadata and sandboxed interactive preview sessions.'},paths:{
  '/api/v1/health':{get:{summary:'Service health'}},'/api/v1/stats':{get:{summary:'Proxy pool statistics'}},'/api/v1/regions':{get:{summary:'Region counts'}},'/api/v1/countries':{get:{summary:'Country names and counts'}},'/api/v1/nodes':{get:{summary:'Filtered public node metadata'}},
  '/api/v1/test':{post:{summary:'Test one URL through a selected/best route'}},'/api/v1/test-matrix':{post:{summary:'Compare one URL across multiple routes'}},'/api/v1/scan':{post:{summary:'Defensive website scan through a proxy'}},'/api/v1/preview/session':{post:{summary:'Create a sandboxed interactive preview session'}},'/api/v1/preview/session/{id}/resources':{get:{summary:'List page-linked resources discovered in an active preview session'}},'/api/v1/browser-ticket':{post:{summary:'Create a one-time ticket for the optional local Firefox Bridge extension'}},'/api/v1/browser-ticket/{ticket}':{get:{summary:'Consume a one-time Firefox Bridge ticket'}}
}}));

app.post('/api/admin/refresh',requireAdmin,async(_req,res,next)=>{try{res.json(await pool.refreshSources());}catch(e){next(e);}});
app.post('/api/admin/sweep',requireAdmin,async(_req,res,next)=>{try{await pool.healthSweep();res.json({ok:true,stats:pool.stats()});}catch(e){next(e);}});
app.post('/api/admin/ip-classifications/refresh',requireAdmin,async(req,res,next)=>{try{const force=req.body?.force!==false,onlineOnly=req.body?.onlineOnly!==false;res.json({ok:true,...await pool.refreshIpClassifications({force,onlineOnly})});}catch(e){next(e);}});
app.post('/api/admin/threat-intel/refresh',requireAdmin,async(_req,res,next)=>{try{res.json(await refreshThreatIntel(config));}catch(e){next(e);}});

const testRouteHandler=async(req,res,next)=>{try{const target=await validatePublicTarget(req.body?.url),sel=selector(req.body);let node=req.body?.nodeRef?findNodeByRef(String(req.body.nodeRef)):pool.select(sel);if(!node||node.status!=='online')return res.status(503).json({error:'No healthy proxy matches that selection'});let lastError;for(let i=0;i<3&&node;i++)try{const r=await requestViaProxy(node,target,{timeoutMs:config.testTimeoutMs,maxBytes:config.maxTestBytes});return res.json({ok:true,node:safeNode(node),target:target.toString(),statusCode:r.statusCode,statusText:http.STATUS_CODES[r.statusCode]||'',latencyMs:r.latencyMs,contentType:r.headers['content-type']||null,location:r.headers.location||null,preview:r.body.slice(0,6000)});}catch(e){lastError=e;node.status='degraded';node.consecutiveFailures=(node.consecutiveFailures||0)+1;node=pool.list({...sel,status:'online'}).find(n=>n.id!==node?.id)||null;}res.status(502).json({error:lastError?.message||'All matching routes failed'});}catch(e){next(e);}};
const testMatrixHandler=async(req,res,next)=>{try{const target=await validatePublicTarget(req.body?.url),sel=selector(req.body),count=Math.max(1,Math.min(config.matrixMaxNodes,Number(req.body?.limit||8)));let nodes=pool.list({...sel,status:'online'});if(req.body?.nodeRef){const n=findNodeByRef(String(req.body.nodeRef));nodes=n&&n.status==='online'?[n]:[];}nodes=nodes.slice(0,count);if(!nodes.length)return res.status(503).json({error:'No healthy proxies match that selection'});const limit=pLimit(config.matrixConcurrency),started=Date.now();const results=await Promise.all(nodes.map(node=>limit(async()=>{try{const r=await requestViaProxy(node,target,{timeoutMs:config.testTimeoutMs,maxBytes:8192,headersOnly:true});return{ok:true,node:safeNode(node),statusCode:r.statusCode,statusText:http.STATUS_CODES[r.statusCode]||'',latencyMs:r.latencyMs,location:r.headers.location||null,contentType:r.headers['content-type']||null};}catch(e){return{ok:false,node:safeNode(node),statusCode:null,statusText:'',latencyMs:null,error:String(e.message||e)};}})));const counts={};for(const r of results){const k=r.statusCode==null?'error':String(r.statusCode);counts[k]=(counts[k]||0)+1;}res.json({ok:true,target:target.toString(),durationMs:Date.now()-started,tested:results.length,counts,results});}catch(e){next(e);}};
const scanHandler=async(req,res,next)=>{try{const target=await validatePublicTarget(req.body?.url),requested=req.body?.nodeRef?findNodeByRef(String(req.body.nodeRef)):null,node=requested||pool.select(selector(req.body));if(!node||node.status!=='online')return res.status(503).json({error:'No healthy proxy matches that selection'});const report=await scanWebsite(node,target.toString(),config),output={ok:true,...report,node:safeNode(node),notice:'Heuristic, local-feed and reputation results are indicators, not a guarantee that a site is safe or malicious.'};if(config.storeScanHistory)saveScanResult({target:report.target,nodeId:node.id,country:node.country,verdict:report.verdict,score:report.score,statusCode:report.statusCode,findings:report.findings,providers:report.providers}).catch(e=>console.error('[scanner] persist:',e.message));res.json(output);}catch(e){next(e);}};
app.post(['/api/test-route','/api/v1/test'],rateLimit(),testRouteHandler);
app.post(['/api/test-matrix','/api/v1/test-matrix'],rateLimit(),testMatrixHandler);
app.post(['/api/scan','/api/v1/scan'],rateLimit(config.scanRateLimitMax),scanHandler);

const sessions=new Map();
setInterval(()=>{const now=Date.now();for(const[id,s]of sessions)if(s.expiresAt<=now)sessions.delete(id);},60000).unref();
const getSession=id=>{const s=sessions.get(id);if(!s||s.expiresAt<=Date.now()){sessions.delete(id);return null;}return s;};
const absolute=(value,base)=>{try{const u=new URL(value,base);return['http:','https:'].includes(u.protocol)?u.toString():null;}catch{return null;}};
const pageUrl=(id,url)=>`/api/preview/${encodeURIComponent(id)}?url=${encodeURIComponent(url)}`;
function registerResource(id,session,url,kind='resource',referer=''){
  const token=createHash('sha256').update(`${kind}\0${url}\0${referer||''}`).digest('hex').slice(0,28);
  if(session.resources.size>2500){const first=session.resources.keys().next().value;if(first)session.resources.delete(first);}
  session.resources.set(token,{url,kind,referer:referer||''});
  return `/api/preview-resource/${encodeURIComponent(id)}/${token}`;
}
function rewriteCss(css,base,id,session){
  let out=String(css).replace(/url\(\s*(['"]?)([^'"\)]+)\1\s*\)/gi,(m,_q,v)=>{const raw=v.trim();if(/^(data:|blob:|#)/i.test(raw))return m;const u=absolute(raw,base);return u?`url("${registerResource(id,session,u,'resource',base)}")`:m;});
  out=out.replace(/@import\s+(?:url\()?\s*(['"])([^'"]+)\1\s*\)?([^;]*);/gi,(m,_q,v,tail)=>{const u=absolute(v,base);return u?`@import url("${registerResource(id,session,u,'style',base)}")${tail||''};`:m;});
  return out;
}
const mediaExt=/\.(?:mp3|m4a|aac|wav|ogg|oga|opus|flac|mp4|m4v|webm|mov|jpg|jpeg|png|gif|webp|avif|svg|pdf)(?:$|[?#])/i;
function rewriteSrcset(value,base,id,session){return String(value||'').split(',').map(part=>{const bits=part.trim().split(/\\s+/);const u=absolute(bits[0],base);if(u)bits[0]=registerResource(id,session,u,'image',base);return bits.join(' ');}).join(', ');}
function guessMimeFromUrl(value){
  try{const ext=path.extname(new URL(value).pathname).toLowerCase();return ({'.jpg':'image/jpeg','.jpeg':'image/jpeg','.png':'image/png','.gif':'image/gif','.webp':'image/webp','.avif':'image/avif','.svg':'image/svg+xml','.ico':'image/x-icon','.bmp':'image/bmp','.woff':'font/woff','.woff2':'font/woff2','.ttf':'font/ttf','.otf':'font/otf','.mp3':'audio/mpeg','.m4a':'audio/mp4','.aac':'audio/aac','.ogg':'audio/ogg','.oga':'audio/ogg','.opus':'audio/ogg','.wav':'audio/wav','.flac':'audio/flac','.mp4':'video/mp4','.webm':'video/webm','.mov':'video/quicktime','.pdf':'application/pdf','.css':'text/css','.js':'application/javascript','.mjs':'application/javascript'})[ext]||null;}catch{return null;}
}
function linkResourceKind(el){
  const rel=String(el.attr('rel')||'').toLowerCase().split(/\\s+/).filter(Boolean),as=String(el.attr('as')||'').toLowerCase();
  if(rel.includes('stylesheet'))return 'style';
  if(rel.includes('modulepreload'))return 'script';
  if(rel.some(x=>['icon','apple-touch-icon','apple-touch-startup-image','mask-icon'].includes(x)))return 'image';
  if(rel.includes('preload')){if(as==='style')return 'style';if(as==='script'||as==='worker')return 'script';if(as==='image')return 'image';if(as==='font')return 'font';if(as==='audio'||as==='video')return 'media';return 'resource';}
  return 'resource';
}
const lazySrcAttrs=['data-src','data-original','data-lazy-src','data-lazy','data-image','data-img','data-url'];
const lazySrcsetAttrs=['data-srcset','data-lazy-srcset'];
const lazyBgAttrs=['data-background','data-bg','data-background-image','data-lazy-background'];
function compactText(value,max=280){const t=String(value||'').replace(/\s+/g,' ').trim();return t.length>max?t.slice(0,max-1)+'…':t;}
function collectPageHints($,rawHtml,base){
  const links=[]; const media=[]; const seenLinks=new Set(); const seenMedia=new Set();
  const addLink=(url,label='Link')=>{const u=absolute(url,base);if(!u||seenLinks.has(u))return;seenLinks.add(u);links.push({url:u,label:compactText(label||u,120)});};
  const addMedia=(url,label='Media')=>{const u=absolute(url,base);if(!u||seenMedia.has(u))return;seenMedia.add(u);media.push({url:u,label:compactText(label||u,120)});};
  $('a[href]').each((_i,e)=>{const a=$(e),raw=a.attr('href'),label=a.text()||a.attr('title')||a.attr('aria-label')||raw;if(!raw)return;mediaExt.test(raw)||a.is('[download]')?addMedia(raw,label):addLink(raw,label);});
  for(const[sel,attr]of[['audio','src'],['video','src'],['source','src'],['track','src']])$(sel).each((_i,e)=>{const raw=$(e).attr(attr);if(raw)addMedia(raw,$(e).attr('title')||$(e).attr('type')||raw);});
  for(const key of ['og:audio','og:audio:url','og:video','og:video:url','twitter:player:stream']){
    const raw=$(`meta[property="${key}"],meta[name="${key}"]`).first().attr('content'); if(raw)addMedia(raw,key);
  }
  $('*').each((_i,e)=>{for(const [name,val] of Object.entries(e.attribs||{})){if(!val)continue;const n=String(name).toLowerCase();if(/(?:src|href|url|download|media|audio|file)/.test(n)&&mediaExt.test(String(val)))addMedia(val,n);}});
  const normalized=String(rawHtml||'').replace(/\\\//g,'/').replace(/&amp;/g,'&');
  for(const m of normalized.matchAll(/https?:\/\/[^\s"'<>\\]+/gi)){
    const raw=m[0].replace(/[),.;]+$/,''); if(mediaExt.test(raw))addMedia(raw,'Detected media URL');
  }
  for(const m of normalized.matchAll(/["']([^"']+\.(?:mp3|m4a|aac|wav|ogg|oga|opus|flac|mp4|m4v|webm|mov|pdf)(?:\?[^"']*)?)["']/gi))addMedia(m[1],'Detected media URL');
  const title=compactText($('title').first().text()||$('meta[property="og:title"]').attr('content')||new URL(base).hostname,160);
  const description=compactText($('meta[name="description"]').attr('content')||$('meta[property="og:description"]').attr('content')||'',500);
  const bodyClone=$('body').clone();bodyClone.find('script,style,template').remove();const bodyText=compactText(bodyClone.text(),2400);
  return {title,description,bodyText,links:links.slice(0,80),media:media.slice(0,80)};
}
function resourcePanel(hints,id,session,base,full=false){
  const media=hints.media.map(item=>{const href=registerResource(id,session,item.url,'download',base)+'?download=1';return `<li style="margin:7px 0;overflow-wrap:anywhere"><a href="${href}" style="color:#34d399;text-decoration:underline" download>${escapeHtml(item.label||'Download media')}</a><div style="font:11px ui-monospace,monospace;color:#71717a">${escapeHtml(item.url)}</div></li>`;}).join('');
  const links=hints.links.map(item=>`<li style="margin:7px 0;overflow-wrap:anywhere"><a href="#" data-neko-url="${escapeHtml(item.url)}" style="color:#67e8f9;text-decoration:underline">${escapeHtml(item.label||item.url)}</a><div style="font:11px ui-monospace,monospace;color:#71717a">${escapeHtml(item.url)}</div></li>`).join('');
  if(!media&&!links&&!full)return '';
  const intro=full?`<h2 style="all:initial;display:block!important;color:#e4e4e7!important;font:700 20px system-ui!important;margin:0 0 8px!important">${escapeHtml(hints.title||'Proxied page')}</h2>${hints.description?`<p style="all:initial;display:block!important;color:#a1a1aa!important;font:14px/1.5 system-ui!important;margin:0 0 10px!important">${escapeHtml(hints.description)}</p>`:''}${hints.bodyText?`<p style="all:initial;display:block!important;white-space:pre-wrap!important;color:#d4d4d8!important;font:14px/1.5 system-ui!important;margin:0 0 14px!important">${escapeHtml(hints.bodyText)}</p>`:''}`:'';
  const body=`${intro}${media?`<div style="all:initial;display:block!important;margin-top:12px!important"><b style="color:#fbbf24;font:700 14px system-ui">Detected media/downloads (${hints.media.length})</b><ul style="all:initial;display:block!important;padding-left:20px!important;margin:6px 0!important;color:#e4e4e7!important;font:13px/1.4 system-ui!important">${media}</ul></div>`:''}${links?`<div style="all:initial;display:block!important;margin-top:12px!important"><b style="color:#a7f3d0;font:700 14px system-ui">Page links (${hints.links.length})</b><ul style="all:initial;display:block!important;padding-left:20px!important;margin:6px 0!important;color:#e4e4e7!important;font:13px/1.4 system-ui!important">${links}</ul></div>`:''}`;
  if(full)return `<section data-neko-fallback style="all:initial;display:block!important;box-sizing:border-box!important;max-width:1100px!important;margin:24px auto!important;padding:20px!important;background:#090d0b!important;color:#e4e4e7!important;border:1px solid #14532d!important;border-radius:16px!important;font-family:system-ui!important">${body||'<p style="color:#a1a1aa">The remote page contains no server-rendered content after scripts were disabled.</p>'}</section>`;
  return `<details data-neko-resources style="all:initial;display:block!important;box-sizing:border-box!important;margin:16px!important;padding:12px 14px!important;background:#090d0b!important;color:#e4e4e7!important;border:1px solid #14532d!important;border-radius:12px!important;font-family:system-ui!important"><summary style="cursor:pointer;color:#a7f3d0;font:700 13px system-ui">NekoRoute detected resources${hints.media.length?` · ${hints.media.length} media/download`:''}</summary>${body}</details>`;
}
function runtimeUrl(id,url){return `/api/preview-runtime/${encodeURIComponent(id)}?url=${encodeURIComponent(url)}`;}
function rewriteJavascript(js,base,id,session){
  let out=String(js||'');
  const map=raw=>{const u=absolute(raw,base);return u?registerResource(id,session,u,'script',base):raw;};
  // Rewrite common ES module specifiers so module/chunk imports stay inside the selected proxy session.
  out=out.replace(/(\b(?:import|export)\s+(?:[^'"\n;]*?\s+from\s*)?)(['"])([^'"\n]+)\2/g,(m,p,q,v)=>`${p}${q}${map(v)}${q}`);
  out=out.replace(/(\bimport\s*\(\s*)(['"])([^'"\n]+)\2(\s*\))/g,(m,p,q,v,t)=>`${p}${q}${map(v)}${q}${t}`);
  return out;
}
function previewBootstrap(base,id){
  const baseJson=JSON.stringify(base),idJson=JSON.stringify(id);
  return `(function(){\n`+
  `const REMOTE_BASE=${baseJson},SID=${idJson};\n`+
  `const localPreview=(v)=>{try{const u=new URL(String(v),location.href);return u.pathname.startsWith('/api/preview-')}catch{return false}};\n`+
  `const abs=(v)=>{try{const u=new URL(String(v),REMOTE_BASE);return /^(https?:)$/.test(u.protocol)?u.href:null}catch{return null}};\n`+
  `const runtime=(v,kind)=>{if(localPreview(v))return String(v);const u=abs(v);return u?('/api/preview-runtime/'+encodeURIComponent(SID)+'?url='+encodeURIComponent(u)+(kind?'&kind='+encodeURIComponent(kind):'')):v};\n`+
  `const resource=(v,kind)=>runtime(v,kind||'resource');const page=(v)=>{if(localPreview(v))return String(v);const u=abs(v);return u?('/api/preview/'+encodeURIComponent(SID)+'?url='+encodeURIComponent(u)):v};\n`+
  `window.__NEKOROUTE_REMOTE_BASE__=REMOTE_BASE;window.__NEKOROUTE_SESSION__=SID;\n`+
  `try{const f=window.fetch.bind(window);window.fetch=function(input,init){init=init||{};let raw=typeof input==='string'||input instanceof URL?String(input):input&&input.url;let method=String(init.method||(input&&input.method)||'GET').toUpperCase();if(!raw||raw.startsWith('/api/preview-'))return f(input,init);if(method!=='GET'&&method!=='HEAD')return Promise.reject(new TypeError('NekoRoute sandbox blocks write fetch methods'));const next=Object.assign({},init,{method,credentials:'omit'});delete next.mode;return f(runtime(raw,'fetch'),next)}}catch(_){};\n`+
  `try{const o=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(method,url){const args=[].slice.call(arguments);const m=String(method||'GET').toUpperCase();if(m==='GET'||m==='HEAD')args[1]=runtime(url,'fetch');else args[1]='/api/preview-runtime-blocked/'+encodeURIComponent(SID);return o.apply(this,args)}}catch(_){};\n`+
  `try{const orig=Element.prototype.setAttribute;Element.prototype.setAttribute=function(name,value){const n=String(name).toLowerCase(),tag=this.tagName;if(n==='src'&&tag==='IFRAME')value=page(value);else if(n==='src'&&tag==='SCRIPT')value=resource(value,'script');else if(n==='href'&&tag==='LINK'){const rel=String(this.getAttribute('rel')||'').toLowerCase(),as=String(this.getAttribute('as')||'').toLowerCase();const kind=rel.includes('stylesheet')?'style':rel.includes('modulepreload')?'script':rel.includes('icon')?'image':rel.includes('preload')?(as==='style'?'style':as==='script'?'script':as==='image'?'image':as==='font'?'font':/^(audio|video)$/.test(as)?'media':'resource'):'resource';value=resource(value,kind)}else if(n==='src'&&tag==='IMG')value=resource(value,'image');else if(n==='src'&&/^(SOURCE|VIDEO|AUDIO|TRACK)$/.test(tag))value=resource(value,'media');else if(n==='poster'&&tag==='VIDEO')value=resource(value,'image');else if(n==='srcset'&&/^(IMG|SOURCE)$/.test(tag))value=String(value).split(',').map(p=>{const b=p.trim().split(/\\s+/);if(b[0])b[0]=resource(b[0],'image');return b.join(' ')}).join(', ');else if(/^data-(?:src|original|lazy-src|image|img)$/.test(n)&&tag==='IMG')value=resource(value,'image');return orig.call(this,name,value)}}catch(_){};\n`+
  `const patch=(proto,key,kind)=>{try{const d=Object.getOwnPropertyDescriptor(proto,key);if(!d||!d.set||!d.get)return;Object.defineProperty(proto,key,{configurable:d.configurable,enumerable:d.enumerable,get:d.get,set:function(v){return d.set.call(this,resource(v,kind))}})}catch(_){}};\n`+
  `patch(HTMLScriptElement.prototype,'src','script');patch(HTMLImageElement.prototype,'src','image');patch(HTMLImageElement.prototype,'srcset','image');if(window.HTMLSourceElement){patch(HTMLSourceElement.prototype,'src','media');patch(HTMLSourceElement.prototype,'srcset','image')}if(window.HTMLMediaElement){patch(HTMLMediaElement.prototype,'src','media');try{const realPlay=HTMLMediaElement.prototype.play;HTMLMediaElement.prototype.play=function(){const raw=this.getAttribute&&this.getAttribute('src');if(raw&&!localPreview(raw)){try{this.src=resource(raw,'media')}catch(_){}}return realPlay.apply(this,arguments)}}catch(_){}}if(window.HTMLVideoElement)patch(HTMLVideoElement.prototype,'poster','image');try{const RealAudio=window.Audio;if(RealAudio){const WrappedAudio=function(src){const a=new RealAudio();if(src)a.src=resource(src,'media');return a};WrappedAudio.prototype=RealAudio.prototype;Object.setPrototypeOf(WrappedAudio,RealAudio);window.Audio=WrappedAudio}}catch(_){};try{const d=Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype,'src');if(d&&d.set&&d.get)Object.defineProperty(HTMLIFrameElement.prototype,'src',{configurable:d.configurable,enumerable:d.enumerable,get:d.get,set:function(v){return d.set.call(this,page(v))}})}catch(_){};\n`+`try{const cssUrl=(v)=>String(v).replace(/url\\(([^)]+)\\)/gi,(m,u)=>{u=String(u).trim().replace(/^['\"]|['\"]$/g,'');return /^(?:data:|blob:|#)/i.test(u)?m:'url(\"'+resource(u,'image')+'\")'});const sp=CSSStyleDeclaration.prototype.setProperty;CSSStyleDeclaration.prototype.setProperty=function(n,v,p){return sp.call(this,n,/background|mask|content|list-style/i.test(String(n))?cssUrl(v):v,p)};for(const k of ['background','backgroundImage','borderImage','mask','maskImage','listStyleImage']){const d=Object.getOwnPropertyDescriptor(CSSStyleDeclaration.prototype,k);if(d&&d.set&&d.get)Object.defineProperty(CSSStyleDeclaration.prototype,k,{configurable:d.configurable,enumerable:d.enumerable,get:d.get,set:function(v){return d.set.call(this,cssUrl(v))}})}}catch(_){};\n`+
  `try{const fix=(root)=>{if(!root||root.nodeType!==1)return;const all=[root].concat(Array.from(root.querySelectorAll?root.querySelectorAll('script[src],link[href],img[src],img[srcset],source[src],source[srcset],video[src],video[poster],audio[src],track[src],iframe[src],[data-src],[data-original],[data-lazy-src],[data-background],[data-bg]'):[]));for(const el of all){const t=el.tagName;if(t==='IFRAME'&&el.getAttribute('src'))el.setAttribute('src',page(el.getAttribute('src')));else if(t==='SCRIPT'&&el.getAttribute('src'))el.setAttribute('src',resource(el.getAttribute('src'),'script'));else if(t==='LINK'&&el.getAttribute('href'))el.setAttribute('href',el.getAttribute('href'));else{if(t==='IMG'&&el.getAttribute('src'))el.setAttribute('src',resource(el.getAttribute('src'),'image'));else if(el.getAttribute&&el.getAttribute('src'))el.setAttribute('src',resource(el.getAttribute('src'),'media'));if((t==='IMG'||t==='SOURCE')&&el.getAttribute('srcset'))el.setAttribute('srcset',el.getAttribute('srcset'));if(t==='VIDEO'&&el.getAttribute('poster'))el.setAttribute('poster',resource(el.getAttribute('poster'),'image'));for(const a of ['data-src','data-original','data-lazy-src'])if(el.getAttribute&&el.getAttribute(a)){const k=t==='IMG'?'image':'media';el.setAttribute(a,resource(el.getAttribute(a),k));}}}};new MutationObserver(ms=>{for(const m of ms){for(const n of m.addedNodes)fix(n);if(m.type==='attributes')fix(m.target)}}).observe(document.documentElement,{childList:true,subtree:true,attributes:true,attributeFilter:['src','srcset','href','poster','data-src','data-original','data-lazy-src','style']})}catch(_){};\n`+
  `try{const makeStore=()=>{const m=new Map();return{get length(){return m.size},key:i=>Array.from(m.keys())[i]??null,getItem:k=>m.has(String(k))?m.get(String(k)):null,setItem:(k,v)=>m.set(String(k),String(v)),removeItem:k=>m.delete(String(k)),clear:()=>m.clear()}};try{void window.localStorage}catch{Object.defineProperty(window,'localStorage',{value:makeStore()})}try{void window.sessionStorage}catch{Object.defineProperty(window,'sessionStorage',{value:makeStore()})}try{Object.defineProperty(Document.prototype,'cookie',{configurable:true,get:function(){return ''},set:function(){return true}})}catch(_){}}catch(_){};\n`+
  `try{const W=window.WebSocket;window.WebSocket=function(){throw new DOMException('WebSocket disabled in NekoRoute sandbox','SecurityError')};window.WebSocket.prototype=W&&W.prototype}catch(_){};\n`+
  `})();`;
}
function rewriteHtml(html,base,id,session){
  const $=cheerio.load(html,{decodeEntities:false});
  const hints=collectPageHints($,html,base);
  $('object,embed,portal').remove();$('base').remove();
  $('meta[http-equiv]').each((_i,e)=>{const v=String($(e).attr('http-equiv')||'').toLowerCase();if(v==='content-security-policy'||v==='refresh')$(e).remove();});

  // Proxy original scripts instead of stripping them. Inline scripts and event handlers stay enabled,
  // but the outer iframe remains sandboxed without allow-same-origin.
  $('script[src]').each((_i,e)=>{const el=$(e),u=absolute(el.attr('src'),base);if(u)el.attr('src',registerResource(id,session,u,'script',base)).removeAttr('integrity').removeAttr('crossorigin').removeAttr('nonce');});
  $('script:not([src])').each((_i,e)=>$(e).removeAttr('nonce'));

  $('a[href]').each((_i,e)=>{const a=$(e),raw=a.attr('href');if(!raw||raw.startsWith('#'))return;const u=absolute(raw,base);if(!u){a.attr('href','#').attr('data-neko-blocked','true');return;}const explicit=a.is('[download]')||mediaExt.test(u);if(explicit){a.attr('href',registerResource(id,session,u,'download',base)+'?download=1').attr('rel','nofollow noopener');}else{a.attr('href',pageUrl(id,u)).attr('data-neko-url',u).removeAttr('target');}});

  for(const[sel,attr,kind]of[
    ['img','src','image'],['input[type="image"]','src','image'],['source','src','media'],['video','src','media'],['video','poster','image'],['audio','src','media'],['track','src','media'],['iframe[src]','src','page']
  ])$(sel).each((_i,e)=>{const el=$(e),u=absolute(el.attr(attr),base);if(!u)return;if(kind==='page')el.attr(attr,pageUrl(id,u));else el.attr(attr,registerResource(id,session,u,kind,base));el.removeAttr('integrity').removeAttr('crossorigin').removeAttr('nonce');});

  // Link elements are not all stylesheets. Preserve icons, module preloads, image/font preloads, etc.
  $('link[href]').each((_i,e)=>{const el=$(e),rel=String(el.attr('rel')||'').toLowerCase();if(/(?:preconnect|dns-prefetch)/.test(rel)){el.remove();return;}const u=absolute(el.attr('href'),base);if(!u)return;el.attr('href',registerResource(id,session,u,linkResourceKind(el),base)).removeAttr('integrity').removeAttr('crossorigin').removeAttr('nonce');});

  $('img[srcset],source[srcset]').each((_i,e)=>$(e).attr('srcset',rewriteSrcset($(e).attr('srcset'),base,id,session)));

  // Common lazy-loading conventions. Rewrite both the lazy attribute and the live attribute so pages
  // remain visible even when their lazy-loader only partly works inside an opaque sandbox origin.
  $('img,source,video').each((_i,e)=>{const el=$(e);for(const attr of lazySrcAttrs){const raw=el.attr(attr);if(!raw)continue;const u=absolute(raw,base);if(!u)continue;const kind=el.is('img')?'image':'media',proxied=registerResource(id,session,u,kind,base);el.attr(attr,proxied);if(el.is('img')&&(!el.attr('src')||/^(?:data:|about:blank|#|javascript:)/i.test(el.attr('src'))))el.attr('src',proxied);if(el.is('source')&&!el.attr('src'))el.attr('src',proxied);}
    for(const attr of lazySrcsetAttrs){const raw=el.attr(attr);if(!raw)continue;const proxied=rewriteSrcset(raw,base,id,session);el.attr(attr,proxied);if(!el.attr('srcset'))el.attr('srcset',proxied);}
  });
  $('[data-background],[data-bg],[data-background-image],[data-lazy-background]').each((_i,e)=>{const el=$(e);for(const attr of lazyBgAttrs){const raw=el.attr(attr);if(!raw)continue;const u=absolute(raw,base);if(!u)continue;const proxied=registerResource(id,session,u,'image',base);el.attr(attr,proxied);const current=String(el.attr('style')||'');if(!/background(?:-image)?\s*:/i.test(current))el.attr('style',`${current}${current&&!current.trim().endsWith(';')?';':''}background-image:url("${proxied}")`);break;}});

  // SVG image/use references are common for logos and icon sprites.
  for(const sel of ['image[href]','use[href]','image[xlink\:href]','use[xlink\:href]'])$(sel).each((_i,e)=>{const el=$(e),attr=el.attr('href')?'href':'xlink:href',u=absolute(el.attr(attr),base);if(u)el.attr(attr,registerResource(id,session,u,'image',base));});

  $('[style]').each((_i,e)=>$(e).attr('style',rewriteCss($(e).attr('style'),base,id,session)));$('style').each((_i,e)=>$(e).text(rewriteCss($(e).html()||'',base,id,session)));

  // GET/search forms remain usable; write forms stay disabled in embedded preview.
  $('form').each((_i,e)=>{const form=$(e);const method=String(form.attr('method')||'get').toLowerCase();const action=absolute(form.attr('action')||base,base);if(method==='get'&&action&&!form.find('input[type="password"],input[type="file"]').length){form.attr('data-neko-get-form','true').attr('data-neko-action',action).attr('action','#').attr('method','get');}else{form.attr('data-neko-form-disabled','true');form.find('input[type="password"],input[type="file"],button[type="submit"],input[type="submit"]').attr('disabled','disabled');}});

  // Bootstrap must run before the site's scripts. It keeps fetch/XHR and dynamically-added assets
  // inside this proxy session while preserving the iframe's opaque sandbox origin.
  const bootstrap=`<script data-nekoroute-bootstrap>${previewBootstrap(base,id)}</script>`;
  if($('head').length)$('head').prepend(bootstrap);else $.root().prepend(`<head>${bootstrap}</head>`);

  // Keep a small status bar, without replacing the site's own page layout.
  $('body').prepend(`<div data-nekoroute-bar style="position:sticky;top:0;z-index:2147483647;padding:7px 11px;background:#07110b;color:#a7f3d0;border-bottom:1px solid #14532d;font:12px system-ui">NekoRoute proxied interactive preview · CSS + JavaScript enabled in sandbox · downloads proxied</div>`);
  if(hints.media.length)$('body').append(resourcePanel(hints,id,session,base,false));

  // Notify the outer UI about normal navigation, but do not steal clicks already handled by site JS.
  $('body').append(`<script data-nekoroute-nav>(function(){document.addEventListener('click',function(e){if(e.defaultPrevented)return;var a=e.target.closest&&e.target.closest('a[data-neko-url]');if(!a)return;parent.postMessage({type:'nekoroute-preview-nav',url:a.getAttribute('data-neko-url')},'*')},false);document.addEventListener('submit',function(e){var f=e.target;if(!f||!f.matches||!f.matches('form[data-neko-get-form]'))return;e.preventDefault();var action=f.getAttribute('data-neko-action');try{var u=new URL(action);var fd=new FormData(f);for(var pair of fd.entries())u.searchParams.append(pair[0],pair[1]);parent.postMessage({type:'nekoroute-preview-nav',url:u.toString()},'*')}catch(_){}},false)})()</script>`);
  return $.html();
}

const escapeHtml=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const previewErrorHtml=input=>{
  const x=typeof input==='string'?{message:input}:input||{};
  const code=Number(x.statusCode||0);
  const statusText=code?(http.STATUS_CODES[code]||'HTTP error'):'';
  const title=code?`HTTP ${code} ${statusText}`:'Proxy transport error';
  const accent=code>=500?'#fb7185':code>=400?'#fbbf24':'#34d399';
  const node=x.node;
  const proxy=node?`${countryName(node.country)} (${normalizeCountry(node.country)}) · ${node.protocol} · ${node.city||'Unknown city'}${node.latencyMs!=null?` · ${node.latencyMs} ms`:''}`:'';
  const body=x.bodyExcerpt?`<pre style="white-space:pre-wrap;max-height:220px;overflow:auto;background:#020403;border:1px solid #27272a;border-radius:12px;padding:12px;color:#a1a1aa;font:12px/1.45 ui-monospace,monospace">${escapeHtml(x.bodyExcerpt)}</pre>`:'';
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head><body style="margin:0;background:#050807;color:#e4e4e7;font:15px system-ui"><div style="max-width:820px;margin:64px auto;padding:28px;border:1px solid #27272a;border-radius:20px;background:#080b09"><div style="font:700 12px ui-monospace,monospace;color:#71717a;text-transform:uppercase;letter-spacing:.12em">NekoRoute preview</div><h1 style="margin:10px 0 6px;color:${accent};font-size:30px">${escapeHtml(title)}</h1><p style="color:#d4d4d8">${escapeHtml(x.message||'The selected proxy could not load this page.')}</p>${x.target?`<p style="overflow-wrap:anywhere;color:#a1a1aa"><b style="color:#e4e4e7">URL:</b> ${escapeHtml(x.target)}</p>`:''}${proxy?`<p style="color:#a1a1aa"><b style="color:#e4e4e7">Proxy:</b> ${escapeHtml(proxy)}</p>`:''}${code?`<p style="color:#a1a1aa">The proxy connected successfully, but the upstream website returned <b style="color:${accent}">${code}</b>. Try another node if the site is blocking this exit.</p>`:`<p style="color:#a1a1aa">No HTTP status code was received. This usually means the proxy socket/TLS connection closed, timed out, or failed before the website responded.</p>`}${body}</div><script>try{parent.postMessage({type:'nekoroute-preview-error',statusCode:${code||0},statusText:${JSON.stringify(statusText)},message:${JSON.stringify(String(x.message||''))}},'*')}catch(_){}</script></body></html>`;
};
const errorHtml=m=>previewErrorHtml(m);
function nonHtmlPreview(id,session,url,type){const src=registerResource(id,session,url,'download');const isAudio=type.startsWith('audio/'),isVideo=type.startsWith('video/'),isImage=type.startsWith('image/'),isPdf=type.includes('pdf');const player=isAudio?`<audio controls preload="metadata" style="width:100%" src="${src}"></audio>`:isVideo?`<video controls preload="metadata" playsinline style="max-width:100%;max-height:70vh" src="${src}"></video>`:isImage?`<img style="max-width:100%;max-height:75vh" src="${src}"/>`:isPdf?`<iframe style="width:100%;height:70vh;border:0" src="${src}"></iframe>`:'';return`<!doctype html><html><body style="background:#050807;color:#e4e4e7;font:15px system-ui"><div style="max-width:1000px;margin:30px auto;padding:24px"><h2 style="color:#34d399">Proxied resource</h2><p>${escapeHtml(type)}</p>${player}<p><a style="color:#34d399" href="${src}?download=1">Download this page-linked resource through the selected proxy</a></p></div></body></html>`;}

async function pipeProxyStream(req,res,{node,target,kind='media',referer='',download=false,cors=false}={}){
  let current=target instanceof URL?target:new URL(target);
  let redirects=0;
  while(true){
    const range=req.get('range');
    const upstream=await openProxyStream(node,current,{
      timeoutMs:config.previewTimeoutMs,
      method:req.method==='HEAD'?'HEAD':'GET',
      headers:{
        accept:kind==='media'?'audio/*,video/*,*/*;q=0.6':'*/*',
        'user-agent':config.previewUserAgent,
        'accept-language':req.get('accept-language')||'en-GB,en;q=0.9',
        ...(referer?{referer}:{}),
        ...(range?{range}:{}),
        ...(req.get('if-range')?{'if-range':req.get('if-range')}:{}),
        ...(req.get('if-none-match')?{'if-none-match':req.get('if-none-match')}:{}),
        ...(req.get('if-modified-since')?{'if-modified-since':req.get('if-modified-since')}:{}),
      }
    });
    const r=upstream.response;
    if(upstream.statusCode>=300&&upstream.statusCode<400&&r.headers.location&&redirects<5){
      const next=absolute(r.headers.location,current);
      r.resume();
      if(!next){r.destroy();return res.status(502).type('text').send('Invalid upstream redirect');}
      current=await validatePublicTarget(next);
      redirects++;
      continue;
    }
    let type=String(r.headers['content-type']||'application/octet-stream').toLowerCase();
    const guessed=guessMimeFromUrl(current.toString());
    if((type.includes('octet-stream')||type==='text/plain'||!r.headers['content-type'])&&guessed)type=guessed;
    const mediaLike=type.startsWith('audio/')||type.startsWith('video/')||type.includes('octet-stream')||/\.(?:mp3|m4a|aac|ogg|oga|opus|wav|flac|mp4|webm|mov)(?:$|[?#])/i.test(current.toString());
    if(kind==='media'&&!mediaLike){r.destroy();return res.status(415).end();}

    const length=Number(r.headers['content-length']||0);
    if(length&&length>config.previewMaxStreamBytes){r.destroy();return res.status(413).type('text').send(`Stream exceeds ${config.previewMaxStreamBytes} byte limit`);}
    const headers={
      'content-type':type||'application/octet-stream',
      'cache-control':'private, max-age=120',
      'accept-ranges':r.headers['accept-ranges']||'bytes',
      'cross-origin-resource-policy':'cross-origin'
    };
    for(const h of ['content-length','content-range','etag','last-modified'])if(r.headers[h])headers[h]=r.headers[h];
    if(cors){headers['access-control-allow-origin']='*';headers['access-control-expose-headers']='content-type,content-length,content-range,accept-ranges,etag,last-modified';}
    if(download){
      const remoteDisposition=String(r.headers['content-disposition']||'');
      const match=/filename\*?=(?:UTF-8''|")?([^";]+)/i.exec(remoteDisposition);
      let filename=path.basename(current.pathname)||'download';
      if(match?.[1]){try{filename=decodeURIComponent(match[1].trim());}catch{filename=match[1].trim();}}
      headers['content-disposition']=`attachment; filename="${filename.replace(/["\\\r\n]/g,'_')}"`;
    }
    res.status(upstream.statusCode||200).set(headers);
    if(req.method==='HEAD'){r.destroy();return res.end();}

    let sent=0,closed=false;
    const abort=()=>{if(closed)return;closed=true;r.destroy();};
    res.once('close',abort);
    r.on('data',chunk=>{sent+=chunk.length;if(sent>config.previewMaxStreamBytes){r.destroy(new Error('Preview stream byte limit exceeded'));if(!res.destroyed)res.destroy();}});
    r.on('error',()=>{if(!res.headersSent)res.status(502).end();else if(!res.destroyed)res.destroy();});
    r.on('end',()=>{closed=true;res.removeListener('close',abort);});
    r.pipe(res);
    return;
  }
}


const browserTickets=new Map();
setInterval(()=>{const now=Date.now();for(const[k,t]of browserTickets)if(t.expiresAt<=now)browserTickets.delete(k);},30000).unref();
const browserTicketHandler=async(req,res,next)=>{try{const target=await validatePublicTarget(req.body?.url),requested=req.body?.nodeRef?findNodeByRef(String(req.body.nodeRef)):null,node=requested||pool.select(selector(req.body));if(!node||node.status!=='online')return res.status(503).json({error:'No healthy proxy matches that selection'});const ticket=randomUUID(),expiresAt=Date.now()+config.browserTicketTtlMs;browserTickets.set(ticket,{nodeId:node.id,target:target.toString(),expiresAt});res.json({ok:true,ticket,ticketUrl:`/api/v1/browser-ticket/${encodeURIComponent(ticket)}`,expiresAt:new Date(expiresAt).toISOString(),target:target.toString(),node:safeNode(node),note:'Consume this ticket with the NekoRoute Firefox Bridge extension. Tickets are single-use and expire quickly.'});}catch(e){next(e);}};
app.post('/api/v1/browser-ticket',rateLimit(),browserTicketHandler);
app.get('/api/v1/browser-ticket/:ticket',rateLimit(),(req,res)=>{const key=String(req.params.ticket),ticket=browserTickets.get(key);if(!ticket||ticket.expiresAt<=Date.now()){browserTickets.delete(key);return res.status(410).json({error:'Browser ticket expired or already used'});}const node=pool.nodes.get(ticket.nodeId);if(!node||node.status!=='online'){browserTickets.delete(key);return res.status(503).json({error:'Selected proxy is no longer online'});}browserTickets.delete(key);const type=node.protocol==='socks5'?'socks':node.protocol;res.set('cache-control','no-store').json({ok:true,target:ticket.target,proxy:{type,host:node.ip,port:node.port,proxyDNS:type==='socks'||type==='socks4',failoverTimeout:8},node:safeNode(node)});});

const previewSessionHandler=async(req,res,next)=>{
  try{
    const target=await validatePublicTarget(req.body?.url);
    const requested=req.body?.nodeRef?findNodeByRef(String(req.body.nodeRef)):null;
    const node=requested||pool.select(selector(req.body));
    if(!node||node.status!=='online')return res.status(503).json({error:'No healthy proxy matches that selection'});
    const id=randomUUID(),expiresAt=Date.now()+config.previewSessionTtlMs;
    sessions.set(id,{nodeId:node.id,expiresAt,resources:new Map(),currentPage:target.toString()});
    res.json({
      ok:true,sessionId:id,expiresAt:new Date(expiresAt).toISOString(),url:target.toString(),frameUrl:pageUrl(id,target.toString()),node:safeNode(node),
      capabilities:{navigation:true,getForms:true,pageLinkedMedia:true,pageLinkedDownloads:true,audioVideoPlayback:true,rangeStreaming:true,remoteScripts:true,sandboxedScripts:true,runtimeGetFetch:true,cookies:false,postForms:false,webSockets:false}
    });
  }catch(e){next(e);}
};
app.post(['/api/preview-session','/api/v1/preview/session'],rateLimit(),previewSessionHandler);
app.get('/api/v1/preview/session/:id/resources',rateLimit(),(req,res)=>{
  const s=getSession(String(req.params.id));if(!s)return res.status(410).json({error:'Preview session expired'});
  const rows=[...s.resources.entries()].map(([token,entry])=>({token,kind:entry.kind,url:entry.url,fetchUrl:`/api/preview-resource/${encodeURIComponent(req.params.id)}/${token}`,downloadUrl:`/api/preview-resource/${encodeURIComponent(req.params.id)}/${token}?download=1`}));
  res.json({sessionId:req.params.id,expiresAt:new Date(s.expiresAt).toISOString(),count:rows.length,resources:rows});
});

app.get('/api/preview/:id',async(req,res)=>{
  // Important: iframe Preview errors intentionally return HTTP 200 to the outer
  // reverse proxy/CDN. Cloudflare replaces origin 5xx responses with its own
  // Bad Gateway page, which hides NekoRoute's useful proxy/upstream diagnostics.
  // The real upstream/proxy status is carried in X-NekoRoute-* headers and the
  // HTML postMessage payload instead. API tester endpoints still return their
  // normal HTTP status codes.
  const sendFrameError=(input,{kind='preview'}={})=>{
    const upstream=Number(input?.statusCode||0);
    const headers={
      'cache-control':'no-store',
      'content-type':'text/html; charset=utf-8',
      'x-nekoroute-preview-error':kind,
      ...(upstream?{'x-nekoroute-upstream-status':String(upstream)}:{})
    };
    return res.status(200).set(headers).send(previewErrorHtml(input));
  };
  const s=getSession(String(req.params.id));if(!s)return sendFrameError({message:'Preview session expired.'},{kind:'session-expired'});
  const node=pool.nodes.get(s.nodeId);if(!node||node.status==='offline')return sendFrameError({message:'Selected proxy is unavailable.',node},{kind:'proxy-unavailable'});
  try{
    const target=await validatePublicTarget(String(req.query.url||''));
    s.currentPage=target.toString();
    const r=await requestViaProxy(node,target,{timeoutMs:config.previewTimeoutMs,maxBytes:config.previewMaxHtmlBytes,headers:{accept:'text/html,application/xhtml+xml,audio/*,video/*,image/*,application/pdf;q=0.8,text/plain;q=0.7,*/*;q=0.2','user-agent':config.previewUserAgent,'accept-language':'en-GB,en;q=0.9'}});
    if(r.statusCode>=300&&r.statusCode<400&&r.headers.location){const next=absolute(r.headers.location,target);if(next){await validatePublicTarget(next);return res.redirect(302,pageUrl(req.params.id,next));}}
    const type=String(r.headers['content-type']||'text/html').toLowerCase();
    if(r.statusCode>=400){
      const textual=type.includes('text/')||type.includes('json')||type.includes('html')||type.includes('xml');
      const excerpt=textual?String(r.body||'').replace(/\s+/g,' ').trim().slice(0,1800):'';
      return sendFrameError({
        statusCode:r.statusCode,
        message:`The upstream website returned HTTP ${r.statusCode} through this proxy.`,
        node,target:target.toString(),bodyExcerpt:excerpt
      },{kind:'upstream-http'});
    }
    if(!type.includes('html')){
      const allowed=type.startsWith('audio/')||type.startsWith('video/')||type.startsWith('image/')||type.includes('application/pdf');
      if(allowed)return res.status(200).type('html').send(nonHtmlPreview(req.params.id,s,target.toString(),type));
      return res.status(415).type('html').send(errorHtml(`Preview cannot render ${type}.`));
    }
    res.status(r.statusCode||200).set({'cache-control':'no-store','content-type':'text/html; charset=utf-8','cross-origin-resource-policy':'cross-origin'}).send(rewriteHtml(r.body,target.toString(),req.params.id,s));
  }catch(e){return sendFrameError({message:e.message||String(e),node,target:s.currentPage||String(req.query.url||'')},{kind:'proxy-transport'});}
});

const previewCors=(req,res)=>{
  res.set({
    'access-control-allow-origin':'*',
    'access-control-allow-methods':'GET,HEAD,OPTIONS',
    'access-control-allow-headers':req.get('access-control-request-headers')||'content-type,range,accept',
    'access-control-expose-headers':'content-type,content-length,content-range,accept-ranges,etag,last-modified',
    'cross-origin-resource-policy':'cross-origin',
    'cache-control':'no-store'
  });
};
app.options('/api/preview-runtime/:id',(req,res)=>{previewCors(req,res);res.status(204).end();});
app.all('/api/preview-runtime/:id',async(req,res)=>{
  previewCors(req,res);
  if(!['GET','HEAD'].includes(req.method))return res.status(405).json({error:'NekoRoute embedded preview only proxies GET/HEAD script requests'});
  const s=getSession(String(req.params.id));if(!s)return res.status(410).json({error:'Preview session expired'});
  const node=pool.nodes.get(s.nodeId);if(!node||node.status==='offline')return res.status(503).json({error:'Selected proxy is unavailable'});
  try{
    let target=await validatePublicTarget(String(req.query.url||''));
    const kind=String(req.query.kind||'');
    if(req.method==='GET'&&(kind==='media'||kind==='fetch')){
      return await pipeProxyStream(req,res,{node,target,kind:kind==='media'?'media':'download',referer:s.currentPage||target.origin+'/',cors:true});
    }
    let r,redirects=0;
    while(true){
      const range=req.get('range');
      r=await requestViaProxy(node,target,{timeoutMs:config.previewTimeoutMs,maxBytes:config.previewMaxResourceBytes,headers:{accept:req.get('accept')||'*/*','user-agent':config.previewUserAgent,'accept-language':req.get('accept-language')||'en-GB,en;q=0.9',referer:s.currentPage||target.origin+'/',...(range?{range}:{})},headersOnly:req.method==='HEAD'});
      if(r.statusCode>=300&&r.statusCode<400&&r.headers.location&&redirects<5){const next=absolute(r.headers.location,target);if(!next)break;target=await validatePublicTarget(next);redirects++;continue;}
      break;
    }
    let type=String(r.headers['content-type']||'application/octet-stream').toLowerCase();
    const guessed=guessMimeFromUrl(target.toString());
    if((type.includes('octet-stream')||type==='text/plain'||!r.headers['content-type'])&&guessed)type=guessed;
    const headers={'content-type':type||'application/octet-stream','cache-control':'private, max-age=120','cross-origin-resource-policy':'cross-origin'};
    for(const h of ['content-range','accept-ranges','etag','last-modified'])if(r.headers[h])headers[h]=r.headers[h];
    if(req.method==='HEAD')return res.status(r.statusCode||200).set(headers).end();
    if(type.includes('text/css')||kind==='style'){
      headers['content-type']='text/css; charset=utf-8';
      const body=rewriteCss(r.body,target.toString(),req.params.id,s);headers['content-length']=String(Buffer.byteLength(body));return res.status(r.statusCode||200).set(headers).send(body);
    }
    if(/(?:javascript|ecmascript)/i.test(type)||type.includes('text/js')||kind==='script'){
      headers['content-type']='application/javascript; charset=utf-8';
      const body=rewriteJavascript(r.body,target.toString(),req.params.id,s);headers['content-length']=String(Buffer.byteLength(body));return res.status(r.statusCode||200).set(headers).send(body);
    }
    headers['content-length']=String(r.bodyBuffer.length);
    return res.status(r.statusCode||200).set(headers).send(r.bodyBuffer);
  }catch(e){return res.status(502).json({error:e.message||'Runtime proxy request failed'});}
});
app.all('/api/preview-runtime-blocked/:id',(req,res)=>{previewCors(req,res);res.status(405).json({error:'Write requests are disabled in sandboxed Preview. Use Real Firefox mode for full site interactions.'});});

app.get('/api/preview-resource/:id/:token',async(req,res)=>{
  const s=getSession(String(req.params.id));if(!s)return res.status(410).end();
  const entry=s.resources.get(String(req.params.token));if(!entry)return res.status(404).end();
  const node=pool.nodes.get(s.nodeId);if(!node||node.status==='offline')return res.status(503).end();
  try{
    const target=await validatePublicTarget(entry.url);
    if(entry.kind==='media'||entry.kind==='download'){
      return await pipeProxyStream(req,res,{node,target,kind:entry.kind==='media'?'media':'download',referer:entry.referer||s.currentPage||target.origin+'/',download:req.query.download==='1',cors:true});
    }
    const range=req.get('range');
    const acceptByKind={image:'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',style:'text/css,*/*;q=0.2',script:'application/javascript,text/javascript,*/*;q=0.2',font:'font/woff2,font/woff,application/font-woff,application/octet-stream;q=0.8,*/*;q=0.2',media:'audio/*,video/*,*/*;q=0.5',download:'*/*',resource:'*/*'};
    const r=await requestViaProxy(node,target,{timeoutMs:config.previewTimeoutMs,maxBytes:req.query.download==='1'?config.previewMaxDownloadBytes:config.previewMaxResourceBytes,headers:{accept:acceptByKind[entry.kind]||'*/*','user-agent':config.previewUserAgent,'accept-language':'en-GB,en;q=0.9',...(entry.referer?{referer:entry.referer}:s.currentPage?{referer:s.currentPage}:{}),...(range?{range}:{})}});
    if(r.statusCode>=300&&r.statusCode<400&&r.headers.location){const next=absolute(r.headers.location,target);if(next){await validatePublicTarget(next);const newUrl=registerResource(req.params.id,s,next,entry.kind,entry.referer);return res.redirect(302,newUrl+(req.query.download==='1'?'?download=1':''));}}
    let type=String(r.headers['content-type']||'application/octet-stream').toLowerCase();
    const guessed=guessMimeFromUrl(target.toString());
    if((type.includes('octet-stream')||type==='text/plain'||!r.headers['content-type'])&&guessed)type=guessed;
    const scriptAllowed=entry.kind==='script'&&(/(?:javascript|ecmascript)/i.test(type)||type.includes('text/js')||type.startsWith('text/')||type.includes('application/octet-stream'));
    const styleAllowed=entry.kind==='style'&&(type.includes('css')||type.startsWith('text/')||type.includes('application/octet-stream'));
    const imageAllowed=entry.kind==='image'&&(type.startsWith('image/')||type.includes('octet-stream'));
    const fontAllowed=entry.kind==='font'&&(type.startsWith('font/')||type.includes('font-woff')||type.includes('octet-stream'));
    const mediaAllowed=entry.kind==='media'&&(type.startsWith('audio/')||type.startsWith('video/')||type.includes('octet-stream'));
    const normalAllowed=scriptAllowed||styleAllowed||imageAllowed||fontAllowed||mediaAllowed||type.startsWith('image/')||type.startsWith('font/')||type.startsWith('audio/')||type.startsWith('video/')||type.includes('text/css')||type.includes('font-woff')||type.includes('application/pdf');
    const downloadAllowed=entry.kind==='download'&&(normalAllowed||type.includes('application/octet-stream')||type.includes('application/force-download')||type.includes('application/download')||type.includes('application/x-download')||type.includes('binary/octet-stream'));
    if(!normalAllowed&&!downloadAllowed)return res.status(415).end();
    const headers={'cache-control':'private, max-age=120','content-type':type||r.headers['content-type']||'application/octet-stream','access-control-allow-origin':'*','cross-origin-resource-policy':'cross-origin'};
    if(r.headers['content-range'])headers['content-range']=r.headers['content-range'];if(r.headers['accept-ranges'])headers['accept-ranges']=r.headers['accept-ranges'];
    if(req.query.download==='1'){
      const remoteDisposition=String(r.headers['content-disposition']||'');const match=/filename\*?=(?:UTF-8''|")?([^";]+)/i.exec(remoteDisposition);let filename=path.basename(target.pathname)||'download';
      if(match?.[1]){try{filename=decodeURIComponent(match[1].trim());}catch{filename=match[1].trim();}}
      headers['content-disposition']=`attachment; filename="${filename.replace(/["\\\r\n]/g,'_')}"`;
    }
    if(type.includes('text/css')||styleAllowed){headers['content-type']='text/css; charset=utf-8';const body=rewriteCss(r.body,target.toString(),req.params.id,s);headers['content-length']=String(Buffer.byteLength(body));return res.status(r.statusCode||200).set(headers).send(body);}
    if(scriptAllowed){headers['content-type']='application/javascript; charset=utf-8';const body=rewriteJavascript(r.body,target.toString(),req.params.id,s);headers['content-length']=String(Buffer.byteLength(body));return res.status(r.statusCode||200).set(headers).send(body);}
    headers['content-length']=String(r.bodyBuffer.length);return res.status(r.statusCode||200).set(headers).send(r.bodyBuffer);
  }catch{return res.status(404).end();}
});

app.use((err,_req,res,_next)=>{console.error(err);res.status(400).json({error:err.message||'Request failed'});});
app.get('/tester',(_req,res)=>res.sendFile(path.join(root,'public','tester.html')));app.get('/preview',(_req,res)=>res.sendFile(path.join(root,'public','preview.html')));app.get('/browser',(_req,res)=>res.sendFile(path.join(root,'public','browser.html')));app.get('/scanner',(_req,res)=>res.sendFile(path.join(root,'public','scanner.html')));app.get(['/api','/api/docs'],(_req,res)=>res.sendFile(path.join(root,'public','api-docs.html')));app.get('/{*splat}',(_req,res)=>res.sendFile(path.join(root,'public','index.html')));
const server=app.listen(config.port,'0.0.0.0',()=>console.log(`[NekoRoute] listening on :${config.port}`));
const gateways=startProxyGateways(pool,{
  enabled:bool('PROXY_GATEWAY_ENABLED',false),
  host:process.env.PROXY_GATEWAY_HOST||'0.0.0.0',
  socksPort:int('SOCKS5_GATEWAY_PORT',1080),
  httpPort:int('HTTP_GATEWAY_PORT',8080),
  httpsPort:int('HTTPS_GATEWAY_PORT',8443),
  username:process.env.PROXY_GATEWAY_USERNAME||'',
  password:process.env.PROXY_GATEWAY_PASSWORD||'',
  timeoutMs:int('PROXY_GATEWAY_TIMEOUT_MS',12000),
  maxRetries:int('PROXY_GATEWAY_MAX_RETRIES',4),
  tlsCert:process.env.PROXY_GATEWAY_TLS_CERT||'',
  tlsKey:process.env.PROXY_GATEWAY_TLS_KEY||'',
  networkType:(process.env.PROXY_GATEWAY_NETWORK_TYPE||'any').toLowerCase()
});
let sourceBusy=false,sweepBusy=false;
const refresh=async()=>{if(sourceBusy)return;sourceBusy=true;try{const r=await pool.refreshSources();console.log(`[sources] ${r.retained?'retained':'loaded'} ${r.count} proxies (${r.discoveredThisRefresh??0} seen this refresh)`);for(const stat of r.sourceStats||[]){if(stat.ok)console.log(`[sources:${stat.source}] ${stat.count} proxies${stat.endpoint?` via ${stat.endpoint}`:''}`);else console.error(`[sources:${stat.source}] failed - ${(stat.errors||[]).map(x=>`${x.endpoint}: ${x.error}`).join(' | ')}`);}}catch(e){console.error('[sources]',e.message);}finally{sourceBusy=false;}};
const sweep=async()=>{if(sweepBusy)return;sweepBusy=true;try{await pool.healthSweep();console.log('[health] sweep complete');}catch(e){console.error('[health]',e.message);}finally{sweepBusy=false;}};
refresh().then(sweep);setInterval(refresh,config.sourceRefreshMs).unref();setInterval(sweep,config.healthIntervalMs).unref();setInterval(()=>pool.saveState(),120000).unref();
if(config.openPhishEnabled)setInterval(()=>refreshThreatIntel(config).then(s=>console.log(`[threat-intel] OpenPhish cache ${s.cachedUrls} URLs`)).catch(e=>console.error('[threat-intel]',e.message)),config.threatFeedRefreshMs).unref();
for(const signal of ['SIGTERM','SIGINT'])process.on(signal,async()=>{await pool.saveState();gateways.close();server.close(()=>process.exit(0));setTimeout(()=>process.exit(1),5000).unref();});
