import net from 'node:net';
import { createHash } from 'node:crypto';

const VT_BASE = 'https://www.virustotal.com/api/v3';
const bounded = (value, min, max) => Math.min(max, Math.max(min, Number(value) || min));

export function sha256(buffer) {
  return createHash('sha256').update(buffer).digest('hex');
}

export async function clamavScanFile(buffer, {host, port = 3310, timeoutMs = 30000} = {}) {
  if (!host) return {available:false, status:'not_configured'};
  return await new Promise(resolve => {
    const socket = net.createConnection({host, port});
    let completed = false;
    let response = '';
    const finish = result => {
      if (completed) return;
      completed = true;
      socket.destroy();
      resolve(result);
    };
    socket.setTimeout(bounded(timeoutMs, 3000, 120000));
    socket.once('error', error => finish({available:false,status:'error',error:String(error.message || error)}));
    socket.once('timeout', () => finish({available:false,status:'timeout'}));
    socket.once('close', () => { if (!completed) finish({available:false,status:'error',error:'ClamAV connection closed before reply'}); });
    socket.once('connect', () => {
      socket.write(Buffer.from('zINSTREAM\0'));
      for (let off = 0; off < buffer.length; off += 64 * 1024) {
        const chunk = buffer.subarray(off, off + 64 * 1024);
        const size = Buffer.alloc(4);
        size.writeUInt32BE(chunk.length);
        socket.write(size);
        socket.write(chunk);
      }
      socket.write(Buffer.alloc(4));
    });
    socket.on('data', chunk => {
      response += chunk.toString('utf8');
      if (response.length > 4096) return finish({available:false,status:'error',error:'Oversized ClamAV response'});
      const stop = response.indexOf('\0');
      if (stop < 0 && !response.includes('\n')) return;
      const line = response.slice(0, stop < 0 ? response.indexOf('\n') : stop).trim();
      const found = /:\s*(.*?)\s+FOUND$/.exec(line);
      if (found) return finish({available:true,status:'infected',clean:false,signature:found[1]});
      if (/:\s*OK$/.test(line)) return finish({available:true,status:'clean',clean:true});
      return finish({available:false,status:'error',error:line.slice(0,250)});
    });
  });
}

function presentReport(json, sha) {
  const attributes = json?.data?.attributes || {};
  const rawResults = attributes.last_analysis_results || {};
  const engines = Object.entries(rawResults).map(([name, item]) => ({
    name: item?.engine_name || name,
    category: item?.category || 'unknown',
    result: item?.result || null,
    method: item?.method || null,
    engineVersion: item?.engine_version || null,
    engineUpdate: item?.engine_update || null
  }));
  engines.sort((a,b) => a.name.localeCompare(b.name));
  return {
    available:true, known:true, sha256:sha,
    stats:attributes.last_analysis_stats || null,
    lastAnalysisDate:attributes.last_analysis_date || null,
    engines,
    permalink:`https://www.virustotal.com/gui/file/${sha}/detection`
  };
}

async function vtRequest(path, key, {method='GET', body, headers={}} = {}) {
  const response = await fetch(`${VT_BASE}${path}`, {
    method, headers:{'x-apikey':key,accept:'application/json',...headers},
    body, signal:AbortSignal.timeout(30000)
  });
  const text = await response.text();
  const json = (() => { try {return JSON.parse(text);} catch {return {}; } })();
  return {status:response.status, json};
}

export async function virusTotalFileScan(buffer, {apiKey, upload=false, filename='sample.bin'}={}) {
  if (!apiKey) return {available:false,status:'not_configured'};
  const sha = sha256(buffer);
  try {
    const lookup = await vtRequest(`/files/${sha}`, apiKey);
    if (lookup.status === 200) return presentReport(lookup.json,sha);
    if (lookup.status !== 404) return {available:false,status:'provider_error',httpStatus:lookup.status};
    if (!upload) return {available:true,known:false,sha256:sha,uploaded:false};
    // Public VirusTotal submissions can be shared with security researchers. Never implicit.
    if (buffer.length > 32 * 1024 * 1024) return {available:false,status:'file_too_large_for_upload'};
    const form = new FormData();
    form.set('file', new Blob([buffer]), String(filename).slice(0,180));
    const submission = await vtRequest('/files', apiKey, {method:'POST',body:form});
    if (submission.status !== 200 && submission.status !== 201) return {available:false,status:'upload_failed',httpStatus:submission.status};
    return {available:true,known:false,sha256:sha,uploaded:true,status:'queued',analysisId:submission.json?.data?.id || null};
  } catch (error) {
    return {available:false,status:'provider_error',error:String(error.message || error)};
  }
}

export async function virusTotalAnalysis(id, apiKey) {
  if (!apiKey) return {available:false,status:'not_configured'};
  if (!/^[A-Za-z0-9_-]{1,1024}$/.test(id)) return {available:false,status:'invalid_id'};
  try {
    const result = await vtRequest(`/analyses/${encodeURIComponent(id)}`,apiKey);
    if (result.status !== 200) return {available:false,status:'provider_error',httpStatus:result.status};
    const attrs = result.json?.data?.attributes || {};
    const engines = Object.entries(attrs.results || {}).map(([name,value])=>({
      name:value.engine_name||name,category:value.category||'unknown',result:value.result||null
    })).sort((a,b)=>a.name.localeCompare(b.name));
    return {available:true,status:attrs.status||'unknown',stats:attrs.stats||null,engines};
  } catch(error) {return {available:false,status:'provider_error',error:String(error.message||error)};}
}
