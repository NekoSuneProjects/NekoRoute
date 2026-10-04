import http from 'node:http';
import https from 'node:https';
import { HttpProxyAgent } from 'http-proxy-agent';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { SocksProxyAgent } from 'socks-proxy-agent';

function guardEmitter(emitter, onError) {
  if (!emitter || typeof emitter.on !== 'function') return;
  emitter.on('error', error => {
    try { onError(error); } catch {}
  });
}

function guardProxyRequest(req, agent, onError) {
  guardEmitter(agent, onError);
  guardEmitter(req, onError);
  req.on('socket', socket => {
    // Covers HTTP, HTTPS/CONNECT, SOCKS4 and SOCKS5 sockets. Public proxies can
    // reset/refuse/drop connections at any point, including before ClientRequest
    // receives the error. Keeping a listener on the actual socket prevents Node
    // from treating those transport failures as fatal unhandled events.
    guardEmitter(socket, onError);
  });
}

function proxyTransportUrl(proxy) {
  const raw = new URL(proxy.url);

  // Public proxy feeds usually label a node "https" when it supports HTTPS
  // CONNECT tunnelling. That does NOT mean the proxy listener itself accepts a
  // TLS connection. Using https:// here makes Node start TLS with the proxy and
  // many public nodes immediately reset that socket (ECONNRESET).
  //
  // Keep the logical protocol as "https" for filtering/UI, but use ordinary
  // HTTP transport to reach the proxy. HttpsProxyAgent will still issue CONNECT
  // when the destination itself is HTTPS.
  if (proxy.protocol === 'https') raw.protocol = 'http:';
  return raw.toString();
}

export function makeAgent(proxy, targetProtocol = 'https:') {
  const transportUrl = proxyTransportUrl(proxy);
  if (proxy.protocol === 'socks4' || proxy.protocol === 'socks5') {
    return new SocksProxyAgent(transportUrl);
  }
  return targetProtocol === 'http:'
    ? new HttpProxyAgent(transportUrl)
    : new HttpsProxyAgent(transportUrl);
}

export function requestViaProxy(proxy, targetUrl, {
  timeoutMs = 7000,
  maxBytes = 65536,
  headersOnly = false,
  headers = {},
  method = 'GET',
  body = null
} = {}) {
  const target = targetUrl instanceof URL ? targetUrl : new URL(targetUrl);
  const lib = target.protocol === 'http:' ? http : https;
  const agent = makeAgent(proxy, target.protocol);
  const started = Date.now();

  return new Promise((resolve, reject) => {
    let settled = false;
    const done = value => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    const fail = error => {
      if (settled) return;
      settled = true;
      reject(error);
    };

    const req = lib.request(target, {
      agent,
      method: headersOnly ? 'HEAD' : String(method || 'GET').toUpperCase(),
      timeout: timeoutMs,
      headers: {
        'user-agent': 'NekoRoute/0.3 (+region-egress-test)',
        accept: 'text/html,application/xhtml+xml,application/json,text/plain,image/avif,image/webp,*/*;q=0.6',
        'accept-encoding': 'identity',
        ...headers
      }
    }, res => {
      const base = {
        statusCode: res.statusCode || 0,
        headers: res.headers,
        latencyMs: Date.now() - started
      };

      if (headersOnly) {
        res.destroy();
        done({ ...base, body: '', bodyBuffer: Buffer.alloc(0) });
        return;
      }

      let bytes = 0;
      const chunks = [];
      res.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > maxBytes) {
          res.destroy(new Error(`Response exceeded ${maxBytes} byte limit`));
          return;
        }
        chunks.push(chunk);
      });
      res.on('end', () => {
        const bodyBuffer = Buffer.concat(chunks);
        done({
          ...base,
          bodyBuffer,
          body: bodyBuffer.toString('utf8')
        });
      });
      res.on('error', fail);
    });
    guardProxyRequest(req, agent, fail);
    req.on('timeout', () => req.destroy(new Error('Proxy request timed out')));
    if (body != null && !headersOnly) req.write(body);
    req.end();
  });
}
export function openProxyStream(proxy, targetUrl, {
  timeoutMs = 15000,
  headers = {},
  method = 'GET'
} = {}) {
  const target = targetUrl instanceof URL ? targetUrl : new URL(targetUrl);
  const lib = target.protocol === 'http:' ? http : https;
  const agent = makeAgent(proxy, target.protocol);
  const started = Date.now();

  return new Promise((resolve, reject) => {
    let settled = false;
    const req = lib.request(target, {
      agent,
      method: String(method || 'GET').toUpperCase(),
      timeout: timeoutMs,
      headers: {
        'user-agent': 'NekoRoute/0.5 (+proxied-media-stream)',
        accept: '*/*',
        'accept-encoding': 'identity',
        ...headers
      }
    }, response => {
      // Streaming responses can fail after the promise has resolved. Keep a
      // listener attached so a late proxy/socket reset is never unhandled.
      guardEmitter(response, error => {
        if (!settled) {
          settled = true;
          reject(error);
        }
      });
      guardEmitter(response.socket, error => {
        if (!settled) {
          settled = true;
          reject(error);
        }
      });
      if (settled) {
        response.destroy();
        return;
      }
      settled = true;
      resolve({
        request: req,
        response,
        statusCode: response.statusCode || 0,
        headers: response.headers,
        latencyMs: Date.now() - started
      });
    });
    const fail = error => {
      if (settled) return;
      settled = true;
      reject(error);
    };
    guardProxyRequest(req, agent, fail);
    req.on('timeout', () => req.destroy(new Error('Proxy request timed out')));
    req.end();
  });
}

