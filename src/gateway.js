import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import { readExact, readHttpHeaders, readSocksAddress } from './gateway-framing.js';

const timeout = (socket, ms) => {
  socket.setTimeout(ms);
  return socket;
};
const write = (socket, data) => new Promise((resolve, reject) => socket.write(data, error => error ? reject(error) : resolve()));

function credentials(node) {
  try {
    const u = new URL(node.url);
    return { username: decodeURIComponent(u.username || ''), password: decodeURIComponent(u.password || '') };
  } catch { return { username: '', password: '' }; }
}

function connectSocket(host, port, secure, timeoutMs) {
  return new Promise((resolve, reject) => {
    const opts = { host, port, servername: secure && net.isIP(host) === 0 ? host : undefined, rejectUnauthorized: true };
    const socket = secure ? tls.connect(opts) : net.connect(opts);
    timeout(socket, timeoutMs);
    socket.once('connect', () => !secure && resolve(socket));
    if (secure) socket.once('secureConnect', () => resolve(socket));
    const fail = error => {
      socket.destroy();
      reject(error);
    };
    socket.once('error', fail);
    socket.once('timeout', () => fail(new Error('Proxy connection timed out')));
  });
}

async function httpTunnel(node, host, port, timeoutMs) {
  const secure = node.protocol === 'https';
  const socket = await connectSocket(node.ip, node.port, secure, timeoutMs);
  const { username, password } = credentials(node);
  const auth = username ? `Proxy-Authorization: Basic ${Buffer.from(`${username}:${password}`).toString('base64')}\r\n` : '';
  await write(socket, `CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n${auth}Proxy-Connection: Keep-Alive\r\n\r\n`);
  const response = await readHttpHeaders(socket);
  const status = Number((response.toString('latin1').match(/^HTTP\/\d\.\d\s+(\d+)/) || [])[1]);
  if (status !== 200) { socket.destroy(); throw new Error(`Upstream HTTP proxy CONNECT returned ${status || 'invalid response'}`); }
  return socket;
}

async function socks5Tunnel(node, host, port, timeoutMs) {
  const socket = await connectSocket(node.ip, node.port, false, timeoutMs);
  const { username, password } = credentials(node);
  await write(socket, Buffer.from(username ? [5,2,0,2] : [5,1,0]));
  let reply = await readExact(socket, 2);
  if (reply[0] !== 5 || reply[1] === 0xff) throw new Error('SOCKS5 authentication method rejected');
  if (reply[1] === 2) {
    const u = Buffer.from(username), p = Buffer.from(password);
    if (u.length > 255 || p.length > 255) throw new Error('SOCKS5 credentials too long');
    await write(socket, Buffer.concat([Buffer.from([1,u.length]),u,Buffer.from([p.length]),p]));
    reply = await readExact(socket, 2);
    if (reply[1] !== 0) throw new Error('SOCKS5 authentication failed');
  }
  let address;
  if (net.isIP(host) === 4) address = Buffer.concat([Buffer.from([1]), Buffer.from(host.split('.').map(Number))]);
  else {
    const h = Buffer.from(host);
    if (h.length > 255) throw new Error('SOCKS5 hostname too long');
    address = Buffer.concat([Buffer.from([3,h.length]),h]);
  }
  await write(socket, Buffer.concat([Buffer.from([5,1,0]), address, Buffer.from([(port >> 8) & 255, port & 255])]));
  reply = await readExact(socket, 4);
  if (reply[0] !== 5 || reply[1] !== 0) throw new Error(`SOCKS5 upstream connect failed (${reply[1] ?? 'invalid'})`);
  await readSocksAddress(socket, reply[3]);
  await readExact(socket, 2); // BND.PORT; must consume before forwarding TLS
  return socket;
}

async function tunnelVia(node, host, port, timeoutMs) {
  if (node.protocol === 'socks5') return socks5Tunnel(node, host, port, timeoutMs);
  if (node.protocol === 'http' || node.protocol === 'https') return httpTunnel(node, host, port, timeoutMs);
  throw new Error(`Unsupported gateway upstream protocol: ${node.protocol}`);
}

function markFailure(node, error) {
  node.failures = (node.failures || 0) + 1;
  node.consecutiveFailures = (node.consecutiveFailures || 0) + 1;
  node.status = node.consecutiveFailures >= 2 ? 'offline' : 'degraded';
  node.gatewayCooldownUntil = Date.now() + Math.min(10 * 60_000, 30_000 * 2 ** Math.min(5, node.consecutiveFailures - 1));
  node.lastCheck = new Date().toISOString();
  node.lastError = String(error?.message || error).slice(0,180);
}
function markSuccess(node) {
  node.successes = (node.successes || 0) + 1;
  node.consecutiveFailures = 0;
  node.gatewayCooldownUntil = 0;
  node.status = 'online';
  node.lastSuccess = new Date().toISOString();
  node.lastError = null;
}

function authOk(header, username, password) {
  if (!username) return true;
  if (!header?.startsWith('Basic ')) return false;
  try { return Buffer.from(header.slice(6), 'base64').toString() === `${username}:${password}`; } catch { return false; }
}

export function startProxyGateways(pool, {
  enabled = false, host = '0.0.0.0', socksPort = 1080, httpPort = 8080, httpsPort = 8443,
  username = '', password = '', timeoutMs = 12000, maxRetries = 4, tlsCert = '', tlsKey = '', networkType = 'any'
} = {}) {
  if (!enabled) return { close: () => {} };
  const servers = [];
  // Only recently verified, repeatedly successful proxies are safe candidates.
  const candidates = () => pool.list({status:'online',networkType}).filter(n =>
    ['socks5','http','https'].includes(n.protocol) &&
    n.sourcePresent !== false &&
    (n.successes || 0) >= 2 &&
    (n.consecutiveFailures || 0) === 0 &&
    n.lastSuccess && Date.now() - Date.parse(n.lastSuccess) <= 5 * 60_000 &&
    Date.now() >= (n.gatewayCooldownUntil || 0)
  );

  async function connectBest(hostname, port) {
    let lastError;
    for (const node of candidates().slice(0, Math.max(1,maxRetries))) {
      try {
        const socket = await tunnelVia(node, hostname, port, timeoutMs);
        markSuccess(node);
        return { socket, node };
      } catch (error) { lastError = error; markFailure(node,error); }
    }
    throw lastError || new Error('No healthy SOCKS5/HTTP/HTTPS upstream proxies are available');
  }

  const handleConnect = async (req, client, head) => {
    if (!authOk(req.headers['proxy-authorization'], username, password)) {
      client.end('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="NekoRoute"\r\n\r\n'); return;
    }
    const [hostname, rawPort] = String(req.url).split(':');
    const port = Number(rawPort || 443);
    try {
      const {socket,node} = await connectBest(hostname, port);
      client.setTimeout(0);
      socket.setTimeout(0);
      client.write('HTTP/1.1 200 Connection Established\r\nProxy-Agent: NekoRoute\r\n\r\n');
      if (head?.length) socket.write(head);
      // Socket errors must never take down the gateway process.
      const started = Date.now();
      let receivedUpstream = false;
      socket.once('data', () => { receivedUpstream = true; });
      const terminate = () => { if (!client.destroyed) client.destroy(); if (!socket.destroyed) socket.destroy(); };
      socket.on('error', error => { if (!receivedUpstream && Date.now() - started < 10000) markFailure(node, error); terminate(); });
      client.on('error', terminate);
      socket.on('close', () => { if (!receivedUpstream && Date.now() - started < 2500) markFailure(node, new Error('Upstream closed before responding')); terminate(); });
      client.on('close', terminate);
      socket.pipe(client); client.pipe(socket);
    } catch { client.end('HTTP/1.1 502 Bad Gateway\r\n\r\n'); }
  };

  const handleHttp = async (req, res) => {
    if (!authOk(req.headers['proxy-authorization'], username, password)) {
      res.writeHead(407, {'proxy-authenticate':'Basic realm="NekoRoute"'}); return res.end();
    }
    let target;
    try { target = new URL(req.url); } catch { res.writeHead(400); return res.end('Absolute proxy URL required'); }
    try {
      const port = Number(target.port || (target.protocol === 'https:' ? 443 : 80));
      const {socket} = await connectBest(target.hostname, port);
      socket.setTimeout(0);
      const headers = {...req.headers, host:target.host};
      delete headers['proxy-authorization']; delete headers['proxy-connection'];
      const lines = [`${req.method} ${target.pathname || '/'}${target.search} HTTP/1.1`, ...Object.entries(headers).map(([k,v])=>`${k}: ${v}`), '', ''];
      socket.write(lines.join('\r\n')); req.pipe(socket);
      const terminate = () => { if (!socket.destroyed) socket.destroy(); };
      socket.on('error', terminate);
      res.socket.on('error', terminate);
      res.socket.on('close', terminate);
      socket.pipe(res.socket);
    } catch { if (!res.headersSent) res.writeHead(502); res.end(); }
  };

  const makeHttpServer = secure => {
    const handler = (req,res) => handleHttp(req,res);
    let server;
    if (secure) {
      if (!tlsCert || !tlsKey) { console.warn('[gateway] HTTPS proxy disabled: set PROXY_GATEWAY_TLS_CERT and PROXY_GATEWAY_TLS_KEY'); return null; }
      server = https.createServer({cert:fs.readFileSync(tlsCert),key:fs.readFileSync(tlsKey)},handler);
    } else server = http.createServer(handler);
    server.on('connect', handleConnect);
    return server;
  };

  const httpServer = makeHttpServer(false);
  httpServer.listen(httpPort,host,()=>console.log(`[gateway] HTTP proxy listening on ${host}:${httpPort}`)); servers.push(httpServer);
  const httpsServer = makeHttpServer(true);
  if (httpsServer) { httpsServer.listen(httpsPort,host,()=>console.log(`[gateway] HTTPS proxy listening on ${host}:${httpsPort}`)); servers.push(httpsServer); }

  const socksServer = net.createServer(client => {
    timeout(client, timeoutMs);
    client.on('error', () => client.destroy());
    (async () => {
      const greeting = await readExact(client, 2);
      if (greeting[0] !== 5) throw new Error('SOCKS5 only');
      const methods = [...await readExact(client, greeting[1])];
      const needAuth = Boolean(username);
      const method = needAuth ? (methods.includes(2) ? 2 : 255) : (methods.includes(0) ? 0 : 255);
      await write(client, Buffer.from([5, method]));
      if (method === 255) return client.end();
      if (method === 2) {
        const authHeader = await readExact(client, 2);
        if (authHeader[0] !== 1) throw new Error('Invalid authentication version');
        const user = (await readExact(client, authHeader[1])).toString();
        const passLength = (await readExact(client, 1))[0];
        const pass = (await readExact(client, passLength)).toString();
        const ok = user === username && pass === password;
        await write(client, Buffer.from([1, ok ? 0 : 1]));
        if (!ok) return client.end();
      }
      const request = await readExact(client, 4);
      if (request[0] !== 5 || request[1] !== 1 || request[2] !== 0) throw new Error('Only SOCKS5 CONNECT is supported');
      let hostname;
      if (request[3] === 1) hostname = [...await readExact(client, 4)].join('.');
      else if (request[3] === 3) {
        const size = (await readExact(client, 1))[0];
        hostname = (await readExact(client, size)).toString();
      } else if (request[3] === 4) {
        const data = await readExact(client, 16);
        hostname = Array.from({length: 8}, (_,i) => data.readUInt16BE(i*2).toString(16)).join(':');
      } else throw new Error('Unsupported SOCKS5 address type');
      const port = (await readExact(client, 2)).readUInt16BE(0);
      const { socket, node } = await connectBest(hostname, port);
      await write(client, Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]));
      client.setTimeout(0);
      socket.setTimeout(0);
      const started = Date.now();
      let receivedUpstream = false;
      let failureRecorded = false;
      const reportEarlyFailure = reason => {
        if (failureRecorded || receivedUpstream || Date.now() - started > 10000) return;
        failureRecorded = true;
        markFailure(node, reason);
      };
      const terminate = () => { if (!client.destroyed) client.destroy(); if (!socket.destroyed) socket.destroy(); };
      socket.once('data', () => { receivedUpstream = true; });
      socket.on('error', error => { reportEarlyFailure(error); terminate(); });
      socket.on('close', () => { if (Date.now() - started < 2500) reportEarlyFailure(new Error('Upstream closed before responding')); terminate(); });
      client.on('close', terminate);
      socket.pipe(client);
      client.pipe(socket);
    })().catch(error => {
      if (!client.destroyed) {
        client.end(Buffer.from([5, 1, 0, 1, 0, 0, 0, 0, 0, 0]));
      }
      console.warn('[gateway] SOCKS5 tunnel failed:', error.message);
    });
  });
  socksServer.listen(socksPort,host,()=>console.log(`[gateway] SOCKS5 proxy listening on ${host}:${socksPort}`)); servers.push(socksServer);

  return { close: () => servers.forEach(server => server.close()) };
}
