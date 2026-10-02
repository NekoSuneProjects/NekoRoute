import https from 'node:https';
import { regionForCountry } from './regions.js';

const SOURCE_TIMEOUT_MS = Math.max(5000, Number.parseInt(process.env.SOURCE_FETCH_TIMEOUT_MS || '25000', 10));
const MAX_SOURCE_BYTES = Math.max(1024 * 1024, Number.parseInt(process.env.MAX_SOURCE_BYTES || String(32 * 1024 * 1024), 10));
const PROVIDER_ITEM_CAP = Math.max(500, Number.parseInt(process.env.SOURCE_PROVIDER_ITEM_CAP || '2500', 10));
const SOURCE_MAX_PAGES = Math.max(1, Number.parseInt(process.env.SOURCE_MAX_PAGES || '20', 10));
const SOURCE_CONCURRENCY = Math.max(1, Math.min(8, Number.parseInt(process.env.SOURCE_CONCURRENCY || '4', 10)));
const SOURCE_PAGE_CONCURRENCY = Math.max(1, Math.min(6, Number.parseInt(process.env.SOURCE_PAGE_CONCURRENCY || '2', 10)));
const SOCKS5PROXIES_MAX_PAGES = Math.max(1, Math.min(SOURCE_MAX_PAGES, Number.parseInt(process.env.SOCKS5PROXIES_MAX_PAGES || '5', 10)));

function normalizeCountry(value) {
  let v = String(value || 'XX').trim().toUpperCase();
  if (v === 'UK') v = 'GB';
  return /^[A-Z]{2}$/.test(v) ? v : 'XX';
}

function normalizeProtocol(value) {
  const v = String(value || '').trim().toLowerCase();
  if (v === 'socks') return 'socks5';
  return v;
}

function parseProxyUrl(value) {
  try {
    const u = new URL(String(value || ''));
    const protocol = normalizeProtocol(u.protocol.replace(':', ''));
    const defaultPort = protocol === 'https' ? 443 : protocol === 'http' ? 80 : 0;
    const port = Number(u.port || defaultPort);
    if (!u.hostname || !port) return null;
    return { protocol, ip: u.hostname, port };
  } catch {
    return null;
  }
}

function parseHostPort(value, protocol) {
  const line = String(value || '').trim();
  if (!line || line.startsWith('#')) return null;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(line)) return parseProxyUrl(line);
  const match = line.match(/^\[([^\]]+)\]:(\d+)$|^([^:\s]+):(\d+)$/);
  if (!match) return null;
  const ip = match[1] || match[3];
  const port = Number(match[2] || match[4]);
  if (!ip || !port) return null;
  return { protocol: normalizeProtocol(protocol), ip, port };
}

function score01(value, divisor = 1) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(1, n / divisor));
}

function providerScore(uptime, latencyMs) {
  const uptimeScore = Number.isFinite(Number(uptime)) ? score01(uptime, 100) : 0.5;
  const latency = Number(latencyMs);
  const latencyScore = Number.isFinite(latency) && latency >= 0 ? Math.max(0, Math.min(1, 1 - latency / 10000)) : 0.5;
  return Math.max(0, Math.min(1, uptimeScore * 0.82 + latencyScore * 0.18));
}

function splitProtocols(value) {
  const raw = Array.isArray(value) ? value : String(value || '').split(/[\s,|/]+/);
  return [...new Set(raw.map(normalizeProtocol).filter(Boolean))];
}

function withQuery(url, params = {}) {
  const out = new URL(url);
  for (const [key, value] of Object.entries(params)) {
    if (value == null || value === '') out.searchParams.delete(key);
    else out.searchParams.set(key, String(value));
  }
  return out.toString();
}

function downloadText(url, redirectsLeft = 4) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, {
      family: 4,
      headers: {
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0',
        accept: 'application/json,text/plain;q=0.9,*/*;q=0.5',
        'accept-encoding': 'identity',
        'cache-control': 'no-cache'
      }
    }, res => {
      const status = res.statusCode || 0;
      if (status >= 300 && status < 400 && res.headers.location) {
        res.resume();
        if (redirectsLeft <= 0) return reject(new Error('too many redirects'));
        const redirected = new URL(res.headers.location, url).toString();
        return downloadText(redirected, redirectsLeft - 1).then(resolve, reject);
      }
      if (status < 200 || status >= 300) {
        res.resume();
        return reject(new Error(`HTTP ${status}`));
      }

      let bytes = 0;
      const chunks = [];
      res.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > MAX_SOURCE_BYTES) {
          req.destroy(new Error(`source exceeded ${MAX_SOURCE_BYTES} bytes`));
          return;
        }
        chunks.push(chunk);
      });
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      res.on('error', reject);
    });

    req.setTimeout(SOURCE_TIMEOUT_MS, () => req.destroy(new Error(`timeout after ${SOURCE_TIMEOUT_MS}ms`)));
    req.on('error', reject);
  });
}

async function downloadJson(url) {
  return JSON.parse(await downloadText(url));
}

async function mapLimited(values, concurrency, fn) {
  const results = new Array(values.length);
  let cursor = 0;
  const workers = Array.from({ length: Math.min(concurrency, values.length) }, async () => {
    while (true) {
      const index = cursor++;
      if (index >= values.length) break;
      results[index] = await fn(values[index], index);
    }
  });
  await Promise.all(workers);
  return results;
}

function validProxy(p) {
  return ['http','https','socks4','socks5'].includes(p.protocol) &&
    typeof p.ip === 'string' && p.ip.length > 0 && p.ip.length <= 255 &&
    Number.isInteger(p.port) && p.port > 0 && p.port < 65536;
}

function baseItem({ protocol, ip, port, https = false, anonymity = 'unknown', sourceScore = 0, country = 'XX', city = 'Unknown' }) {
  return {
    protocol: normalizeProtocol(protocol),
    ip: String(ip || '').trim(),
    port: Number(port),
    https: Boolean(https) || normalizeProtocol(protocol) === 'https',
    anonymity: String(anonymity || 'unknown').toLowerCase(),
    sourceScore: Math.max(0, Math.min(1, Number(sourceScore) || 0)),
    country: normalizeCountry(country),
    city: city || 'Unknown'
  };
}

async function loadPaginatedJson({ makeUrl, pageSize, parsePage, totalFrom, maxItems = PROVIDER_ITEM_CAP, maxPages = SOURCE_MAX_PAGES }) {
  const errors = [];
  const firstEndpoint = makeUrl(1);
  let first;
  try {
    first = await downloadJson(firstEndpoint);
  } catch (error) {
    errors.push({ endpoint: firstEndpoint, error: String(error?.message || error).slice(0, 240) });
    return { items: [], endpoint: null, errors, pages: 0, totalAvailable: 0 };
  }

  const firstItems = parsePage(first).filter(validProxy);
  const totalAvailable = Math.max(firstItems.length, Number(totalFrom(first)) || firstItems.length);
  const requiredPages = Math.max(1, Math.ceil(Math.min(maxItems, totalAvailable || maxItems) / pageSize));
  const totalPages = Math.min(maxPages, requiredPages);
  const pageNumbers = [];
  for (let page = 2; page <= totalPages; page++) pageNumbers.push(page);

  const pageResults = await mapLimited(pageNumbers, SOURCE_PAGE_CONCURRENCY, async page => {
    const endpoint = makeUrl(page);
    try {
      const data = await downloadJson(endpoint);
      return { page, endpoint, items: parsePage(data).filter(validProxy), error: null };
    } catch (error) {
      return { page, endpoint, items: [], error: String(error?.message || error).slice(0, 240) };
    }
  });

  const items = [...firstItems];
  for (const result of pageResults) {
    if (result.error) errors.push({ endpoint: result.endpoint, error: result.error });
    else items.push(...result.items);
  }

  return {
    items: diversityPick(items, maxItems),
    endpoint: firstEndpoint,
    errors,
    pages: 1 + pageResults.filter(x => !x.error).length,
    totalAvailable
  };
}

async function loadOffsetPaginatedJson({ makeUrl, pageSize, parsePage, totalFrom, pageSizeFrom, maxItems = PROVIDER_ITEM_CAP, maxPages = SOURCE_MAX_PAGES }) {
  const errors = [];
  const firstEndpoint = makeUrl(0, pageSize);
  let first;
  try {
    first = await downloadJson(firstEndpoint);
  } catch (error) {
    errors.push({ endpoint: firstEndpoint, error: String(error?.message || error).slice(0, 240) });
    return { items: [], endpoint: null, errors, pages: 0, totalAvailable: 0 };
  }

  const firstItems = parsePage(first).filter(validProxy);
  const actualPageSize = Math.max(1, Number(pageSizeFrom?.(first)) || pageSize || firstItems.length || 1);
  const totalAvailable = Math.max(firstItems.length, Number(totalFrom(first)) || firstItems.length);
  const requiredPages = Math.max(1, Math.ceil(Math.min(maxItems, totalAvailable || maxItems) / actualPageSize));
  const totalPages = Math.min(maxPages, requiredPages);
  const offsets = [];
  for (let page = 1; page < totalPages; page++) offsets.push(page * actualPageSize);

  const pageResults = await mapLimited(offsets, SOURCE_PAGE_CONCURRENCY, async offset => {
    const endpoint = makeUrl(offset, actualPageSize);
    try {
      const data = await downloadJson(endpoint);
      return { offset, endpoint, items: parsePage(data).filter(validProxy), error: null };
    } catch (error) {
      return { offset, endpoint, items: [], error: String(error?.message || error).slice(0, 240) };
    }
  });

  const items = [...firstItems];
  for (const result of pageResults) {
    if (result.error) errors.push({ endpoint: result.endpoint, error: result.error });
    else items.push(...result.items);
  }

  return {
    items: diversityPick(items, maxItems),
    endpoint: firstEndpoint,
    errors,
    pages: 1 + pageResults.filter(x => !x.error).length,
    totalAvailable
  };
}

async function loadAdvancedName() {
  const baseUrl = String(process.env.ADVANCED_NAME_FEED_URL || '').trim();
  if (!baseUrl) return { items: [], endpoint: null, errors: [], pages: 0, totalAvailable: 0, disabled: true };

  const definitions = ['http', 'https', 'socks4', 'socks5'];
  const results = await mapLimited(definitions, Math.min(definitions.length, SOURCE_PAGE_CONCURRENCY), async protocol => {
    const endpoint = withQuery(baseUrl, { type: protocol });
    try {
      const raw = await downloadText(endpoint);
      const items = String(raw || '').split(/\r?\n/)
        .map(line => parseHostPort(line, protocol))
        .filter(Boolean)
        .map(x => baseItem({ ...x, sourceScore: 0.4, country: 'XX', city: 'Unknown' }))
        .filter(validProxy);
      return { protocol, items, error: null };
    } catch (error) {
      return { protocol, items: [], error: String(error?.message || error).slice(0, 240) };
    }
  });

  const all = [];
  const errors = [];
  for (const result of results) {
    if (result.error) errors.push({ endpoint: `Advanced.name?type=${result.protocol}`, error: result.error });
    else all.push(...result.items);
  }
  return {
    items: diversityPick(all, PROVIDER_ITEM_CAP),
    endpoint: 'Advanced.name configured export',
    errors,
    pages: results.filter(x => !x.error).length,
    totalAvailable: all.length
  };
}

function parseProxMintPage(data) {
  const rows = Array.isArray(data?.rows) ? data.rows : [];
  return rows.map(x => baseItem({
    protocol: x.protocol,
    ip: x.ip,
    port: x.port,
    https: normalizeProtocol(x.protocol) === 'https',
    anonymity: x.anonymity,
    sourceScore: Math.max(score01(x.score, 100), providerScore(x.uptimePct, x.latencyMs)),
    country: x.countryCode,
    city: 'Unknown'
  }));
}

function parseSocks5ProxiesPage(data) {
  const rows = Array.isArray(data?.data) ? data.data : [];
  const out = [];
  for (const x of rows) {
    const protocols = new Set(splitProtocols(x.protocols));
    if (Number(x.http) === 1) protocols.add('http');
    if (Number(x.socks4) === 1) protocols.add('socks4');
    if (Number(x.socks5) === 1) protocols.add('socks5');
    if (Number(x.ssl) === 1 && Number(x.http) === 1) protocols.add('https');
    for (const protocol of protocols) {
      out.push(baseItem({
        protocol,
        ip: x.ip || x.host,
        port: x.port,
        https: protocol === 'https',
        anonymity: x.anonymity_level,
        sourceScore: Number.isFinite(Number(x.health_score))
          ? score01(x.health_score, 100)
          : providerScore(x.uptime, x.delay),
        country: x.country_code,
        city: x.city
      }));
    }
  }
  return out;
}

async function loadSocks5Proxies() {
  return loadOffsetPaginatedJson({
    pageSize: 100,
    maxItems: PROVIDER_ITEM_CAP,
    maxPages: SOCKS5PROXIES_MAX_PAGES,
    makeUrl: (offset, limit) => `https://api.socks5proxies.com/api/proxies?limit=${limit}&offset=${offset}&sort=health`,
    totalFrom: data => data?.meta?.total,
    pageSizeFrom: data => data?.meta?.limit,
    parsePage: parseSocks5ProxiesPage
  });
}

function utcDate(daysOffset = 0) {
  const date = new Date(Date.now() + daysOffset * 86400000);
  return date.toISOString().slice(0, 10);
}

async function loadRolaIp() {
  const errors = [];
  for (const date of [utcDate(0), utcDate(-1)]) {
    const result = await loadPaginatedJson({
      pageSize: 100,
      maxItems: PROVIDER_ITEM_CAP,
      makeUrl: page => `https://rola-ip.co/api/external/free-proxy/daily-list?date=${encodeURIComponent(date)}&page=${page}&page_size=100`,
      totalFrom: data => data?.data?.total,
      parsePage: data => {
        const rows = Array.isArray(data?.data?.items) ? data.data.items : [];
        const out = [];
        for (const x of rows) {
          for (const protocol of splitProtocols(x.protocols)) {
            out.push(baseItem({
              protocol,
              ip: x.ip,
              port: x.port,
              https: protocol === 'https',
              anonymity: x.anonymity,
              sourceScore: providerScore(x.uptime, x.response),
              country: x.code,
              city: 'Unknown'
            }));
          }
        }
        return out;
      }
    });
    errors.push(...result.errors);
    if (result.items.length) return { ...result, errors, date };
  }
  return { items: [], endpoint: null, errors, pages: 0, totalAvailable: 0 };
}

async function loadVakhov() {
  const definitions = [
    ['http', 'https://vakhov.github.io/fresh-proxy-list/http.txt'],
    ['https', 'https://vakhov.github.io/fresh-proxy-list/https.txt'],
    ['socks4', 'https://vakhov.github.io/fresh-proxy-list/socks4.txt'],
    ['socks5', 'https://vakhov.github.io/fresh-proxy-list/socks5.txt']
  ];
  const errors = [];
  const results = await mapLimited(definitions, Math.min(4, SOURCE_PAGE_CONCURRENCY), async ([protocol, endpoint]) => {
    try {
      const raw = await downloadText(endpoint);
      const items = raw.split(/\r?\n/).map(line => parseHostPort(line, protocol)).filter(Boolean).map(x => baseItem({
        ...x,
        sourceScore: 0.35,
        country: 'XX',
        city: 'Unknown'
      })).filter(validProxy);
      return { protocol, endpoint, items };
    } catch (error) {
      return { protocol, endpoint, items: [], error: String(error?.message || error).slice(0, 240) };
    }
  });
  const all = [];
  for (const result of results) {
    if (result.error) errors.push({ endpoint: result.endpoint, error: result.error });
    else all.push(...result.items);
  }
  return {
    items: diversityPick(all, PROVIDER_ITEM_CAP),
    endpoint: 'https://vakhov.github.io/fresh-proxy-list/',
    errors,
    pages: results.filter(x => !x.error).length,
    totalAvailable: all.length
  };
}


function evenlySample(values, maxItems) {
  if (values.length <= maxItems) return values;
  const out = [];
  const step = values.length / maxItems;
  for (let i = 0; i < maxItems; i++) out.push(values[Math.min(values.length - 1, Math.floor(i * step))]);
  return out;
}

async function loadProtocolTextFeeds(definitions, {
  endpointLabel = 'protocol text feeds',
  sourceScore = 0.3,
  maxItems = PROVIDER_ITEM_CAP
} = {}) {
  const errors = [];
  const perFeedCap = Math.max(100, Math.ceil(maxItems / Math.max(1, definitions.length)));
  const results = await mapLimited(definitions, Math.min(definitions.length, SOURCE_PAGE_CONCURRENCY), async ([protocol, endpoint]) => {
    try {
      const raw = await downloadText(endpoint);
      const lines = String(raw || '').split(/\r?\n/).map(line => line.trim()).filter(Boolean);
      const sampled = evenlySample(lines, perFeedCap);
      const items = sampled
        .map(line => parseHostPort(line, protocol))
        .filter(Boolean)
        .map(x => baseItem({ ...x, sourceScore, country: 'XX', city: 'Unknown' }))
        .filter(validProxy);
      return { protocol, endpoint, items, totalAvailable: lines.length, error: null };
    } catch (error) {
      return { protocol, endpoint, items: [], totalAvailable: 0, error: String(error?.message || error).slice(0, 240) };
    }
  });

  const all = [];
  let totalAvailable = 0;
  for (const result of results) {
    totalAvailable += result.totalAvailable || 0;
    if (result.error) errors.push({ endpoint: result.endpoint, error: result.error });
    else all.push(...result.items);
  }

  return {
    items: diversityPick(all, maxItems),
    endpoint: endpointLabel,
    errors,
    pages: results.filter(x => !x.error).length,
    totalAvailable
  };
}

async function loadSoliSpirit() {
  return loadProtocolTextFeeds([
    ['http', 'https://raw.githubusercontent.com/SoliSpirit/proxy-list/main/http.txt'],
    ['https', 'https://raw.githubusercontent.com/SoliSpirit/proxy-list/main/https.txt'],
    ['socks4', 'https://raw.githubusercontent.com/SoliSpirit/proxy-list/main/socks4.txt'],
    ['socks5', 'https://raw.githubusercontent.com/SoliSpirit/proxy-list/main/socks5.txt']
  ], {
    endpointLabel: 'https://github.com/SoliSpirit/proxy-list',
    sourceScore: 0.28
  });
}

async function loadTheSpeedX() {
  return loadProtocolTextFeeds([
    ['http', 'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt'],
    ['socks4', 'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt'],
    ['socks5', 'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt']
  ], {
    endpointLabel: 'https://github.com/TheSpeedX/PROXY-List',
    sourceScore: 0.3
  });
}

const SOURCES = [
  {
    name: 'Proxifly',
    endpoints: [
      'https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.json',
      'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.json'
    ],
    parse(data) {
      if (!Array.isArray(data)) return [];
      return data.map(x => {
        const fromUrl = parseProxyUrl(x.proxy);
        return baseItem({
          protocol: x.protocol || fromUrl?.protocol,
          ip: x.ip || fromUrl?.ip,
          port: x.port || fromUrl?.port,
          https: x.https,
          anonymity: x.anonymity,
          sourceScore: score01(x.score),
          country: x.geolocation?.country,
          city: x.geolocation?.city
        });
      });
    }
  },
  {
    name: 'ProxyScrape',
    endpoints: [
      'https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/all/data.json',
      'https://raw.githubusercontent.com/proxyscrape/free-proxy-list/main/proxies/all/data.json'
    ],
    parse(data) {
      if (!Array.isArray(data)) return [];
      return data.map(x => baseItem({
        protocol: x.protocol,
        ip: x.ip,
        port: x.port,
        https: Boolean(x.ssl) || normalizeProtocol(x.protocol) === 'https',
        anonymity: x.anonymity,
        sourceScore: providerScore(x.uptime_percent, x.latency_ms),
        country: x.country_code,
        city: x.city
      }));
    }
  },
  {
    name: 'Proxio',
    endpoints: [
      'https://raw.githubusercontent.com/proxio-io/proxy-list/main/all.json',
      'https://cdn.jsdelivr.net/gh/proxio-io/proxy-list@main/all.json'
    ],
    parse(data) {
      const rows = Array.isArray(data) ? data : (Array.isArray(data?.proxies) ? data.proxies : []);
      const out = [];
      for (const x of rows) {
        const protocols = Array.isArray(x.protocols) ? x.protocols : [x.protocol || x.type].filter(Boolean);
        for (const protocolRaw of protocols) {
          const protocol = normalizeProtocol(protocolRaw);
          out.push(baseItem({
            protocol,
            ip: x.ip || x.host,
            port: x.port,
            https: protocol === 'https' || Boolean(x.ssl),
            anonymity: x.anonymity,
            sourceScore: Number.isFinite(Number(x.reliability)) ? score01(x.reliability, 100) : score01(x.uptime),
            country: x.country_code || x.countryCode || x.country,
            city: x.city
          }));
        }
      }
      return out;
    }
  },
  {
    name: 'IPLocate',
    endpoints: [
      'https://cdn.jsdelivr.net/gh/iplocate/free-proxy-list@main/all-proxies.txt',
      'https://raw.githubusercontent.com/iplocate/free-proxy-list/main/all-proxies.txt'
    ],
    format: 'text',
    parse(raw) {
      return String(raw || '').split(/\r?\n/).map(parseProxyUrl).filter(Boolean).map(x => baseItem({
        ...x,
        sourceScore: 0.45,
        country: 'XX',
        city: 'Unknown'
      }));
    }
  },
  {
    name: 'GeoNode',
    load: () => loadPaginatedJson({
      pageSize: 500,
      maxItems: PROVIDER_ITEM_CAP,
      makeUrl: page => `https://proxylist.geonode.com/api/proxy-list?page=${page}&limit=500&sort_by=lastChecked&sort_type=desc`,
      totalFrom: data => data?.total,
      parsePage: data => {
        const rows = Array.isArray(data?.data) ? data.data : [];
        const out = [];
        for (const x of rows) {
          for (const protocol of splitProtocols(x.protocols)) {
            out.push(baseItem({
              protocol,
              ip: x.ip,
              port: x.port,
              https: protocol === 'https',
              anonymity: x.anonymityLevel,
              sourceScore: providerScore(x.upTime, x.responseTime ?? x.latency),
              country: x.country,
              city: x.city
            }));
          }
        }
        return out;
      }
    })
  },
  {
    name: 'SoliSpirit',
    load: loadSoliSpirit
  },
  {
    name: 'TheSpeedX',
    load: loadTheSpeedX
  },
  {
    name: 'FreshProxyList',
    load: loadVakhov
  },
  {
    name: 'RolaIP',
    load: loadRolaIp
  },
  {
    name: 'DataBay',
    load: () => loadPaginatedJson({
      pageSize: 500,
      maxItems: PROVIDER_ITEM_CAP,
      makeUrl: page => `https://databay.com/api/v1/proxy-list?page=${page}&limit=500`,
      totalFrom: data => data?.total,
      parsePage: data => {
        const rows = Array.isArray(data?.data) ? data.data : [];
        return rows.map(x => baseItem({
          protocol: x.protocol,
          ip: x.ip,
          port: x.port,
          https: x.ssl || normalizeProtocol(x.protocol) === 'https',
          anonymity: x.anonymity,
          sourceScore: providerScore(x.uptime, x.latency),
          country: x.iso,
          city: 'Unknown'
        }));
      }
    })
  },
  {
    name: 'AdvancedName',
    enabled: () => Boolean(String(process.env.ADVANCED_NAME_FEED_URL || '').trim()),
    load: loadAdvancedName
  },
  {
    name: 'ProxMint',
    load: () => loadPaginatedJson({
      pageSize: 200,
      maxItems: PROVIDER_ITEM_CAP,
      makeUrl: page => `https://proxmint.com/api/free-proxies?page=${page}&pageSize=200&format=json`,
      totalFrom: data => data?.total,
      parsePage: parseProxMintPage
    })
  },
  {
    name: 'Socks5Proxies',
    load: loadSocks5Proxies
  }
];

function staticNodes() {
  const raw = String(process.env.STATIC_PROXY_NODES || '').trim();
  if (!raw) return [];
  const out = [];
  for (const entry of raw.split(';').map(x => x.trim()).filter(Boolean)) {
    const [rawUrl, rawCountry = 'XX', city = 'Static', source = 'Static'] = entry.split('|');
    try {
      const u = new URL(rawUrl);
      if (u.username || u.password) continue;
      const protocol = normalizeProtocol(u.protocol.replace(':',''));
      const port = Number(u.port);
      const country = normalizeCountry(rawCountry);
      const item = {
        id: rawUrl,
        url: rawUrl,
        protocol,
        ip: u.hostname,
        port,
        https: protocol === 'https',
        anonymity: 'trusted',
        sourceScore: 1,
        country,
        city,
        source,
        region: regionForCountry(country),
        status: 'unknown',
        latencyMs: null,
        exitIp: null,
        successes: 0,
        failures: 0,
        consecutiveFailures: 0,
        lastCheck: null,
        lastSuccess: null
      };
      if (validProxy(item)) out.push(item);
    } catch {}
  }
  return out;
}

function manualProxyItem(rawUrl, source = 'Manual') {
  try {
    const u = new URL(String(rawUrl || '').trim());
    const protocol = normalizeProtocol(u.protocol.replace(':',''));
    if (!['http','https','socks4','socks5'].includes(protocol)) return null;
    const port = Number(u.port || (protocol === 'https' ? 443 : protocol === 'http' ? 80 : 0));
    if (!u.hostname || !port) return null;
    const url = u.toString().replace(/\/$/, '');
    return {
      id:url,url,protocol,ip:u.hostname,port,https:protocol==='https',anonymity:'unknown',
      sourceScore:1,country:'XX',city:'Manual',source,region:regionForCountry('XX'),
      status:'unknown',latencyMs:null,exitIp:null,successes:0,failures:0,consecutiveFailures:0,lastCheck:null,lastSuccess:null
    };
  } catch { return null; }
}

function manualProxyNodes() {
  const raw = String(process.env.MANUAL_PROXIES || '').trim();
  if (!raw) return [];
  return raw.split(/[;\n,]+/).map(x => manualProxyItem(x, 'ManualEnv')).filter(Boolean);
}

async function manualProxyLists() {
  const raw = String(process.env.MANUAL_PROXY_LISTS || '').trim();
  if (!raw) return { items:[], stats:[] };
  const specs = raw.split(/[;\n]+/).map(x=>x.trim()).filter(Boolean);
  const items=[], stats=[];
  for (const spec of specs) {
    const split = spec.indexOf('|');
    const protocol = split > 0 ? normalizeProtocol(spec.slice(0,split)) : '';
    const endpoint = split > 0 ? spec.slice(split+1).trim() : spec;
    if (!['http','https','socks4','socks5'].includes(protocol)) {
      stats.push({source:'ManualList',ok:false,count:0,errors:[{endpoint,error:'Prefix list URL with protocol, e.g. socks5|https://example/list.txt'}]});
      continue;
    }
    try {
      const text = await downloadText(endpoint);
      const parsed = text.split(/\r?\n/).map(line=>parseHostPort(line,protocol)).filter(Boolean)
        .map(x=>manualProxyItem(`${x.protocol}://${x.ip}:${x.port}`, 'ManualList'));
      items.push(...parsed.filter(Boolean));
      stats.push({source:`ManualList:${protocol}`,ok:true,count:parsed.length,endpoint});
    } catch(error) {
      stats.push({source:`ManualList:${protocol}`,ok:false,count:0,errors:[{endpoint,error:String(error.message||error).slice(0,240)}]});
    }
  }
  return {items,stats};
}

function diversityPick(items, max) {
  if (items.length <= max) return items;
  const buckets = new Map();
  for (const item of items) {
    const key = `${item.country}:${item.protocol}`;
    if (!buckets.has(key)) buckets.set(key, []);
    buckets.get(key).push(item);
  }
  const queues = [...buckets.values()];
  const result = [];
  let cursor = 0;
  while (result.length < max && queues.length) {
    const index = cursor % queues.length;
    const queue = queues[index];
    const item = queue.shift();
    if (item) result.push(item);
    if (!queue.length) queues.splice(index, 1);
    else cursor++;
  }
  return result;
}

function metadataQuality(item) {
  let quality = Number(item.sourceScore || 0) * 10;
  if (item.country && item.country !== 'XX') quality += 4;
  if (item.city && item.city !== 'Unknown') quality += 1;
  if (item.anonymity && item.anonymity !== 'unknown') quality += 1;
  return quality;
}

function mergeCandidate(existing, incoming) {
  if (!existing) return incoming;
  const primary = metadataQuality(incoming) > metadataQuality(existing) ? incoming : existing;
  const secondary = primary === incoming ? existing : incoming;
  return {
    ...secondary,
    ...primary,
    country: primary.country !== 'XX' ? primary.country : secondary.country,
    city: primary.city !== 'Unknown' ? primary.city : secondary.city,
    anonymity: primary.anonymity !== 'unknown' ? primary.anonymity : secondary.anonymity,
    sourceScore: Math.max(Number(existing.sourceScore || 0), Number(incoming.sourceScore || 0))
  };
}

async function loadSource(source) {
  if (typeof source.load === 'function') {
    try {
      const result = await source.load();
      const items = (result.items || []).filter(validProxy);
      if (!items.length) throw new Error('source loaded successfully but contained 0 valid proxies');
      return { ...result, items };
    } catch (error) {
      return { items: [], endpoint: null, errors: [{ endpoint: source.name, error: String(error?.message || error).slice(0, 240) }] };
    }
  }

  const errors = [];
  for (const endpoint of source.endpoints) {
    try {
      const raw = await downloadText(endpoint);
      const input = source.format === 'text' ? raw : JSON.parse(raw);
      const items = source.parse(input).filter(validProxy);
      if (!items.length) throw new Error('source parsed successfully but contained 0 valid proxies');
      return { items: diversityPick(items, PROVIDER_ITEM_CAP), endpoint, errors, pages: 1, totalAvailable: items.length };
    } catch (error) {
      errors.push({ endpoint, error: String(error?.message || error).slice(0, 240) });
    }
  }
  return { items: [], endpoint: null, errors };
}

export async function fetchProxySources(maxProxies = 5000) {
  const all = [];
  const sourceStats = [];

  const activeSources = SOURCES.filter(source => typeof source.enabled !== 'function' || source.enabled());
  const results = await mapLimited(activeSources, SOURCE_CONCURRENCY, async source => ({ source, result: await loadSource(source) }));
  for (const { source, result } of results) {
    if (result.items.length) {
      all.push(...result.items.map(item => ({ ...item, source: source.name })));
      sourceStats.push({
        source: source.name,
        ok: true,
        count: result.items.length,
        endpoint: result.endpoint,
        pages: result.pages || 1,
        totalAvailable: result.totalAvailable ?? result.items.length,
        fallbackErrors: result.errors || []
      });
    } else {
      sourceStats.push({ source: source.name, ok: false, count: 0, errors: result.errors || [] });
    }
  }

  const manualLists = await manualProxyLists();
  all.push(...manualLists.items);
  sourceStats.push(...manualLists.stats);

  const merged = new Map();
  for (const item of all) {
    const url = `${item.protocol}://${item.ip}:${item.port}`;
    merged.set(url, mergeCandidate(merged.get(url), item));
  }

  const hydrated = [...merged.entries()].map(([url, item]) => ({
    id: url,
    url,
    ...item,
    region: regionForCountry(item.country),
    status: 'unknown',
    latencyMs: null,
    exitIp: null,
    successes: 0,
    failures: 0,
    consecutiveFailures: 0,
    lastCheck: null,
    lastSuccess: null
  }));

  const statics = [...staticNodes(), ...manualProxyNodes()];
  sourceStats.push({ source: 'ManualEnv', ok: true, count: manualProxyNodes().length });
  const staticIds = new Set(statics.map(x => x.id));
  const budget = Math.max(0, maxProxies - statics.length);
  const picked = diversityPick(hydrated.filter(x => !staticIds.has(x.id)), budget);
  sourceStats.push({ source: 'Static', ok: true, count: statics.length });
  return { proxies: [...statics, ...picked], sourceStats };
}
