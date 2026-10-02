import fs from 'node:fs/promises';
import pLimit from 'p-limit';
import { fetchProxySources } from './sources.js';
import { requestViaProxy } from './proxy.js';
import { initDatabase, ProxyNode, getState, setState, persistNodes } from './database.js';
import { regionForCountry } from './regions.js';

const IP_LOOKUP_URL = process.env.IP_LOOKUP_URL || 'https://api.nekosunevr.co.uk/v5/proxy/iplookup';
const IP_LOOKUP_TIMEOUT_MS = Math.max(1000, Number.parseInt(process.env.IP_LOOKUP_TIMEOUT_MS || '5000', 10));
const IP_LOOKUP_TTL_MS = Math.max(60000, Number.parseInt(process.env.IP_LOOKUP_TTL_MS || '21600000', 10));
const ipLookupCache = new Map();

async function lookupExitIp(ip) {
  if (!ip) return null;
  const cached = ipLookupCache.get(ip);
  if (cached && Date.now() - cached.at < IP_LOOKUP_TTL_MS) return cached.data;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), IP_LOOKUP_TIMEOUT_MS);
  try {
    const response = await fetch(`${IP_LOOKUP_URL}?ip=${encodeURIComponent(ip)}`, {
      signal: controller.signal,
      headers: { accept: 'application/json', 'user-agent': 'NekoRoute/0.6 (+proxy-ip-classification)' }
    });
    if (!response.ok) throw new Error(`IP lookup HTTP ${response.status}`);
    const data = await response.json();
    if (!data?.valid) throw new Error('IP lookup returned invalid result');
    ipLookupCache.set(ip, { at: Date.now(), data });
    return data;
  } finally { clearTimeout(timer); }
}

function applyIpLookup(node, data) {
  if (!data) return;
  Object.assign(node, {
    connectionType: data.connection_type || null,
    isVpn: data.is_vpn ?? null,
    isProxy: data.is_proxy ?? null,
    isTor: data.is_tor ?? null,
    isHostingProvider: data.is_hosting_provider ?? null,
    isNonResidential: data.is_non_residential ?? null,
    isHomeResidential: data.is_home_residential ?? null,
    ipAsn: data.asn ?? null,
    ipOrg: data.org || null,
    ipConfidence: data.confidence || null,
    ipDetectionSource: data.detection_source || null,
    ipDetectionReason: data.detection_reason || null,
    ipLookupAt: new Date().toISOString()
  });
}

export class ProxyPool {
  constructor(config) {
    this.config = config;
    this.nodes = new Map();
    this.sourceStats = [];
    this.lastSourceRefresh = null;
    this.lastHealthSweep = null;
    this.cursor = 0;
    this.databaseReady = false;
  }

  async loadState() {
    await initDatabase();
    this.databaseReady = true;

    const rows = await ProxyNode.findAll({ raw: true });
    for (const row of rows) {
      const country = String(row.country || 'XX').toUpperCase() === 'UK' ? 'GB' : String(row.country || 'XX').toUpperCase();
      const node = {
        ...row,
        country,
        region: regionForCountry(country),
        lastCheck: row.lastCheck ? new Date(row.lastCheck).toISOString() : null,
        lastSuccess: row.lastSuccess ? new Date(row.lastSuccess).toISOString() : null,
        firstSeen: row.firstSeen ? new Date(row.firstSeen).toISOString() : null,
        lastSeen: row.lastSeen ? new Date(row.lastSeen).toISOString() : null
      };
      this.nodes.set(node.id, node);
    }

    // One-time migration from the original JSON snapshot.
    if (!this.nodes.size) {
      try {
        const legacy = JSON.parse(await fs.readFile('/app/data/proxy-state.json', 'utf8'));
        const now = new Date().toISOString();
        for (const old of legacy.nodes || []) {
          const node = { ...old, firstSeen: old.firstSeen || old.lastCheck || now, lastSeen: old.lastSeen || old.lastCheck || now, sourcePresent: true };
          this.nodes.set(node.id, node);
        }
        if (this.nodes.size) {
          await persistNodes([...this.nodes.values()]);
          console.log(`[state] migrated ${this.nodes.size} legacy proxy nodes into SQLite`);
        }
      } catch {}
    }

    this.cursor = Number(await getState('healthCursor', 0)) || 0;
    this.lastSourceRefresh = await getState('lastSourceRefresh', null);
    this.lastHealthSweep = await getState('lastHealthSweep', null);
  }

  async saveState(nodes = null) {
    try {
      if (!this.databaseReady) return;
      await persistNodes(nodes || [...this.nodes.values()]);
      await Promise.all([
        setState('healthCursor', this.cursor),
        setState('lastSourceRefresh', this.lastSourceRefresh),
        setState('lastHealthSweep', this.lastHealthSweep)
      ]);
    } catch (error) {
      console.error('[state] SQLite save failed:', error.message);
    }
  }

  async refreshSources() {
    const { proxies, sourceStats } = await fetchProxySources(this.config.maxProxies);
    const now = new Date().toISOString();

    // Keep every previously known node. A source refresh only updates/adds records;
    // it never deletes historical nodes because public nodes often disappear temporarily.
    // Only mark nodes missing when at least one upstream source actually succeeded.
    // If every source timed out/failed, retain the previous sourcePresent state.
    const successfulSources = new Set(sourceStats.filter(stat => stat.ok).map(stat => stat.source));
    if (successfulSources.size) {
      for (const node of this.nodes.values()) {
        if (successfulSources.has(node.source)) node.sourcePresent = false;
      }
    }

    for (const incoming of proxies) {
      const previous = this.nodes.get(incoming.id);
      if (!previous) {
        this.nodes.set(incoming.id, {
          ...incoming,
          firstSeen: now,
          lastSeen: now,
          sourcePresent: true
        });
        continue;
      }
      this.nodes.set(incoming.id, {
        ...previous,
        ...incoming,
        status: previous.status || incoming.status,
        latencyMs: previous.latencyMs ?? incoming.latencyMs,
        exitIp: previous.exitIp ?? incoming.exitIp,
        successes: previous.successes || 0,
        failures: previous.failures || 0,
        consecutiveFailures: previous.consecutiveFailures || 0,
        lastCheck: previous.lastCheck || null,
        lastSuccess: previous.lastSuccess || null,
        lastError: previous.lastError || null,
        firstSeen: previous.firstSeen || now,
        lastSeen: now,
        sourcePresent: true
      });
    }

    this.sourceStats = sourceStats;
    this.lastSourceRefresh = now;
    await this.saveState();
    return { count: this.nodes.size, discoveredThisRefresh: proxies.length, retained: proxies.length === 0 && this.nodes.size > 0, sourceStats };
  }

  async checkNode(node) {
    const checkedAt = new Date().toISOString();
    try {
      const result = await requestViaProxy(node, this.config.healthcheckUrl, {
        timeoutMs: this.config.healthTimeoutMs,
        maxBytes: 8192
      });
      if (result.statusCode < 200 || result.statusCode >= 400) throw new Error(`health endpoint HTTP ${result.statusCode}`);
      let exitIp = null;
      try { exitIp = JSON.parse(result.body).ip || null; } catch {}
      Object.assign(node, {
        status: 'online',
        latencyMs: result.latencyMs,
        exitIp,
        successes: (node.successes || 0) + 1,
        consecutiveFailures: 0,
        lastCheck: checkedAt,
        lastSuccess: checkedAt,
        lastError: null
      });
      if (exitIp) {
        const lookupExpired = !node.ipLookupAt || Date.now() - new Date(node.ipLookupAt).getTime() >= IP_LOOKUP_TTL_MS;
        if (node.exitIp !== exitIp || lookupExpired) {
          try { applyIpLookup(node, await lookupExitIp(exitIp)); }
          catch (error) { console.warn(`[iplookup] ${exitIp}: ${error.message}`); }
        }
      }
    } catch (error) {
      const failures = (node.failures || 0) + 1;
      const consecutiveFailures = (node.consecutiveFailures || 0) + 1;
      Object.assign(node, {
        status: consecutiveFailures >= 2 ? 'offline' : 'degraded',
        failures,
        consecutiveFailures,
        lastCheck: checkedAt,
        lastError: String(error.message || error).slice(0, 180)
      });
    }
  }

  async healthSweep() {
    const nodes = [...this.nodes.values()];
    if (!nodes.length) return;
    const batch = [];
    for (let i = 0; i < Math.min(this.config.healthBatchSize, nodes.length); i++) {
      batch.push(nodes[(this.cursor + i) % nodes.length]);
    }
    this.cursor = (this.cursor + batch.length) % nodes.length;
    const limit = pLimit(12);
    await Promise.allSettled(batch.map(node => limit(() => this.checkNode(node))));
    this.lastHealthSweep = new Date().toISOString();
    await this.saveState(batch);
  }

  score(node) {
    const total = (node.successes || 0) + (node.failures || 0);
    const reliability = total ? (node.successes || 0) / total : 0.3;
    const latency = node.latencyMs ?? 6000;
    const source = Math.max(0, Math.min(1, Number(node.sourceScore || 0)));
    return reliability * 70 + source * 20 + Math.max(0, 10 - latency / 700);
  }

  select({ country, region, protocol } = {}) {
    return [...this.nodes.values()]
      .filter(n => n.status === 'online')
      .filter(n => !country || n.country === country)
      .filter(n => !region || n.region === region)
      .filter(n => !protocol || n.protocol === protocol)
      .sort((a,b) => this.score(b) - this.score(a))[0] || null;
  }

  list(filters = {}) {
    return [...this.nodes.values()]
      .filter(n => !filters.status || n.status === filters.status)
      .filter(n => !filters.country || n.country === filters.country)
      .filter(n => !filters.region || n.region === filters.region)
      .filter(n => !filters.protocol || n.protocol === filters.protocol)
      .sort((a,b) => this.score(b) - this.score(a));
  }

  stats() {
    const nodes = [...this.nodes.values()];
    const countBy = key => nodes.reduce((acc,n) => { const v=n[key] || 'Unknown'; acc[v]=(acc[v]||0)+1; return acc; }, {});
    return {
      total: nodes.length,
      online: nodes.filter(n=>n.status==='online').length,
      degraded: nodes.filter(n=>n.status==='degraded').length,
      offline: nodes.filter(n=>n.status==='offline').length,
      unchecked: nodes.filter(n=>n.status==='unknown').length,
      sourceMissing: nodes.filter(n=>n.sourcePresent === false).length,
      database: 'sqlite',
      healthCursor: this.cursor,
      byProtocol: countBy('protocol'),
      byCountry: countBy('country'),
      byRegion: countBy('region'),
      lastSourceRefresh: this.lastSourceRefresh,
      lastHealthSweep: this.lastHealthSweep,
      sourceStats: this.sourceStats
    };
  }
}
