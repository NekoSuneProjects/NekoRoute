import dns from 'node:dns/promises';
import net from 'node:net';

function isPrivateIp(ip) {
  if (!net.isIP(ip)) return true;
  if (ip.includes(':')) {
    const n = ip.toLowerCase();
    return n === '::1' || n.startsWith('fc') || n.startsWith('fd') || n.startsWith('fe80:') || n === '::';
  }
  const [a,b] = ip.split('.').map(Number);
  return a === 10 || a === 127 || a === 0 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224;
}


function mediaPortAllowed(port) {
  const spec = String(process.env.MEDIA_ALLOWED_PORTS || '80,443,8000-8999').trim();
  for (const token of spec.split(',').map(x => x.trim()).filter(Boolean)) {
    const range = token.match(/^(\d+)-(\d+)$/);
    if (range) {
      const start = Number(range[1]), end = Number(range[2]);
      if (port >= start && port <= end) return true;
      continue;
    }
    if (Number(token) === port) return true;
  }
  return false;
}

async function validateCommon(rawUrl, { media = false } = {}) {
  let url;
  try { url = new URL(rawUrl); } catch { throw new Error('Invalid URL'); }
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Only HTTP/HTTPS URLs are allowed');
  if (url.username || url.password) throw new Error('Credentials in URLs are not allowed');

  // General public tools stay restricted to normal web ports. Media sessions get
  // a separate, explicit allowlist for common Icecast/Shoutcast-style ports.
  if (url.port) {
    const port = Number(url.port);
    const standard = (url.protocol === 'http:' && port === 80) || (url.protocol === 'https:' && port === 443);
    if (!standard && !(media && mediaPortAllowed(port))) {
      throw new Error(media
        ? 'Media stream port is not allowed by MEDIA_ALLOWED_PORTS'
        : 'Only standard web ports 80 and 443 are allowed');
    }
  }

  const records = await dns.lookup(url.hostname, { all: true, verbatim: true });
  if (!records.length) throw new Error('Target hostname did not resolve');
  for (const record of records) {
    if (isPrivateIp(record.address)) throw new Error('Target resolves to a private/reserved network');
  }
  return url;
}

export async function validatePublicTarget(rawUrl) {
  return validateCommon(rawUrl);
}

export async function validatePublicMediaTarget(rawUrl) {
  return validateCommon(rawUrl, { media: true });
}

