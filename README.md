# NekoRoute v0.5.7

NekoRoute is a Dockerized regional availability, moderation and defensive website-analysis service. It discovers public HTTP/HTTPS/SOCKS4/SOCKS5 exits, persists proxy health in SQLite, compares HTTP behaviour across regions, provides a sandboxed interactive server-side preview, and can hand a selected route to an optional **local Firefox Bridge** for full browser compatibility and direct-to-PC downloads.

> **Responsible-use notice:** Users are responsible for complying with applicable law and website terms. Public proxies are third-party infrastructure. NekoRoute does not guarantee anonymity, privacy, safety or availability. Do not send passwords, private tokens, payment data or other sensitive traffic through random public proxies.

## Tools

### Dashboard `/`

- Persistent SQLite proxy inventory and health history.
- Full country names such as `France (FR)` and `United Kingdom (GB)`.
- Filters by region, country, protocol and state.
- **Paginated proxy table** with 25/50/100/200 rows per page.

### Site Tester `/tester`

Compare one public HTTP/HTTPS URL across multiple healthy exits. Results include HTTP status, redirect, latency, country, region and protocol.

The specific-node selector is paginated (50 nodes per page) instead of loading hundreds of `<option>` rows at once.

### Sandboxed Interactive Proxy Preview `/preview`

The embedded preview now keeps the iframe sandbox but loads the target page's CSS and JavaScript through the selected proxy session:

- Back / forward / reload and URL bar.
- Proxied page-to-page navigation.
- External stylesheets, fonts, images, scripts, module/chunk imports and dynamically-added page assets.
- Inline JavaScript and event handlers execute inside the sandboxed iframe.
- Common `fetch()` and XHR **GET/HEAD** requests are routed through the selected proxy session.
- Simple `GET`/search forms.
- Audio/video/PDF resources and tokenised page-linked downloads.
- The iframe intentionally omits `allow-same-origin`, keeping the remote page isolated from the NekoRoute dashboard origin.

Cookies/authenticated browser storage, write/POST requests, service workers and WebSockets remain disabled in embedded mode. Use **Open in real Firefox** when a site requires those full browser features.

### Real Firefox Bridge `/browser`

This is the v0.5 feature for sites that needs more browser capabilities than the sandboxed preview.

The optional Firefox extension:

1. Receives a short-lived, one-time NekoRoute route ticket.
2. Opens the target in a **real Firefox tab on the visitor's own PC**.
3. Routes that tab through the selected HTTP/HTTPS/SOCKS4/SOCKS5 public proxy.
4. Allows ordinary JavaScript, cookies, browser media handling, forms and navigation because the site is running in actual Firefox.
5. Lets Firefox save downloads **directly to the visitor's computer**. NekoRoute does not spool those browser-mode files onto the VPS.

This architecture is intentional: a Firefox instance physically running inside a Docker/VNC session on the VPS would necessarily receive/download the file on the server first. A website also cannot silently change a user's local Firefox proxy settings. The bridge extension is the way to satisfy both “real Firefox” and “download straight to my PC”.

The bridge defaults to trusting:

```text
https://proxyweb.nekosunevr.co.uk
```

Self-hosted users can add their own NekoRoute origin in the extension options.

Development extension source/download:

```text
/firefox-extension/
/downloads/nekoroute-firefox-bridge.zip
```

For permanent one-click public installation in normal Firefox, the extension should be signed through Mozilla Add-ons. For development, load `manifest.json` from `about:debugging#/runtime/this-firefox`.

The bridge also supports optional leak protection while routed tabs exist: Firefox network prediction is temporarily disabled and WebRTC is set to proxy-only, then the previous settings are restored after the final routed tab closes.

### Malware & Domain Scanner `/scanner`

The scanner fetches a public website through the selected proxy without executing remote JavaScript and combines:

- NekoRoute local HTML/header/redirect heuristics.
- OpenPhish Community feed cached locally.
- Optional self-hosted ClamAV.
- Optional VirusTotal API v3.
- Optional Google Web Risk.

## Public proxy providers

NekoRoute v0.5.7 merges and de-duplicates multiple independent public sources:

- **Proxifly** — metadata-rich HTTP/HTTPS/SOCKS lists.
- **ProxyScrape** — metadata-rich HTTP/HTTPS/SOCKS lists.
- **Proxio** — multi-protocol JSON list.
- **IPLocate** — verified `all-proxies.txt` list (protocol/IP/port; country is filled from richer sources when the same node overlaps).
- **GeoNode** — paginated API with country, city, anonymity, uptime and response-time metadata.
- **SoliSpirit** — large HTTP/HTTPS/SOCKS4/SOCKS5 raw GitHub feeds; NekoRoute samples across each feed before its own validation so huge lists do not monopolize the active pool.
- **TheSpeedX** — HTTP/SOCKS4/SOCKS5 raw GitHub feeds; entries are treated as candidates and still have to pass NekoRoute health checks.
- **Fresh Proxy List (vakhov)** — separate HTTP, HTTPS, SOCKS4 and SOCKS5 feeds.
- **Rola IP** — paginated daily API with country, protocol, anonymity, response time and uptime.
- **DataBay** — paginated no-key JSON API with protocol, country, latency and uptime.
- **Advanced.name** — optional operator-configured plain-text export, queried separately for HTTP/HTTPS/SOCKS4/SOCKS5 so protocol is retained. Set `ADVANCED_NAME_FEED_URL` to enable it; the token-like export URL is intentionally not hard-coded.
- **ProxMint** — paginated no-key JSON API with protocol, country, anonymity, latency, uptime and provider score.
- **Socks5Proxies.com** — public offset-paginated JSON feed; protocol flags, country, city, anonymity, uptime/check data and health score are used when available. Its public endpoint is best-effort/IP-rate-limited, so NekoRoute defaults this provider to five pages per refresh even if the global page cap is higher.
- **Static** — optional operator-supplied trusted nodes from `STATIC_PROXY_NODES`.

Paginated and large raw-list providers are ingested only up to `SOURCE_PROVIDER_ITEM_CAP` (default 2500 per provider) so a single large feed cannot dominate refresh time. Cross-provider duplicates are merged before the final region/protocol diversity pick. NekoRoute prefers richer country/city/anonymity metadata when the same endpoint appears in multiple sources.

`topfreeproxylist.com` is intentionally not scraped because it currently exposes a browser table/export UI rather than a documented stable machine API. Scraping its HTML would be brittle and could break NekoRoute whenever that site changes layout.

Useful tuning:

```dotenv
MAX_PROXIES=5000
SOURCE_PROVIDER_ITEM_CAP=2500
SOURCE_MAX_PAGES=20
SOURCE_CONCURRENCY=4
SOURCE_PAGE_CONCURRENCY=2
SOCKS5PROXIES_MAX_PAGES=5
ADVANCED_NAME_FEED_URL=
```

## SQLite persistence

NekoRoute uses Sequelize + SQLite at:

```text
/app/data/nekoroute.sqlite
```

Nodes are not deleted just because they go offline. Their health history remains in SQLite, the health cursor is persisted across restarts, and offline nodes are revisited so they can become online again later.

## Paginated node API

The v1 node endpoint now returns a pagination object:

```http
GET /api/v1/nodes?status=online&country=FR&page=1&pageSize=50
```

Example response shape:

```json
{
  "items": [],
  "total": 543,
  "page": 1,
  "pageSize": 50,
  "pages": 11,
  "hasPrevious": false,
  "hasNext": true
}
```

`pageSize` is capped at 200.

The compatibility endpoint remains an array and supports `limit` + `offset`:

```http
GET /api/proxies?status=online&limit=50&offset=100
```

It also returns `X-Total-Count`, `X-Offset` and `X-Limit` headers.


## Interactive sandboxed Proxy Preview

The `/preview` tool now preserves and proxies the target page's external CSS and JavaScript instead of stripping scripts. The iframe remains sandboxed **without `allow-same-origin`**, while NekoRoute rewrites stylesheet/script/media URLs through the selected proxy session. A small bootstrap layer routes common `fetch()`/XHR GET/HEAD calls and dynamically-added script/image/style/media URLs through the same session.

The embedded mode still intentionally blocks cookies/authenticated browser storage, write/POST fetches/forms, service workers and WebSockets. Use `/browser` + the Firefox Bridge for sites that require a complete browser session.

## Public API v1

Documentation:

```text
GET /api/docs
GET /api/v1
GET /api/openapi.json
```

Useful endpoints:

```text
GET  /api/v1/health
GET  /api/v1/stats
GET  /api/v1/regions
GET  /api/v1/countries?region=Europe
GET  /api/v1/nodes?status=online&country=FR&page=1&pageSize=50
GET  /api/v1/threat-intel
POST /api/v1/test
POST /api/v1/test-matrix
POST /api/v1/scan
POST /api/v1/preview/session
GET  /api/v1/preview/session/:id/resources
POST /api/v1/browser-ticket
GET  /api/v1/browser-ticket/:ticket
```

### Firefox Bridge ticket

Create a one-time ticket:

```bash
curl -sS https://proxyweb.example.com/api/v1/browser-ticket \
  -H 'content-type: application/json' \
  -d '{"url":"https://example.com/","country":"FR"}'
```

The public response contains the opaque ticket and selected node metadata, not the raw proxy address. The Firefox extension consumes `ticketUrl` once; that one-time response contains the raw public proxy host/port needed by Firefox.

Tickets expire quickly (`BROWSER_TICKET_TTL_MS`, default 90 seconds) and are removed after first successful consumption.

## Run

```bash
cp .env.example .env
nano .env

docker compose up -d --build
docker compose logs -f nekoroute
```

Open:

```text
http://SERVER-IP:3210/
http://SERVER-IP:3210/tester
http://SERVER-IP:3210/preview
http://SERVER-IP:3210/browser
http://SERVER-IP:3210/scanner
http://SERVER-IP:3210/api/docs
```

## Optional ClamAV

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.clamav.yml \
  up -d --build
```

## Recommended environment

```dotenv
PORT=3210
ADMIN_TOKEN=use-a-long-random-maintenance-secret
SQLITE_PATH=/app/data/nekoroute.sqlite

PUBLIC_RATE_LIMIT_WINDOW_MS=60000
PUBLIC_RATE_LIMIT_MAX=60
SCAN_RATE_LIMIT_MAX=12
STORE_SCAN_HISTORY=false

OPENPHISH_ENABLED=true
THREAT_FEED_REFRESH_MS=43200000
THREAT_FEED_CACHE_PATH=/app/data/openphish-cache.json

EXPOSE_NODE_ADDRESSES=false
PREVIEW_TIMEOUT_MS=45000
BROWSER_TICKET_TTL_MS=90000
```

`ADMIN_TOKEN` is maintenance-only. Normal visitor tools do not require it.

## Safety controls

Public server-side URL tools are restricted to HTTP/HTTPS ports 80/443. NekoRoute rejects localhost/private/link-local/CGNAT/reserved targets and credentials embedded in URLs.

The local Firefox Bridge is different: after the route ticket is consumed, the visitor's Firefox communicates directly with the selected public proxy. The NekoRoute VPS is no longer in that page/download data path. The public proxy itself remains untrusted and can observe the visitor's connection to it.

## v0.5.5 preview asset compatibility

The sandboxed Preview now rewrites additional asset patterns used by modern sites: lazy image attributes (`data-src`, `data-original`, `data-lazy-src`, lazy `srcset`), `<picture>/<source>`, CSS background/mask/list-style URLs set at runtime, SVG image/use references, favicons and typed preload/modulepreload links. Dynamic preview requests use the current proxied page as their Referer, and generic/octet-stream image/font/media responses can be MIME-inferred from the resource URL. The default preview resource cap is 16 MiB.


## v0.5.7 HTTP status and media streaming

Preview error pages now show the actual upstream HTTP status when a selected proxy receives a response such as `403 Forbidden`, `404 Not Found`, `429 Too Many Requests`, or `500/502/503`. Transport failures such as `Socket closed`, TLS errors, and timeouts are labelled separately because no HTTP status code was received. The parent Preview status bar also mirrors that result.

Audio/video and page-linked downloads now use a streaming relay rather than buffering the whole response in NekoRoute memory. `Range` requests, `206 Partial Content`, `Content-Range`, `Accept-Ranges`, `ETag`, and `Last-Modified` are forwarded so HTML5 audio/video players can seek and play progressively. Streamed bytes are relayed through the selected proxy and are not written to NekoRoute disk. `PREVIEW_MAX_STREAM_BYTES` defaults to 512 MiB per response.

## v0.5.7 Cloudflare-safe Preview errors

Preview iframe error pages intentionally return HTTP 200 to the outer CDN/reverse proxy while preserving the real failure in the rendered card, `postMessage`, and response headers. This prevents Cloudflare from replacing NekoRoute's diagnostic iframe with its own `502 Bad Gateway` page.

Useful response headers include:

```text
X-NekoRoute-Preview-Error: upstream-http | proxy-transport | proxy-unavailable | session-expired
X-NekoRoute-Upstream-Status: 403
```

The Site Tester/API endpoints are unchanged and still report real upstream status codes in their JSON results.


## Automatic SOCKS5 / HTTP / HTTPS gateway

NekoRoute can expose its continuously refreshed, health-checked proxy pool as stable local proxy endpoints. Enable `PROXY_GATEWAY_ENABLED=true`. Only upstream nodes currently marked online and using SOCKS5, HTTP, or HTTPS are eligible; failed connection attempts are marked back into the pool and the gateway retries another healthy node.

Client formats:

```text
socks5://127.0.0.1:1080
socks5://user:pass@127.0.0.1:1080

http://127.0.0.1:8080
http://user:pass@127.0.0.1:8080

https://127.0.0.1:8443
https://user:pass@127.0.0.1:8443
```

The HTTPS listener is a TLS-wrapped forward proxy and requires `PROXY_GATEWAY_TLS_CERT` and `PROXY_GATEWAY_TLS_KEY`. HTTP port 8080 supports normal HTTP proxy traffic and HTTPS destinations through CONNECT. Set `PROXY_GATEWAY_USERNAME` and `PROXY_GATEWAY_PASSWORD` to require client authentication; leave both blank only on a trusted network.

The gateway does not use unchecked entries directly. Proxy sources continue to be refreshed by NekoRoute and its normal health sweeps determine the eligible pool.
