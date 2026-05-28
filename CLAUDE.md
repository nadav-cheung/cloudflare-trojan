# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A Trojan-protocol proxy running on Cloudflare Workers. Clients connect via WebSocket over TLS (WSS), the Worker authenticates via SHA224 password hash, parses a SOCKS5-like destination address, then proxies TCP traffic through `cloudflare:sockets`.

**Requires Cloudflare Workers paid plan** for `connect()` TCP outbound.

## Commands

```bash
wrangler deploy       # Deploy to Cloudflare (CI/CD handles this on push)
wrangler tail         # View production logs
wrangler secret put SHA224PASS   # Set secret (preferred over toml for sensitive values)
```

No build step, no tests, no linting. `worker.js` is deployed directly. Do not run `wrangler dev` locally — workerd's WebSocket binary data types differ from production.

## Architecture

Single-file Worker (`worker.js`) with this data flow:

```
Client (Trojan over WSS)
  → fetch() — routes WebSocket vs HTTP endpoints (/link, /pool, /)
  → trojanOverWSHandler() — creates WebSocketPair + ReadableStream pipe
    → parseTrojanHeader() — validates password + parses SOCKS5 target
    → handleTCPOutBound() — connects to target via cloudflare:sockets
      → remoteSocketToWS() — TCP→WebSocket data forwarding, retries via proxy pool on zero-data
```

## Critical Implementation Details

### WebSocket binaryType
**Must** set `webSocket.binaryType = 'arraybuffer'` after `webSocket.accept()`. Without this, Cloudflare Workers defaults to `'blob'`, causing `new DataView(blob)` to fail in `parseTrojanHeader`. The function has a defensive fallback (handles Blob via `.arrayBuffer()`, other types via `new Uint8Array()`), but the `binaryType` fix is the root cause.

### Trojan Wire Format

```
SHA224(password)  CRLF  CMD  ATYP  DST.ADDR  DST.PORT  CRLF  PAYLOAD
     56 bytes     2B    1B   1B    variable   2B       2B    variable
```

The 56-byte password hash is the hex-encoded SHA224 (ASCII), not raw bytes. `rawClientData` starts at `portIndex + 4` (port 2B + CRLF 2B). CMD must be 0x01 (CONNECT). ATYP: 1=IPv4, 3=domain, 4=IPv6.

### Early Data via Sec-WebSocket-Protocol
Clients can send the Trojan header as a base64-encoded `Sec-WebSocket-Protocol` request header. The Worker decodes and enqueues it as the first chunk in the ReadableStream, before any WebSocket messages arrive. This is an optimization for clients that want to avoid a round trip.

### Retry Logic
`remoteSocketToWS()` triggers retry when `hasIncomingData === false` after the TCP readable stream closes — meaning the remote sent zero bytes. This covers both connection failures and silent drops. Retry tries up to 4 proxy IPs from the pool before giving up and closing the WebSocket.

## Key Functions

- `fetch()` — Entry point. Routes HTTP (`/link`, `/pool`) vs WebSocket upgrade. Picks a random proxy IP from pool, triggers non-blocking `quickRefill()` if pool empty and not recently failed.
- `scheduled()` — Cron handler (every 10 min). Runs `healthCheck()` (probe all pool IPs, prune dead), then `refill()` if pool < `POOL_MIN` (10).
- `getPool()` — Returns healthy IP pool or `FALLBACK_PROXY_IPS`. Synchronous, zero blocking.
- `quickRefill()` — Fast partial refill using DoH + one GitHub source only. Non-blocking, single-flight via `_quickRefilling` flag. Used at request-time when pool is empty.
- `healthCheck()` — Probes all pool IPs concurrently (`PROBE_CONCURRENCY`=6, `PROBE_TIMEOUT_MS`=100ms), removes dead ones.
- `refill()` — Full refill from all `SOURCE_TIERS`. Single-flight via `_refilling` promise. 90s stuck-lock detection.
- `parseTrojanHeader(buffer, sha224Password)` — Parses Trojan wire format. Handles Blob/ArrayBufferView fallback.
- `handleTCPOutBound()` — Direct TCP connect to target; on failure or zero-data, retries through proxy pool.
- `remoteSocketToWS()` — Pipes TCP readable→WebSocket send. Triggers `retry()` if zero incoming data.
- `timingSafeEqual()` — Constant-time comparison that re-encodes both sides to avoid timing leaks from the TextDecoder path.
- `probeOne(addr)` — TCP connectivity check. Defaults to port 443. Used to validate pool candidates.
- `isPublicIP(ip)` — Filters out private, loopback, CGNAT, and reserved ranges.

## Proxy IP Pool

Pool-health-driven model (no TTL, no cache expiry):
- Pool target: `POOL_MIN`=10 to `POOL_MAX`=50 healthy IPs
- Cron (every 10 min): health check all → prune dead → refill from IPDB if pool < 10
- Request time: `getPool()` reads pool synchronously, picks random IP, zero blocking
- Cold start: `quickRefill()` (DoH + GitHub, 15s timeout) on first request; falls back to `FALLBACK_PROXY_IPS`

IP sources (`SOURCE_TIERS`, tried in order):
1. DoH: Resolves `proxyip.cmliussss.net` A records via Cloudflare DNS
2. GitHub raw: bestproxy.txt, proxy.txt (multiple repos)
3. API: `ipdb.api.030101.xyz` (bestproxy and proxy endpoints)

## HTTP Endpoints

| Path | Auth | Returns |
|------|------|---------|
| `/link` | `?token=` if `LINK_TOKEN` set | Trojan config URL for client import |
| `/pool` | `?token=` if `LINK_TOKEN` set | JSON: current pool array + fallback IPs |
| `/` (WebSocket upgrade) | SHA224 password | Proxied TCP tunnel |

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `SHA224PASS` | SHA224 hex hash for auth (56 chars) | Built-in default |
| `PASSWORD` | Cleartext password for `/link` URL generation | `ca110us` |
| `PROXYIP` | Fallback proxy for retry (bypasses pool) | Empty (use pool) |
| `PROXYPORT` | Port override for proxy connections | Empty (use target port) |
| `LINK_TOKEN` | Gate `/link` and `/pool` endpoints with `?token=` param | Disabled if unset |
