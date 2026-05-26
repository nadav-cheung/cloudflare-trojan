# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A Trojan-protocol proxy running on Cloudflare Workers. Clients connect via WebSocket over TLS (WSS), the Worker authenticates via SHA224 password hash, parses a SOCKS5-like destination address, then proxies TCP traffic through `cloudflare:sockets`.

**Requires Cloudflare Workers paid plan** for `connect()` TCP outbound.

## Commands

```bash
wrangler dev          # Local dev server
wrangler deploy       # Deploy to Cloudflare
wrangler secret put SHA224PASS   # Set secret (preferred over toml for sensitive values)
```

No build step, no tests, no linting. `worker.js` is deployed directly.

## Architecture

Single-file Worker (`worker.js`) with this data flow:

```
Client (Trojan over WSS)
  → fetch() — routes WebSocket vs HTTP
  → trojanOverWSHandler() — creates WebSocketPair + ReadableStream pipe
    → parseTrojanHeader() — validates password + parses SOCKS5 target
    → handleTCPOutBound() — connects to target via cloudflare:sockets
      → remoteSocketToWS() — TCP→WebSocket data forwarding, with retry fallback
```

### Key Functions

- `fetch()` — Entry point. Per-request config from `env` (no mutable globals). Routes WebSocket upgrades vs `/link` endpoint.
- `parseTrojanHeader(buffer, sha224Password)` — Parses Trojan wire format: SHA224(56 bytes) + CRLF + SOCKS5 request. Includes boundary validation for IPv4/domain/IPv6 addresses.
- `handleTCPOutBound()` — Establishes TCP connection, retries via `proxyIP` if no data received. Awaits `tcpSocket.opened` before writing.
- `remoteSocketToWS()` — Forwards remote TCP data to WebSocket. Retry logic runs before WebSocket close.
- `timingSafeEqual()` — Constant-time string comparison for password verification.

### Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `SHA224PASS` | SHA224 hex hash for auth | Built-in default |
| `PASSWORD` | Cleartext password for `/link` URL generation | `ca110us` |
| `PROXYIP` | Fallback proxy for retry | Empty (direct) |
| `LINK_TOKEN` | Gate `/link` endpoint with `?token=` param | Disabled if unset |

### Trojan Wire Format

```
SHA224(password)  CRLF  CMD  ATYP  DST.ADDR  DST.PORT  CRLF  PAYLOAD
     56 bytes     2B    1B   1B    variable   2B       2B    variable
```

`rawClientData` starts at `portIndex + 4` (port 2B + CRLF 2B).
