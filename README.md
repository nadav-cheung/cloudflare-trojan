# cloudflare-trojan

A Trojan-protocol proxy running on Cloudflare Workers, tunneling TCP traffic over WebSocket + TLS.

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/nadav-cheung/cloudflare-trojan)

[中文文档](README_CN.md)

## How It Works

Client connects via WSS (WebSocket over TLS) → Worker authenticates via SHA224 password hash → Worker parses SOCKS5 destination address → Worker establishes TCP outbound via `cloudflare:sockets` → Data is transparently forwarded.

## Prerequisites

- Cloudflare Workers **paid plan** (required for `cloudflare:sockets` `connect()` API)
- A domain added to Cloudflare with DNS proxy enabled (orange cloud icon)

## Quick Start

### Option 1: One-Click Deploy

Click the **Deploy to Cloudflare Workers** button above to deploy via the Cloudflare Dashboard.

### Option 2: CLI Deploy

```bash
# 1. Install Wrangler CLI
npm install -g wrangler

# 2. Login to Cloudflare
wrangler login

# 3. Clone the repo
git clone https://github.com/nadav-cheung/cloudflare-trojan.git
cd cloudflare-trojan

# 4. Generate your own password hash
echo -n "your-password" | sha224sum
# Output similar to: 08f32643dbdacf81d0d511f1ee24b06de759e90f8edf742bbdc57d88

# 5. Configure password (choose one)
#    Option A: Edit vars in wrangler.toml (for testing, will be committed to git)
#    Option B: Use secrets (recommended, not stored in repo)
wrangler secret put SHA224PASS
wrangler secret put PASSWORD

# 6. Deploy
wrangler deploy
```

After successful deployment:
```
Published worker-trojan (x.xx sec)
  https://worker-trojan.your-username.workers.dev
```

### Bind Custom Domain (Optional)

1. Go to Cloudflare Dashboard → Workers & Pages → `worker-trojan`
2. Settings → Domains & Routes → Add → Custom Domain
3. Enter your domain (must already be managed by Cloudflare)
4. Wait for DNS to propagate (usually a few seconds)

## Usage

### Get Trojan Link

After deployment, visit the following URL to get a configuration link for client import:

```bash
# If LINK_TOKEN is set
curl https://your-domain/link?token=your-token

# If LINK_TOKEN is not set
curl https://your-domain/link
```

Response example:
```
trojan://ca110us@your-domain:443/?type=ws&host=your-domain&security=tls
```

### Client Configuration

Import the link above into a Trojan client, or manually configure:

| Field | Value |
|-------|-------|
| Type | Trojan |
| Address | your-domain |
| Port | 443 |
| Password | your-cleartext-password |
| Transport | ws (WebSocket) |
| TLS | Enabled |
| SNI / WS Host | your-domain |
| Path | / |

### Recommended Clients

| Platform | Client |
|----------|--------|
| Windows | v2rayN, Clash Verge |
| macOS | Clash Verge, V2rayU |
| iOS | Shadowrocket, Stash |
| Android | v2rayNG, Clash Meta |

Import the link and connect — no additional setup required.

## Environment Variables

| Variable | Required | Description | Default |
|----------|----------|-------------|---------|
| `SHA224PASS` | Yes | SHA224 hash of the password (56 hex characters) | Built-in default |
| `PASSWORD` | No | Cleartext password (for `/link` URL generation) | `ca110us` |
| `PROXYIP` | No | Fallback proxy IP, used when direct connection fails | Empty (direct) |
| `LINK_TOKEN` | No | When set, `/link` endpoint requires `?token=` parameter | Public if unset |

> For sensitive values, prefer `wrangler secret put` over writing them in `wrangler.toml`.

## Troubleshooting

**Connection failed?**
- Verify Workers paid plan is active (free plan does not support `cloudflare:sockets`)
- Verify domain DNS proxy is enabled (orange cloud icon, not grey)
- Verify client password matches the plaintext corresponding to `SHA224PASS`
- Check logs: `wrangler tail`

**Direct connection to some sites not working?**
- Set `PROXYIP` to an intermediate proxy IP — the Worker will automatically fall back when direct connection fails

**How to change password?**
```bash
# Generate new hash
echo -n "new-password" | sha224sum

# Update secrets
wrangler secret put SHA224PASS
wrangler secret put PASSWORD

# Get new link
curl https://your-domain/link
```
