# cloudflare-trojan

基于 Cloudflare Workers 的 Trojan 代理，通过 WebSocket 隧道传输 TLS 流量。

## 工作原理

客户端通过 WSS（WebSocket over TLS）连接到此 Worker → Worker 验证 SHA224 密码 → Worker 解析 SOCKS5 目标地址 → Worker 通过 `cloudflare:sockets` 建立 TCP 出站连接 → 数据透传。

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/nadav-cheung/cloudflare-trojan)

## 前提条件

- Cloudflare Workers **付费计划**（`cloudflare:sockets` 的 `connect()` API 需要）
- 域名已添加到 Cloudflare 并启用 DNS 代理

## 部署

```bash
npm install -g wrangler

# 登录
wrangler login

# 设置密码和后备代理 IP
# 编辑 wrangler.toml 中的 vars：
#   SHA224PASS - 你的 SHA224 哈希密码
#   PASSWORD   - 明文密码（用于 /link 端点生成 Trojan URL）
#   PROXYIP    - （可选）后备代理 IP
#   LINK_TOKEN - （可选）/link 端点访问令牌

# 对于敏感值，推荐使用 secret：
wrangler secret put SHA224PASS
wrangler secret put PASSWORD

# 部署
wrangler deploy
```

## 生成 SHA224 密码

```bash
echo -n "你的密码" | sha224sum
```

## 客户端配置

部署后，访问以下地址获取 Trojan 链接（可直接导入兼容客户端）：

- 如未设置 `LINK_TOKEN`：`https://你的域名/link`
- 如设置了 `LINK_TOKEN`：`https://你的域名/link?token=你的令牌`

或手动配置：

```
类型:     Trojan
地址:     你的域名
端口:     443
密码:     ca110us
传输:     ws
TLS:      开启
WS 主机:  你的域名
路径:     /
```