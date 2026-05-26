# cloudflare-trojan

基于 Cloudflare Workers 的 Trojan 代理，通过 WebSocket 隧道传输 TLS 流量。

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/nadav-cheung/cloudflare-trojan)

[English](README.md)

## 工作原理

客户端通过 WSS（WebSocket over TLS）连接到此 Worker → Worker 验证 SHA224 密码 → Worker 解析 SOCKS5 目标地址 → Worker 通过 `cloudflare:sockets` 建立 TCP 出站连接 → 数据透传。

## 前提条件

- Cloudflare Workers **付费计划**（`cloudflare:sockets` 的 `connect()` API 需要）
- 域名已添加到 Cloudflare 并启用 DNS 代理（橙色云图标）

## 快速开始

### 方式一：一键部署

点击上方 **Deploy to Cloudflare Workers** 按钮，在 Cloudflare Dashboard 中完成部署。

### 方式二：命令行部署

```bash
# 1. 安装 Wrangler CLI
npm install -g wrangler

# 2. 登录 Cloudflare 账户
wrangler login

# 3. 克隆仓库
git clone https://github.com/nadav-cheung/cloudflare-trojan.git
cd cloudflare-trojan

# 4. 生成你自己的密码哈希
echo -n "你的密码" | sha224sum
# 输出类似: 08f32643dbdacf81d0d511f1ee24b06de759e90f8edf742bbdc57d88

# 5. 配置密码（二选一）
#    方式 A：编辑 wrangler.toml 中的 vars（适合测试，会提交到 git）
#    方式 B：使用 secret（推荐，不会入库）
wrangler secret put SHA224PASS
wrangler secret put PASSWORD

# 6. 部署
wrangler deploy
```

部署成功后输出类似：
```
Published worker-trojan (x.xx sec)
  https://worker-trojan.你的用户名.workers.dev
```

### 绑定自定义域名（可选）

1. 进入 Cloudflare Dashboard → Workers & Pages → `worker-trojan`
2. Settings → Domains & Routes → Add → Custom Domain
3. 输入你的域名（必须已在 Cloudflare 管理）
4. 等待 DNS 生效（通常几秒）

## 使用方法

### 获取 Trojan 链接

部署后访问以下地址获取配置链接，可直接导入客户端：

```bash
# 如果设置了 LINK_TOKEN
curl https://你的域名/link?token=你的令牌

# 如果未设置 LINK_TOKEN
curl https://你的域名/link
```

返回内容类似：
```
trojan://ca110us@你的域名:443/?type=ws&host=你的域名&security=tls
```

### 客户端配置

将上述链接导入 Trojan 客户端，或手动填写：

| 字段 | 值 |
|------|----|
| 类型 | Trojan |
| 地址 | 你的域名 |
| 端口 | 443 |
| 密码 | 你的明文密码 |
| 传输方式 | ws (WebSocket) |
| TLS | 开启 |
| SNI / WS Host | 你的域名 |
| 路径 | / |

### 推荐客户端

| 平台 | 客户端 |
|------|--------|
| Windows | v2rayN、Clash Verge |
| macOS | Clash Verge、V2rayU |
| iOS | Shadowrocket、Stash |
| Android | v2rayNG、Clash Meta |

导入链接后连接即可使用，无需额外设置。

## 环境变量

| 变量 | 必需 | 说明 | 默认值 |
|------|------|------|--------|
| `SHA224PASS` | 是 | 密码的 SHA224 哈希值（56位十六进制） | 内置默认 |
| `PASSWORD` | 否 | 明文密码（用于 `/link` 生成 URL） | `ca110us` |
| `PROXYIP` | 否 | 后备代理 IP，直连失败时使用 | 空（直连） |
| `LINK_TOKEN` | 否 | 设置后 `/link` 端点需带 `?token=` 参数 | 未设置则公开 |

> 敏感值推荐使用 `wrangler secret put` 而非写入 `wrangler.toml`。

## 常见问题

**连接失败？**
- 确认 Workers 付费计划已生效（免费计划不支持 `cloudflare:sockets`）
- 确认域名 DNS 代理已开启（橙色云图标，非灰色）
- 确认客户端密码与 `SHA224PASS` 对应的明文一致
- 查看日志：`wrangler tail`

**直连某些网站不通？**
- 设置 `PROXYIP` 为一个中间代理 IP，Worker 会在直连失败时自动回退

**如何更换密码？**
```bash
# 生成新哈希
echo -n "新密码" | sha224sum

# 更新 secret
wrangler secret put SHA224PASS
wrangler secret put PASSWORD

# 重新获取链接
curl https://你的域名/link
```
