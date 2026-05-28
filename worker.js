import { connect } from "cloudflare:sockets";

const DEFAULT_SHA224_PASS = '08f32643dbdacf81d0d511f1ee24b06de759e90f8edf742bbdc57d88';
const DEFAULT_PASSWORD = 'ca110us';
const DEFAULT_PROXYIP = '';
const FALLBACK_PROXY_IPS = [
    '166.1.160.140',
    '107.172.16.110',
    '64.188.27.145',
    '43.169.18.179',
];
const SOURCE_TIERS = [
    { name: 'doh', type: 'doh' },
    { name: 'gh-bestproxy', url: 'https://raw.githubusercontent.com/ymyuuu/IPDB/master/BestProxy/bestproxy.txt' },
    { name: 'gh-proxy', url: 'https://raw.githubusercontent.com/ymyuuu/IPDB/master/BestProxy/proxy.txt' },
    { name: 'gh-proxy-root', url: 'https://raw.githubusercontent.com/ymyuuu/IPDB/master/proxy.txt' },
    { name: 'api-bestproxy', url: 'https://ipdb.api.030101.xyz/?type=bestproxy' },
    { name: 'api-proxy', url: 'https://ipdb.api.030101.xyz/?type=proxy' },
];
const PROXYIP_DOH_DOMAINS = [
    'proxyip.cmliussss.net',
];
const POOL_MIN = 10;
const POOL_MAX = 50;
const PROBE_CONCURRENCY = 6;
const PROBE_TIMEOUT_MS = 100;

let _pool = [];
let _refilling = null;
let _refillingStart = 0;
let _refillGen = 0;
let _quickRefilling = false;
let _lastRefillFail = 0;
const REFILL_RETRY_INTERVAL_MS = 60_000;

function getPool() {
    return _pool.length > 0 ? _pool : FALLBACK_PROXY_IPS;
}

async function healthCheck() {
    if (_refilling) await _refilling;
    if (_pool.length === 0) return;
    const before = [..._pool];
    const start = Date.now();
    const alive = await probeBatch(_pool);
    const dead = before.filter(ip => !alive.includes(ip));
    _pool = alive;
    console.log(`[health] ${alive.length}/${before.length} alive, ${dead.length} dead (${Date.now() - start}ms)`);
    if (dead.length > 0) console.log(`[health] removed: ${dead.join(', ')}`);
}

function isPublicIP(ip) {
    const parts = ip.includes(':') ? null : ip.split('.').map(Number);
    if (!parts || parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) return false;
    const [a, b, c, d] = parts;
    if (a === 0 || a === 127) return false;
    if (a === 10) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 169 && b === 254) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a === 192 && b === 0 && c === 0) return false;
    if (a === 198 && b === 51 && c === 100) return false;
    if (a === 203 && b === 0 && c === 113) return false;
    if (a === 224) return false;
    if (a >= 240) return false;
    return true;
}

async function quickRefill() {
    if (_quickRefilling) return;
    _quickRefilling = true;
    try {
        const existing = new Set(_pool);
        const candidates = [];
        const [dohResult, ghResult] = await Promise.allSettled([
            resolveDoH(),
            fetchSourceURL(SOURCE_TIERS[1].url),
        ]);
        for (const r of [dohResult, ghResult]) {
            if (r.status === 'fulfilled') {
                for (const ip of r.value) {
                    if (!existing.has(ip) && isPublicIP(ip)) {
                        candidates.push(ip);
                        existing.add(ip);
                    }
                }
            }
        }
        if (candidates.length === 0) return;
        console.log(`[quick-refill] probing ${candidates.length}`);
        const alive = await probeBatch(candidates);
        const room = Math.max(0, POOL_MAX - _pool.length);
        const toAdd = alive.slice(0, room);
        _pool.push(...toAdd);
        console.log(`[quick-refill] +${toAdd.length} added, pool=${_pool.length}`);
    } finally {
        _quickRefilling = false;
    }
}

async function refill() {
    if (_refilling) {
        if (_refillingStart && Date.now() - _refillingStart > 90_000) {
            console.error('[refill] stuck lock detected, clearing');
            _refilling = null;
        } else {
            return _refilling;
        }
    }
    _refillingStart = Date.now();
    const gen = ++_refillGen;
    _refilling = _doRefill().finally(() => {
        if (_refillGen === gen) { _refilling = null; _refillingStart = 0; }
    });
    return _refilling;
}

async function _doRefill() {
    const start = Date.now();
    for (const tier of SOURCE_TIERS) {
        if (_pool.length >= POOL_MAX) break;

        let ips;
        try {
            ips = tier.type === 'doh' ? await resolveDoH() : await fetchSourceURL(tier.url);
        } catch (e) {
            console.log(`[refill] ${tier.name}: fetch failed - ${e.message}`);
            continue;
        }

        const existing = new Set(_pool);
        const candidates = ips.filter(ip => !existing.has(ip) && isPublicIP(ip));
        if (candidates.length === 0) {
            console.log(`[refill] ${tier.name}: 0 new IPs, skip`);
            continue;
        }

        const needed = POOL_MAX - _pool.length;
        const tierStart = Date.now();
        console.log(`[refill] ${tier.name}: probing ${candidates.length} (need ${needed})`);
        const alive = await probeBatch(candidates, needed);
        const room = Math.max(0, POOL_MAX - _pool.length);
        const toAdd = alive.slice(0, room);
        _pool.push(...toAdd);
        if (_pool.length > POOL_MAX) _pool.length = POOL_MAX;
        console.log(`[refill] ${tier.name}: ${candidates.length} probed, ${alive.length} alive, +${toAdd.length} added, pool=${_pool.length} (${Date.now() - tierStart}ms)`);
    }
    console.log(`[refill] done: pool=${_pool.length} total=${Date.now() - start}ms`);
}

async function fetchSourceURL(url) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    try {
        const resp = await fetch(url, { signal: controller.signal });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const text = await resp.text();
        const ips = text.trim().split('\n')
            .map(s => s.trim())
            .filter(s => s && !s.startsWith('#'));
        if (ips.length === 0) throw new Error('empty');
        const parsed = new URL(url);
        const tag = parsed.search || parsed.pathname.split('/').pop() || parsed.hostname;
        console.log(`[ipdb] ${tag}: ${ips.length} IPs`);
        return ips;
    } finally {
        clearTimeout(timer);
    }
}

async function resolveDoH() {
    const all = [];
    const results = await Promise.allSettled(PROXYIP_DOH_DOMAINS.map(async (domain) => {
        const resp = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=A`, {
            headers: { accept: 'application/dns-json' },
        });
        if (!resp.ok) throw new Error(`DoH ${domain}: HTTP ${resp.status}`);
        const data = await resp.json();
        const ips = (data.Answer || []).filter(a => a.type === 1).map(a => a.data);
        if (ips.length === 0) throw new Error(`DoH ${domain}: no IPs`);
        console.log(`[doh] ${domain}: ${ips.length} IPs`);
        return ips;
    }));
    for (const r of results) {
        if (r.status === 'fulfilled' && r.value) all.push(...r.value);
    }
    if (all.length === 0) throw new Error('DoH: all domains failed');
    return [...new Set(all)];
}

async function probeBatch(candidates, maxAlive = Infinity) {
    const alive = [];
    for (let i = 0; i < candidates.length && alive.length < maxAlive; i += PROBE_CONCURRENCY) {
        const chunk = candidates.slice(i, i + PROBE_CONCURRENCY);
        const results = await Promise.allSettled(chunk.map(addr => probeOne(addr)));
        for (const r of results) {
            if (r.status === 'fulfilled') {
                alive.push(r.value);
                if (alive.length >= maxAlive) break;
            }
        }
    }
    return alive;
}

async function probeOne(addr) {
    const [host, portStr] = addr.includes(':') ? addr.split(':') : [addr, '443'];
    const port = parseInt(portStr);
    if (!Number.isFinite(port) || port < 1 || port > 65535) {
        throw new Error(`invalid port: ${addr}`);
    }
    const start = Date.now();
    const sock = connect({ hostname: host, port });
    try {
        await Promise.race([
            sock.opened,
            new Promise((_, r) => setTimeout(() => r(new Error('timeout')), PROBE_TIMEOUT_MS))
        ]);
        console.log(`[probe] ${addr} OK ${Date.now() - start}ms`);
    } catch (e) {
        console.log(`[probe] ${addr} FAIL ${Date.now() - start}ms ${e.message}`);
        throw e;
    } finally {
        sock.close();
    }
    return addr;
}

const textDecoder = new TextDecoder();

if (!isValidSHA224(DEFAULT_SHA224_PASS)) {
    throw new Error('sha224Password is not valid');
}

const worker_default = {
    /**
     * @param {import("@cloudflare/workers-types").Request} request
     * @param {{SHA224PASS: string, PROXYIP: string, PASSWORD: string, LINK_TOKEN: string}} env
     * @param {import("@cloudflare/workers-types").ExecutionContext} ctx
     * @returns {Promise<Response>}
     */
    async fetch(request, env, ctx) {
        try {
            const sha224Password = env.SHA224PASS || DEFAULT_SHA224_PASS;
            if (env.SHA224PASS && !isValidSHA224(env.SHA224PASS)) {
                return new Response("Server configuration error", { status: 500 });
            }
            const configProxyIP = env.PROXYIP || DEFAULT_PROXYIP;
            if (!configProxyIP && _pool.length === 0 && !_refilling && (Date.now() - _lastRefillFail) > REFILL_RETRY_INTERVAL_MS) {
                try {
                    await Promise.race([
                        quickRefill(),
                        new Promise((_, r) => setTimeout(() => r(new Error('timeout')), 15_000)),
                    ]);
                } catch (e) {
                    console.error('[pool] quick-refill:', e.message);
                }
                if (_pool.length === 0) _lastRefillFail = Date.now();
            }
            const pool = configProxyIP ? [] : getPool();
            const proxyIP = configProxyIP || pool[Math.floor(Math.random() * pool.length)];
            const proxyPort = env.PROXYPORT ? parseInt(env.PROXYPORT) : null;
            const cleartextPassword = env.PASSWORD || DEFAULT_PASSWORD;
            const upgradeHeader = request.headers.get("Upgrade");
            if (!upgradeHeader || upgradeHeader.toLowerCase() !== "websocket") {
                const url = new URL(request.url);
                switch (url.pathname) {
                    case "/pool": {
                        const linkToken = env.LINK_TOKEN;
                        if (linkToken && url.searchParams.get('token') !== linkToken) {
                            return new Response("404 Not found", { status: 404 });
                        }
                        return new Response(
                            JSON.stringify({ pool: _pool, fallback: FALLBACK_PROXY_IPS }, null, 2),
                            { status: 200, headers: { "Content-Type": "application/json" } }
                        );
                    }
                    case "/link": {
                        const linkToken = env.LINK_TOKEN;
                        if (linkToken && url.searchParams.get('token') !== linkToken) {
                            return new Response("404 Not found", { status: 404 });
                        }
                        const host = request.headers.get('Host');
                        return new Response(
                            `trojan://${encodeURIComponent(cleartextPassword)}@${host}:443/?type=ws&host=${host}&security=tls`,
                            {
                                status: 200,
                                headers: { "Content-Type": "text/plain;charset=utf-8" }
                            }
                        );
                    }
                    default:
                        return new Response("404 Not found", { status: 404 });
                }
            } else {
                return await trojanOverWSHandler(request, sha224Password, proxyIP, proxyPort);
            }
        } catch (err) {
            console.error("fetch error:", err);
            return new Response("Bad Request", { status: 400 });
        }
    },

    async scheduled(controller, env, ctx) {
        try {
            console.log('[pool] cron: health check');
            await healthCheck();
            if (_pool.length < POOL_MIN) {
                console.log(`[pool] cron: pool at ${_pool.length}, refilling`);
                await refill();
            }
            console.log(`[pool] cron: done, pool size ${_pool.length}`);
        } catch (e) {
            console.error(`[pool] cron error:`, e);
        }
    }
};

async function trojanOverWSHandler(request, sha224Password, proxyIP, proxyPort) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();
    let address = "";
    let portWithRandomLog = "";
    const log = (info, event) => {
        console.log(`[${address}:${portWithRandomLog}] ${info}`, event || "");
    };
    const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);
    let remoteSocketWrapper = { value: null };

    readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            if (remoteSocketWrapper.value) {
                const writer = remoteSocketWrapper.value.writable.getWriter();
                try {
                    await writer.write(chunk);
                } finally {
                    writer.releaseLock();
                }
                return;
            }
            const {
                hasError,
                message,
                portRemote = 443,
                addressRemote = "",
                rawClientData
            } = await parseTrojanHeader(chunk, sha224Password);
            address = addressRemote;
            portWithRandomLog = `${portRemote}--${Math.random()} tcp`;
            if (hasError) {
                throw new Error(message);
            }
            handleTCPOutBound(remoteSocketWrapper, addressRemote, portRemote, rawClientData, webSocket, proxyIP, proxyPort, log).catch((err) => {
                log("handleTCPOutBound error", err);
                safeCloseWebSocket(webSocket);
            });
        },
        close() {
            log(`readableWebSocketStream is closed`);
        },
        abort(reason) {
            log(`readableWebSocketStream is aborted`, JSON.stringify(reason));
        }
    })).catch((err) => {
        log("readableWebSocketStream pipeTo error", err);
        safeCloseWebSocket(webSocket);
    });
    return new Response(null, {
        status: 101,
        webSocket: client
    });
}

async function parseTrojanHeader(buffer, sha224Password) {
    if (buffer.byteLength < 58) {
        return { hasError: true, message: "invalid data" };
    }
    const bufView = new DataView(buffer);
    if (bufView.getUint8(56) !== 0x0d || bufView.getUint8(57) !== 0x0a) {
        return { hasError: true, message: "invalid header format (missing CR LF)" };
    }
    const password = textDecoder.decode(buffer.slice(0, 56));
    if (!timingSafeEqual(password, sha224Password)) {
        return { hasError: true, message: "invalid password" };
    }

    const socks5DataBuffer = buffer.slice(58);
    if (socks5DataBuffer.byteLength < 4) {
        return { hasError: true, message: "invalid SOCKS5 request data" };
    }

    const socks5View = new DataView(socks5DataBuffer);
    const cmd = socks5View.getUint8(0);
    if (cmd !== 1) {
        return { hasError: true, message: "unsupported command, only TCP (CONNECT) is allowed" };
    }

    const atype = socks5View.getUint8(1);
    let addressLength = 0;
    let addressIndex = 2;
    let address = "";
    switch (atype) {
        case 1: {
            addressLength = 4;
            if (socks5DataBuffer.byteLength < addressIndex + addressLength + 2) {
                return { hasError: true, message: "invalid IPv4 address data" };
            }
            address = new Uint8Array(
                socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)
            ).join(".");
            break;
        }
        case 3: {
            if (socks5DataBuffer.byteLength < addressIndex + 1) {
                return { hasError: true, message: "invalid domain address data" };
            }
            addressLength = new Uint8Array(
                socks5DataBuffer.slice(addressIndex, addressIndex + 1)
            )[0];
            if (socks5DataBuffer.byteLength < addressIndex + 1 + addressLength + 2) {
                return { hasError: true, message: "invalid domain address data" };
            }
            addressIndex += 1;
            address = textDecoder.decode(
                socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)
            );
            break;
        }
        case 4: {
            addressLength = 16;
            if (socks5DataBuffer.byteLength < addressIndex + addressLength + 2) {
                return { hasError: true, message: "invalid IPv6 address data" };
            }
            const dataView = new DataView(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            address = compressIPv6(ipv6);
            break;
        }
        default:
            return { hasError: true, message: `invalid addressType is ${atype}` };
    }

    if (!address) {
        return { hasError: true, message: `address is empty, addressType is ${atype}` };
    }

    const portIndex = addressIndex + addressLength;
    const portRemote = new DataView(socks5DataBuffer.slice(portIndex, portIndex + 2)).getUint16(0);
    return {
        hasError: false,
        addressRemote: address,
        portRemote,
        rawClientData: socks5DataBuffer.slice(portIndex + 4)
    };
}

async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, proxyIP, proxyPort, log) {
    async function connectAndWrite(address, port) {
        if (remoteSocket.value) {
            try { remoteSocket.value.close(); } catch (_) {}
        }
        const tcpSocket = connect({ hostname: address, port });
        log(`connecting to ${address}:${port}`);
        await tcpSocket.opened;
        remoteSocket.value = tcpSocket;
        log(`connected to ${address}:${port}`);
        const writer = tcpSocket.writable.getWriter();
        try {
            await writer.write(rawClientData);
        } finally {
            writer.releaseLock();
        }
        return tcpSocket;
    }
    async function tryRetry(retryAddr, retryPort) {
        const tcpSocket = await connectAndWrite(retryAddr, retryPort);
        tcpSocket.closed.catch((error) => {
            console.log("retry tcpSocket closed error", error);
        }).finally(() => {
            safeCloseWebSocket(webSocket);
        });
        await remoteSocketToWS(tcpSocket, webSocket, null, log);
    }
    async function retry() {
        const pool = getPool();
        const tried = new Set();
        const candidates = [];
        if (proxyIP && proxyIP !== addressRemote) {
            candidates.push(proxyIP);
            tried.add(proxyIP.includes(':') ? proxyIP.split(':')[0] : proxyIP);
        }
        for (let i = 0; i < 50 && candidates.length < 4 && tried.size < pool.length; i++) {
            const addr = pool[Math.floor(Math.random() * pool.length)];
            const key = addr.includes(':') ? addr.split(':')[0] : addr;
            if (!tried.has(key)) {
                tried.add(key);
                candidates.push(addr);
            }
        }
        for (const addr of candidates) {
            const [host, portStr] = addr.includes(':') ? addr.split(':') : [addr, null];
            const port = portStr ? parseInt(portStr) : (proxyPort || portRemote);
            try {
                await tryRetry(host, port);
                log(`retry success via ${host}:${port}`);
                return;
            } catch (e) {
                log(`retry ${host}:${port} failed: ${e.message}`);
            }
        }
        log(`retry exhausted after ${candidates.length} attempts`);
        safeCloseWebSocket(webSocket);
    }
    try {
        const tcpSocket = await connectAndWrite(addressRemote, portRemote);
        await remoteSocketToWS(tcpSocket, webSocket, retry, log);
    } catch (e) {
        log(`direct connect failed: ${e.message}, retrying via proxy`);
        await retry();
    }
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let readableStreamCancel = false;
    const stream = new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener("message", (event) => {
                if (readableStreamCancel) return;
                controller.enqueue(event.data);
            });
            webSocketServer.addEventListener("close", () => {
                safeCloseWebSocket(webSocketServer);
                if (readableStreamCancel) return;
                controller.close();
            });
            webSocketServer.addEventListener("error", (err) => {
                log("webSocketServer error");
                controller.error(err);
            });
            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) {
                controller.error(error);
            } else if (earlyData) {
                controller.enqueue(earlyData);
            }
        },
        cancel(reason) {
            if (readableStreamCancel) return;
            log(`readableStream was canceled, due to ${reason}`);
            readableStreamCancel = true;
            safeCloseWebSocket(webSocketServer);
        }
    });
    return stream;
}

async function remoteSocketToWS(remoteSocket, webSocket, retry, log) {
    let hasIncomingData = false;
    await remoteSocket.readable.pipeTo(
        new WritableStream({
            async write(chunk, controller) {
                hasIncomingData = true;
                if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                    controller.error("webSocket connection is not open");
                    return;
                }
                webSocket.send(chunk);
            },
            close() {
                log(`remoteSocket.readable is closed, hasIncomingData: ${hasIncomingData}`);
            },
            abort(reason) {
                console.error("remoteSocket.readable abort", reason);
            }
        })
    ).catch((error) => {
        console.error(`remoteSocketToWS error:`, error.stack || error);
    });
    if (hasIncomingData === false && retry) {
        log(`retry`);
        await retry();
    } else {
        safeCloseWebSocket(webSocket);
    }
}

function timingSafeEqual(a, b) {
    const encoder = new TextEncoder();
    const bufA = encoder.encode(a);
    const bufB = encoder.encode(b);
    const len = Math.max(bufA.length, bufB.length);
    let result = bufA.length ^ bufB.length;
    for (let i = 0; i < len; i++) {
        result |= (bufA[i] || 0) ^ (bufB[i] || 0);
    }
    return result === 0;
}

function compressIPv6(groups) {
    let bestStart = -1, bestLen = 0;
    let curStart = -1, curLen = 0;
    for (let i = 0; i < groups.length; i++) {
        if (groups[i] === '0') {
            if (curStart === -1) curStart = i;
            curLen++;
            if (curLen > bestLen) {
                bestStart = curStart;
                bestLen = curLen;
            }
        } else {
            curStart = -1;
            curLen = 0;
        }
    }
    if (bestLen >= 2) {
        const before = groups.slice(0, bestStart).join(':');
        const after = groups.slice(bestStart + bestLen).join(':');
        return before + '::' + after;
    }
    return groups.join(':');
}

function isValidSHA224(hash) {
    const sha224Regex = /^[0-9a-f]{56}$/i;
    return sha224Regex.test(hash);
}

function base64ToArrayBuffer(base64Str) {
    if (!base64Str) {
        return { error: null };
    }
    try {
        base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
        const decode = atob(base64Str);
        const arrayBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
        return { earlyData: arrayBuffer.buffer, error: null };
    } catch (error) {
        return { error };
    }
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
            socket.close();
        }
    } catch (error) {
        console.error("safeCloseWebSocket error", error);
    }
}
export { worker_default as default };
//# sourceMappingURL=worker.js.map