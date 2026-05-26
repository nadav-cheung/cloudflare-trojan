import { connect } from "cloudflare:sockets";

const DEFAULT_SHA224_PASS = '08f32643dbdacf81d0d511f1ee24b06de759e90f8edf742bbdc57d88';
const DEFAULT_PASSWORD = 'ca110us';
const DEFAULT_PROXYIP = '';
const FALLBACK_PROXY_IPS = [
    '64.110.104.30',
    '144.24.140.37',
];
const PROXY_IP_SOURCES = [
    'https://ipdb.api.030101.xyz/?type=proxy',
];
const PROXY_IP_CACHE_TTL = 30 * 60 * 1000;

const PROXY_IP_REFRESH_MS = 10 * 60 * 1000;

let _proxyIPCache = null;
let _proxyIPCacheExpiry = 0;
let _proxyIPFetching = null;

const _coldStartInit = _doFetchProxyIPs().then((valid) => {
    if (valid.length > 0) {
        _proxyIPCache = valid;
        _proxyIPCacheExpiry = Date.now() + PROXY_IP_CACHE_TTL;
        console.log(`[proxyip] cold start: ${valid.length} valid — ${valid.join(', ')}`);
    }
}).catch(() => {
    console.log('[proxyip] cold start init failed, deferring to first request');
});

function _doFetchProxyIPs() {
    return Promise.any(PROXY_IP_SOURCES.map(async (url) => {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 5000);
        let rawIPs = [];
        try {
            const resp = await fetch(url, { signal: controller.signal });
            if (resp.ok) {
                const text = await resp.text();
                rawIPs = text.trim().split('\n')
                    .map(s => s.trim())
                    .filter(s => s && !s.startsWith('#'));
            }
        } catch (e) {
            if (e.name === 'AbortError') {
                console.error(`[proxyip] fetch timeout: ${url}`);
            } else {
                console.error(`[proxyip] fetch error: ${e.message}`);
            }
        } finally {
            clearTimeout(timer);
        }
        if (rawIPs.length === 0) throw new Error(`source empty: ${url}`);

        const pool = [...rawIPs];
        for (let i = pool.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [pool[i], pool[j]] = [pool[j], pool[i]];
        }

        const valid = [];
        const maxValid = 10;
        for (const addr of pool) {
            const [host, portStr] = addr.includes(':') ? addr.split(':') : [addr, '443'];
            const port = parseInt(portStr);
            try {
                const sock = connect({ hostname: host, port });
                await Promise.race([
                    sock.opened,
                    new Promise((_, r) => setTimeout(() => r(new Error('timeout')), 3000))
                ]);
                sock.close();
                valid.push(addr);
                if (valid.length >= maxValid) break;
            } catch (_) {
                // dead IP, skip
            }
        }

        if (valid.length > 0) {
            _proxyIPCache = valid;
            _proxyIPCacheExpiry = Date.now() + PROXY_IP_CACHE_TTL;
            console.log(`[proxyip] validated ${valid.length}/${maxValid}: ${valid.join(', ')} (${url})`);
        } else {
            console.error(`[proxyip] 0 valid after probing ${pool.length} IPs from ${url}`);
            throw new Error(`0 valid from ${url}`);
        }
        return valid;
    }));
}

async function getProxyIPList(ctx) {
    const now = Date.now();
    if (_proxyIPCache && _proxyIPCache.length > 0 && now < _proxyIPCacheExpiry) {
        const age = now - (_proxyIPCacheExpiry - PROXY_IP_CACHE_TTL);
        if (age > PROXY_IP_REFRESH_MS && !_proxyIPFetching) {
            triggerBackgroundRefresh(ctx);
        }
        return _proxyIPCache;
    }
    if (_coldStartInit) {
        await _coldStartInit;
        if (_proxyIPCache && _proxyIPCache.length > 0 && now < _proxyIPCacheExpiry) {
            return _proxyIPCache;
        }
    }
    if (!_proxyIPFetching) {
        _proxyIPFetching = _doFetchProxyIPs().catch(() => {
            return _proxyIPCache && _proxyIPCache.length > 0 ? _proxyIPCache : FALLBACK_PROXY_IPS;
        }).finally(() => {
            _proxyIPFetching = null;
        });
    }
    return _proxyIPFetching;
}

function triggerBackgroundRefresh(ctx) {
    _proxyIPFetching = _doFetchProxyIPs().then((valid) => {
        if (valid.length > 0) {
            _proxyIPCache = valid;
            _proxyIPCacheExpiry = Date.now() + PROXY_IP_CACHE_TTL;
        }
        return valid;
    }).catch(() => {
        return _proxyIPCache || FALLBACK_PROXY_IPS;
    }).finally(() => {
        _proxyIPFetching = null;
    });
    if (ctx) ctx.waitUntil(_proxyIPFetching);
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
            const proxyIPList = await getProxyIPList(ctx);
            const proxyIP = configProxyIP || proxyIPList[Math.floor(Math.random() * proxyIPList.length)];
            const proxyPort = env.PROXYPORT ? parseInt(env.PROXYPORT) : null;
            const cleartextPassword = env.PASSWORD || DEFAULT_PASSWORD;
            const upgradeHeader = request.headers.get("Upgrade");
            if (!upgradeHeader || upgradeHeader.toLowerCase() !== "websocket") {
                const url = new URL(request.url);
                switch (url.pathname) {
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
        console.log('[proxyip] cron refresh start');
        triggerBackgroundRefresh(ctx);
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
        const tcpSocket = connect({ hostname: address, port });
        remoteSocket.value = tcpSocket;
        log(`connected to ${address}:${port}`);
        await tcpSocket.opened;
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
        const pool = (_proxyIPCache && _proxyIPCache.length > 0) ? _proxyIPCache : FALLBACK_PROXY_IPS;
        const maxRetries = 3;
        const tried = new Set();
        const candidates = proxyIP && proxyIP !== addressRemote ? [proxyIP] : [];
        for (let i = 0; i < maxRetries && tried.size < pool.length; i++) {
            let idx;
            do { idx = Math.floor(Math.random() * pool.length); } while (tried.has(idx));
            tried.add(idx);
            candidates.push(pool[idx]);
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