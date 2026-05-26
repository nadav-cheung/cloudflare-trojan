import { connect } from "cloudflare:sockets";

const DEFAULT_SHA224_PASS = '08f32643dbdacf81d0d511f1ee24b06de759e90f8edf742bbdc57d88';
const DEFAULT_PASSWORD = 'ca110us';
const DEFAULT_PROXYIP = '';
const PROXY_IPS = [
    'cdn.xn--b6gac.eu.org',
    'cdn-all.xn--b6gac.eu.org',
    'workers.bestip.one'
];
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
            const proxyIP = configProxyIP || PROXY_IPS[Math.floor(Math.random() * PROXY_IPS.length)];
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
    async function retry() {
        const retryPort = proxyPort || portRemote;
        const tcpSocket = await connectAndWrite(proxyIP || addressRemote, retryPort);
        tcpSocket.closed.catch((error) => {
            console.log("retry tcpSocket closed error", error);
        }).finally(() => {
            safeCloseWebSocket(webSocket);
        });
        await remoteSocketToWS(tcpSocket, webSocket, null, log);
    }
    const tcpSocket = await connectAndWrite(addressRemote, portRemote);
    await remoteSocketToWS(tcpSocket, webSocket, retry, log);
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