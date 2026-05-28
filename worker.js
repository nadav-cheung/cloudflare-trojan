import { connect } from "cloudflare:sockets";

const DEFAULT_SHA224_PASS = '08f32643dbdacf81d0d511f1ee24b06de759e90f8edf742bbdc57d88';
const DEFAULT_PASSWORD = 'ca110us';
const DEFAULT_PROXYIP = '';
const textDecoder = new TextDecoder();
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

export default {
    async fetch(request, env, ctx) {
        try {
            const sha224Password = env.SHA224PASS || DEFAULT_SHA224_PASS;
            const cleartextPassword = env.PASSWORD || DEFAULT_PASSWORD;
            const proxyIP = env.PROXYIP || DEFAULT_PROXYIP;
            const proxyPort = env.PROXYPORT ? parseInt(env.PROXYPORT) : null;
            const upgradeHeader = request.headers.get("Upgrade");
            if (!upgradeHeader || upgradeHeader.toLowerCase() !== "websocket") {
                const url = new URL(request.url);
                if (url.pathname === "/link") {
                    const host = request.headers.get('Host');
                    return new Response(
                        `trojan://${encodeURIComponent(cleartextPassword)}@${host}:443/?type=ws&host=${host}&security=tls`,
                        { status: 200, headers: { "Content-Type": "text/plain;charset=utf-8" } }
                    );
                }
                return new Response("OK", { status: 200 });
            }
            return await trojanOverWSHandler(request, sha224Password, proxyIP, proxyPort);
        } catch (err) {
            return new Response(`Error: ${err.message}`, { status: 500 });
        }
    },

    async scheduled(controller, env, ctx) {}
};

async function trojanOverWSHandler(request, sha224Password, proxyIP, proxyPort) {
    const pair = new WebSocketPair();
    const [client, ws] = Object.values(pair);
    ws.accept();

    let remoteSocket = null;
    let parsed = false;

    ws.addEventListener("message", async (event) => {
        try {
            const buffer = typeof event.data === 'string' ? new TextEncoder().encode(event.data) : event.data;
            if (!parsed) {
                parsed = true;
                const header = parseTrojanHeader(buffer, sha224Password);
                if (header.hasError) {
                    ws.close(4000, header.message);
                    return;
                }
                const tcpSocket = connect({ hostname: header.addressRemote, port: header.portRemote });
                await tcpSocket.opened;
                remoteSocket = tcpSocket;
                if (header.rawClientData && header.rawClientData.byteLength > 0) {
                    const writer = tcpSocket.writable.getWriter();
                    await writer.write(header.rawClientData);
                    writer.releaseLock();
                }
                pipeRemoteToWS(tcpSocket, ws);
            } else if (remoteSocket) {
                const writer = remoteSocket.writable.getWriter();
                await writer.write(buffer);
                writer.releaseLock();
            }
        } catch (e) {
            safeClose(ws);
        }
    });

    ws.addEventListener("close", () => {
        if (remoteSocket) {
            try { remoteSocket.close(); } catch (_) {}
            remoteSocket = null;
        }
    });

    return new Response(null, { status: 101, webSocket: client });
}

function pipeRemoteToWS(tcpSocket, ws) {
    const reader = tcpSocket.readable.getReader();
    (async () => {
        try {
            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                if (ws.readyState === WS_READY_STATE_OPEN) {
                    ws.send(value);
                }
            }
        } catch (_) {}
        safeClose(ws);
    })();
}

function parseTrojanHeader(buffer, sha224Password) {
    if (buffer.byteLength < 58) return { hasError: true, message: "invalid data" };
    const view = new DataView(buffer);
    if (view.getUint8(56) !== 0x0d || view.getUint8(57) !== 0x0a)
        return { hasError: true, message: "invalid header" };
    const password = textDecoder.decode(buffer.slice(0, 56));
    if (!timingSafeEqual(password, sha224Password))
        return { hasError: true, message: "invalid password" };

    const rest = buffer.slice(58);
    if (rest.byteLength < 4) return { hasError: true, message: "invalid SOCKS5" };
    const rv = new DataView(rest);
    if (rv.getUint8(0) !== 1) return { hasError: true, message: "unsupported cmd" };

    const atype = rv.getUint8(1);
    let addrLen = 0, addrIdx = 2, address = "";

    if (atype === 1) {
        addrLen = 4;
        if (rest.byteLength < addrIdx + addrLen + 2) return { hasError: true, message: "invalid IPv4" };
        address = new Uint8Array(rest.slice(addrIdx, addrIdx + addrLen)).join(".");
    } else if (atype === 3) {
        if (rest.byteLength < addrIdx + 1) return { hasError: true, message: "invalid domain" };
        addrLen = new Uint8Array(rest.slice(addrIdx, addrIdx + 1))[0];
        if (rest.byteLength < addrIdx + 1 + addrLen + 2) return { hasError: true, message: "invalid domain" };
        addrIdx += 1;
        address = textDecoder.decode(rest.slice(addrIdx, addrIdx + addrLen));
    } else if (atype === 4) {
        addrLen = 16;
        if (rest.byteLength < addrIdx + addrLen + 2) return { hasError: true, message: "invalid IPv6" };
        const dv = new DataView(rest.slice(addrIdx, addrIdx + addrLen));
        const parts = [];
        for (let i = 0; i < 8; i++) parts.push(dv.getUint16(i * 2).toString(16));
        address = parts.join(":");
    } else {
        return { hasError: true, message: "invalid atype" };
    }

    const portIdx = addrIdx + addrLen;
    const port = new DataView(rest.slice(portIdx, portIdx + 2)).getUint16(0);
    return { hasError: false, addressRemote: address, portRemote: port, rawClientData: rest.slice(portIdx + 4) };
}

function timingSafeEqual(a, b) {
    const enc = new TextEncoder();
    const ba = enc.encode(a), bb = enc.encode(b);
    const len = Math.max(ba.length, bb.length);
    let r = ba.length ^ bb.length;
    for (let i = 0; i < len; i++) r |= (ba[i] || 0) ^ (bb[i] || 0);
    return r === 0;
}

function safeClose(socket) {
    try { if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) socket.close(); } catch (_) {}
}
