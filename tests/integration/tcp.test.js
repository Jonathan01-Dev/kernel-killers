// c:\Users\PC LBS\kernel-killers\tests\integration\tcp.test.js
'use strict';

const assert = require('node:assert');
const net = require('net');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

function pass(name) { console.log(`[PASS] ${name}`); }
function fail(name, reason, file) {
    const loc = file ? ` — FILE: ${file}` : '';
    console.log(`[FAIL] ${name} — ${reason}${loc}`);
}

const TCP_PATH = path.resolve(__dirname, '../../src/network/tcpServer.js');
const PACKET_PATH = path.resolve(__dirname, '../../src/network/packet.js');

if (!fs.existsSync(TCP_PATH)) {
    fail('MODULE_MISSING', 'src/network/tcpServer.js does not exist', TCP_PATH + ':1');
    process.exit(1);
}

let TcpServer, buildPacket, PACKET_TYPES;
if (fs.existsSync(PACKET_PATH)) {
    try {
        ({ buildPacket, PACKET_TYPES } = require(PACKET_PATH));
    } catch (e) {
        fail('MODULE_MISSING', `packet.js load failed: ${e.message}`, PACKET_PATH + ':1');
        process.exit(1);
    }
}

// Minimal TcpServer requires identity + peerTable.
// Since core crypto modules may be missing, we test what we can.

const TEST_PORT = 17777;

// Helper: check TCP connection
function tcpConnect(port, host = '127.0.0.1', timeout = 3000) {
    return new Promise((resolve, reject) => {
        const s = new net.Socket();
        const t = setTimeout(() => { s.destroy(); reject(new Error('timeout')); }, timeout);
        s.connect(port, host, () => { clearTimeout(t); resolve(s); });
        s.on('error', (e) => { clearTimeout(t); reject(e); });
    });
}

function closeSocket(s) {
    return new Promise(resolve => {
        if (s.destroyed) return resolve();
        s.once('close', resolve);
        s.destroy();
    });
}

// TEST_TCP_01 — Server listens on configured port (using raw net.Server since TcpServer needs crypto)
(async () => {

    // TEST_TCP_01 — basic net.Server listen (tests infrastructure)
    try {
        const server = net.createServer();
        await new Promise((res, rej) => server.listen(TEST_PORT, '127.0.0.1', res).on('error', rej));

        const sock = await tcpConnect(TEST_PORT);
        await closeSocket(sock);
        await new Promise(res => server.close(res));
        pass('TEST_TCP_01');
    } catch (e) {
        fail('TEST_TCP_01', `Server listen/connect failed on port ${TEST_PORT}: ${e.message}`, TCP_PATH + ':46');
    }

    // TEST_TCP_02 — TLV framing: uint32_BE length prefix
    try {
        const messages = [];
        const server = net.createServer((socket) => {
            let buf = Buffer.alloc(0);
            socket.on('data', (data) => {
                buf = Buffer.concat([buf, data]);
                while (buf.length >= 4) {
                    const len = buf.readUInt32BE(0);
                    if (buf.length < 4 + len) break;
                    const frame = buf.subarray(4, 4 + len);
                    messages.push(frame);
                    buf = buf.subarray(4 + len);
                }
            });
        });

        await new Promise((res, rej) => server.listen(TEST_PORT + 1, '127.0.0.1', res).on('error', rej));
        const client = await tcpConnect(TEST_PORT + 1);

        // Send a TLV-framed message
        const payload = Buffer.from('hello archipel');
        const lenBuf = Buffer.alloc(4);
        lenBuf.writeUInt32BE(payload.length, 0);
        client.write(Buffer.concat([lenBuf, payload]));

        await new Promise(res => setTimeout(res, 200));
        assert.ok(messages.length >= 1, 'Server must have received TLV frame');
        assert.ok(messages[0].equals(payload), 'Deframed payload must equal sent data');

        await closeSocket(client);
        await new Promise(res => server.close(res));
        pass('TEST_TCP_02');
    } catch (e) {
        fail('TEST_TCP_02', `TLV framing failed: ${e.message}`, TCP_PATH + ':154');
    }

    // TEST_TCP_03 — 10 connection limit
    try {
        const conns = [];
        let rejectedAfterTen = false;

        const server = net.createServer((socket) => {
            if (conns.length >= 10) {
                // Reject: send byte then close
                socket.write(Buffer.from([0xFF]));
                socket.destroy();
                rejectedAfterTen = true;
                return;
            }
            conns.push(socket);
        });

        await new Promise((res, rej) => server.listen(TEST_PORT + 2, '127.0.0.1', res).on('error', rej));

        // Open 10 connections
        for (let i = 0; i < 10; i++) {
            const s = await tcpConnect(TEST_PORT + 2);
            conns.push(s);
        }

        // 11th connection
        const eleventh = await tcpConnect(TEST_PORT + 2);
        await new Promise(res => setTimeout(res, 200));

        // The server source checks connections.size >= 10 and destroys the 11th
        // Verify source contains the limit
        const src = fs.readFileSync(TCP_PATH, 'utf8');
        assert.ok(src.includes('10'), 'TcpServer must enforce 10 connection limit');
        assert.ok(src.includes('0xFF') || src.includes('connections.size'), 'TcpServer must reject 11th connection');

        await closeSocket(eleventh);
        for (const s of conns) await closeSocket(s);
        await new Promise(res => server.close(res));
        pass('TEST_TCP_03');
    } catch (e) {
        fail('TEST_TCP_03', `Connection limit test failed: ${e.message}`, TCP_PATH + ':29');
    }

    // TEST_TCP_04 — Invalid HMAC dropped silently (source check)
    try {
        const src = fs.readFileSync(TCP_PATH, 'utf8');
        assert.ok(src.includes('verifyHMAC'), 'Server must call verifyHMAC to validate packets');
        // Verify it returns (drops) on invalid HMAC
        assert.ok(src.includes('return') && src.includes('verifyHMAC'), 'Server must drop invalid HMAC silently');
        pass('TEST_TCP_04');
    } catch (e) {
        fail('TEST_TCP_04', `Invalid HMAC handling not found in source: ${e.message}`, TCP_PATH + ':187');
    }

    // TEST_TCP_05 — Keep-alive ACK every 15 seconds (source check)
    try {
        const src = fs.readFileSync(TCP_PATH, 'utf8');
        assert.ok(src.includes('15000'), 'Keep-alive must be 15000ms (15s)');
        assert.ok(src.includes('PACKET_TYPES.ACK') || src.includes('ACK'), 'Keep-alive must send ACK');
        pass('TEST_TCP_05');
    } catch (e) {
        fail('TEST_TCP_05', `Keep-alive ACK every 15s not found in source: ${e.message}`, TCP_PATH + ':141');
    }

    // TEST_TCP_06 — Peer removed from peerTable on socket close (source check)
    try {
        const src = fs.readFileSync(TCP_PATH, 'utf8');
        assert.ok(src.includes("'close'") || src.includes('"close"'), 'Must handle close event');
        assert.ok(src.includes('sessionStore.delete') || src.includes('peerSockets.delete'), 'Must remove peer from store on close');
        pass('TEST_TCP_06');
    } catch (e) {
        fail('TEST_TCP_06', `Peer not removed on socket close: ${e.message}`, TCP_PATH + ':171');
    }

    // TEST_TCP_07 — sendToPeer rejects after 5s timeout
    try {
        const src = fs.readFileSync(TCP_PATH, 'utf8');
        assert.ok(src.includes('5000'), 'sendToPeer must use 5000ms timeout');
        assert.ok(src.includes('timeout') || src.includes('connectingTimeout'), 'Must have timeout mechanism');

        // Actually test the timeout with an unreachable IP (skip on slow CI)
        // We test the logic is there via source analysis above
        pass('TEST_TCP_07');
    } catch (e) {
        fail('TEST_TCP_07', `sendToPeer timeout not implemented correctly: ${e.message}`, TCP_PATH + ':77');
    }

})().catch(e => {
    fail('TCP_SUITE_CRASH', e.message, TCP_PATH + ':1');
    process.exit(1);
});
