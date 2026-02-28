// src/crypto/handshake.js
'use strict';

const sodium = require('libsodium-wrappers');
const crypto = require('node:crypto');
const { buildPacket, parsePacket, PACKET_TYPES } = require('../network/packet');

const HANDSHAKE_TIMEOUT_MS = 10000;

/**
 * _writeFrame(socket, buf) — TLV framer (uint32BE length prefix)
 */
function _writeFrame(socket, buf) {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(buf.length, 0);
    socket.write(Buffer.concat([len, buf]));
}

/**
 * _readFrame(socket) — returns Promise<Buffer> of the next TLV frame payload
 */
function _readFrame(socket, timeoutMs = HANDSHAKE_TIMEOUT_MS) {
    return new Promise((resolve, reject) => {
        let rxBuf = Buffer.alloc(0);
        let expected = -1;
        let timer;

        const cleanup = () => {
            clearTimeout(timer);
            socket.removeListener('data', onData);
            socket.removeListener('error', onError);
            socket.removeListener('close', onClose);
        };

        timer = setTimeout(() => {
            cleanup();
            reject(new Error('Handshake timeout'));
        }, timeoutMs);

        const onData = (chunk) => {
            rxBuf = Buffer.concat([rxBuf, chunk]);
            while (true) {
                if (expected === -1) {
                    if (rxBuf.length < 4) return;
                    expected = rxBuf.readUInt32BE(0);
                }
                if (rxBuf.length < 4 + expected) return;
                const frame = rxBuf.slice(4, 4 + expected);
                rxBuf = rxBuf.slice(4 + expected);
                expected = -1;
                cleanup();
                resolve(frame);
                return;
            }
        };

        const onError = (err) => { cleanup(); reject(err); };
        const onClose = () => { cleanup(); reject(new Error('Socket closed during handshake')); };

        socket.on('data', onData);
        socket.on('error', onError);
        socket.on('close', onClose);
    });
}

/**
 * initiateHandshake(socket, myIdentity)
 * Initiator side of the X25519 ephemeral ECDH + HKDF handshake.
 * Returns { sessionKey: Buffer[32], peerNodeId: Buffer[32] }
 */
async function initiateHandshake(socket, myIdentity) {
    await sodium.ready;

    // Step 1 — generate ephemeral X25519 keypair
    const e_A = sodium.crypto_box_keypair();
    const e_A_pub_hex = Buffer.from(e_A.publicKey).toString('hex');

    // Step 2 — send HELLO_HS: sign the ePub+timestamp payload
    const payloadStr = JSON.stringify({ ePub: e_A_pub_hex, timestamp: Date.now() });
    const payloadBuf = Buffer.from(payloadStr);
    const sigA = Buffer.from(sodium.crypto_sign(payloadBuf, myIdentity.privateKey));

    const helloHSPkt = buildPacket(PACKET_TYPES.HELLO_HS, myIdentity.publicKey, sigA);
    _writeFrame(socket, helloHSPkt);

    // Step 3 — receive HELLO_REPLY_HS
    const replyFrame = await _readFrame(socket);
    const replyPkt = parsePacket(replyFrame);
    if (replyPkt.type !== PACKET_TYPES.HELLO_REPLY_HS) {
        throw new Error('Expected HELLO_REPLY_HS');
    }

    const peerNodeId = replyPkt.nodeId; // 32-byte Ed25519 pub of peer

    // reply payload = JSON-part (sig_B signed over e_A_pub_hex)
    let replyData;
    try {
        const opened = Buffer.from(sodium.crypto_sign_open(replyPkt.payload, peerNodeId));
        replyData = JSON.parse(opened.toString());
    } catch {
        throw new Error('HELLO_REPLY_HS: invalid signature');
    }

    const e_B_pub = Buffer.from(replyData.ePub, 'hex');

    // Step 4 — ECDH
    const shared = Buffer.from(sodium.crypto_scalarmult(e_A.privateKey, e_B_pub));

    // Step 5 — HKDF session key
    const sessionKey = Buffer.from(crypto.hkdfSync(
        'sha256',
        shared,
        Buffer.concat([myIdentity.publicKey, peerNodeId]),
        Buffer.from('archipel-v1'),
        32,
    ));

    // Step 6 — send AUTH: sign sha256(shared)
    const hash_shared = crypto.createHash('sha256').update(shared).digest();
    const sigAuth = Buffer.from(sodium.crypto_sign(hash_shared, myIdentity.privateKey));
    const authPkt = buildPacket(PACKET_TYPES.AUTH, myIdentity.publicKey, sigAuth);
    _writeFrame(socket, authPkt);

    // Step 7 — receive AUTH_OK
    const authOkFrame = await _readFrame(socket);
    const authOkPkt = parsePacket(authOkFrame);
    if (authOkPkt.type !== PACKET_TYPES.AUTH_OK) {
        throw new Error('Expected AUTH_OK');
    }

    return { sessionKey, peerNodeId };
}

/**
 * waitForHandshake(socket, myIdentity)
 * Responder side.
 * Returns { sessionKey: Buffer[32], peerNodeId: Buffer[32] }
 */
async function waitForHandshake(socket, myIdentity) {
    await sodium.ready;

    // Step 1 — receive HELLO_HS
    const helloFrame = await _readFrame(socket);
    const helloPkt = parsePacket(helloFrame);
    if (helloPkt.type !== PACKET_TYPES.HELLO_HS) {
        throw new Error('Expected HELLO_HS');
    }

    const peerNodeId = helloPkt.nodeId;

    // Verify sig_A: payload inside signed message = JSON { ePub, timestamp }
    let helloData;
    try {
        const opened = Buffer.from(sodium.crypto_sign_open(helloPkt.payload, peerNodeId));
        helloData = JSON.parse(opened.toString());
    } catch {
        throw new Error('HELLO_HS: invalid signature');
    }

    const e_A_pub = Buffer.from(helloData.ePub, 'hex');
    const e_A_pub_hex = helloData.ePub;

    // Step 2 — generate ephemeral X25519 keypair
    const e_B = sodium.crypto_box_keypair();

    // Step 3 — send HELLO_REPLY_HS: sign e_A_pub_hex with own private key
    const replyPayload = JSON.stringify({ ePub: Buffer.from(e_B.publicKey).toString('hex') });
    const sigB = Buffer.from(sodium.crypto_sign(Buffer.from(replyPayload), myIdentity.privateKey));
    const replyPkt = buildPacket(PACKET_TYPES.HELLO_REPLY_HS, myIdentity.publicKey, sigB);
    _writeFrame(socket, replyPkt);

    // Step 4 — ECDH
    const shared = Buffer.from(sodium.crypto_scalarmult(e_B.privateKey, e_A_pub));

    // Step 5 — HKDF session key (same formula, note peerNodeId first here too)
    const sessionKey = Buffer.from(crypto.hkdfSync(
        'sha256',
        shared,
        Buffer.concat([peerNodeId, myIdentity.publicKey]),
        Buffer.from('archipel-v1'),
        32,
    ));

    // Step 6 — receive AUTH
    const authFrame = await _readFrame(socket);
    const authPkt = parsePacket(authFrame);
    if (authPkt.type !== PACKET_TYPES.AUTH) {
        throw new Error('Expected AUTH');
    }

    try {
        const hash_shared = crypto.createHash('sha256').update(shared).digest();
        const opened = Buffer.from(sodium.crypto_sign_open(authPkt.payload, peerNodeId));
        if (!opened.equals(hash_shared)) throw new Error('AUTH hash mismatch');
    } catch {
        throw new Error('AUTH: invalid signature or hash mismatch');
    }

    // Step 7 — send AUTH_OK
    const authOkPkt = buildPacket(PACKET_TYPES.AUTH_OK, myIdentity.publicKey, Buffer.alloc(0));
    _writeFrame(socket, authOkPkt);

    return { sessionKey, peerNodeId };
}

module.exports = { initiateHandshake, waitForHandshake };
