// src/network/packet.js
'use strict';

const crypto = require('node:crypto');

const MAGIC = Buffer.from([0x41, 0x52, 0x43, 0x48]); // "ARCH"

const PACKET_TYPES = {
    HELLO: 0x01,
    PEER_LIST: 0x02,
    MSG: 0x03,
    CHUNK_REQ: 0x04,
    CHUNK_DATA: 0x05,
    MANIFEST: 0x06,
    ACK: 0x07,
    HELLO_HS: 0x10,
    HELLO_REPLY_HS: 0x11,
    AUTH: 0x12,
    AUTH_OK: 0x13,
};

/**
 * buildPacket(type, nodeId, payload)
 * Layout: MAGIC(4) + TYPE(1) + NODE_ID(32) + PAYLOAD_LEN(4) + PAYLOAD + HMAC(32)
 * HMAC-SHA256 key = nodeId, data = everything before the HMAC
 */
function buildPacket(type, nodeId, payload) {
    if (!Buffer.isBuffer(nodeId) || nodeId.length !== 32) {
        throw new Error('nodeId must be a Buffer of exactly 32 bytes');
    }
    if (!Buffer.isBuffer(payload)) payload = Buffer.from(payload);

    const payloadLen = payload.length;
    const header = Buffer.alloc(41);

    MAGIC.copy(header, 0);                        // bytes 0..3
    header.writeUInt8(type, 4);                   // byte 4
    nodeId.copy(header, 5);                       // bytes 5..36
    header.writeUInt32BE(payloadLen, 37);          // bytes 37..40

    const dataToSign = Buffer.concat([header, payload]);
    const hmac = crypto.createHmac('sha256', nodeId).update(dataToSign).digest();

    return Buffer.concat([dataToSign, hmac]);
}

/**
 * parsePacket(buffer)
 * Returns { type, nodeId, payloadLen, payload, hmac }
 */
function parsePacket(buffer) {
    if (!Buffer.isBuffer(buffer) || buffer.length < 41) {
        throw new Error('Buffer too short to be a valid packet');
    }

    const magic = buffer.slice(0, 4);
    if (!magic.equals(MAGIC)) {
        throw new Error('INVALID_MAGIC: packet does not start with ARCH');
    }

    const type = buffer.readUInt8(4);
    const nodeId = buffer.slice(5, 37);
    const payloadLen = buffer.readUInt32BE(37);
    const payload = buffer.slice(41, 41 + payloadLen);
    const hmac = buffer.slice(buffer.length - 32);

    return { type, nodeId, payloadLen, payload, hmac };
}

/**
 * verifyHMAC(packet)
 * Recomputes HMAC over all bytes except the last 32, compares with timingSafeEqual.
 * Returns true/false, never throws.
 */
function verifyHMAC(packet) {
    try {
        if (!Buffer.isBuffer(packet) || packet.length < 41 + 32) return false;

        const nodeId = packet.slice(5, 37);
        const dataToVerify = packet.slice(0, packet.length - 32);
        const receivedHMAC = packet.slice(packet.length - 32);

        const expectedHMAC = crypto.createHmac('sha256', nodeId).update(dataToVerify).digest();

        return crypto.timingSafeEqual(receivedHMAC, expectedHMAC);
    } catch {
        return false;
    }
}

module.exports = { MAGIC, PACKET_TYPES, buildPacket, parsePacket, verifyHMAC };
