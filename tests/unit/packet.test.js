// c:\Users\PC LBS\kernel-killers\tests\unit\packet.test.js
'use strict';

const assert = require('node:assert');
const path = require('path');
const fs = require('fs');

// ─── helpers ─────────────────────────────────────────────────────────────────
function pass(name) { console.log(`[PASS] ${name}`); }
function fail(name, reason, file) {
    const loc = file ? ` — FILE: ${file}` : '';
    console.log(`[FAIL] ${name} — ${reason}${loc}`);
}

// ─── load module ─────────────────────────────────────────────────────────────
const PACKET_PATH = path.resolve(__dirname, '../../src/network/packet.js');
let buildPacket, parsePacket, verifyHMAC, PACKET_TYPES, mod;

if (!fs.existsSync(PACKET_PATH)) {
    fail('MODULE_MISSING', 'src/network/packet.js does not exist', PACKET_PATH + ':1');
    process.exit(1);
}
try {
    mod = require(PACKET_PATH);
    ({ buildPacket, parsePacket, verifyHMAC, PACKET_TYPES } = mod);
} catch (e) {
    fail('MODULE_LOAD', `Cannot require packet.js: ${e.message}`, PACKET_PATH + ':1');
    process.exit(1);
}

// ─── shared fixtures ─────────────────────────────────────────────────────────
const nodeId = Buffer.alloc(32, 0xAB);
const hmacKey = Buffer.alloc(32, 0x12);   // 32-byte key for HMAC
const payloadSmall = Buffer.from('hello');

// Helper: call buildPacket with proper arg count
// The spec says: buildPacket(type, nodeId, payload, [hmacKey])
// We detect arity here
function build(type, nid, payload) {
    // Try with 4 args (with hmacKey), fall back to 3
    try {
        const r = buildPacket(type, nid, payload, hmacKey);
        return r;
    } catch (e) {
        return buildPacket(type, nid, payload);
    }
}

function verify(buf) {
    try {
        return verifyHMAC(buf, hmacKey);
    } catch (e) {
        return verifyHMAC(buf);
    }
}

// ─── TEST_PKT_01 ─────────────────────────────────────────────────────────────
try {
    const buf = build(0x01, nodeId, payloadSmall);
    const magic = [buf[0], buf[1], buf[2], buf[3]];
    assert.deepStrictEqual(magic, [0x41, 0x52, 0x43, 0x48]);
    pass('TEST_PKT_01');
} catch (e) {
    fail('TEST_PKT_01', `Magic bytes wrong: ${e.message}`, PACKET_PATH + ':1');
}

// ─── TEST_PKT_02 ─────────────────────────────────────────────────────────────
try {
    const buf = build(0x01, nodeId, payloadSmall);
    // Get payload content from bytes after header (offset 41)
    // Total = 41 + payloadLen + 32(HMAC)
    // payloadLen at offset 37 (uint32BE)
    const payloadLen = buf.readUInt32BE(37);
    assert.strictEqual(payloadLen, payloadSmall.length);
    // Verify header is 41 bytes: content at 41 should start payload
    const payloadSuffix = buf.slice(41, 41 + payloadLen);
    assert.ok(payloadSuffix.equals(payloadSmall), 'payload at offset 41 should match');
    pass('TEST_PKT_02');
} catch (e) {
    fail('TEST_PKT_02', `Header size not 41 bytes: ${e.message}`, PACKET_PATH + ':1');
}

// ─── TEST_PKT_03 ─────────────────────────────────────────────────────────────
try {
    const buf = build(0x03, nodeId, payloadSmall);
    assert.strictEqual(buf[4], 0x03);
    pass('TEST_PKT_03');
} catch (e) {
    fail('TEST_PKT_03', `TYPE byte at offset 4 wrong: ${e.message}`, PACKET_PATH + ':1');
}

// ─── TEST_PKT_04 ─────────────────────────────────────────────────────────────
try {
    const buf = build(0x01, nodeId, payloadSmall);
    const nodeIdSlice = buf.slice(5, 37);
    assert.ok(nodeIdSlice.equals(nodeId));
    pass('TEST_PKT_04');
} catch (e) {
    fail('TEST_PKT_04', `NODE_ID at offset 5..36 wrong: ${e.message}`, PACKET_PATH + ':1');
}

// ─── TEST_PKT_05 ─────────────────────────────────────────────────────────────
try {
    const payload256 = Buffer.alloc(256);
    const buf = build(0x01, nodeId, payload256);
    const len = buf.readUInt32BE(37);
    assert.strictEqual(len, 256);
    pass('TEST_PKT_05');
} catch (e) {
    fail('TEST_PKT_05', `PAYLOAD_LEN uint32BE at offset 37 wrong: ${e.message}`, PACKET_PATH + ':1');
}

// ─── TEST_PKT_06 ─────────────────────────────────────────────────────────────
try {
    const buf = build(0x01, nodeId, payloadSmall);
    const expectedLen = 41 + payloadSmall.length + 32;
    assert.strictEqual(buf.length, expectedLen);
    pass('TEST_PKT_06');
} catch (e) {
    fail('TEST_PKT_06', `Total length wrong (expected 41+payloadLen+32): ${e.message}`, PACKET_PATH + ':1');
}

// ─── TEST_PKT_07 ─────────────────────────────────────────────────────────────
try {
    const buf = build(0x01, nodeId, payloadSmall);
    const result = verify(buf);
    assert.strictEqual(result, true);
    pass('TEST_PKT_07');
} catch (e) {
    fail('TEST_PKT_07', `verifyHMAC returned false on valid packet: ${e.message}`, PACKET_PATH + ':1');
}

// ─── TEST_PKT_08 ─────────────────────────────────────────────────────────────
try {
    const buf = build(0x01, nodeId, payloadSmall);
    // Flip a byte inside payload (offset 41)
    buf[41] ^= 0xFF;
    const result = verify(buf);
    assert.strictEqual(result, false);
    pass('TEST_PKT_08');
} catch (e) {
    fail('TEST_PKT_08', `verifyHMAC returned true on tampered payload: ${e.message}`, PACKET_PATH + ':1');
}

// ─── TEST_PKT_09 ─────────────────────────────────────────────────────────────
try {
    const buf = build(0x01, nodeId, payloadSmall);
    // Flip last byte (HMAC byte)
    buf[buf.length - 1] ^= 0xFF;
    const result = verify(buf);
    assert.strictEqual(result, false);
    pass('TEST_PKT_09');
} catch (e) {
    fail('TEST_PKT_09', `verifyHMAC returned true on tampered HMAC: ${e.message}`, PACKET_PATH + ':1');
}

// ─── TEST_PKT_10 ─────────────────────────────────────────────────────────────
try {
    const src = fs.readFileSync(PACKET_PATH, 'utf8');
    assert.ok(src.includes('timingSafeEqual'), 'source must use timingSafeEqual');
    pass('TEST_PKT_10');
} catch (e) {
    fail('TEST_PKT_10', `timingSafeEqual not found — timing attack vulnerability: ${e.message}`, PACKET_PATH + ':1');
}

// ─── TEST_PKT_11 ─────────────────────────────────────────────────────────────
try {
    const fullPayload = Buffer.from('archipel-roundtrip-test');
    const buf = build(0x05, nodeId, fullPayload);
    const parsed = parsePacket(buf);
    assert.strictEqual(parsed.type, 0x05);
    assert.ok(parsed.nodeId.equals(nodeId));
    assert.ok(parsed.payload.equals(fullPayload));
    pass('TEST_PKT_11');
} catch (e) {
    fail('TEST_PKT_11', `parsePacket roundtrip failed: ${e.message}`, PACKET_PATH + ':1');
}

// ─── TEST_PKT_12 ─────────────────────────────────────────────────────────────
try {
    assert.throws(() => parsePacket(Buffer.alloc(10)), /./);
    pass('TEST_PKT_12');
} catch (e) {
    fail('TEST_PKT_12', `parsePacket did not throw on short buffer: ${e.message}`, PACKET_PATH + ':1');
}

// ─── TEST_PKT_13 ─────────────────────────────────────────────────────────────
try {
    const buf = build(0x01, nodeId, payloadSmall);
    buf[0] = 0x00; buf[1] = 0x00; buf[2] = 0x00; buf[3] = 0x00;
    assert.throws(() => parsePacket(buf), (err) => {
        assert.ok(/MAGIC/i.test(err.message), `Error message should contain MAGIC, got: ${err.message}`);
        return true;
    });
    pass('TEST_PKT_13');
} catch (e) {
    fail('TEST_PKT_13', `parsePacket did not throw with MAGIC error on wrong magic: ${e.message}`, PACKET_PATH + ':1');
}

// ─── TEST_PKT_14 ─────────────────────────────────────────────────────────────
try {
    assert.strictEqual(PACKET_TYPES.HELLO, 0x01, 'HELLO');
    assert.strictEqual(PACKET_TYPES.PEER_LIST, 0x02, 'PEER_LIST');
    assert.strictEqual(PACKET_TYPES.MSG, 0x03, 'MSG');
    assert.strictEqual(PACKET_TYPES.CHUNK_REQ, 0x04, 'CHUNK_REQ');
    assert.strictEqual(PACKET_TYPES.CHUNK_DATA, 0x05, 'CHUNK_DATA');
    assert.strictEqual(PACKET_TYPES.MANIFEST, 0x06, 'MANIFEST');
    assert.strictEqual(PACKET_TYPES.ACK, 0x07, 'ACK');
    pass('TEST_PKT_14');
} catch (e) {
    fail('TEST_PKT_14', `PACKET_TYPES values wrong: ${e.message}`, PACKET_PATH + ':1');
}

// ─── TEST_PKT_15 ─────────────────────────────────────────────────────────────
try {
    const emptyPayload = Buffer.alloc(0);
    const buf = build(0x07, nodeId, emptyPayload);
    const result = verify(buf);
    assert.strictEqual(result, true);
    pass('TEST_PKT_15');
} catch (e) {
    fail('TEST_PKT_15', `Zero-length payload failed: ${e.message}`, PACKET_PATH + ':1');
}
