// c:\Users\PC LBS\kernel-killers\tests\unit\session.test.js
'use strict';

const assert = require('node:assert');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

function pass(name) { console.log(`[PASS] ${name}`); }
function fail(name, reason, file) {
    const loc = file ? ` — FILE: ${file}` : '';
    console.log(`[FAIL] ${name} — ${reason}${loc}`);
}

const CANDIDATES = [
    path.resolve(__dirname, '../../src/crypto/session.js'),
    path.resolve(__dirname, '../../src/session.js'),
];
let SESSION_PATH = CANDIDATES.find(p => fs.existsSync(p));

if (!SESSION_PATH) {
    fail('MODULE_MISSING', `No session module found (tried ${CANDIDATES.join(', ')})`, CANDIDATES[0] + ':1');
    process.exit(1);
}

let encryptPayload, decryptPayload, SessionStore;
try {
    const mod = require(SESSION_PATH);
    ({ encryptPayload, decryptPayload, SessionStore } = mod);
} catch (e) {
    fail('MODULE_LOAD', `Cannot require session module: ${e.message}`, SESSION_PATH + ':1');
    process.exit(1);
}

const sessionKey = crypto.randomBytes(32);
const plaintext = Buffer.from('archipel test message');

// TEST_SES_01
try {
    const encrypted = encryptPayload(sessionKey, plaintext);
    // nonce(12) + authTag(16) + ciphertext(plaintext.length)
    assert.strictEqual(encrypted.length, 12 + 16 + plaintext.length);
    pass('TEST_SES_01');
} catch (e) {
    fail('TEST_SES_01', `encryptPayload length wrong: ${e.message}`, SESSION_PATH + ':1');
}

// TEST_SES_02
try {
    const encrypted = encryptPayload(sessionKey, plaintext);
    const decrypted = decryptPayload(sessionKey, encrypted);
    assert.ok(decrypted.equals(plaintext));
    pass('TEST_SES_02');
} catch (e) {
    fail('TEST_SES_02', `decryptPayload did not recover plaintext: ${e.message}`, SESSION_PATH + ':1');
}

// TEST_SES_03
try {
    const enc1 = encryptPayload(sessionKey, plaintext);
    const enc2 = encryptPayload(sessionKey, plaintext);
    const nonce1 = enc1.slice(0, 12);
    const nonce2 = enc2.slice(0, 12);
    assert.ok(!nonce1.equals(nonce2), 'nonces must differ — nonce reuse is catastrophic');
    assert.ok(!enc1.equals(enc2), 'ciphertexts must differ');
    pass('TEST_SES_03');
} catch (e) {
    fail('TEST_SES_03', `Nonce reuse detected — catastrophic security vulnerability: ${e.message}`, SESSION_PATH + ':1');
}

// TEST_SES_04
try {
    const encrypted = encryptPayload(sessionKey, plaintext);
    const tampered = Buffer.from(encrypted);
    // Flip a byte in ciphertext (after nonce+authTag = 28 bytes)
    if (tampered.length > 28) tampered[28] ^= 0xFF;
    assert.throws(() => decryptPayload(sessionKey, tampered), /DECRYPT_FAILED|decipher|auth/i);
    pass('TEST_SES_04');
} catch (e) {
    fail('TEST_SES_04', `decryptPayload did not throw on tampered ciphertext: ${e.message}`, SESSION_PATH + ':1');
}

// TEST_SES_05
try {
    const encrypted = encryptPayload(sessionKey, plaintext);
    const tampered = Buffer.from(encrypted);
    // Flip a byte in authTag (bytes 12..27)
    tampered[12] ^= 0xFF;
    assert.throws(() => decryptPayload(sessionKey, tampered), /.+/);
    pass('TEST_SES_05');
} catch (e) {
    fail('TEST_SES_05', `decryptPayload did not throw on tampered auth tag: ${e.message}`, SESSION_PATH + ':1');
}

// TEST_SES_06
try {
    const keyA = crypto.randomBytes(32);
    const keyB = crypto.randomBytes(32);
    const encrypted = encryptPayload(keyA, plaintext);
    assert.throws(() => decryptPayload(keyB, encrypted), /.+/);
    pass('TEST_SES_06');
} catch (e) {
    fail('TEST_SES_06', `decryptPayload did not throw on wrong key: ${e.message}`, SESSION_PATH + ':1');
}

// TEST_SES_07
try {
    const encrypted = encryptPayload(sessionKey, plaintext);
    const nonce = encrypted.slice(0, 12);
    assert.strictEqual(nonce.length, 12);
    const src = fs.readFileSync(SESSION_PATH, 'utf8');
    assert.ok(src.includes('randomBytes(12)'), 'source must use randomBytes(12) for nonce');
    pass('TEST_SES_07');
} catch (e) {
    fail('TEST_SES_07', `Nonce is not 12 bytes or randomBytes(12) not found: ${e.message}`, SESSION_PATH + ':1');
}

// TEST_SES_08
try {
    const src = fs.readFileSync(SESSION_PATH, 'utf8');
    assert.ok(src.includes('getAuthTag'), 'source must use getAuthTag()');
    const encrypted = encryptPayload(sessionKey, plaintext);
    // auth tag bytes 12..27 (16 bytes)
    const authTag = encrypted.slice(12, 28);
    assert.strictEqual(authTag.length, 16);
    pass('TEST_SES_08');
} catch (e) {
    fail('TEST_SES_08', `Auth tag is not 16 bytes or getAuthTag() not found: ${e.message}`, SESSION_PATH + ':1');
}

// TEST_SES_09
try {
    const store = new SessionStore();
    const nodeId = crypto.randomBytes(32);
    const key = crypto.randomBytes(32);
    store.set(nodeId, key);
    const retrieved = store.get(nodeId);
    assert.ok(retrieved.equals(key));
    pass('TEST_SES_09');
} catch (e) {
    fail('TEST_SES_09', `SessionStore.set/get roundtrip failed: ${e.message}`, SESSION_PATH + ':1');
}

// TEST_SES_10
try {
    const store = new SessionStore();
    const unknown = crypto.randomBytes(32);
    assert.strictEqual(store.has(unknown), false);
    pass('TEST_SES_10');
} catch (e) {
    fail('TEST_SES_10', `SessionStore.has returned true for unknown peer: ${e.message}`, SESSION_PATH + ':1');
}

// TEST_SES_11
try {
    const store = new SessionStore();
    const nodeId = crypto.randomBytes(32);
    const key = crypto.randomBytes(32);
    store.set(nodeId, key);
    store.delete(nodeId);
    assert.strictEqual(store.has(nodeId), false);
    pass('TEST_SES_11');
} catch (e) {
    fail('TEST_SES_11', `SessionStore.delete did not remove entry: ${e.message}`, SESSION_PATH + ':1');
}
