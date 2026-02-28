// c:\Users\PC LBS\kernel-killers\tests\unit\manifest.test.js
'use strict';

const assert = require('node:assert');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const os = require('os');

function pass(name) { console.log(`[PASS] ${name}`); }
function fail(name, reason, file) {
    const loc = file ? ` — FILE: ${file}` : '';
    console.log(`[FAIL] ${name} — ${reason}${loc}`);
}

const MANIFEST_PATH = path.resolve(__dirname, '../../src/transfer/manifest.js');
if (!fs.existsSync(MANIFEST_PATH)) {
    fail('MODULE_MISSING', 'src/transfer/manifest.js does not exist', MANIFEST_PATH + ':1');
    process.exit(1);
}

let buildManifest, verifyManifest, encodeManifest, decodeManifest;
try {
    ({ buildManifest, verifyManifest, encodeManifest, decodeManifest } = require(MANIFEST_PATH));
} catch (e) {
    fail('MODULE_LOAD', `Cannot require manifest.js: ${e.message}`, MANIFEST_PATH + ':1');
    process.exit(1);
}

// ─── locate identity module ───────────────────────────────────────────────────
const IDENTITY_CANDIDATES = [
    path.resolve(__dirname, '../../src/crypto/identity.js'),
    path.resolve(__dirname, '../../src/identity.js'),
];
const IDENTITY_PATH = IDENTITY_CANDIDATES.find(p => fs.existsSync(p));

(async () => {
    // Build a real or mock identity
    let identity;
    if (IDENTITY_PATH) {
        try {
            const { generateIdentity, loadIdentity } = require(IDENTITY_PATH);
            identity = await loadIdentity().catch(() => null) || await generateIdentity();
        } catch (e) {
            identity = null;
        }
    }

    // Fallback: generate Ed25519 keypair via libsodium
    if (!identity) {
        try {
            const sodium = require('libsodium-wrappers');
            await sodium.ready;
            const kp = sodium.crypto_sign_keypair();
            identity = {
                publicKey: Buffer.from(kp.publicKey),
                privateKey: Buffer.from(kp.privateKey),
            };
        } catch (e) {
            fail('IDENTITY_SETUP', `Cannot create test identity: ${e.message}`, MANIFEST_PATH + ':1');
            return;
        }
    }

    // Fake chunk result
    const chunkResult = {
        fileId: crypto.randomBytes(32).toString('hex'),
        filename: 'archipel_test.bin',
        size: 100 * 1024,
        nbChunks: 1,
        chunks: [{ index: 0, hash: crypto.randomBytes(32).toString('hex'), size: 100 * 1024 }],
    };

    let manifest;

    // TEST_MAN_01
    try {
        manifest = await buildManifest(chunkResult, identity);
        const required = ['file_id', 'filename', 'size', 'chunk_size', 'nb_chunks', 'chunks', 'sender_id', 'signature'];
        for (const field of required) {
            assert.ok(manifest[field] !== undefined && manifest[field] !== null && manifest[field] !== '',
                `Missing or empty field: ${field}`);
        }
        pass('TEST_MAN_01');
    } catch (e) {
        fail('TEST_MAN_01', `buildManifest missing required fields: ${e.message}`, MANIFEST_PATH + ':9');
    }

    // TEST_MAN_02
    try {
        assert.strictEqual(manifest.chunk_size, 524288);
        pass('TEST_MAN_02');
    } catch (e) {
        fail('TEST_MAN_02', `chunk_size is not 524288: ${e.message}`, MANIFEST_PATH + ':13');
    }

    // TEST_MAN_03
    try {
        const isValid = await verifyManifest(manifest, identity.publicKey.toString('hex'));
        assert.strictEqual(isValid, true);
        pass('TEST_MAN_03');
    } catch (e) {
        fail('TEST_MAN_03', `Ed25519 signature verification failed: ${e.message}`, MANIFEST_PATH + ':28');
    }

    // TEST_MAN_04
    try {
        const tampered = { ...manifest, filename: 'evil.exe' };
        const isValid = await verifyManifest(tampered, identity.publicKey.toString('hex'));
        assert.strictEqual(isValid, false);
        pass('TEST_MAN_04');
    } catch (e) {
        fail('TEST_MAN_04', `Tampered manifest should fail verification: ${e.message}`, MANIFEST_PATH + ':28');
    }

    // TEST_MAN_05
    try {
        const encoded = encodeManifest(manifest);
        const decoded = decodeManifest(encoded);
        assert.strictEqual(decoded.file_id, manifest.file_id);
        assert.strictEqual(decoded.nb_chunks, manifest.nb_chunks);
        pass('TEST_MAN_05');
    } catch (e) {
        fail('TEST_MAN_05', `encodeManifest/decodeManifest roundtrip failed: ${e.message}`, MANIFEST_PATH + ':46');
    }

    // TEST_MAN_06
    try {
        const expectedSenderId = identity.publicKey.toString('hex');
        assert.strictEqual(manifest.sender_id, expectedSenderId);
        pass('TEST_MAN_06');
    } catch (e) {
        fail('TEST_MAN_06', `sender_id does not match identity publicKey hex: ${e.message}`, MANIFEST_PATH + ':16');
    }

})().catch(e => {
    fail('MANIFEST_SUITE_CRASH', e.message, MANIFEST_PATH + ':1');
    process.exit(1);
});
