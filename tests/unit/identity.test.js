// c:\Users\PC LBS\kernel-killers\tests\unit\identity.test.js
'use strict';

const assert = require('node:assert');
const path = require('path');
const fs = require('fs');
const os = require('os');

// ─── helpers ─────────────────────────────────────────────────────────────────
function pass(name) { console.log(`[PASS] ${name}`); }
function fail(name, reason, file) {
    const loc = file ? ` — FILE: ${file}` : '';
    console.log(`[FAIL] ${name} — ${reason}${loc}`);
}

// ─── locate identity module ───────────────────────────────────────────────────
// Could be at src/crypto/identity.js or src/identity.js
const CANDIDATES = [
    path.resolve(__dirname, '../../src/crypto/identity.js'),
    path.resolve(__dirname, '../../src/identity.js'),
    path.resolve(__dirname, '../../src/network/identity.js'),
];
let IDENTITY_PATH = CANDIDATES.find(p => fs.existsSync(p));

if (!IDENTITY_PATH) {
    fail('MODULE_MISSING', `No identity module found (tried ${CANDIDATES.join(', ')})`, CANDIDATES[0] + ':1');
    process.exit(1);
}

let generateIdentity, loadIdentity;
try {
    const mod = require(IDENTITY_PATH);
    ({ generateIdentity, loadIdentity } = mod);
} catch (e) {
    fail('MODULE_LOAD', `Cannot require identity module: ${e.message}`, IDENTITY_PATH + ':1');
    process.exit(1);
}

// ─── TEST_ID_01 ─────────────────────────────────────────────────────────────
(async () => {
    const ARCHIPEL_KEY = path.resolve(process.cwd(), '.archipel/identity.key');

    // TEST_ID_01
    try {
        if (fs.existsSync(ARCHIPEL_KEY)) fs.unlinkSync(ARCHIPEL_KEY);
        await generateIdentity();
        assert.ok(fs.existsSync(ARCHIPEL_KEY));
        pass('TEST_ID_01');
    } catch (e) {
        fail('TEST_ID_01', `generateIdentity did not create .archipel/identity.key: ${e.message}`, IDENTITY_PATH + ':1');
    }

    // TEST_ID_02
    try {
        const gitignorePath = path.resolve(process.cwd(), '.gitignore');
        assert.ok(fs.existsSync(gitignorePath), '.gitignore must exist');
        const gitignore = fs.readFileSync(gitignorePath, 'utf8');
        assert.ok(gitignore.includes('.archipel/'), '.gitignore must contain .archipel/');
        assert.ok(gitignore.includes('*.key'), '.gitignore must contain *.key');
        pass('TEST_ID_02');
    } catch (e) {
        fail('TEST_ID_02', `identity.key not in .gitignore: ${e.message}`, path.resolve(process.cwd(), '.gitignore') + ':1');
    }

    // TEST_ID_03
    try {
        const identity = await loadIdentity();
        assert.strictEqual(identity.publicKey.length, 32);
        pass('TEST_ID_03');
    } catch (e) {
        fail('TEST_ID_03', `publicKey is not 32 bytes: ${e.message}`, IDENTITY_PATH + ':1');
    }

    // TEST_ID_04
    try {
        const identity = await loadIdentity();
        assert.strictEqual(identity.privateKey.length, 64);
        pass('TEST_ID_04');
    } catch (e) {
        fail('TEST_ID_04', `privateKey is not 64 bytes: ${e.message}`, IDENTITY_PATH + ':1');
    }

    // TEST_ID_05
    try {
        const id1 = await generateIdentity();
        const id2 = await generateIdentity();
        assert.ok(id1.publicKey.equals(id2.publicKey), 'generateIdentity must not overwrite existing key');
        pass('TEST_ID_05');
    } catch (e) {
        fail('TEST_ID_05', `generateIdentity is not idempotent — would break identity: ${e.message}`, IDENTITY_PATH + ':1');
    }

    // TEST_ID_06
    try {
        const sodium = require('libsodium-wrappers');
        await sodium.ready;
        const identity = await loadIdentity();
        const message = Buffer.from('archipel-sign-test');
        const signed = sodium.crypto_sign(message, identity.privateKey);
        const verified = Buffer.from(sodium.crypto_sign_open(signed, identity.publicKey));
        assert.ok(verified.equals(message));
        pass('TEST_ID_06');
    } catch (e) {
        fail('TEST_ID_06', `Ed25519 sign+verify roundtrip failed: ${e.message}`, IDENTITY_PATH + ':1');
    }

    // TEST_ID_07
    try {
        const logs = [];
        const originalLog = console.log;
        console.log = (...args) => logs.push(args.join(' '));
        await loadIdentity();
        await generateIdentity();
        console.log = originalLog;
        const identity = await loadIdentity();
        const privHex = identity.privateKey.toString('hex');
        const allLogs = logs.join('\n');
        assert.ok(!allLogs.includes(privHex), 'privateKey hex must not appear in console output');
        pass('TEST_ID_07');
    } catch (e) {
        fail('TEST_ID_07', `Private key was logged: ${e.message}`, IDENTITY_PATH + ':1');
    }

    // TEST_ID_08
    try {
        const archipelDir = path.resolve(process.cwd(), '.archipel');
        const backupDir = path.resolve(process.cwd(), '.archipel_backup_test');

        if (fs.existsSync(backupDir)) fs.rmSync(backupDir, { recursive: true });
        if (fs.existsSync(archipelDir)) fs.renameSync(archipelDir, backupDir);

        try {
            await generateIdentity();
            assert.ok(fs.existsSync(archipelDir), '.archipel must be created if missing');
            pass('TEST_ID_08');
        } finally {
            // Restore
            if (fs.existsSync(archipelDir)) fs.rmSync(archipelDir, { recursive: true });
            if (fs.existsSync(backupDir)) fs.renameSync(backupDir, archipelDir);
        }
    } catch (e) {
        fail('TEST_ID_08', `.archipel/ not created when missing: ${e.message}`, IDENTITY_PATH + ':1');
    }

})().catch(e => {
    fail('IDENTITY_SUITE_CRASH', e.message, IDENTITY_PATH + ':1');
    process.exit(1);
});
