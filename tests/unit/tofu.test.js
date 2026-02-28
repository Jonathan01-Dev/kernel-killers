// c:\Users\PC LBS\kernel-killers\tests\unit\tofu.test.js
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

const CANDIDATES = [
    path.resolve(__dirname, '../../src/trust/tofu.js'),
    path.resolve(__dirname, '../../src/crypto/tofu.js'),
    path.resolve(__dirname, '../../src/tofu.js'),
];
let TOFU_PATH = CANDIDATES.find(p => fs.existsSync(p));

if (!TOFU_PATH) {
    fail('MODULE_MISSING', `No tofu module found (tried ${CANDIDATES.join(', ')})`, CANDIDATES[0] + ':1');
    process.exit(1);
}

let TofuStore;
try {
    TofuStore = require(TOFU_PATH);
} catch (e) {
    fail('MODULE_LOAD', `Cannot require tofu module: ${e.message}`, TOFU_PATH + ':1');
    process.exit(1);
}

// Use a temp dir for persistence tests
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'archipel-tofu-'));
const trustFile = path.join(tmpDir, 'trust.json');

function freshStore(tfile = null) {
    return new TofuStore(tfile || trustFile);
}

// TEST_TOFU_01
try {
    const store = freshStore();
    const nodeId = crypto.randomBytes(32);
    const pubKey = crypto.randomBytes(32);
    const result = store.check(nodeId, pubKey);
    assert.strictEqual(result, 'NEW');
    pass('TEST_TOFU_01');
} catch (e) {
    fail('TEST_TOFU_01', `First contact should return NEW: ${e.message}`, TOFU_PATH + ':1');
}

// TEST_TOFU_02
try {
    const store = freshStore();
    const nodeId = crypto.randomBytes(32);
    const pubKey = crypto.randomBytes(32);
    store.trust(nodeId, pubKey);
    const result = store.check(nodeId, pubKey);
    assert.strictEqual(result, 'TRUSTED');
    pass('TEST_TOFU_02');
} catch (e) {
    fail('TEST_TOFU_02', `Known peer with matching key should return TRUSTED: ${e.message}`, TOFU_PATH + ':1');
}

// TEST_TOFU_03
try {
    const store = freshStore();
    const nodeId = crypto.randomBytes(32);
    const pubKeyA = crypto.randomBytes(32);
    const pubKeyB = crypto.randomBytes(32);
    store.trust(nodeId, pubKeyA);
    const result = store.check(nodeId, pubKeyB);
    assert.strictEqual(result, 'CONFLICT', 'MITM attack undetected — returned TRUSTED instead of CONFLICT');
    pass('TEST_TOFU_03');
} catch (e) {
    fail('TEST_TOFU_03', `CONFLICT not detected for different key — MITM attack undetected: ${e.message}`, TOFU_PATH + ':1');
}

// TEST_TOFU_04
try {
    const store = freshStore();
    const nodeId = crypto.randomBytes(32);
    const pubKeyA = crypto.randomBytes(32);
    const pubKeyB = crypto.randomBytes(32);
    store.trust(nodeId, pubKeyA);

    const logs = [];
    const origWarn = console.warn;
    const origLog = console.log;
    console.warn = (...args) => logs.push(args.join(' '));
    console.log = (...args) => logs.push(args.join(' '));

    store.check(nodeId, pubKeyB);

    console.warn = origWarn;
    console.log = origLog;

    const allLogs = logs.join('\n').toLowerCase();
    const hasWarning = allLogs.includes('tofu conflict') || allLogs.includes('conflict') || allLogs.includes('mitm');
    assert.ok(hasWarning, `Expected TOFU CONFLICT or MITM in logs, got: ${logs.join('|')}`);
    pass('TEST_TOFU_04');
} catch (e) {
    fail('TEST_TOFU_04', `CONFLICT not logged with security warning: ${e.message}`, TOFU_PATH + ':1');
}

// TEST_TOFU_05
try {
    const store = freshStore();
    const nodeId = crypto.randomBytes(32);
    const pubKeyA = crypto.randomBytes(32);
    const pubKeyB = crypto.randomBytes(32);
    store.trust(nodeId, pubKeyA);
    // Should not throw
    store.check(nodeId, pubKeyB);
    pass('TEST_TOFU_05');
} catch (e) {
    fail('TEST_TOFU_05', `CONFLICT caused a crash: ${e.message}`, TOFU_PATH + ':1');
}

// TEST_TOFU_06
(async () => {
    try {
        const tfile = path.join(tmpDir, `trust_persist_${Date.now()}.json`);
        const store1 = new TofuStore(tfile);
        const nodeId = crypto.randomBytes(32);
        const pubKey = crypto.randomBytes(32);
        store1.trust(nodeId, pubKey);
        if (typeof store1.save === 'function') {
            await store1.save();
        } else {
            fail('TEST_TOFU_06', 'store.save() not implemented', TOFU_PATH + ':1');
            return;
        }
        const store2 = new TofuStore(tfile);
        if (typeof store2.load === 'function') {
            await store2.load();
        }
        const result = store2.check(nodeId, pubKey);
        assert.strictEqual(result, 'TRUSTED');
        pass('TEST_TOFU_06');
    } catch (e) {
        fail('TEST_TOFU_06', `trust.json persistence failed: ${e.message}`, TOFU_PATH + ':1');
    }
})();

// TEST_TOFU_07
try {
    const src = fs.readFileSync(TOFU_PATH, 'utf8');
    assert.ok(src.includes('timingSafeEqual'), 'source must use timingSafeEqual in check()');
    pass('TEST_TOFU_07');
} catch (e) {
    fail('TEST_TOFU_07', `timingSafeEqual not found — timing side-channel on key comparison: ${e.message}`, TOFU_PATH + ':1');
}

// TEST_TOFU_08
try {
    const store = freshStore();
    const nodeId = crypto.randomBytes(32);
    const pubKey = crypto.randomBytes(32);
    store.trust(nodeId, pubKey);

    if (typeof store.revoke !== 'function') {
        fail('TEST_TOFU_08', 'store.revoke() method not implemented', TOFU_PATH + ':1');
    } else {
        store.revoke(nodeId);
        const result = store.check(nodeId, pubKey);
        assert.strictEqual(result, 'NEW');
        pass('TEST_TOFU_08');
    }
} catch (e) {
    fail('TEST_TOFU_08', `revoke() failed: ${e.message}`, TOFU_PATH + ':1');
}
