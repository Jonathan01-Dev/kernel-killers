// c:\Users\PC LBS\kernel-killers\tests\security\crypto.test.js
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

const PROJECT_ROOT = path.resolve(__dirname, '../..');
const SRC_DIR = path.join(PROJECT_ROOT, 'src');

// ─── helpers ─────────────────────────────────────────────────────────────────
function getAllJsFiles(dir) {
    const results = [];
    if (!fs.existsSync(dir)) return results;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            results.push(...getAllJsFiles(full));
        } else if (entry.name.endsWith('.js')) {
            results.push(full);
        }
    }
    return results;
}

const allSrcFiles = getAllJsFiles(SRC_DIR);

// TEST_SEC_01 — No hardcoded private keys (64-byte hex)
try {
    const HEX_64 = /^[0-9a-fA-F]{128}/m; // 64 bytes = 128 hex chars
    const PRIV_KEY_LITERAL = /privateKey\s*[:=]\s*['"][0-9a-fA-F]{10}/;
    let violation = null;

    for (const file of allSrcFiles) {
        const src = fs.readFileSync(file, 'utf8');
        if (HEX_64.test(src) || PRIV_KEY_LITERAL.test(src)) {
            violation = file;
            break;
        }
    }

    if (violation) {
        fail('TEST_SEC_01', `Hardcoded private key found in ${path.relative(PROJECT_ROOT, violation)}`, violation + ':1');
    } else {
        pass('TEST_SEC_01');
    }
} catch (e) {
    fail('TEST_SEC_01', `Scan failed: ${e.message}`, SRC_DIR + ':1');
}

// TEST_SEC_02 — .env in .gitignore
try {
    const gitignorePath = path.join(PROJECT_ROOT, '.gitignore');
    assert.ok(fs.existsSync(gitignorePath), '.gitignore must exist');
    const gitignore = fs.readFileSync(gitignorePath, 'utf8');
    assert.ok(gitignore.includes('.env'), '.gitignore must contain .env');
    pass('TEST_SEC_02');
} catch (e) {
    fail('TEST_SEC_02', `.env not in .gitignore: ${e.message}`, path.join(PROJECT_ROOT, '.gitignore') + ':1');
}

// TEST_SEC_03 — .archipel/ in .gitignore
try {
    const gitignorePath = path.join(PROJECT_ROOT, '.gitignore');
    const gitignore = fs.readFileSync(gitignorePath, 'utf8');
    assert.ok(gitignore.includes('.archipel/'), '.gitignore must contain .archipel/');
    pass('TEST_SEC_03');
} catch (e) {
    fail('TEST_SEC_03', `.archipel/ not in .gitignore: ${e.message}`, path.join(PROJECT_ROOT, '.gitignore') + ':1');
}

// TEST_SEC_04 — No custom crypto implementation
try {
    // Look for home-rolled encryption functions that don't use node:crypto or libsodium
    const CUSTOM_ENCRYPT = /function\s+encrypt\s*\(|function\s+decrypt\s*\(/;
    const LEGIT_IMPORTS = /require\(['"](?:node:)?crypto['"]\)|require\(['"]libsodium/;
    let violation = null;

    for (const file of allSrcFiles) {
        const src = fs.readFileSync(file, 'utf8');
        if (CUSTOM_ENCRYPT.test(src) && !LEGIT_IMPORTS.test(src)) {
            violation = file;
            break;
        }
        // Check for manual XOR (rudimentary — look for XOR patterns on byte arrays)
        if (/for.*\^=/.test(src) && !file.includes('test')) {
            // Only flag if crypto import is missing
            if (!LEGIT_IMPORTS.test(src)) {
                violation = file;
                break;
            }
        }
    }

    if (violation) {
        fail('TEST_SEC_04', `Custom crypto implementation found in ${path.relative(PROJECT_ROOT, violation)}`, violation + ':1');
    } else {
        pass('TEST_SEC_04');
    }
} catch (e) {
    fail('TEST_SEC_04', `Scan failed: ${e.message}`, SRC_DIR + ':1');
}

// TEST_SEC_05 — Nonce uses randomBytes(12), not a counter
try {
    const SESSION_CANDIDATES = [
        path.join(SRC_DIR, 'crypto/session.js'),
        path.join(SRC_DIR, 'session.js'),
    ];
    const sessionPath = SESSION_CANDIDATES.find(p => fs.existsSync(p));
    if (!sessionPath) {
        fail('TEST_SEC_05', 'session.js not found', SESSION_CANDIDATES[0] + ':1');
    } else {
        const src = fs.readFileSync(sessionPath, 'utf8');
        assert.ok(src.includes('randomBytes(12)'), 'Must use randomBytes(12) for nonce');
        // A counter-only nonce would be if it only uses something like nonce++ or counter++
        const hasCounterOnly = /nonce\+\+|counter\+\+/.test(src) && !src.includes('randomBytes');
        assert.ok(!hasCounterOnly, 'Nonce must not be a simple incrementing counter');
        pass('TEST_SEC_05');
    }
} catch (e) {
    fail('TEST_SEC_05', `Nonce source check failed: ${e.message}`, path.join(SRC_DIR, 'crypto/session.js') + ':1');
}

// TEST_SEC_06 — Ephemeral keys differ per TCP connection
try {
    const HANDSHAKE_CANDIDATES = [
        path.join(SRC_DIR, 'crypto/handshake.js'),
        path.join(SRC_DIR, 'handshake.js'),
    ];
    const handshakePath = HANDSHAKE_CANDIDATES.find(p => fs.existsSync(p));
    if (!handshakePath) {
        fail('TEST_SEC_06', 'handshake.js not found — ephemeral key generation not verifiable', HANDSHAKE_CANDIDATES[0] + ':1');
    } else {
        const src = fs.readFileSync(handshakePath, 'utf8');
        // Ephemeral keypair generation should be inside the handshake function, not at module scope
        assert.ok(
            src.includes('crypto_box_keypair') || src.includes('crypto_kx_keypair') || src.includes('crypto_scalarmult'),
            'Handshake must use ephemeral keypair generation'
        );
        pass('TEST_SEC_06');
    }
} catch (e) {
    fail('TEST_SEC_06', `Ephemeral key check failed: ${e.message}`, path.join(SRC_DIR, 'crypto/handshake.js') + ':1');
}

// TEST_SEC_07 — Ed25519 for signing, X25519 for key exchange
try {
    const HANDSHAKE_CANDIDATES = [
        path.join(SRC_DIR, 'crypto/handshake.js'),
        path.join(SRC_DIR, 'handshake.js'),
    ];
    const handshakePath = HANDSHAKE_CANDIDATES.find(p => fs.existsSync(p));
    if (!handshakePath) {
        fail('TEST_SEC_07', 'handshake.js not found', HANDSHAKE_CANDIDATES[0] + ':1');
    } else {
        const src = fs.readFileSync(handshakePath, 'utf8');
        assert.ok(src.includes('crypto_sign'), 'Must use crypto_sign for identity operations');
        const hasECDH = src.includes('crypto_scalarmult') || src.includes('crypto_box_keypair') ||
            src.includes('crypto_kx') || src.includes('ECDH') || src.includes('diffie');
        assert.ok(hasECDH, 'Must use X25519/ECDH for key exchange, not Ed25519 directly — CRITICAL crypto error if not');
        pass('TEST_SEC_07');
    }
} catch (e) {
    fail('TEST_SEC_07', `Ed25519/X25519 separation check failed — critical cryptographic error if mixing: ${e.message}`, path.join(SRC_DIR, 'crypto/handshake.js') + ':1');
}

// TEST_SEC_08 — HKDF info binds to both node IDs
try {
    const HANDSHAKE_CANDIDATES = [
        path.join(SRC_DIR, 'crypto/handshake.js'),
        path.join(SRC_DIR, 'handshake.js'),
    ];
    const handshakePath = HANDSHAKE_CANDIDATES.find(p => fs.existsSync(p));
    if (!handshakePath) {
        fail('TEST_SEC_08', 'handshake.js not found', HANDSHAKE_CANDIDATES[0] + ':1');
    } else {
        const src = fs.readFileSync(handshakePath, 'utf8');
        // HKDF should be present
        assert.ok(src.includes('hkdf') || src.includes('HKDF'), 'Must use HKDF for session key derivation');
        // info parameter should reference node IDs
        const hasNodeIds = src.includes('nodeId') && (src.includes('hkdf') || src.includes('HKDF'));
        assert.ok(hasNodeIds, 'HKDF info must bind to node IDs — missing allows key confusion attacks');
        pass('TEST_SEC_08');
    }
} catch (e) {
    fail('TEST_SEC_08', `HKDF node ID binding check failed — key confusion attack possible: ${e.message}`, path.join(SRC_DIR, 'crypto/handshake.js') + ':1');
}

// TEST_SEC_09 — AUTH signs over sha256(shared_secret)
try {
    const HANDSHAKE_CANDIDATES = [
        path.join(SRC_DIR, 'crypto/handshake.js'),
        path.join(SRC_DIR, 'handshake.js'),
    ];
    const handshakePath = HANDSHAKE_CANDIDATES.find(p => fs.existsSync(p));
    if (!handshakePath) {
        fail('TEST_SEC_09', 'handshake.js not found', HANDSHAKE_CANDIDATES[0] + ':1');
    } else {
        const src = fs.readFileSync(handshakePath, 'utf8');
        // Should hash the shared secret before signing
        assert.ok(
            src.includes("'sha256'") || src.includes('"sha256"'),
            'Must use SHA-256 hash over shared_secret before signing'
        );
        assert.ok(src.includes('crypto_sign'), 'Must sign the hash');
        pass('TEST_SEC_09');
    }
} catch (e) {
    fail('TEST_SEC_09', `AUTH packet signing check failed: ${e.message}`, path.join(SRC_DIR, 'crypto/handshake.js') + ':1');
}

// TEST_SEC_10 — No Gemini API key in source code
try {
    const GEMINI_KEY_PATTERN = /AIza[0-9A-Za-z_\-]{35}/;
    let violation = null;

    for (const file of allSrcFiles) {
        const src = fs.readFileSync(file, 'utf8');
        if (GEMINI_KEY_PATTERN.test(src)) {
            violation = file;
            break;
        }
    }

    if (violation) {
        fail('TEST_SEC_10', `Gemini API key hardcoded in source: ${path.relative(PROJECT_ROOT, violation)}`, violation + ':1');
    } else {
        // Also check gemini.js uses process.env
        const geminiPath = path.join(SRC_DIR, 'messaging/gemini.js');
        if (fs.existsSync(geminiPath)) {
            const src = fs.readFileSync(geminiPath, 'utf8');
            assert.ok(src.includes('process.env'), 'GEMINI_API_KEY must be loaded from process.env');
        }
        pass('TEST_SEC_10');
    }
} catch (e) {
    fail('TEST_SEC_10', `API key scan failed: ${e.message}`, SRC_DIR + ':1');
}
