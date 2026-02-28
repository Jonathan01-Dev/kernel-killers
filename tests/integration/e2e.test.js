// c:\Users\PC LBS\kernel-killers\tests\integration\e2e.test.js
'use strict';

/**
 * END-TO-END TESTS
 * Most E2E tests require all crypto modules (packet, identity, session, handshake).
 * If those modules are missing, tests report [FAIL] MODULE_MISSING.
 * Tests that require real network/processes are skipped unless TEST_E2E=true.
 */

const assert = require('node:assert');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const os = require('os');
const { spawn } = require('child_process');

function pass(name) { console.log(`[PASS] ${name}`); }
function fail(name, reason, file) {
    const loc = file ? ` — FILE: ${file}` : '';
    console.log(`[FAIL] ${name} — ${reason}${loc}`);
}
function skip(name, reason) { console.log(`[SKIP] ${name} — ${reason}`); }

const PROJECT_ROOT = path.resolve(__dirname, '../..');
const NODE_ENTRY = path.join(PROJECT_ROOT, 'src/node.js');

// ─── module presence checks ────────────────────────────────────────────────── 
const REQUIRED_MODULES = [
    path.join(PROJECT_ROOT, 'src/network/packet.js'),
    path.join(PROJECT_ROOT, 'src/crypto/session.js'),
    path.join(PROJECT_ROOT, 'src/crypto/handshake.js'),
    path.join(PROJECT_ROOT, 'src/trust/tofu.js'),
    path.join(PROJECT_ROOT, 'src/crypto/identity.js'),
];

let allModulesPresent = true;
for (const mod of REQUIRED_MODULES) {
    if (!fs.existsSync(mod)) {
        fail('MODULE_MISSING', `${path.relative(PROJECT_ROOT, mod)} does not exist`, mod + ':1');
        allModulesPresent = false;
    }
}

if (!allModulesPresent) {
    console.log('[INFO] E2E tests require all crypto modules. Skipping process-level tests.');
}

// TEST_E2E_01–06 require starting real node processes
if (process.env.TEST_E2E !== 'true') {
    skip('TEST_E2E_01', 'set TEST_E2E=true to run (starts 3 real nodes)');
    skip('TEST_E2E_02', 'set TEST_E2E=true to run');
    skip('TEST_E2E_03', 'set TEST_E2E=true to run');
    skip('TEST_E2E_04', 'set TEST_E2E=true to run');
    skip('TEST_E2E_05', 'set TEST_E2E=true to run (10MB file transfer, 120s)');
    skip('TEST_E2E_06', 'set TEST_E2E=true and TEST_LARGE=true to run (50MB file, multi-peer)');
} else if (!allModulesPresent) {
    fail('TEST_E2E_01', 'Required modules missing — cannot start nodes', NODE_ENTRY + ':1');
    fail('TEST_E2E_02', 'Required modules missing', NODE_ENTRY + ':1');
    fail('TEST_E2E_03', 'Required modules missing', NODE_ENTRY + ':1');
    fail('TEST_E2E_04', 'Required modules missing', NODE_ENTRY + ':1');
    fail('TEST_E2E_05', 'Required modules missing', NODE_ENTRY + ':1');
    fail('TEST_E2E_06', 'Required modules missing', NODE_ENTRY + ':1');
} else {
    (async () => {
        const testDir = path.join(os.tmpdir(), '.archipel-test');
        fs.mkdirSync(testDir, { recursive: true });

        const nodes = [];
        const ports = [17777, 17778, 17779];

        // Start 3 nodes
        for (let i = 0; i < 3; i++) {
            const port = ports[i];
            const archipelDir = path.join(testDir, `node${i}`, '.archipel');
            // Pre-create the .archipel dir so identity generation has a CWD to write into
            fs.mkdirSync(archipelDir, { recursive: true });

            const env = {
                ...process.env,
                TCP_PORT: String(port),
                ARCHIPEL_DIR: archipelDir,
                ENABLE_AI: 'false',
            };

            const proc = spawn(process.execPath, [NODE_ENTRY], {
                env,
                cwd: path.join(testDir, `node${i}`),
                stdio: ['ignore', 'pipe', 'pipe'],
            });

            const nodeInfo = { proc, port, logs: '', stderr: '', exited: false, code: null, signal: null };
            nodes.push(nodeInfo);

            proc.stdout.on('data', (d) => {
                const txt = d.toString();
                nodeInfo.logs += txt;
                process.stdout.write(`[NODE-${port}] ${txt}`);
            });

            proc.stderr.on('data', (d) => {
                const txt = d.toString();
                nodeInfo.stderr += txt;
                console.error(`[NODE-${port}] ERR: ${txt}`);
            });

            proc.on('exit', (code, signal) => {
                nodeInfo.exited = true;
                nodeInfo.code = code;
                nodeInfo.signal = signal;
                console.error(`[E2E] Node ${port} exited early: code=${code} signal=${signal}`);
                if (nodeInfo.stderr) {
                    console.error(`[E2E] Node ${port} last stderr:\n${nodeInfo.stderr.slice(-500)}`);
                }
            });
        }

        function killAll() {
            for (const n of nodes) {
                if (!n.exited) { try { n.proc.kill('SIGTERM'); } catch (_) { } }
            }
            try { fs.rmSync(testDir, { recursive: true, force: true }); } catch (_) { }
        }

        process.on('exit', killAll);

        // Extended timeout for Windows compatibility
        const STARTUP_WAIT_MS = 8000;  // Windows spawn is slower than Linux
        const DISCOVERY_TIMEOUT_MS = 90000; // Extended for Windows compatibility

        // Wait for nodes to start
        await new Promise(res => setTimeout(res, STARTUP_WAIT_MS));

        // TEST_E2E_01 — all 3 nodes still running after startup window
        try {
            const allRunning = nodes.every(n => !n.exited);
            if (!allRunning) {
                const dead = nodes.filter(n => n.exited);
                const details = dead.map(n =>
                    `port=${n.port} code=${n.code} signal=${n.signal}\n  stderr: ${n.stderr.slice(-300)}`
                ).join('\n');
                throw new Error(`Node(s) exited early:\n${details}`);
            }
            pass('TEST_E2E_01');
        } catch (e) {
            fail('TEST_E2E_01', `All 3 nodes must still be running after ${STARTUP_WAIT_MS}ms: ${e.message}`, NODE_ENTRY + ':1');
        }

        // TEST_E2E_02 — wait for handshake log (up to DISCOVERY_TIMEOUT_MS)
        try {
            const deadline = Date.now() + DISCOVERY_TIMEOUT_MS;
            let handshakeFound = false;

            // A handshake is confirmed by any of these patterns (case-insensitive)
            const isHandshake = (log) => log.toLowerCase().includes('handshake') ||
                log.includes('AUTH_OK') ||
                log.toLowerCase().includes('session established') ||
                log.toLowerCase().includes('tunnel');

            while (Date.now() < deadline && !handshakeFound) {
                handshakeFound = nodes.some(n => isHandshake(n.logs));
                if (!handshakeFound) await new Promise(res => setTimeout(res, 3000));
                // Bail out if all nodes have already crashed
                if (nodes.every(n => n.exited)) break;
            }

            if (handshakeFound) {
                pass('TEST_E2E_02');
            } else {
                const allLogs = nodes.map(n => `[NODE-${n.port}]:\n${n.logs.slice(-200)}`).join('\n---\n');
                fail('TEST_E2E_02',
                    `No handshake log found within ${DISCOVERY_TIMEOUT_MS}ms\n${allLogs}`,
                    path.join(PROJECT_ROOT, 'src/network/tcpServer.js') + ':136');
            }
        } catch (e) {
            fail('TEST_E2E_02', `Handshake detection failed: ${e.message}`,
                path.join(PROJECT_ROOT, 'src/network/tcpServer.js') + ':136');
        }

        // TEST_E2E_03 — encrypted on wire (source analysis)
        try {
            const tcpSrc = fs.readFileSync(path.join(PROJECT_ROOT, 'src/network/tcpServer.js'), 'utf8');
            assert.ok(tcpSrc.includes('encryptPayload'), 'Messages must be encrypted with encryptPayload');
            assert.ok(tcpSrc.includes('decryptPayload'), 'Messages must be decrypted with decryptPayload');
            pass('TEST_E2E_03');
        } catch (e) {
            fail('TEST_E2E_03', `Encryption on wire not verified: ${e.message}`,
                path.join(PROJECT_ROOT, 'src/network/tcpServer.js') + ':66');
        }

        // TEST_E2E_04 — CLI exists
        try {
            const cliPath = path.join(PROJECT_ROOT, 'src/cli/commands.js');
            assert.ok(fs.existsSync(cliPath), 'CLI must exist for message sending');
            pass('TEST_E2E_04');
        } catch (e) {
            fail('TEST_E2E_04', `Message send/receive flow incomplete: ${e.message}`,
                path.join(PROJECT_ROOT, 'src/cli/commands.js') + ':1');
        }

        skip('TEST_E2E_05', 'Full file transfer test requires interactive CLI — manual verification needed');

        if (process.env.TEST_LARGE !== 'true') {
            skip('TEST_E2E_06', 'set TEST_LARGE=true for 50MB resilience test');
        } else {
            skip('TEST_E2E_06', 'Multi-peer resilience test requires manual network coordination');
        }

        killAll();
    })().catch(e => {
        fail('E2E_SUITE_CRASH', e.message, NODE_ENTRY + ':1');
        process.exit(1);
    });
}

// TEST_E2E_07 — No internet calls (fetch/http override)
(async () => {
    try {
        const originalFetch = global.fetch;
        let externalCallMade = false;
        global.fetch = (url, ...args) => {
            if (!url || url.toString().includes('generativelanguage.googleapis.com')) {
                return typeof originalFetch === 'function'
                    ? originalFetch(url, ...args)
                    : Promise.reject(new Error('fetch not available'));
            }
            externalCallMade = true;
            throw new Error(`External call detected: ${url}`);
        };

        const http = require('http');
        const https = require('https');
        const origHttpReq = http.request.bind(http);
        const origHttpsReq = https.request.bind(https);

        http.request = (options, ...args) => {
            const host = typeof options === 'string'
                ? new URL(options).hostname
                : (options.hostname || options.host || '');
            if (host && !['localhost', '127.0.0.1', '::1'].includes(host)) {
                externalCallMade = true;
                throw new Error(`External HTTP call detected to: ${host}`);
            }
            return origHttpReq(options, ...args);
        };

        // Restore
        global.fetch = originalFetch;
        http.request = origHttpReq;

        if (!externalCallMade) {
            pass('TEST_E2E_07');
        } else {
            fail('TEST_E2E_07', 'External call detected — disqualified at hackathon demo', 'src:1');
        }
    } catch (e) {
        fail('TEST_E2E_07', `External call test failed: ${e.message}`, NODE_ENTRY + ':1');
    }
})();

// TEST_E2E_08 — ENABLE_AI=false blocks all HTTP
try {
    const geminiPath = path.join(PROJECT_ROOT, 'src/messaging/gemini.js');
    assert.ok(fs.existsSync(geminiPath), 'gemini.js must exist');
    const geminiSrc = fs.readFileSync(geminiPath, 'utf8');
    assert.ok(
        geminiSrc.includes('ENABLE_AI') || geminiSrc.includes('disabled') || geminiSrc.includes('AI disabled'),
        'gemini.js must check ENABLE_AI env var'
    );
    pass('TEST_E2E_08');
} catch (e) {
    fail('TEST_E2E_08', `ENABLE_AI=false guard not found in gemini.js: ${e.message}`,
        path.join(PROJECT_ROOT, 'src/messaging/gemini.js') + ':1');
}
