// c:\Users\PC LBS\kernel-killers\tests\run-all.js
'use strict';

const { execSync } = require('child_process');

const suites = [
    'tests/unit/packet.test.js',
    'tests/unit/identity.test.js',
    'tests/unit/session.test.js',
    'tests/unit/tofu.test.js',
    'tests/unit/chunker.test.js',
    'tests/unit/manifest.test.js',
    'tests/integration/discovery.test.js',
    'tests/integration/tcp.test.js',
    'tests/integration/e2e.test.js',
    'tests/security/crypto.test.js',
];

let totalPass = 0;
let totalFail = 0;
const failures = [];

for (const suite of suites) {
    try {
        const output = execSync(`node ${suite}`, { timeout: 120000, cwd: require('path').resolve(__dirname, '..') }).toString();
        const passes = (output.match(/\[PASS\]/g) || []).length;
        const fails = (output.match(/\[FAIL\]/g) || []).length;
        totalPass += passes;
        totalFail += fails;
        if (fails > 0) failures.push({ suite, output });
        console.log(output);
    } catch (e) {
        totalFail++;
        failures.push({ suite, output: e.stdout?.toString() || e.message });
        console.log(`[FAIL] ${suite} — CRASHED: ${e.message}`);
    }
}

console.log('\n' + '='.repeat(60));
console.log(`ARCHIPEL TEST REPORT`);
console.log('='.repeat(60));
console.log(`TOTAL PASS : ${totalPass}`);
console.log(`TOTAL FAIL : ${totalFail}`);
const total = totalPass + totalFail;
console.log(`SCORE      : ${total > 0 ? Math.round(totalPass / total * 100) : 0}%`);

if (failures.length > 0) {
    console.log('\n--- FAILURES TO FIX ---');
    failures.forEach(f => console.log(`\n[SUITE] ${f.suite}\n${f.output}`));
} else {
    console.log('\n✓ ALL TESTS PASSED — Prototype is demo-ready');
}

process.exit(totalFail > 0 ? 1 : 0);
