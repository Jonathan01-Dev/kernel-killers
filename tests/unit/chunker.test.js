// c:\Users\PC LBS\kernel-killers\tests\unit\chunker.test.js
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

const CHUNKER_PATH = path.resolve(__dirname, '../../src/transfer/chunker.js');
if (!fs.existsSync(CHUNKER_PATH)) {
    fail('MODULE_MISSING', 'src/transfer/chunker.js does not exist', CHUNKER_PATH + ':1');
    process.exit(1);
}

let CHUNK_SIZE, chunkFile, readChunk, verifyChunk;
try {
    ({ CHUNK_SIZE, chunkFile, readChunk, verifyChunk } = require(CHUNKER_PATH));
} catch (e) {
    fail('MODULE_LOAD', `Cannot require chunker.js: ${e.message}`, CHUNKER_PATH + ':1');
    process.exit(1);
}

// ─── create test files ────────────────────────────────────────────────────────
const SMALL_PATH = path.join(os.tmpdir(), 'test_small.bin');
const EXACT_PATH = path.join(os.tmpdir(), 'test_exact.bin');
const MULTI_PATH = path.join(os.tmpdir(), 'test_multi.bin');

function mkFile(fpath, sizeBytes) {
    const buf = crypto.randomBytes(Math.min(sizeBytes, 65536));
    const fd = fs.openSync(fpath, 'w');
    let written = 0;
    while (written < sizeBytes) {
        const toWrite = Math.min(buf.length, sizeBytes - written);
        fs.writeSync(fd, buf, 0, toWrite, written);
        written += toWrite;
    }
    fs.closeSync(fd);
}

mkFile(SMALL_PATH, 100 * 1024);        // 100KB
mkFile(EXACT_PATH, 512 * 1024);        // 512KB
mkFile(MULTI_PATH, 2 * 1024 * 1024);   // 2MB

// Large test only if TEST_LARGE=true
const LARGE_PATH = path.join(os.tmpdir(), 'test_50mb.bin');
if (process.env.TEST_LARGE === 'true') {
    mkFile(LARGE_PATH, 50 * 1024 * 1024);
}

// TEST_CHK_01
try {
    assert.strictEqual(CHUNK_SIZE, 524288, `CHUNK_SIZE must be 524288 (512*1024), got ${CHUNK_SIZE}`);
    pass('TEST_CHK_01');
} catch (e) {
    fail('TEST_CHK_01', `CHUNK_SIZE is not 524288: ${e.message}`, CHUNKER_PATH + ':7');
}

// Run async tests
(async () => {
    // TEST_CHK_02
    try {
        const result = await chunkFile(MULTI_PATH);
        assert.strictEqual(result.nbChunks, 4);
        pass('TEST_CHK_02');
    } catch (e) {
        fail('TEST_CHK_02', `nbChunks wrong for 2MB file: ${e.message}`, CHUNKER_PATH + ':12');
    }

    // TEST_CHK_03
    try {
        const result = await chunkFile(SMALL_PATH);
        assert.strictEqual(result.chunks[0].size, 100 * 1024);
        pass('TEST_CHK_03');
    } catch (e) {
        fail('TEST_CHK_03', `Last chunk size wrong for small file: ${e.message}`, CHUNKER_PATH + ':33');
    }

    // TEST_CHK_04
    try {
        const result = await chunkFile(SMALL_PATH);
        const expected = crypto.createHash('sha256').update(fs.readFileSync(SMALL_PATH)).digest('hex');
        assert.strictEqual(result.fileId, expected);
        pass('TEST_CHK_04');
    } catch (e) {
        fail('TEST_CHK_04', `fileId SHA-256 mismatch: ${e.message}`, CHUNKER_PATH + ':16');
    }

    // TEST_CHK_05
    try {
        const result = await chunkFile(SMALL_PATH);
        for (const chunk of result.chunks) {
            const data = await readChunk(SMALL_PATH, chunk.index);
            const ok = await verifyChunk(data, chunk.hash);
            assert.strictEqual(ok, true, `chunk ${chunk.index} hash verification failed`);
        }
        pass('TEST_CHK_05');
    } catch (e) {
        fail('TEST_CHK_05', `Chunk hash mismatch: ${e.message}`, CHUNKER_PATH + ':47');
    }

    // TEST_CHK_06
    try {
        const result = await chunkFile(SMALL_PATH);
        const data = await readChunk(SMALL_PATH, 0);
        const corrupted = Buffer.from(data);
        corrupted[0] ^= 0xFF;
        const ok = await verifyChunk(corrupted, result.chunks[0].hash);
        assert.strictEqual(ok, false);
        pass('TEST_CHK_06');
    } catch (e) {
        fail('TEST_CHK_06', `verifyChunk returned true on corrupted data: ${e.message}`, CHUNKER_PATH + ':67');
    }

    // TEST_CHK_07
    try {
        const src = fs.readFileSync(CHUNKER_PATH, 'utf8');
        // readChunk should use fd.read / fs.open, not readFileSync/readFile for the whole file
        const readChunkFnMatch = src.match(/async function readChunk[\s\S]+?^}/m);
        assert.ok(readChunkFnMatch, 'readChunk function not found in source');
        const fnBody = readChunkFnMatch[0];
        const usesStreaming = fnBody.includes('fs.open') || fnBody.includes("fs/promises") || fnBody.includes('fd.read') || fnBody.includes('.open(') || fnBody.includes('.read(');
        assert.ok(usesStreaming, 'readChunk must use fs.open/fd.read, not load full file');
        // Ensure no readFileSync for full file in readChunk
        const hasFullFileRead = fnBody.includes('readFileSync') && !fnBody.includes('readFileSync(filePath');
        assert.ok(!hasFullFileRead, 'readChunk must not use readFileSync for full file');
        pass('TEST_CHK_07');
    } catch (e) {
        fail('TEST_CHK_07', `readChunk memory usage concern: ${e.message}`, CHUNKER_PATH + ':47');
    }

    // TEST_CHK_08
    try {
        const result = await chunkFile(MULTI_PATH);
        const parts = [];
        for (const chunk of result.chunks) {
            parts.push(await readChunk(MULTI_PATH, chunk.index));
        }
        const reassembled = Buffer.concat(parts);
        const sha = crypto.createHash('sha256').update(reassembled).digest('hex');
        assert.strictEqual(sha, result.fileId);
        pass('TEST_CHK_08');
    } catch (e) {
        fail('TEST_CHK_08', `Reassembled file SHA-256 mismatch: ${e.message}`, CHUNKER_PATH + ':25');
    }

    // TEST_CHK_09
    try {
        const result = await chunkFile(SMALL_PATH);
        assert.ok(typeof result.fileId === 'string', 'fileId must be string');
        assert.ok(typeof result.filename === 'string', 'filename must be string');
        assert.ok(typeof result.size === 'number', 'size must be number');
        assert.ok(typeof result.nbChunks === 'number', 'nbChunks must be number');
        assert.ok(Array.isArray(result.chunks), 'chunks must be array');
        for (const c of result.chunks) {
            assert.ok(typeof c.index === 'number', 'chunk.index must be number');
            assert.ok(typeof c.hash === 'string', 'chunk.hash must be string');
            assert.ok(typeof c.size === 'number', 'chunk.size must be number');
            assert.ok(typeof c.offset === 'number', 'chunk.offset must be number');
        }
        pass('TEST_CHK_09');
    } catch (e) {
        fail('TEST_CHK_09', `Manifest-compatible shape assertion failed: ${e.message}`, CHUNKER_PATH + ':44');
    }

    // cleanup
    [SMALL_PATH, EXACT_PATH, MULTI_PATH].forEach(p => { try { fs.unlinkSync(p); } catch { } });
    if (process.env.TEST_LARGE === 'true') { try { fs.unlinkSync(LARGE_PATH); } catch { } }

})().catch(e => {
    fail('CHUNKER_SUITE_CRASH', e.message, CHUNKER_PATH + ':1');
    process.exit(1);
});
