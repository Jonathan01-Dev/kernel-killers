// c:\Users\PC LBS\kernel-killers\src\transfer\chunker.js
const fs = require('fs/promises');
const path = require('path');
const crypto = require('crypto');
const { createReadStream } = require('fs');

const CHUNK_SIZE = 512 * 1024; // 512 KB

async function chunkFile(filePath) {
    const stat = await fs.stat(filePath);
    const size = stat.size;
    const nbChunks = Math.ceil(size / CHUNK_SIZE);
    const filename = path.basename(filePath);

    // Compute full file hash using stream
    const fileHashStream = crypto.createHash('sha256');
    const readStream = createReadStream(filePath);

    await new Promise((resolve, reject) => {
        readStream.on('error', reject);
        readStream.pipe(fileHashStream).on('finish', resolve).on('error', reject);
    });
    const fileId = fileHashStream.read().toString('hex');

    const chunks = [];

    // Actually chunking it without full memory load
    // We'll read the chunk hashes
    const fd = await fs.open(filePath, 'r');
    try {
        for (let i = 0; i < nbChunks; i++) {
            const offset = i * CHUNK_SIZE;
            const currentChunkSize = Math.min(CHUNK_SIZE, size - offset);
            const buffer = Buffer.alloc(currentChunkSize);
            await fd.read(buffer, 0, currentChunkSize, offset);

            const hash = crypto.createHash('sha256').update(buffer).digest('hex');
            chunks.push({ index: i, hash, size: currentChunkSize, offset });
        }
    } finally {
        await fd.close();
    }

    return { fileId, filename, size, nbChunks, chunks };
}

async function readChunk(filePath, index) {
    const stat = await fs.stat(filePath);
    const size = stat.size;
    const offset = index * CHUNK_SIZE;

    if (offset >= size) throw new Error('Chunk index out of bounds');

    const currentChunkSize = Math.min(CHUNK_SIZE, size - offset);
    const buffer = Buffer.alloc(currentChunkSize);

    const fd = await fs.open(filePath, 'r');
    try {
        await fd.read(buffer, 0, currentChunkSize, offset);
    } finally {
        await fd.close();
    }

    return buffer;
}

async function verifyChunk(data, expectedHash) {
    const hash = crypto.createHash('sha256').update(data).digest('hex');
    return hash === expectedHash;
}

module.exports = { CHUNK_SIZE, chunkFile, readChunk, verifyChunk };
