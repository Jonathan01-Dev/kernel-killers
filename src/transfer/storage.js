// c:\Users\PC LBS\kernel-killers\src\transfer\storage.js
const fs = require('fs/promises');
const path = require('path');

const STORAGE_DIR = path.join(process.cwd(), '.archipel');
const CHUNKS_DIR = path.join(STORAGE_DIR, 'chunks');
const MANIFESTS_DIR = path.join(STORAGE_DIR, 'manifests');

async function saveChunk(fileId, index, data) {
    const dir = path.join(CHUNKS_DIR, fileId);
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(path.join(dir, `${index}.chunk`), data);
}

async function loadChunk(fileId, index) {
    try {
        const filePath = path.join(CHUNKS_DIR, fileId, `${index}.chunk`);
        return await fs.readFile(filePath);
    } catch (err) {
        if (err.code === 'ENOENT') return null;
        throw err;
    }
}

async function hasChunk(fileId, index) {
    try {
        const filePath = path.join(CHUNKS_DIR, fileId, `${index}.chunk`);
        await fs.access(filePath);
        return true;
    } catch {
        return false;
    }
}

async function listLocalChunks(fileId) {
    const dir = path.join(CHUNKS_DIR, fileId);
    try {
        const files = await fs.readdir(dir);
        return files
            .filter(f => f.endsWith('.chunk'))
            .map(f => parseInt(f.replace('.chunk', ''), 10))
            .sort((a, b) => a - b);
    } catch (err) {
        if (err.code === 'ENOENT') return [];
        throw err;
    }
}

async function saveManifest(manifest) {
    await fs.mkdir(MANIFESTS_DIR, { recursive: true });
    const filePath = path.join(MANIFESTS_DIR, `${manifest.file_id}.json`);
    await fs.writeFile(filePath, JSON.stringify(manifest, null, 2));
}

async function loadManifest(fileId) {
    try {
        const filePath = path.join(MANIFESTS_DIR, `${fileId}.json`);
        const data = await fs.readFile(filePath, 'utf8');
        return JSON.parse(data);
    } catch (err) {
        if (err.code === 'ENOENT') return null;
        throw err;
    }
}

module.exports = {
    STORAGE_DIR,
    saveChunk,
    loadChunk,
    hasChunk,
    listLocalChunks,
    saveManifest,
    loadManifest
};
