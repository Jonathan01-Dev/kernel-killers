// c:\Users\PC LBS\kernel-killers\src\transfer\manifest.js
const sodium = require('libsodium-wrappers');
const crypto = require('crypto');

async function buildManifest(chunkResult, myIdentity) {
    await sodium.ready;

    // Build JSON excluding signature
    const manifestDict = {
        file_id: chunkResult.fileId,
        filename: chunkResult.filename,
        size: chunkResult.size,
        chunk_size: 524288,
        nb_chunks: chunkResult.nbChunks,
        chunks: chunkResult.chunks.map(c => ({ index: c.index, hash: c.hash, size: c.size })),
        sender_id: Buffer.from(myIdentity.publicKey).toString('hex')
    };

    const jsonStr = JSON.stringify(manifestDict);
    const hashToSign = crypto.createHash('sha256').update(jsonStr).digest();

    const sig = Buffer.from(sodium.crypto_sign_detached(hashToSign, myIdentity.privateKey)).toString('hex');
    manifestDict.signature = sig;

    return manifestDict;
}

async function verifyManifest(manifest, senderPublicKeyHex) {
    await sodium.ready;

    const manifestCopy = { ...manifest };
    const sigHex = manifestCopy.signature;
    delete manifestCopy.signature;

    if (!sigHex) return false;

    const jsonStr = JSON.stringify(manifestCopy);
    const hashToSign = crypto.createHash('sha256').update(jsonStr).digest();

    const pkBuffer = Buffer.from(senderPublicKeyHex, 'hex');
    const sigBuffer = Buffer.from(sigHex, 'hex');

    return sodium.crypto_sign_verify_detached(sigBuffer, hashToSign, pkBuffer);
}

function encodeManifest(manifest) {
    return Buffer.from(JSON.stringify(manifest), 'utf8');
}

function decodeManifest(buffer) {
    return JSON.parse(buffer.toString('utf8'));
}

module.exports = { buildManifest, verifyManifest, encodeManifest, decodeManifest };
