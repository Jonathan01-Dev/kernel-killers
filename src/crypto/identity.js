// src/crypto/identity.js
'use strict';

const sodium = require('libsodium-wrappers');
const fs = require('fs');
const path = require('path');

const IDENTITY_PATH = path.resolve(process.cwd(), '.archipel', 'identity.key');

/**
 * generateIdentity()
 * Creates a new Ed25519 keypair if none exists, or returns the existing one.
 * NEVER logs the private key.
 */
async function generateIdentity() {
    await sodium.ready;

    if (fs.existsSync(IDENTITY_PATH)) {
        return loadIdentity();
    }

    const kp = sodium.crypto_sign_keypair();
    const data = JSON.stringify({
        publicKey: Buffer.from(kp.publicKey).toString('hex'),
        privateKey: Buffer.from(kp.privateKey).toString('hex'),
    });

    fs.mkdirSync(path.dirname(IDENTITY_PATH), { recursive: true });
    fs.writeFileSync(IDENTITY_PATH, data, { mode: 0o600 });

    return {
        publicKey: Buffer.from(kp.publicKey),
        privateKey: Buffer.from(kp.privateKey),
    };
}

/**
 * loadIdentity()
 * Reads .archipel/identity.key and returns { publicKey, privateKey } as Buffers.
 * Throws 'IDENTITY_NOT_FOUND' if the file is missing.
 */
async function loadIdentity() {
    if (!fs.existsSync(IDENTITY_PATH)) {
        throw new Error('IDENTITY_NOT_FOUND');
    }

    const raw = fs.readFileSync(IDENTITY_PATH, 'utf8');
    const data = JSON.parse(raw);

    return {
        publicKey: Buffer.from(data.publicKey, 'hex'),
        privateKey: Buffer.from(data.privateKey, 'hex'),
    };
}

module.exports = { generateIdentity, loadIdentity, IDENTITY_PATH };
