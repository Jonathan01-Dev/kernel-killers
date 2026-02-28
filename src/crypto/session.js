// src/crypto/session.js
'use strict';

const crypto = require('node:crypto');

/**
 * encryptPayload(sessionKey, plaintext)
 * Returns: nonce(12) || authTag(16) || ciphertext
 * NEW random nonce on every call — reuse is catastrophic.
 */
function encryptPayload(sessionKey, plaintext) {
    const nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', sessionKey, nonce);

    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag(); // 16 bytes

    return Buffer.concat([nonce, authTag, ciphertext]);
}

/**
 * decryptPayload(sessionKey, encryptedBuffer)
 * Input layout: nonce(12) || authTag(16) || ciphertext
 * Throws Error('DECRYPT_FAILED') on any authentication or decryption failure.
 */
function decryptPayload(sessionKey, encryptedBuffer) {
    try {
        const nonce = encryptedBuffer.slice(0, 12);
        const authTag = encryptedBuffer.slice(12, 28);
        const ciphertext = encryptedBuffer.slice(28);

        const decipher = crypto.createDecipheriv('aes-256-gcm', sessionKey, nonce);
        decipher.setAuthTag(authTag);

        return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } catch {
        throw new Error('DECRYPT_FAILED');
    }
}

/**
 * SessionStore — in-memory map keyed by nodeId hex
 */
class SessionStore {
    constructor() {
        this.store = new Map();
    }

    set(nodeId, sessionKey) {
        this.store.set(nodeId.toString('hex'), sessionKey);
    }

    get(nodeId) {
        return this.store.get(nodeId.toString('hex')) || null;
    }

    has(nodeId) {
        return this.store.has(nodeId.toString('hex'));
    }

    delete(nodeId) {
        this.store.delete(nodeId.toString('hex'));
    }
}

module.exports = { encryptPayload, decryptPayload, SessionStore };
