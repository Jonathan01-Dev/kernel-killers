// src/trust/tofu.js
'use strict';

const crypto = require('node:crypto');
const fs = require('fs');
const path = require('path');

const DEFAULT_TRUST_PATH = path.resolve(process.cwd(), '.archipel', 'trust.json');

class TofuStore {
    /**
     * @param {string} [trustPath] - Optional override for the trust file path (used in tests)
     */
    constructor(trustPath) {
        this.trustPath = trustPath || DEFAULT_TRUST_PATH;
        this.store = new Map(); // nodeId_hex → pubKey_hex
    }

    async load() {
        try {
            if (!fs.existsSync(this.trustPath)) return;
            const raw = fs.readFileSync(this.trustPath, 'utf8');
            const data = JSON.parse(raw);
            for (const [k, v] of Object.entries(data)) {
                this.store.set(k, v);
            }
        } catch {
            // Start with empty store on any error
        }
    }

    async save() {
        try {
            fs.mkdirSync(path.dirname(this.trustPath), { recursive: true });
            const obj = {};
            for (const [k, v] of this.store.entries()) obj[k] = v;
            fs.writeFileSync(this.trustPath, JSON.stringify(obj, null, 2), { mode: 0o600 });
        } catch {
            // Non-fatal
        }
    }

    /**
     * check(nodeId, publicKey)
     * Returns 'NEW' | 'TRUSTED' | 'CONFLICT'. Never throws.
     */
    check(nodeId, publicKey) {
        try {
            const key = nodeId.toString('hex');
            const stored = this.store.get(key);

            if (!stored) return 'NEW';

            const storedBuf = Buffer.from(stored, 'hex');
            const incomingBuf = Buffer.isBuffer(publicKey)
                ? publicKey
                : Buffer.from(publicKey, 'hex');

            // Pad/truncate to same length for timingSafeEqual
            if (storedBuf.length !== incomingBuf.length) {
                console.warn(`[SECURITY] TOFU CONFLICT for ${key.slice(0, 8)} — key length mismatch — possible MITM!`);
                return 'CONFLICT';
            }

            const match = crypto.timingSafeEqual(storedBuf, incomingBuf);
            if (!match) {
                console.warn(`[SECURITY] TOFU CONFLICT for ${key.slice(0, 8)} — possible MITM!`);
                return 'CONFLICT';
            }

            return 'TRUSTED';
        } catch {
            return 'NEW';
        }
    }

    trust(nodeId, publicKey) {
        const key = nodeId.toString('hex');
        const val = Buffer.isBuffer(publicKey) ? publicKey.toString('hex') : publicKey;
        this.store.set(key, val);
        this.save(); // fire-and-forget
    }

    revoke(nodeId) {
        this.store.delete(nodeId.toString('hex'));
        this.save();
    }
}

module.exports = TofuStore;
