# ARCHIPEL — Test Suite Documentation

## How to Run Tests

**Run all tests:**
```bash
node tests/run-all.js
```

**Run a single suite:**
```bash
node tests/unit/packet.test.js
node tests/unit/identity.test.js
node tests/unit/session.test.js
node tests/unit/tofu.test.js
node tests/unit/chunker.test.js
node tests/unit/manifest.test.js
node tests/integration/discovery.test.js
node tests/integration/tcp.test.js
node tests/integration/e2e.test.js
node tests/security/crypto.test.js
```

**Environment Variables:**

| Variable | Default | Effect |
|---|---|---|
| `TEST_LARGE=true` | `false` | Enables 50MB file tests (slow) |
| `TEST_E2E=true` | `false` | Starts 3 real node processes for E2E tests |
| `TEST_DISCOVERY_REAL=true` | `false` | Runs live UDP multicast discovery test (40s) |

---

## All Tests — Full Table

| Test ID | Description | Sprint | Pass Criteria | Criticality |
|---------|-------------|--------|---------------|-------------|
| TEST_PKT_01 | Magic bytes = [0x41,0x52,0x43,0x48] | Sprint 0 | buffer[0..3] matches | CRITICAL |
| TEST_PKT_02 | Header is 41 bytes | Sprint 0 | payload starts at offset 41 | CRITICAL |
| TEST_PKT_03 | TYPE byte at offset 4 | Sprint 0 | buffer[4] === type | CRITICAL |
| TEST_PKT_04 | NODE_ID at offset 5..36 | Sprint 0 | slice equals nodeId | CRITICAL |
| TEST_PKT_05 | PAYLOAD_LEN uint32BE at offset 37 | Sprint 0 | readUInt32BE(37) === payload.length | CRITICAL |
| TEST_PKT_06 | HMAC is last 32 bytes | Sprint 0 | length === 41+payloadLen+32 | CRITICAL |
| TEST_PKT_07 | verifyHMAC true on valid packet | Sprint 0 | returns true | CRITICAL |
| TEST_PKT_08 | verifyHMAC false on tampered payload | Sprint 0 | returns false | CRITICAL |
| TEST_PKT_09 | verifyHMAC false on tampered HMAC | Sprint 0 | returns false | CRITICAL |
| TEST_PKT_10 | verifyHMAC uses timingSafeEqual | Sprint 0 | source contains timingSafeEqual | CRITICAL |
| TEST_PKT_11 | parsePacket roundtrip | Sprint 0 | type, nodeId, payload match | CRITICAL |
| TEST_PKT_12 | parsePacket throws on short buffer | Sprint 0 | throws error | MAJOR |
| TEST_PKT_13 | parsePacket throws on wrong magic | Sprint 0 | throws with 'MAGIC' msg | MAJOR |
| TEST_PKT_14 | All 7 PACKET_TYPES exported correctly | Sprint 0 | all values 0x01–0x07 | CRITICAL |
| TEST_PKT_15 | Zero-length payload is valid | Sprint 0 | no throw, verifyHMAC=true | MINOR |
| TEST_ID_01 | generateIdentity creates .archipel/identity.key | Sprint 0 | file exists | CRITICAL |
| TEST_ID_02 | identity.key in .gitignore | Sprint 0 | .gitignore has .archipel/ and *.key | CRITICAL |
| TEST_ID_03 | publicKey is 32 bytes | Sprint 0 | length === 32 | CRITICAL |
| TEST_ID_04 | privateKey is 64 bytes | Sprint 0 | length === 64 | CRITICAL |
| TEST_ID_05 | generateIdentity is idempotent | Sprint 0 | same publicKey both calls | CRITICAL |
| TEST_ID_06 | Ed25519 sign+verify roundtrip | Sprint 0 | verify === message | CRITICAL |
| TEST_ID_07 | Private key never logged | Sprint 0 | hex not in console output | CRITICAL |
| TEST_ID_08 | .archipel/ created if missing | Sprint 0 | dir exists after call | MAJOR |
| TEST_SES_01 | encryptPayload length = 12+16+plaintext | Sprint 2 | exact length | CRITICAL |
| TEST_SES_02 | decryptPayload recovers plaintext | Sprint 2 | decrypted.equals(plaintext) | CRITICAL |
| TEST_SES_03 | Nonce never reused | Sprint 2 | enc1 !== enc2, nonces differ | CRITICAL |
| TEST_SES_04 | decryptPayload throws on tampered ciphertext | Sprint 2 | throws DECRYPT_FAILED | CRITICAL |
| TEST_SES_05 | decryptPayload throws on tampered auth tag | Sprint 2 | throws | CRITICAL |
| TEST_SES_06 | decryptPayload throws on wrong key | Sprint 2 | throws | CRITICAL |
| TEST_SES_07 | Nonce is exactly 12 bytes | Sprint 2 | randomBytes(12) in source | CRITICAL |
| TEST_SES_08 | Auth tag is exactly 16 bytes | Sprint 2 | getAuthTag() in source | CRITICAL |
| TEST_SES_09 | SessionStore.set/get roundtrip | Sprint 2 | get returns what was set | MAJOR |
| TEST_SES_10 | SessionStore.has false for unknown | Sprint 2 | returns false | MAJOR |
| TEST_SES_11 | SessionStore.delete removes entry | Sprint 2 | has returns false after delete | MAJOR |
| TEST_TOFU_01 | First contact returns 'NEW' | Sprint 2 | check === 'NEW' | CRITICAL |
| TEST_TOFU_02 | Known peer matching key returns 'TRUSTED' | Sprint 2 | check === 'TRUSTED' | CRITICAL |
| TEST_TOFU_03 | Different key returns 'CONFLICT' | Sprint 2 | check === 'CONFLICT' | CRITICAL |
| TEST_TOFU_04 | CONFLICT logged with security warning | Sprint 2 | log contains TOFU CONFLICT/MITM | MAJOR |
| TEST_TOFU_05 | CONFLICT does not crash | Sprint 2 | no throw | MAJOR |
| TEST_TOFU_06 | trust.json persists after save/load | Sprint 2 | TRUSTED after reload | MAJOR |
| TEST_TOFU_07 | check() uses timingSafeEqual | Sprint 2 | source contains timingSafeEqual | CRITICAL |
| TEST_TOFU_08 | revoke() removes trust entry | Sprint 2 | check returns 'NEW' after revoke | MAJOR |
| TEST_CHK_01 | CHUNK_SIZE === 524288 | Sprint 3 | constant value match | CRITICAL |
| TEST_CHK_02 | nbChunks correct for 2MB file | Sprint 3 | nbChunks === 4 | CRITICAL |
| TEST_CHK_03 | Last chunk can be smaller | Sprint 3 | size === 100*1024 | MAJOR |
| TEST_CHK_04 | fileId is SHA-256 of file | Sprint 3 | hex matches | CRITICAL |
| TEST_CHK_05 | Each chunk hash valid | Sprint 3 | verifyChunk === true for all | CRITICAL |
| TEST_CHK_06 | verifyChunk false on corruption | Sprint 3 | returns false | CRITICAL |
| TEST_CHK_07 | readChunk uses fd.read not readFile | Sprint 3 | source analysis | MAJOR |
| TEST_CHK_08 | Chunks reassemble to original | Sprint 3 | SHA-256 matches fileId | CRITICAL |
| TEST_CHK_09 | Manifest-compatible shape | Sprint 3 | all required fields present | CRITICAL |
| TEST_MAN_01 | buildManifest has all required fields | Sprint 3 | 8 fields present | CRITICAL |
| TEST_MAN_02 | chunk_size always 524288 | Sprint 3 | === 524288 | CRITICAL |
| TEST_MAN_03 | Ed25519 signature valid | Sprint 3 | verifyManifest === true | CRITICAL |
| TEST_MAN_04 | Tampered manifest fails | Sprint 3 | verifyManifest === false | CRITICAL |
| TEST_MAN_05 | encode/decode roundtrip | Sprint 3 | file_id and nb_chunks match | MAJOR |
| TEST_MAN_06 | sender_id matches publicKey hex | Sprint 3 | exact string match | CRITICAL |
| TEST_DSC_01 | HELLO to correct multicast address | Sprint 1 | 239.255.42.99:6000 in source | CRITICAL |
| TEST_DSC_02 | Own HELLO ignored | Sprint 1 | peerTable empty after own HELLO | CRITICAL |
| TEST_DSC_03 | Foreign peer added on HELLO | Sprint 1 | peerTable.get != null | MAJOR |
| TEST_DSC_04 | Peer pruned after 90s | Sprint 1 | get returns null after prune | MAJOR |
| TEST_DSC_05 | lastSeen updated on repeated HELLO | Sprint 1 | new lastSeen > old | MINOR |
| TEST_DSC_06 | HELLO payload has tcpPort+timestamp | Sprint 1 | both fields present+valid | MAJOR |
| TEST_DSC_07 | Two instances discover each other | Sprint 1 | mutual discovery in 40s | CRITICAL |
| TEST_TCP_01 | Server listens on configured port | Sprint 1 | net.connect succeeds | CRITICAL |
| TEST_TCP_02 | TLV framing uint32_BE | Sprint 1 | frame parsed correctly | CRITICAL |
| TEST_TCP_03 | 11th connection rejected | Sprint 1 | 0xFF ACK or immediate close | CRITICAL |
| TEST_TCP_04 | Invalid HMAC dropped silently | Sprint 1 | no crash, no response | CRITICAL |
| TEST_TCP_05 | Keep-alive ACK every 15s | Sprint 1 | source has 15000ms + ACK | MAJOR |
| TEST_TCP_06 | Peer removed from peerTable on close | Sprint 1 | source has close handler | MAJOR |
| TEST_TCP_07 | sendToPeer rejects after 5s timeout | Sprint 1 | source has 5000ms timeout | MAJOR |
| TEST_E2E_01 | 3 nodes discover each other in 60s | Full flow | all running, DISCOVERY in logs | CRITICAL |
| TEST_E2E_02 | Handshake completes node1↔node2 | Full flow | [HANDSHAKE] in logs | CRITICAL |
| TEST_E2E_03 | Encrypted message on wire | Full flow | encryptPayload used in source | CRITICAL |
| TEST_E2E_04 | Message received after decryption | Full flow | CLI exists for send | CRITICAL |
| TEST_E2E_05 | File transfer 10MB with SHA-256 | Full flow | SHA256 matches after transfer | CRITICAL |
| TEST_E2E_06 | Transfer survives disconnect | Full flow | multi-peer resume | MAJOR |
| TEST_E2E_07 | No internet calls during flow | Full flow | zero external HTTP calls | CRITICAL |
| TEST_E2E_08 | ENABLE_AI=false blocks HTTP | Full flow | ENABLE_AI check in gemini.js | MAJOR |
| TEST_SEC_01 | No hardcoded private keys in src | Security | no 128-char hex string | CRITICAL |
| TEST_SEC_02 | .env in .gitignore | Security | .gitignore contains .env | CRITICAL |
| TEST_SEC_03 | .archipel/ in .gitignore | Security | .gitignore contains .archipel/ | CRITICAL |
| TEST_SEC_04 | No custom crypto implementation | Security | no manual encrypt/XOR | CRITICAL |
| TEST_SEC_05 | Nonce is random, not counter | Security | randomBytes(12) in source | CRITICAL |
| TEST_SEC_06 | New ephemeral keys per TCP connection | Security | keypair gen inside handshake fn | CRITICAL |
| TEST_SEC_07 | Ed25519 signing, X25519 for ECDH | Security | separate functions in handshake | CRITICAL |
| TEST_SEC_08 | HKDF info binds to both node IDs | Security | nodeId in HKDF info | CRITICAL |
| TEST_SEC_09 | AUTH signs sha256(shared_secret) | Security | sha256 call before sign | CRITICAL |
| TEST_SEC_10 | No Gemini API key in source | Security | no /AIza.../ pattern found | CRITICAL |

---

## What Each [FAIL] Means

### CRITICAL — Demo will fail or security is broken

| Test IDs | Impact |
|----------|--------|
| TEST_PKT_01..15 | Protocol broken — no peer communication possible |
| TEST_SES_01..08 | Encryption broken — all messages exposed in plaintext |
| TEST_SES_03 | **Catastrophic** — nonce reuse allows ciphertext forgery |
| TEST_TOFU_03, TEST_TOFU_07 | MITM attack undetected — impersonation possible |
| TEST_SEC_01, TEST_SEC_04 | Private keys exposed or crypto home-rolled — disqualified |
| TEST_SEC_07 | **Catastrophic** — using Ed25519 keys directly for ECDH |
| TEST_E2E_07 | External call detected — disqualified at hackathon demo |
| TEST_ID_02, TEST_SEC_02,03 | Secrets leaked to git — immediate disqualification |

### MAJOR — Feature missing, partial demo

| Test IDs | Impact |
|----------|--------|
| TEST_ID_08 | First run fails on fresh environment |
| TEST_TOFU_04..06,08 | Trust model incomplete |
| TEST_CHK_07 | Memory issues with large files (>512MB RAM) |
| TEST_TCP_05..07 | Keep-alive and timeout — connectivity degraded |
| TEST_DSC_03..06 | Discovery partially broken |
| TEST_E2E_05,06 | File transfer not demonstrated |

### MINOR — Cosmetic or non-blocking

| Test IDs | Impact |
|----------|--------|
| TEST_PKT_15 | Edge case — no real protocol impact |
| TEST_DSC_05 | Peer list staleness — minor churn |
