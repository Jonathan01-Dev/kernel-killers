# ARCHIPEL – Kernel Killers

## 🚀 Hackathon: Archipel 2026

## 🎯 Mission

Implement a decentralized, encrypted, zero-infrastructure P2P protocol operating purely on local network (LAN).

No central server.
No certificate authority.
No internet dependency.

---

## 🧠 Architecture Overview

Archipel is designed as:

- Fully decentralized P2P mesh network
- UDP multicast for peer discovery
- TCP connections for reliable communication
- End-to-end encryption using modern cryptographic primitives
- Chunk-based file transfer inspired by BitTorrent

---

## 🛠️ Tech Stack

- Node.js
- UDP (dgram)
- TCP (net)
- libsodium-wrappers (Ed25519, X25519)
- Node crypto (AES-256-GCM, SHA256, HMAC)
- dotenv

---

## 📦 Packet Format (ARCHIPEL v1)

HEADER:
- MAGIC (4 bytes)
- TYPE (1 byte)
- NODE_ID (32 bytes)
- PAYLOAD_LEN (uint32 big-endian)

BODY:
- PAYLOAD
- HMAC-SHA256 (32 bytes)

---

## 📍 Sprint 0 Status

- [x] Project initialized
- [x] Folder structure created
- [ ] Packet builder implementation
- [ ] Identity generation