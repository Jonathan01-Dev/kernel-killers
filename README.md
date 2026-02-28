# ARCHIPEL
### Decentralized Encrypted P2P Protocol — Zero Internet Required

> Hackathon ARCHIPEL · Lomé Business School · 24h · kernel-killers

---

## What is Archipel
Archipel is a fully sovereign, end-to-end encrypted peer-to-peer messaging and file transfer protocol that operates entirely without internet access or central servers. Nodes use UDP multicast to autonomously discover each other on local networks, and establish secure Noise-inspired TCP tunnels using ephemeral X25519 keys and AES-256-GCM encryption. It is designed to guarantee communication privacy, integrity, and resilience during infrastructure failures, censorship events, or in strictly air-gapped offline environments.

---

## Architecture

Node topology:
```text
[Node A] <──UDP Multicast──> [Node B] <──UDP Multicast──> [Node C]
    │                              │                              │
    └──────────TCP E2E────────────┘──────────TCP E2E─────────────┘
```

Protocol layers:
```text
┌─────────────────────────────────┐
│        CLI / Application        │  archipel start/peers/msg/send
├─────────────────────────────────┤
│    Transfer (Chunks + Files)    │  512KB chunks, SHA-256, manifest
├─────────────────────────────────┤
│   Crypto (Handshake + E2E)      │  Ed25519 + X25519 + AES-256-GCM
├─────────────────────────────────┤
│   Network (UDP + TCP + P2P)     │  Multicast discovery + TCP mesh
└─────────────────────────────────┘
```

---

## Tech Stack
| Layer | Technology | Justification |
|-------|-----------|---------------|
| Runtime | Node.js | Excellent asynchronous I/O performance ideal for concurrent P2P networking without external dependencies. |
| Discovery | UDP Multicast 239.255.42.99:6000 | Enables zero-configuration autodiscovery on local networks without a central rendezvous server. |
| Transfer | TCP + TLV framing | Provides reliable byte streams. Total-Length-Value (TLV) prevents fragmented packet bugs. |
| Identity | Ed25519 (`libsodium`) | Fast, highly secure signatures resistant to side-channel attacks for node identity and manifest integrity. |
| Key Exchange | X25519 ECDH (`libsodium`) | Industry-standard ephemeral Diffie-Hellman ensuring Perfect Forward Secrecy per session. |
| Encryption | AES-256-GCM (`node:crypto`) | Authenticated encryption (AEAD) guaranteeing both confidentiality and integrity of messages. |
| Key Derivation | HKDF-SHA256 (`node:crypto`) | Safely expands the shared DH secret into strong symmetric session keys. |
| Integrity | HMAC-SHA256 (`node:crypto`) | Authenticates packet framing and metadata before decryption, preventing resource exhaustion attacks. |
| Trust | TOFU — Trust On First Use | Web of Trust model eliminating the need for central Certificate Authorities while detecting MITM. |

---

## Packet Format
| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 4 bytes | MAGIC | 0x41 0x52 0x43 0x48 ("ARCH") |
| 4 | 1 byte | TYPE | Packet type |
| 5 | 32 bytes | NODE_ID | Sender Ed25519 public key |
| 37 | 4 bytes | PAYLOAD_LEN | uint32 big-endian |
| 41 | variable | PAYLOAD | Encrypted data (AES-256-GCM) |
| last 32 | 32 bytes | HMAC | HMAC-SHA256 integrity |

Packet types:
| Hex | Name | Description |
|-----|------|-------------|
| 0x01 | HELLO | Peer presence announcement |
| 0x02 | PEER_LIST | Known peers list |
| 0x03 | MSG | Encrypted message |
| 0x04 | CHUNK_REQ | File chunk request |
| 0x05 | CHUNK_DATA | File chunk transfer |
| 0x06 | MANIFEST | File metadata + signature |
| 0x07 | ACK | Acknowledgement |
| 0x10 | HELLO_HS | Handshake initiation |
| 0x11 | HELLO_REPLY_HS | Handshake response |
| 0x12 | AUTH | Authentication proof |
| 0x13 | AUTH_OK | Handshake complete |

---

## Cryptographic Primitives
| Primitive | Purpose | Library | Why chosen |
|-----------|---------|---------|-----------|
| Ed25519 | Node identity + packet signing | `libsodium` | Provides short keys and fast, deterministic signatures. |
| X25519 | Ephemeral key exchange (ECDH) | `libsodium` | Montgomery curve providing fast, secure key generation for forward secrecy. |
| AES-256-GCM | Symmetric payload encryption | `node:crypto` | Standardized, hardware-accelerated encryption providing IND-CCA2 security. |
| HKDF-SHA256 | Session key derivation | `node:crypto` | Rigorous standard to derive cryptographically strong keys from weak DH shared secrets. |
| HMAC-SHA256 | Packet integrity | `node:crypto` | Used with `timingSafeEqual` to verify frame integrity before passing to the AES decryptor. |
| SHA-256 | File and chunk hashing | `node:crypto` | Creates collision-resistant content-addressable identifiers for robust parallel chunking. |

---

## Installation
```bash
git clone https://github.com/Jonathan01-Dev/kernel-killers.git
cd kernel-killers
npm install
cp .env.example .env
```
*(If `.env.example` is missing, you can simply run it without `.env` or create it manually)*

---

## Running the Demo

### Start 3 nodes (open 3 terminals)
```powershell
# Terminal 1
$env:TCP_PORT="7777"; node src/node.js

# Terminal 2
$env:TCP_PORT="7778"; node src/node.js

# Terminal 3
$env:TCP_PORT="7779"; node src/node.js
```

Wait ~5 seconds for the nodes to auto-discover each other via UDP multicast.

### Send encrypted message
Open a 4th terminal to run commands against the local Node.
```powershell
node src/cli/commands.js msg <nodeId> "Hello Archipel"
```
*(Replace `<nodeId>` with the first 8 characters of a peer's ID printed in the node terminal).*

### Send a file
```powershell
node src/cli/commands.js send <nodeId> <filepath>
```

### Check peers
```powershell
node src/cli/commands.js peers
```

---

## Sprint Status
| Sprint | Title | Status | Key Deliverable |
|--------|-------|--------|----------------|
| S0 | Bootstrap & Architecture | ✅ Done | Packet format, Ed25519 identity |
| S1 | P2P Network Layer | ✅ Done | 3-node UDP discovery + TCP mesh |
| S2 | E2E Encryption & Auth | ✅ Done | AES-256-GCM tunnel, TOFU trust |
| S3 | Chunking & File Transfer | ✅ Done | 512KB chunks, SHA-256 integrity |
| S4 | Integration & CLI | ✅ Done | Demo-ready CLI + full README |

---

## Test Results
```
TOTAL PASS : 82
TOTAL FAIL : 0
SCORE      : 100%
✓ ALL TESTS PASSED — Prototype is demo-ready
```

---

## Known Limitations
1. **No NAT Traversal/STUN:** UDP Multicast limits discovery strictly to the local area network/subnet. Nodes separated by routers will not discover each other.
2. **In-Memory Tracking:** The peer table and active chunk manifests are maintained in RAM. Massive networks (>5000 nodes) or extreme concurrent downloads will challenge V8 memory limits.
3. **No DHT:** Lacking an index like Kademlia, file lookups and routing are rudimentary and scale linearly `O(N)`.
4. **Basic Web of Trust:** The TOFU implementation is strictly point-to-point. It does not algorithmically propagate trust across social graphs (e.g., A trusts B, B trusts C -> A trusts C).
5. **No Broadcast Backoff:** Multicast HELLO packets are fired on fixed intervals without jitter, which could cause broadcast storms on extremely dense zero-configuration networks.

---

## Team — kernel-killers
| Member | Role | Contributions |
|--------|------|--------------|
| **Emmanuel** (`Emmanuel-Prince-T`) | Arch. & Dev | Protocol Specification, Cryptography, P2P Routing, CLI Integration, Serveur TCP, Gestion connexions, BuildPacket(), parsePacket(), Lecture fichier, Découpage 512 KB, SHA256, Reconstruction fichier |
| **Mackenzie** (`mackenzie7-dev`) | Reseau UDP & Peer Discovery | Envoi Hello, Peer table, UMP multicast Cryptography|
| **Walid** (`agrignanwalid02-del`) | Recherches | UDP Multicast, partage de connexion, |
| **Saoban** (`tidjanisaoban478-dot`) | Chercheur | Recherche Coding, partage de connexion, PowerPoint |