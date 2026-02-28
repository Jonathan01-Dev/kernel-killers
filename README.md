# ARCHIPEL — Decentralized Encrypted P2P Protocol

## 1. What is Archipel
Archipel is a sovereign, end-to-end encrypted, Zero-Connection P2P protocol designed to flourish organically even during total terrestrial infrastructure failure. Nodes autonomously discover each other via UDP multicast in ad-hoc LAN settings, seamlessly establish persistent AES-256-GCM encrypted tunnels using an ephemeral Handshake protocol, and efficiently transfer any-size files through a BitTorrent-inspired parallel chunking engine. Trust is explicitly decoupled from IP geometry by leveraging a `Web of Trust` (Trust On First Use) grounded in cryptographic Ed25519 identity.

## 2. Architecture
```text
  ┌──────────────┐         UDP Multicast (Port 6000)          ┌──────────────┐
  │              │ ─────────────────────────────────────────► │              │
  │    Node A    │ ◄───────────────────────────────────────── │    Node B    │
  │ (Initiator)  │         TCP Unicast (Port 7777)            │ (Responder)  │
  │              │                                            │              │
  │ ┌──────────┐ │ ── Noise-inspired Handshake (X25519) ────► │ ┌──────────┐ │
  │ │ Session  │ │ ◄── Session Key Derived (HKDF-SHA256) ───  │ │ Session  │ │
  │ └──────────┘ │                                            │ └──────────┘ │
  │              │ ════ AES-256-GCM Encrypted Tunnel ════════ │              │
  │ ┌──────────┐ │                                            │ ┌──────────┐ │
  │ │ Chunking │ │ ── CHUNK_REQ (Encrypted) ────────────────► │ │ Chunking │ │
  │ │ Download │ │ ◄── CHUNK_DATA (Encrypted) ──────────────  │ │ Storage  │ │
  │ └──────────┘ │                                            │ └──────────┘ │
  └──────────────┘                                            └──────────────┘
```

## 3. Tech Stack
| Layer | Technology | Justification |
| :--- | :--- | :--- |
| **Language** | Node.js / JavaScript | Rapid iteration, async I/O excellence for networking |
| **P2P Routing** | UDP Multicast | Zero-configuration auto-discovery on LAN without servers |
| **Transport** | TCP Sockets (TLV) | Reliable stream control, Total-Length-Value prevents framing bugs |
| **CLI** | `node:readline` / Argv | No external dependencies, POSIX-friendly, strict execution |
| **Storage** | File System (`fs/promises`) | Avoids RAM exhaustion (chunks written aggressively to disk) |

## 4. Packet Format
The core packet structure is strictly 37+ bytes:

| Byte Offset | Length | Field |
| :--- | :--- | :--- |
| `0` | 1 | **TYPE** |
| `1` | 32 | **NODE_ID** (Ed25519 pub key) |
| `33` | 4 | **PAYLOAD_LEN** (uint32_BE) |
| `37` | Variable | **PAYLOAD** |
| End - 32 | 32 | **HMAC-SHA256** (Integrity Tag) |

## 5. Cryptographic Primitives
| Primitive | Purpose | Justification |
| :--- | :--- | :--- |
| **Ed25519** | Node Identity & Manifest Sigs | Fast, secure curve signatures resistant to side-channel attacks (`libsodium`) |
| **X25519** | ECDH Handshake | Industry standard, robust forward secrecy Key Exchange |
| **AES-256-GCM** | Symmetric Session Tunnel | Indistinguishability under Chosen Ciphertext Attack (IND-CCA2) bounds |
| **HKDF-SHA256** | Key Derivation | Securely expands Ephemeral X25519 shared secret against weak randomness |
| **HMAC-SHA256** | Transport Packet Security | Authenticates packet authenticity preventing malicious network fuzzing |

## 6. Installation
```bash
git clone https://github.com/Jonathan01-Dev/kernel-killers
cd kernel-killers
npm install
cp .env.example .env
```
*(If `.env.example` is missing, you can simply run it without `.env` or create it with `TCP_PORT=7777`)*

## 7. Running the Demo
Open three separate terminal windows inside the project directory to simulate the 3-node scenario.

**Terminal 1 (Alice):**
```bash
node src/cli/commands.js start --port 7777
```
**Terminal 2 (Bob):**
```bash
node src/cli/commands.js start --port 7778
```
**Terminal 3 (Charlie):**
```bash
node src/cli/commands.js start --port 7779
```

**Testing the CLI in Terminal 4:**
```bash
node src/cli/commands.js peers
node src/cli/commands.js status
```

## 8. Sprint Status
| Sprint | Deliverable | Status |
| :--- | :--- | :--- |
| **S0** | Bootstrap & PKI keys | ✅ Completed |
| **S1** | UDP Discovery + TCP Mesh | ✅ Completed |
| **S2** | X25519 Handshake + AES Tunnel | ✅ Completed |
| **S3** | Chunking, Manifests, Storage | ✅ Completed |
| **S4** | CLI & Gemini Assistant | ✅ Completed |

## 9. Known Limitations
1. **Network Hopping:** Relying solely on UDP Multicast confines Archipel to local subnets (VLAN/LAN). We currently miss STUN/TURN integration to poke holes across the broader internet.
2. **Synchronous Memory Bottlenecks:** Tracking massive sets of manifest objects concurrently via in-memory Maps could expose the V8 engine to Max Heap memory leaks during 1TB+ transfers.
3. **Flat Routing Hash Table:** Archipel does not feature a Distributed Hash Table (DHT) like Kademlia. Node lookups require a sequential `O(N)` scan against the peer table cache, which breaks down beyond ~5,000 active nodes on limited hardware.

## 10. Team
**kernel-killers**
- Jonathan (`Jonathan01-Dev`) — Architecture, Crypto Engineering, CLI Integration