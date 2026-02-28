# Archipel Protocol Specification

## Overview
Archipel is a secure, decentralized, zero-connection peer-to-peer (P2P) protocol designed to operate on local ad-hoc networks without any reliance on central servers or internet infrastructure. It leverages UDP Multicast for peer discovery and establishes ephemeral, end-to-end encrypted TCP sessions inspired by the Noise Protocol Framework. Data transfer is achieved through BitTorrent-style chunking with parallel downloads and robust verification.

## Packet Format
All packets transmitted over TCP (and UDP) adhere to the following binary structure:

| Offset | Length (bytes) | Field | Description |
| :--- | :--- | :--- | :--- |
| 0 | 1 | `TYPE` | Identifier for the packet type (e.g., `0x01` for HELLO) |
| 1 | 32 | `NODE_ID` | Ed25519 Public Key of the sender |
| 33 | 4 | `PAYLOAD_LEN` | Unsigned 32-bit integer (Big Endian) indicating payload size |
| 37 | Variable | `PAYLOAD` | The packet payload (often encrypted and/or JSON encoded) |
| 37 + `PAYLOAD_LEN`| 32 | `HMAC-SHA256` | Integrity MAC covering the entire packet up to this point |

## Handshake Sequence
```text
HANDSHAKE SEQUENCE (Noise-inspired)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Alice (Initiator)                               Bob (Responder)
   │                                               │
   │ ── HELLO_HS (e_A_pub, timestamp) ───────────► │
   │                                               │ génère e_B
   │ ◄─ HELLO_REPLY_HS (e_B_pub, sig_B) ────────── │
   │                                               │
   │ calcul: shared = X25519(e_A_priv, e_B_pub)    │
   │ sessionKey = HKDF(shared, 'archipel-v1')      │
   │                                               │
   │ ── AUTH (sig_A sur shared_hash) ────────────► │
   │                                               │ vérifie sig_A
   │ ◄─ AUTH_OK ────────────────────────────────── │
   │                                               │
   │ ════ Tunnel AES-256-GCM établi ═══════════════│
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## Cryptographic Primitives
| Primitive | Purpose | Library | Key Size |
| :--- | :--- | :--- | :--- |
| **Ed25519** | Node Identity & Signatures | `libsodium` | 256-bit |
| **X25519** | ECDH Key Exchange | `libsodium` | 256-bit |
| **AES-256-GCM** | Symmetric Payload Encryption | `node:crypto` | 256-bit |
| **HKDF-SHA256** | Session Key Derivation | `node:crypto` | 256-bit |
| **HMAC-SHA256** | Packet Integrity (MAC) | `node:crypto` | 256-bit |

## Packet Types
| Hex | Name | Direction | Payload Description |
| :--- | :--- | :--- | :--- |
| `0x01` | HELLO | Multicast | `{ tcpPort, timestamp, sharedFiles }` |
| `0x02` | PEER_LIST | Unicast | Array of known `{ nodeId, ip, tcpPort }` |
| `0x03` | MSG | Unicast E2E | Encrypted chat message string |
| `0x07` | ACK | Unicast | Empty (Keep-alive) or 5-byte chunk status |
| `0x10` | HELLO_HS | Unicast | `{ ePub, timestamp, sig }` (Initiator Ephemeral) |
| `0x11` | HELLO_REPLY_HS | Unicast | `{ ePub, sig }` (Responder Ephemeral) |
| `0x12` | AUTH | Unicast E2E | `{ sig }` covering `sha256(shared_secret)` |
| `0x13` | AUTH_OK | Unicast E2E | Empty (Confirm tunnel open) |
| `0x04` | CHUNK_REQ | Unicast E2E | `{ fileId, chunkIndex, requesterId }` |
| `0x05` | CHUNK_DATA | Unicast E2E | `{ fileId, chunkIndex, data(base64), signature }` |
| `0x06` | MANIFEST | Unicast E2E | JSON defining file metadata and chunk hashes |

## TOFU Trust Model (Web of Trust)
* **First Contact (TOFU):** When connecting to a peer for the very first time, their `NODE_ID` (Ed25519 public key) is automatically trusted and saved to `.archipel/trust.json`.
* **Persistence:** Trust mappings survive node reboots and network changes, tying identity strictly to cryptographic ownership rather than IP addresses.
* **Verification:** On subsequent connections, the presented `NODE_ID` is byte-compared (using timing-safe comparison) against the stored key.
* **MITM Detection:** If an entity claims a known `NODE_ID` but fails signature checks, or presents a conflicting public key for a known identity, the connection is instantly aborted and a `[SECURITY] TOFU CONFLICT` warning is issued.
* **Manual Override:** Allows a user to run `archipel trust <nodeId>` to enforce updating or resolving manual trust relationships.

## Known Limitations
* **Broadcast Storms:** On very large LANs, multicast HELLO intervals without jitter or backoff could cause network congestion.
* **No NAT Traversal:** Without an explicit STUN/TURN integration or UPnP, the protocol cannot bridge multiple separated subnets.
* **In-Memory Scalability limitations:** While file chunks aren't fully loaded into memory, storing numerous massive file manifests and tracking thousands of peer states in a synchronous `Map` can eventually cause high memory consumption for V8.
* **Basic Web of Trust:** The model lacks recursive trust propagation algorithms (e.g., Alice trusts Bob, Bob trusts Charlie, so Alice trusts Charlie) out-of-the-box, leaning heavily on TOFU point-to-point.
