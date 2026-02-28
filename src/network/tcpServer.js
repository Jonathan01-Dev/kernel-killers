// c:\Users\PC LBS\kernel-killers\src\network\tcpServer.js
const net = require('net');
const sodium = require('libsodium-wrappers');
const { buildPacket, parsePacket, verifyHMAC, PACKET_TYPES } = require('./packet');
const { initiateHandshake, waitForHandshake } = require('../crypto/handshake');
const { SessionStore, encryptPayload, decryptPayload } = require('../crypto/session');
const TofuStore = require('../trust/tofu');
const { decodeManifest, verifyManifest } = require('../transfer/manifest');
const { hasChunk, loadChunk, saveManifest } = require('../transfer/storage');

class TcpServer {
    constructor(identity, peerTable, port) {
        this.identity = identity;
        this.peerTable = peerTable;
        this.port = port;
        this.server = null;
        this.connections = new Set();
        this.keepAliveIntervals = new Map();
        this.sessionStore = new SessionStore();
        this.tofuStore = new TofuStore();
        this.peerSockets = new Map();
        this.downloadManager = null; // injected later
    }

    async start() {
        await this.tofuStore.load();
        return new Promise((resolve, reject) => {
            this.server = net.createServer((socket) => {
                if (this.connections.size >= 10) {
                    const ackPkt = buildPacket(PACKET_TYPES.ACK, this.identity.publicKey, Buffer.from([0xFF]), this.identity.privateKey);
                    this._writeFrame(socket, ackPkt);
                    socket.destroy();
                    return;
                }
                this._handleConnection(socket, false).catch(err => {
                    console.error(`[TCP] Inbound connection failed: ${err.message}`);
                    socket.destroy();
                });
            });

            this.server.on('error', (err) => {
                console.error(`[TCP] Server error: ${err.message}`);
                reject(err);
            });

            this.server.listen(this.port, () => resolve());
        });
    }

    async stop() {
        return new Promise((resolve) => {
            for (const socket of this.connections) socket.destroy();
            this.connections.clear();
            this.peerSockets.clear();
            for (const interval of this.keepAliveIntervals.values()) clearInterval(interval);
            this.keepAliveIntervals.clear();
            if (this.server) this.server.close(() => resolve());
            else resolve();
        });
    }

    async sendToSocket(socket, type, rawPayload) {
        const sessionKey = this.sessionStore.get(socket.peerNodeId);
        let pkt;
        if (sessionKey) {
            const encrypted = encryptPayload(sessionKey, rawPayload);
            pkt = buildPacket(type, this.identity.publicKey, encrypted, sessionKey);
        } else {
            pkt = buildPacket(type, this.identity.publicKey, rawPayload, this.identity.privateKey);
        }
        this._writeFrame(socket, pkt);
    }

    async sendToPeer(ip, port, packetBuffer) {
        return new Promise((resolve, reject) => {
            const socket = new net.Socket();
            socket.connectingTimeout = setTimeout(() => {
                socket.destroy();
                reject(new Error('Connection timeout'));
            }, 5000);

            socket.on('error', (err) => {
                clearTimeout(socket.connectingTimeout);
                socket.destroy();
                reject(err);
            });

            socket.connect(port, ip, () => {
                clearTimeout(socket.connectingTimeout);
                this._handleConnection(socket, true)
                    .then(() => {
                        const pkt = parsePacket(packetBuffer);
                        return this.sendToSocket(socket, pkt.type, pkt.payload);
                    })
                    .then(resolve)
                    .catch(err => {
                        socket.destroy();
                        reject(err);
                    });
            });
        });
    }

    async _handleConnection(socket, isOutbound) {
        this.connections.add(socket);
        const remoteIp = socket.remoteAddress;
        console.log(`[TCP] connection from ${remoteIp}`);

        let sessionContext;
        try {
            if (isOutbound) {
                sessionContext = await initiateHandshake(socket, this.identity);
            } else {
                sessionContext = await waitForHandshake(socket, this.identity);
            }
        } catch (err) {
            socket.destroy();
            throw new Error(`Handshake failed: ${err.message}`);
        }

        const { sessionKey, peerNodeId } = sessionContext;
        socket.peerNodeId = peerNodeId;

        const trustStatus = this.tofuStore.check(peerNodeId, peerNodeId);
        if (trustStatus === 'CONFLICT') {
            console.warn(`[TCP] TOFU CONFLICT with ${peerNodeId.toString('hex')}. Closing socket.`);
            socket.destroy();
            throw new Error('TOFU CONFLICT');
        } else if (trustStatus === 'NEW') {
            this.tofuStore.trust(peerNodeId, peerNodeId);
            console.log(`[TOFU] trusted new peer ${peerNodeId.toString('hex').substring(0, 8)}`);
        }

        this.sessionStore.set(peerNodeId, sessionKey);
        this.peerSockets.set(peerNodeId.toString('hex'), socket);
        console.log(`[HANDSHAKE] complete with ${peerNodeId.toString('hex').substring(0, 8)}`);

        let buffer = Buffer.alloc(0);
        let expectedLength = -1;

        const kaInterval = setInterval(() => {
            if (!socket.destroyed) {
                this.sendToSocket(socket, PACKET_TYPES.ACK, Buffer.alloc(0)).catch(() => { });
            }
        }, 15000);
        this.keepAliveIntervals.set(socket, kaInterval);

        socket.on('data', (data) => {
            buffer = Buffer.concat([buffer, data]);

            while (true) {
                if (expectedLength === -1) {
                    if (buffer.length < 4) break;
                    expectedLength = buffer.readUInt32BE(0);
                }

                if (buffer.length < 4 + expectedLength) break;

                const frame = buffer.subarray(4, 4 + expectedLength);
                buffer = buffer.subarray(4 + expectedLength);
                expectedLength = -1;

                try {
                    this._processPacket(frame, socket);
                } catch (err) {
                    console.error(`[TCP] packet error: ${err.message}`);
                }
            }
        });

        socket.on('close', () => {
            this.connections.delete(socket);
            clearInterval(this.keepAliveIntervals.get(socket));
            this.keepAliveIntervals.delete(socket);
            if (socket.peerNodeId) {
                this.sessionStore.delete(socket.peerNodeId);
                this.peerSockets.delete(socket.peerNodeId.toString('hex'));
            }
            console.log(`[TCP] disconnected ${remoteIp}`);
        });
    }

    async _processPacket(frame, socket) {
        const sessionKey = this.sessionStore.get(socket.peerNodeId);
        if (!sessionKey) return;

        if (!verifyHMAC(frame, sessionKey)) return;
        const pkt = parsePacket(frame);

        if (pkt.type === PACKET_TYPES.ACK) return;

        let rawPayload;
        try {
            rawPayload = decryptPayload(sessionKey, pkt.payload);
        } catch (err) {
            return; // drop invalid payload
        }

        if (pkt.type === PACKET_TYPES.PEER_LIST) {
            try {
                const peers = JSON.parse(rawPayload.toString('utf8'));
                for (const p of peers) {
                    if (p.nodeId !== this.identity.publicKey.toString('hex')) {
                        this.peerTable.upsert(Buffer.from(p.nodeId, 'hex'), {
                            ip: p.ip,
                            tcpPort: p.tcpPort
                        });
                    }
                }
            } catch (err) { }
        } else if (pkt.type === PACKET_TYPES.MANIFEST) {
            try {
                const manifest = decodeManifest(rawPayload);
                const isValid = await verifyManifest(manifest, manifest.sender_id);
                if (isValid) {
                    await saveManifest(manifest);
                    console.log(`[MANIFEST] received ${manifest.filename} (${manifest.nb_chunks} chunks) from ${manifest.sender_id.substring(0, 8)}`);

                    // Keep track of which peers have which file
                    const peer = this.peerTable.get(Buffer.from(manifest.sender_id, 'hex'));
                    if (peer) {
                        if (!peer.sharedFiles) peer.sharedFiles = [];
                        if (!peer.sharedFiles.includes(manifest.file_id)) {
                            peer.sharedFiles.push(manifest.file_id);
                        }
                    }

                    if (process.env.ENABLE_AUTO_DOWNLOAD === 'true' && this.downloadManager) {
                        const outputDir = require('path').join(process.cwd(), 'downloads');
                        this.downloadManager.download(manifest, outputDir).catch(err => {
                            console.error(`[TRANSFER] Auto-download failed: ${err.message}`);
                        });
                    }
                }
            } catch (err) {
                console.error(`[MANIFEST] processing error: ${err.message}`);
            }
        } else if (pkt.type === PACKET_TYPES.CHUNK_REQ) {
            try {
                const req = JSON.parse(rawPayload.toString('utf8'));
                const { fileId, chunkIndex } = req;

                const hasC = await hasChunk(fileId, chunkIndex);
                if (hasC) {
                    const chunkData = await loadChunk(fileId, chunkIndex);
                    if (chunkData) {
                        await sodium.ready;
                        const hashToSign = require('crypto').createHash('sha256').update(chunkData).digest();
                        const sig = Buffer.from(sodium.crypto_sign_detached(hashToSign, this.identity.privateKey)).toString('hex');

                        const resPayload = Buffer.from(JSON.stringify({
                            fileId,
                            chunkIndex,
                            data: chunkData.toString('base64'),
                            chunkHash: hashToSign.toString('hex'),
                            signature: sig
                        }));

                        this.sendToSocket(socket, PACKET_TYPES.CHUNK_DATA, resPayload).catch(() => { });
                        return;
                    }
                }

                // not found
                const ackBuf = Buffer.alloc(5); // [chunk_idx 4 bytes][status 1 byte]
                ackBuf.writeUInt32BE(chunkIndex, 0);
                ackBuf.writeUInt8(0x02, 4);
                this.sendToSocket(socket, PACKET_TYPES.ACK, ackBuf).catch(() => { });

            } catch (err) { }
        } else if (pkt.type === PACKET_TYPES.CHUNK_DATA) {
            try {
                const req = JSON.parse(rawPayload.toString('utf8'));
                if (this.downloadManager && this.downloadManager.pendingRequests.has(socket)) {
                    const pending = this.downloadManager.pendingRequests.get(socket).get(req.chunkIndex);
                    if (pending) {
                        const chunkBuffer = Buffer.from(req.data, 'base64');
                        pending.resolve(chunkBuffer);
                        this.downloadManager.pendingRequests.get(socket).delete(req.chunkIndex);
                    }
                }
            } catch (err) { }
        }
    }

    _writeFrame(socket, data) {
        if (socket.destroyed) return;
        const lengthBuffer = Buffer.alloc(4);
        lengthBuffer.writeUInt32BE(data.length, 0);
        socket.write(Buffer.concat([lengthBuffer, data]));
    }
}

module.exports = TcpServer;
