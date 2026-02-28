// c:\Users\PC LBS\kernel-killers\src\transfer\downloadManager.js
const crypto = require('crypto');
const fs = require('fs/promises');
const path = require('path');
const { PACKET_TYPES } = require('../network/packet');
const { saveChunk, hasChunk } = require('./storage');
const { verifyChunk } = require('./chunker');

class DownloadManager {
    constructor(peerTable, tcpServer, sessionStore, identity) {
        this.peerTable = peerTable;
        this.tcpServer = tcpServer;
        this.sessionStore = sessionStore;
        this.identity = identity;
        this.pendingRequests = new Map(); // socket -> map of expecting chunk index -> resolve/reject
    }

    async download(manifest, outputDir) {
        const fileId = manifest.file_id;
        let chunksNeeded = new Set(manifest.chunks.map(c => c.index));

        // Check local chunks first
        for (const chunk of manifest.chunks) {
            if (await hasChunk(fileId, chunk.index)) {
                chunksNeeded.delete(chunk.index);
            }
        }

        let activeDownloads = 0;
        const downloadedChunks = new Map(); // index -> Buffer
        const workQueue = Array.from(chunksNeeded).reverse(); // simple stack

        if (chunksNeeded.size > 0) {
            console.log(`[TRANSFER] Starting download of ${manifest.filename}...`);
        }

        return new Promise((resolve, reject) => {
            const peers = this.selectPeers(manifest);
            if (peers.length === 0 && chunksNeeded.size > 0) {
                return reject(new Error('No peers found with the file'));
            }

            let peerIndex = 0;

            const pump = () => {
                if (workQueue.length === 0 && activeDownloads === 0) {
                    this.reassemble(downloadedChunks, manifest, outputDir)
                        .then(filePath => resolve(filePath))
                        .catch(reject);
                    return;
                }

                while (activeDownloads < 3 && workQueue.length > 0) {
                    const chunkIdx = workQueue.pop();
                    const peer = peers[peerIndex % peers.length];
                    peerIndex++;

                    if (peer.reputation === 0) {
                        // try next
                        workQueue.push(chunkIdx);
                        continue;
                    }

                    activeDownloads++;

                    this.downloadChunk(peer, fileId, chunkIdx)
                        .then(async (data) => {
                            const chunkMeta = manifest.chunks.find(c => c.index === chunkIdx);
                            if (!(await verifyChunk(data, chunkMeta.hash))) {
                                throw new Error('HASH_MISMATCH');
                            }

                            await saveChunk(fileId, chunkIdx, data);
                            downloadedChunks.set(chunkIdx, data);
                            const totalDone = manifest.chunks.length - workQueue.length - activeDownloads + 1;
                            const pct = Math.round((totalDone / manifest.chunks.length) * 100);
                            console.log(`[TRANSFER] ${totalDone}/${manifest.chunks.length} chunks — ${pct}%`);

                            activeDownloads--;
                            pump();
                        })
                        .catch(err => {
                            activeDownloads--;

                            if (err.message === 'HASH_MISMATCH') {
                                peer.reputation -= 0.1;
                            } else if (err.message === 'TIMEOUT' || err.message === 'PEER_LOST') {
                                peer.reputation = 0;
                            }

                            // Push chunk back to work queue
                            workQueue.push(chunkIdx);
                            pump();
                        });
                }
            };

            pump();
        });
    }

    async downloadChunk(peer, fileId, chunkIndex) {
        return new Promise((resolve, reject) => {
            // Find existing socket for this peer or reject if not connected.
            // For simplicity we reject and expect tcpServer to establish connections independently or via another method,
            // but since we must request it proactively, TCP connections must be handled.
            // The assignment implies tcpServer auto-keeps connections alive, but if disconnected, we throw.
            const socket = this.tcpServer.peerSockets.get(peer.nodeId.toString('hex'));

            if (!socket || socket.destroyed) {
                return reject(new Error('PEER_LOST'));
            }

            const timeout = setTimeout(() => {
                if (this.pendingRequests.has(socket)) {
                    this.pendingRequests.get(socket).delete(chunkIndex);
                }
                reject(new Error('TIMEOUT'));
            }, 15000);

            if (!this.pendingRequests.has(socket)) {
                this.pendingRequests.set(socket, new Map());
            }

            this.pendingRequests.get(socket).set(chunkIndex, {
                resolve: (data) => { clearTimeout(timeout); resolve(data); },
                reject: (err) => { clearTimeout(timeout); reject(err); }
            });

            const reqPayload = Buffer.from(JSON.stringify({
                fileId,
                chunkIndex,
                requesterId: this.identity.publicKey.toString('hex')
            }));

            this.tcpServer.sendToSocket(socket, PACKET_TYPES.CHUNK_REQ, reqPayload).catch(err => {
                clearTimeout(timeout);
                this.pendingRequests.get(socket).delete(chunkIndex);
                reject(new Error('PEER_LOST'));
            });
        });
    }

    selectPeers(manifest) {
        const all = this.peerTable.getAll();
        const havers = all.filter(p => p.sharedFiles && p.sharedFiles.includes(manifest.file_id));
        return havers.sort((a, b) => b.reputation - a.reputation);
    }

    async reassemble(chunksMap, manifest, outputDir) {
        await fs.mkdir(outputDir, { recursive: true });
        const finalPath = path.join(outputDir, manifest.filename);
        const fd = await fs.open(finalPath, 'w');

        try {
            for (let i = 0; i < manifest.nb_chunks; i++) {
                let data = chunksMap.get(i);
                if (!data) {
                    // Read from disk instead
                    data = await fs.readFile(path.join(process.cwd(), '.archipel', 'chunks', manifest.file_id, `${i}.chunk`));
                }
                await fd.write(data, 0, data.length, i * manifest.chunk_size);
            }
        } finally {
            await fd.close();
        }

        // Hash final verify
        const verifyStream = crypto.createHash('sha256');
        const readStream = require('fs').createReadStream(finalPath);
        await new Promise((resolve, reject) => {
            readStream.on('error', reject);
            readStream.pipe(verifyStream).on('finish', resolve);
        });

        const finalHash = verifyStream.read().toString('hex');
        if (finalHash !== manifest.file_id) {
            throw new Error('FINAL_HASH_MISMATCH');
        }

        console.log(`[TRANSFER] complete: ${finalPath}`);
        return finalPath;
    }
}

module.exports = DownloadManager;
