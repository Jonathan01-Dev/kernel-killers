// c:\Users\PC LBS\kernel-killers\src\node.js
'use strict';

process.on('unhandledRejection', (reason) => {
    console.error('[FATAL] Unhandled rejection:', reason);
    process.exit(1);
});

require('dotenv').config();
const fs = require('fs/promises');
const path = require('path');
const { generateIdentity, loadIdentity } = require('./crypto/identity');
const PeerTable = require('./network/peerTable');
const Discovery = require('./network/discovery');
const TcpServer = require('./network/tcpServer');
const DownloadManager = require('./transfer/downloadManager');
const { listLocalChunks } = require('./transfer/storage');
const { buildPacket, parsePacket, verifyHMAC, PACKET_TYPES } = require('./network/packet');

async function getSharedFiles() {
    const chunksDir = path.join(process.cwd(), '.archipel', 'chunks');
    const shared = [];
    try {
        const fileDirs = await fs.readdir(chunksDir);
        for (const fileId of fileDirs) {
            const stat = await fs.stat(path.join(chunksDir, fileId));
            if (stat.isDirectory()) {
                const chunks = await listLocalChunks(fileId);
                if (chunks.length > 0) shared.push(fileId);
            }
        }
    } catch (err) {
        if (err.code !== 'ENOENT') console.error(`[STORAGE] Error reading chunks dir: ${err.message}`);
    }
    return shared;
}

async function main() {
    // generateIdentity is idempotent — creates key on first run, loads on subsequent
    let identity;
    try {
        identity = await generateIdentity();
    } catch (err) {
        console.error('[ARCHIPEL] Failed to load identity:', err.message);
        process.exit(1);
    }

    const tcpPort = process.env.TCP_PORT ? parseInt(process.env.TCP_PORT, 10) : 7777;

    const peerTable = new PeerTable();
    const tcpServer = new TcpServer(identity, peerTable, tcpPort);
    const discovery = new Discovery(identity, peerTable, tcpPort);

    const downloadManager = new DownloadManager(peerTable, tcpServer, tcpServer.sessionStore, identity);
    tcpServer.downloadManager = downloadManager;

    const initialSharedFiles = await getSharedFiles();

    // Start TCP before touching discovery (discovery.socket is null until start())
    await tcpServer.start();

    // Patch _sendHello to include sharedFiles in HELLO payload
    discovery._sendHello = () => {
        if (!discovery.socket) return;
        const payload = Buffer.from(JSON.stringify({
            tcpPort,
            timestamp: Date.now(),
            sharedFiles: initialSharedFiles,
        }));
        const pkt = buildPacket(PACKET_TYPES.HELLO, identity.publicKey, payload);
        discovery.socket.send(pkt, 6000, '239.255.42.99', (err) => {
            if (err) console.error(`[DISCOVERY] Error sending HELLO: ${err.message}`);
        });
    };

    discovery.start(); // socket is created here — safe to attach listeners after this

    // Enrich peer entries when we receive sharedFiles in HELLO
    discovery.socket.on('message', (msg, rinfo) => {
        try {
            if (!verifyHMAC(msg)) return;
            const pkt = parsePacket(msg);
            if (pkt.nodeId.equals(identity.publicKey)) return;
            if (pkt.type === PACKET_TYPES.HELLO) {
                const p = JSON.parse(pkt.payload.toString('utf8'));
                peerTable.upsert(pkt.nodeId, {
                    ip: rinfo.address,
                    tcpPort: p.tcpPort,
                    sharedFiles: p.sharedFiles || [],
                });
            }
        } catch (_) { }
    });

    // When a peer is discovered via UDP, attempt a TCP handshake
    discovery.socket.on('peer_discovered', async (peer) => {
        try {
            const peers = peerTable.getAll().map(p => ({
                nodeId: p.nodeId.toString('hex'),
                ip: p.ip,
                tcpPort: p.tcpPort,
                sharedFiles: p.sharedFiles || [],
            }));
            const pkt = buildPacket(PACKET_TYPES.PEER_LIST, identity.publicKey,
                Buffer.from(JSON.stringify(peers)));
            await tcpServer.sendToPeer(peer.ip, peer.tcpPort, pkt);
        } catch (_) { }
    });

    const shortId = identity.publicKey.toString('hex').substring(0, 16);
    console.log('[ARCHIPEL] Node started');
    console.log(`[ARCHIPEL] NodeID: ${shortId}`);
    console.log(`[ARCHIPEL] TCP: ${tcpPort} | Multicast: 239.255.42.99:6000`);

    process.on('SIGINT', async () => {
        console.log('\n[ARCHIPEL] Shutting down gracefully...');
        discovery.stop();
        peerTable.stop();
        await tcpServer.stop();
        process.exit(0);
    });

    // Keep process alive — prevent Node from exiting when event loop is empty
    setInterval(() => { }, 30000);
}

main().catch(err => {
    console.error(`[ARCHIPEL] Fatal error: ${err.message}`, err.stack);
    process.exit(1);
});
