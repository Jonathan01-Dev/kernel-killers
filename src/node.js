// c:\Users\PC LBS\kernel-killers\src\node.js
require('dotenv').config();
const fs = require('fs/promises');
const path = require('path');
const { loadIdentity } = require('./crypto/identity');
const PeerTable = require('./network/peerTable');
const Discovery = require('./network/discovery');
const TcpServer = require('./network/tcpServer');
const DownloadManager = require('./transfer/downloadManager');
const { listLocalChunks } = require('./transfer/storage');
const { buildPacket, PACKET_TYPES } = require('./network/packet');
const { encodeManifest } = require('./transfer/manifest');

async function getSharedFiles() {
    const chunksDir = path.join(process.cwd(), '.archipel', 'chunks');
    const shared = [];
    try {
        const fileDirs = await fs.readdir(chunksDir);
        for (const fileId of fileDirs) {
            const stat = await fs.stat(path.join(chunksDir, fileId));
            if (stat.isDirectory()) {
                const chunks = await listLocalChunks(fileId);
                if (chunks.length > 0) {
                    shared.push(fileId);
                }
            }
        }
    } catch (err) {
        if (err.code !== 'ENOENT') console.error(`[STORAGE] Error reading chunks dir: ${err.message}`);
    }
    return shared;
}

async function main() {
    const identity = loadIdentity();

    const tcpPort = process.env.TCP_PORT ? parseInt(process.env.TCP_PORT, 10) : 7777;

    const peerTable = new PeerTable();
    const tcpServer = new TcpServer(identity, peerTable, tcpPort);
    const discovery = new Discovery(identity, peerTable, tcpPort);

    // Link components
    const downloadManager = new DownloadManager(peerTable, tcpServer, tcpServer.sessionStore, identity);
    tcpServer.downloadManager = downloadManager;

    const initialSharedFiles = await getSharedFiles();

    // Custom patch for Discovery class HELLO logic
    // Update HELLO sending to include shared_files
    const _originalSendHello = discovery._sendHello.bind(discovery);
    discovery._sendHello = () => {
        const payload = Buffer.from(JSON.stringify({
            tcpPort: tcpPort,
            timestamp: Date.now(),
            sharedFiles: initialSharedFiles
        }));
        const pktStr = buildPacket(PACKET_TYPES.HELLO, identity.publicKey, payload, identity.privateKey);
        discovery.socket.send(pktStr, 6000, '239.255.42.99', (err) => {
            if (err) console.error(`[DISCOVERY] Error sending HELLO: ${err.message}`);
        });
    };

    // Process inbound HELLO with sharedFiles
    discovery.socket.on('message', (msg, rinfo) => {
        try {
            const { parsePacket, verifyHMAC } = require('./network/packet');
            if (!verifyHMAC(msg)) return;
            const pkt = parsePacket(msg);
            if (pkt.nodeId.equals(identity.publicKey)) return;
            if (pkt.type === PACKET_TYPES.HELLO) {
                const p = JSON.parse(pkt.payload.toString('utf8'));
                peerTable.upsert(pkt.nodeId, {
                    ip: rinfo.address,
                    tcpPort: p.tcpPort,
                    sharedFiles: p.sharedFiles || []
                });
            }
        } catch (e) { }
    });

    discovery.socket.on('peer_discovered', async (peer) => {
        try {
            const peers = peerTable.getAll().map(p => ({
                nodeId: p.nodeId.toString('hex'),
                ip: p.ip,
                tcpPort: p.tcpPort,
                sharedFiles: p.sharedFiles || []
            }));

            await tcpServer.sendToPeer(peer.ip, peer.tcpPort, Buffer.from(JSON.stringify({ type: PACKET_TYPES.PEER_LIST, payload: Buffer.from(JSON.stringify(peers)) })));
        } catch (err) { }
    });

    await tcpServer.start();
    discovery.start();

    const nodeIdHex = identity.publicKey.toString('hex');
    const shortId = nodeIdHex.substring(0, 16);

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
}

main().catch(err => {
    console.error(`[ARCHIPEL] Fatal error: ${err.message}`);
    process.exit(1);
});
