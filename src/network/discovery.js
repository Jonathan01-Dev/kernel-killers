// src/network/discovery.js
'use strict';

const dgram = require('dgram');
const { buildPacket, parsePacket, verifyHMAC, PACKET_TYPES } = require('./packet');

const MULTICAST_ADDR = '239.255.42.99';
const MULTICAST_PORT = 6000;

class Discovery {
    constructor(identity, peerTable, tcpPort) {
        this.identity = identity;
        this.peerTable = peerTable;
        this.tcpPort = tcpPort;
        this.socket = null;
        this.interval = null;
    }

    start() {
        this.socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });

        this.socket.on('error', (err) => {
            console.error('[DISCOVERY] error:', err.message);
        });

        this.socket.on('message', (msg, rinfo) => this._onMessage(msg, rinfo));

        this.socket.bind(MULTICAST_PORT, () => {
            try {
                this.socket.addMembership(MULTICAST_ADDR);
                this.socket.setMulticastLoopback(true);
            } catch (e) {
                console.error('[DISCOVERY] multicast join error:', e.message);
            }

            this._sendHello();
            this.interval = setInterval(() => this._sendHello(), 30000);
        });
    }

    stop() {
        if (this.interval) clearInterval(this.interval);
        if (this.socket) {
            try { this.socket.dropMembership(MULTICAST_ADDR); } catch (_) { }
            try { this.socket.close(); } catch (_) { }
        }
    }

    _sendHello() {
        if (!this.socket) return;
        const payload = Buffer.from(JSON.stringify({
            tcpPort: this.tcpPort,
            timestamp: Date.now(),
        }));

        const pkt = buildPacket(PACKET_TYPES.HELLO, this.identity.publicKey, payload);

        // 1. Send via Multicast (Cleanest, works on real switches)
        this.socket.send(pkt, MULTICAST_PORT, MULTICAST_ADDR, (err) => {
            if (err) console.error('[DISCOVERY] send error:', err.message);
        });

        // 2. Send via Global Broadcast (Fallback for Windows Mobile Hotspot and Android AP isolation)
        try {
            this.socket.setBroadcast(true);
            this.socket.send(pkt, MULTICAST_PORT, '255.255.255.255', () => { });
        } catch (_) { }
    }

    _onMessage(msg, rinfo) {
        try {
            const pkt = parsePacket(msg);
            if (!verifyHMAC(msg)) return;
            if (pkt.nodeId.equals(this.identity.publicKey)) return; // ignore self

            if (pkt.type === PACKET_TYPES.HELLO) {
                const data = JSON.parse(pkt.payload.toString('utf8'));
                this.peerTable.upsert(pkt.nodeId, {
                    ip: rinfo.address,
                    tcpPort: data.tcpPort,
                });
                console.log(
                    `[DISCOVERY] HELLO from ${pkt.nodeId.toString('hex').slice(0, 8)} @ ${rinfo.address}:${data.tcpPort}`
                );
                this.socket.emit('peer_discovered', {
                    nodeId: pkt.nodeId,
                    ip: rinfo.address,
                    tcpPort: data.tcpPort,
                });
            }
        } catch (_) {
            // Drop malformed packets silently
        }
    }
}

module.exports = Discovery;
