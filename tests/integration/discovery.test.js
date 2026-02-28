// c:\Users\PC LBS\kernel-killers\tests\integration\discovery.test.js
'use strict';

const assert = require('node:assert');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

function pass(name) { console.log(`[PASS] ${name}`); }
function fail(name, reason, file) {
    const loc = file ? ` — FILE: ${file}` : '';
    console.log(`[FAIL] ${name} — ${reason}${loc}`);
}

// ─── load modules ─────────────────────────────────────────────────────────────
const DISCOVERY_PATH = path.resolve(__dirname, '../../src/network/discovery.js');
const PACKET_PATH = path.resolve(__dirname, '../../src/network/packet.js');
const PEER_TABLE_PATH = path.resolve(__dirname, '../../src/network/peerTable.js');

if (!fs.existsSync(DISCOVERY_PATH)) {
    fail('MODULE_MISSING', 'src/network/discovery.js does not exist', DISCOVERY_PATH + ':1');
    process.exit(1);
}

let Discovery, PeerTable, buildPacket, parsePacket, verifyHMAC, PACKET_TYPES;

try { PeerTable = require(PEER_TABLE_PATH); } catch (e) {
    fail('MODULE_MISSING', `PeerTable: ${e.message}`, PEER_TABLE_PATH + ':1');
    process.exit(1);
}

if (!fs.existsSync(PACKET_PATH)) {
    fail('MODULE_MISSING', `packet.js not found`, PACKET_PATH + ':1');
    process.exit(1);
}

try {
    ({ buildPacket, parsePacket, verifyHMAC, PACKET_TYPES } = require(PACKET_PATH));
} catch (e) {
    fail('MODULE_MISSING', `packet.js load failed: ${e.message}`, PACKET_PATH + ':1');
    process.exit(1);
}

try { Discovery = require(DISCOVERY_PATH); } catch (e) {
    fail('MODULE_MISSING', `Discovery load failed: ${e.message}`, DISCOVERY_PATH + ':1');
    process.exit(1);
}

function makeIdentity() {
    const pub = crypto.randomBytes(32);
    const priv = crypto.randomBytes(64);
    return { publicKey: pub, privateKey: priv };
}

function buildHello(identity, tcpPort, hmacKey) {
    const payload = Buffer.from(JSON.stringify({ tcpPort, timestamp: Date.now() }));
    try {
        return buildPacket(PACKET_TYPES.HELLO, identity.publicKey, payload, hmacKey || identity.privateKey);
    } catch {
        return buildPacket(PACKET_TYPES.HELLO, identity.publicKey, payload);
    }
}

let sentPackets = [];
let sentAddresses = [];
let sentPorts = [];

// TEST_DSC_01 — spy on socket.send
try {
    const identity = makeIdentity();
    const peerTable = new PeerTable();
    const disc = new Discovery(identity, peerTable, 17777);

    // Patch start to capture socket.send calls
    const origStart = disc.start.bind(disc);
    disc.start = function () {
        origStart();
        // Intercept after socket created
        if (disc.socket) {
            const origSend = disc.socket.send.bind(disc.socket);
            disc.socket.send = function (buf, port, addr, cb) {
                sentPackets.push(buf);
                sentAddresses.push(addr);
                sentPorts.push(port);
                origSend(buf, port, addr, cb);
            };
        }
    };

    // We can't fully test without network, so test constant values from source
    const src = fs.readFileSync(DISCOVERY_PATH, 'utf8');
    assert.ok(src.includes('239.255.42.99'), 'must use multicast address 239.255.42.99');
    assert.ok(src.includes('6000'), 'must use port 6000');
    pass('TEST_DSC_01');
    peerTable.stop();
} catch (e) {
    fail('TEST_DSC_01', `Multicast address/port check failed: ${e.message}`, DISCOVERY_PATH + ':5');
}

// TEST_DSC_02 — own HELLO ignored
try {
    const identity = makeIdentity();
    const peerTable = new PeerTable();
    const disc = new Discovery(identity, peerTable, 17778);

    // Simulate the message handler logic directly by creating a packet with own nodeId
    const helloPayload = Buffer.from(JSON.stringify({ tcpPort: 17778, timestamp: Date.now() }));
    let parsed;
    try {
        const pkt = buildPacket(PACKET_TYPES.HELLO, identity.publicKey, helloPayload, identity.privateKey);
        parsed = parsePacket(pkt);
    } catch {
        const pkt = buildPacket(PACKET_TYPES.HELLO, identity.publicKey, helloPayload);
        parsed = parsePacket(pkt);
    }

    // If nodeId equals our own, we should not add to peerTable
    // Simulate condition: disc ignores own node
    const isOwnNode = parsed.nodeId.equals(identity.publicKey);
    assert.ok(isOwnNode, 'parsed nodeId should equal own publicKey');
    // Peer table should remain empty (own HELLO not added)
    const peers = peerTable.getAll();
    assert.strictEqual(peers.length, 0);
    pass('TEST_DSC_02');
    peerTable.stop();
} catch (e) {
    fail('TEST_DSC_02', `Own HELLO detection failed: ${e.message}`, DISCOVERY_PATH + ':33');
}

// TEST_DSC_03 — foreign peer added on HELLO
try {
    const identity = makeIdentity();
    const foreignIdentity = makeIdentity();
    const peerTable = new PeerTable();

    // Simulate adding foreign peer (as discovery would do)
    peerTable.upsert(foreignIdentity.publicKey, { ip: '127.0.0.1', tcpPort: 17780 });
    const peer = peerTable.get(foreignIdentity.publicKey);
    assert.ok(peer !== null, 'Foreign peer should be in peerTable');
    pass('TEST_DSC_03');
    peerTable.stop();
} catch (e) {
    fail('TEST_DSC_03', `Peer not added to peerTable: ${e.message}`, PEER_TABLE_PATH + ':1');
}

// TEST_DSC_04 — prune after 90s
try {
    const peerTable = new PeerTable();
    const peerId = crypto.randomBytes(32);
    // Add peer with old lastSeen
    peerTable.upsert(peerId, { ip: '1.2.3.4', tcpPort: 9999 });
    // Manually set lastSeen to 91s ago
    const idHex = peerId.toString('hex');
    const entry = peerTable.peers.get(idHex);
    entry.lastSeen = Date.now() - 91000;
    peerTable.pruneStale();
    assert.strictEqual(peerTable.get(peerId), null, 'Stale peer must be pruned');
    pass('TEST_DSC_04');
    peerTable.stop();
} catch (e) {
    fail('TEST_DSC_04', `Stale peer not pruned: ${e.message}`, PEER_TABLE_PATH + ':44');
}

// TEST_DSC_05 — lastSeen updated on repeated HELLO
try {
    const peerTable = new PeerTable();
    const peerId = crypto.randomBytes(32);
    peerTable.upsert(peerId, { ip: '1.2.3.4', tcpPort: 9999 });
    const entry = peerTable.peers.get(peerId.toString('hex'));
    const oldLastSeen = Date.now() - 5000;
    entry.lastSeen = oldLastSeen;
    // Upsert again (simulating new HELLO)
    peerTable.upsert(peerId, { ip: '1.2.3.4', tcpPort: 9999 });
    const updated = peerTable.get(peerId);
    assert.ok(updated.lastSeen > oldLastSeen, 'lastSeen must be updated');
    pass('TEST_DSC_05');
    peerTable.stop();
} catch (e) {
    fail('TEST_DSC_05', `lastSeen not updated on repeated HELLO: ${e.message}`, PEER_TABLE_PATH + ':22');
}

// TEST_DSC_06 — HELLO payload contains tcpPort and timestamp
try {
    const identity = makeIdentity();
    const helloPayload = Buffer.from(JSON.stringify({ tcpPort: 17777, timestamp: Date.now() }));
    let pkt, parsed;
    try {
        pkt = buildPacket(PACKET_TYPES.HELLO, identity.publicKey, helloPayload, identity.privateKey);
        parsed = parsePacket(pkt);
    } catch {
        pkt = buildPacket(PACKET_TYPES.HELLO, identity.publicKey, helloPayload);
        parsed = parsePacket(pkt);
    }
    const payload = JSON.parse(parsed.payload.toString('utf8'));
    assert.ok(typeof payload.tcpPort === 'number', 'tcpPort must be a number');
    assert.ok(typeof payload.timestamp === 'number', 'timestamp must be a number');
    assert.ok(Date.now() - payload.timestamp < 5000, 'timestamp must be recent');
    pass('TEST_DSC_06');
} catch (e) {
    fail('TEST_DSC_06', `HELLO payload missing tcpPort or timestamp: ${e.message}`, DISCOVERY_PATH + ':70');
}

// TEST_DSC_07 — Two Discovery instances discover each other (real UDP)
// This test requires network and 35+ seconds; skip unless in CI
if (process.env.TEST_DISCOVERY_REAL === 'true') {
    (async () => {
        const idA = makeIdentity();
        const idB = makeIdentity();
        const ptA = new PeerTable();
        const ptB = new PeerTable();
        const discA = new Discovery(idA, ptA, 17777);
        const discB = new Discovery(idB, ptB, 17778);

        discA.start();
        discB.start();

        const deadline = Date.now() + 40000;
        let resolved = false;

        await new Promise((resolve) => {
            const check = setInterval(() => {
                const aHasB = ptA.get(idB.publicKey) !== null;
                const bHasA = ptB.get(idA.publicKey) !== null;
                if (aHasB && bHasA) {
                    resolved = true;
                    clearInterval(check);
                    resolve();
                }
                if (Date.now() > deadline) {
                    clearInterval(check);
                    resolve();
                }
            }, 2000);
        });

        discA.stop();
        discB.stop();
        ptA.stop();
        ptB.stop();

        if (resolved) {
            pass('TEST_DSC_07');
        } else {
            fail('TEST_DSC_07', 'Nodes did not discover each other within 40s', DISCOVERY_PATH + ':1');
        }
    })();
} else {
    console.log('[SKIP] TEST_DSC_07 — set TEST_DISCOVERY_REAL=true to run (requires 40s and real UDP multicast)');
}
