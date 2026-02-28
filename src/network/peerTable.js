// c:\Users\PC LBS\kernel-killers\src\network\peerTable.js
class PeerTable {
  constructor() {
    this.peers = new Map();
    this.pruneInterval = setInterval(() => this.pruneStale(), 30000);
  }

  upsert(nodeId, { ip, tcpPort, sharedFiles = [], reputation = 1.0 }) {
    const idHex = nodeId.toString('hex');
    const existing = this.peers.get(idHex);
    
    // Create new or update existing
    const entry = existing ? { ...existing } : {
        nodeId,
        ip,
        tcpPort,
        sharedFiles,
        reputation
    };
    
    // Always update lastSeen and strictly update new values
    entry.lastSeen = Date.now();
    if (!existing) {
        entry.ip = ip;
        entry.tcpPort = tcpPort;
    }
    
    this.peers.set(idHex, entry);
  }

  get(nodeId) {
    return this.peers.get(nodeId.toString('hex')) || null;
  }

  getAll() {
    this.pruneStale();
    return Array.from(this.peers.values());
  }

  remove(nodeId) {
    this.peers.delete(nodeId.toString('hex'));
  }

  pruneStale(timeoutMs = 90000) {
    const now = Date.now();
    for (const [idHex, peer] of this.peers.entries()) {
      if (now - peer.lastSeen > timeoutMs) {
        this.peers.delete(idHex);
      }
    }
  }

  stop() {
      clearInterval(this.pruneInterval);
  }
}

module.exports = PeerTable;
