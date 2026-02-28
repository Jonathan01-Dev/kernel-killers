#!/bin/bash
# c:\Users\PC LBS\kernel-killers\demo\demo-jury.sh
# ARCHIPEL — Jury Demo Script

set -e
echo "=== ARCHIPEL Demo ==="

START_TIME=$SECONDS
function timing() {
    elapsed=$(($SECONDS - $START_TIME))
    echo "[T+${elapsed}s] $1"
}

# Cleanup old state
pkill -f 'node src/cli/commands.js' || true
rm -rf .archipel/
mkdir -p .archipel/

# Step 1: Start 3 nodes
timing "Starting 3 nodes..."
TCP_PORT=7777 node src/cli/commands.js start > .archipel/node1.log 2>&1 &
NODE1_PID=$!
TCP_PORT=7778 node src/cli/commands.js start > .archipel/node2.log 2>&1 &
NODE2_PID=$!
TCP_PORT=7779 node src/cli/commands.js start > .archipel/node3.log 2>&1 &
NODE3_PID=$!

timing "Step 1 complete"

# Step 2: Wait for peer discovery
timing "Waiting for peer discovery (max 35s)..."
for i in {1..35}; do
    peers_out=$(node src/cli/commands.js peers)
    lines=$(echo "$peers_out" | wc -l)
    if [ "$lines" -ge 4 ]; then # header + 2 peers roughly
         break
    fi
    sleep 1
done
timing "Step 2 complete"

# Fetch Node2 ID
PEER2_ID=$(node src/cli/commands.js peers | grep "7778" | awk '{print $1}')

# Step 3: Send encrypted message node1 → node2
timing "Sending encrypted message to node 7778 (ID: $PEER2_ID)..."
TCP_PORT=7780 node src/cli/commands.js msg $PEER2_ID "Hello from Jury Script!"
sleep 2
timing "Step 3 complete"

# Step 4: Generate 50MB test file + transfer
timing "Generating 50MB test file..."
dd if=/dev/urandom of=/tmp/archipel_50mb.bin bs=1M count=50 2>/dev/null
SHA_ORIG=$(sha256sum /tmp/archipel_50mb.bin | cut -d' ' -f1)
echo "Original SHA256: $SHA_ORIG"

timing "Transferring file and shutting down node 2 midway to test fallback..."
# node1 (run temporarily on 7781) sends file to node2
TCP_PORT=7781 node src/cli/commands.js send $PEER2_ID /tmp/archipel_50mb.bin &
SEND_PID=$!

# Let transfer run a bit
sleep 5
kill -9 $NODE2_PID 2>/dev/null || true
echo "Node 2 killed mid-transfer."

wait $SEND_PID || true
timing "Step 4 complete"

# Step 5: Verify SHA-256 integrity (Since node 2 is dead, node 3 continues or we just verify node 3 received it eventually via MANIFEST request)
# Since archipel send currently only fires it directly at one peer, the fallback logic applies slightly differently.
# But demonstrating download from node 3:
timing "Node 3 attempting manual download of $SHA_ORIG..."
TCP_PORT=7782 node src/cli/commands.js download $SHA_ORIG || true
timing "Step 5 complete"

# Step 6: Verify final files
if [ -f downloads/archipel_50mb.bin ]; then
    SHA_DOWN=$(sha256sum downloads/archipel_50mb.bin | cut -d' ' -f1)
    if [ "$SHA_ORIG" == "$SHA_DOWN" ]; then
        echo "MATCH: $SHA_DOWN"
    else
        echo "MISMATCH!"
    fi
fi
timing "Step 6 complete"

# Step 7: Print final status
timing "Final status dump:"
node src/cli/commands.js status
pkill -f 'node src/cli/commands.js' || true

timing "Step 7 complete"
exit 0
