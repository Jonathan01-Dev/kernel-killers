#!/bin/bash
# c:\Users\PC LBS\kernel-killers\demo\test-s3.sh

# Generate a 50MB test file
dd if=/dev/urandom of=/tmp/test50mb.bin bs=1M count=50
SHA_ORIG=$(sha256sum /tmp/test50mb.bin | cut -d' ' -f1)
echo "Original SHA256: $SHA_ORIG"

# Start 3 nodes
TCP_PORT=7777 node src/node.js &
sleep 2
TCP_PORT=7778 node src/node.js &
TCP_PORT=7779 node src/node.js &
sleep 5

echo "Send file from node 7777 to peers..."
# (archipel send command will be implemented in Sprint 4)
echo "Expected: all nodes log [TRANSFER] complete"
echo "Verify: sha256sum of received file equals $SHA_ORIG"

echo "Kill all with: pkill -f 'node src/node.js'"
