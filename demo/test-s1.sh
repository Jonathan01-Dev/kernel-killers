#!/bin/bash
# c:\Users\PC LBS\kernel-killers\demo\test-s1.sh

# Launch 3 nodes on ports 7777, 7778, 7779
TCP_PORT=7777 node src/node.js &
TCP_PORT=7778 node src/node.js &
TCP_PORT=7779 node src/node.js &

echo "3 nodes started. Watch peer discovery logs."
echo "Kill all with: pkill -f 'node src/node.js'"
