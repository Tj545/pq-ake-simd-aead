#!/bin/bash
cd ~/myproject/checking
rm -f bench.log
pkill -9 server 2>/dev/null
pkill -9 client 2>/dev/null
rm -f /tmp/srv_in
sleep 1

mkfifo /tmp/srv_in
nohup ./server < /tmp/srv_in > bench.log 2>&1 &
SERVER_PID=$!
exec 9>/tmp/srv_in
echo "Server started (PID $SERVER_PID)"
sleep 2

for i in $(seq 1 10); do
    (
        for j in $(seq 1 100); do
            echo "msg $j from client $i"
            sleep 0.01
        done
        sleep 8
        echo "quit"
    ) | ./client Client$i > /dev/null 2>&1 &
done
echo "10 clients launched"

sleep 4
echo "Sending 30 broadcasts..."
for k in $(seq 1 30); do
    echo "broadcast server message $k" >&9
    sleep 0.15
done
echo "Broadcasts sent."

sleep 10

kill -INT $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null
exec 9>&-
rm -f /tmp/srv_in
sleep 1

echo ""
echo "==================================================="
echo "REPORT"
echo "==================================================="
tail -100 bench.log
