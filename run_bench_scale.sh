#!/bin/bash
N=${1:-10}
cd ~/myproject/checking
rm -f bench_scale_${N}.log

pkill -9 server 2>/dev/null
pkill -9 client 2>/dev/null
rm -f /tmp/srv_in
sleep 1

mkfifo /tmp/srv_in
nohup ./server < /tmp/srv_in > bench_scale_${N}.log 2>&1 &
SERVER_PID=$!

# Open FIFO for writing
exec 9>/tmp/srv_in
echo "[$(date +%T)] Server started (PID $SERVER_PID)"
sleep 2

echo "[$(date +%T)] Launching $N clients..."
for i in $(seq 1 $N); do
    (
        for j in $(seq 1 100); do
            echo "msg $j from client $i"
            sleep 0.01
        done
        sleep 20
        echo "quit"
    ) | ./client Client$i > /dev/null 2>&1 &
done

echo "[$(date +%T)] All $N clients launched, waiting..."
SLEEP_TIME=$((15 + N/10))
sleep $SLEEP_TIME

echo "[$(date +%T)] Sending 10 broadcasts..."
for k in $(seq 1 10); do
    echo "broadcast scale test msg $k" >&9
    sleep 0.2
done

sleep 3

echo "[$(date +%T)] Sending quit via FIFO..."
echo "quit" >&9
sleep 1

# CRITICAL: close the FIFO writer BEFORE waiting
exec 9>&-
rm -f /tmp/srv_in

echo "[$(date +%T)] Waiting for server to exit..."
# Give it 5 seconds to see 'quit' and print report on its own
for i in 1 2 3 4 5; do
    if ! kill -0 $SERVER_PID 2>/dev/null; then
        break
    fi
    sleep 1
done

# If still alive, force SIGINT
if kill -0 $SERVER_PID 2>/dev/null; then
    echo "[$(date +%T)] Server still alive, sending SIGINT..."
    kill -INT $SERVER_PID
    sleep 2
fi

# Final cleanup
if kill -0 $SERVER_PID 2>/dev/null; then
    echo "[$(date +%T)] Force killing..."
    kill -9 $SERVER_PID
fi
wait $SERVER_PID 2>/dev/null
pkill -9 client 2>/dev/null
sleep 1

echo ""
echo "==================================================="
echo "RESULTS FOR N=$N CLIENTS"
echo "==================================================="
sed -n '/CRYPTOGRAPHIC PERFORMANCE REPORT/,$p' bench_scale_${N}.log
