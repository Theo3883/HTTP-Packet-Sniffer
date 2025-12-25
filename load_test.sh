#!/bin/bash
# Load Testing Script for HTTP Packet Sniffer
# Generates 3000 HTTP requests to test packet capture under load

echo "======================================================================"
echo "HTTP PACKET SNIFFER - LOAD TEST"
echo "======================================================================"

# Configuration
TOTAL_REQUESTS=3000
CONCURRENT_JOBS=10
TARGET_URL="http://example.com"

echo "Configuration:"
echo "  Total Requests: $TOTAL_REQUESTS"
echo "  Concurrent Jobs: $CONCURRENT_JOBS"
echo "  Target URL: $TARGET_URL"
echo ""

# Counter file
COUNTER_FILE="/tmp/sniffer_load_test_counter.txt"
# Initialize counter only if it doesn't already exist (allows resuming)
if [ ! -f "$COUNTER_FILE" ]; then
    echo "0" > "$COUNTER_FILE"
fi

# Function to make HTTP request and update counter
make_request() {
    local id=$1
    local url=$2
    
    # Alternate between different request types for variety
    if [ $((id % 4)) -eq 0 ]; then
        # GET request
        curl -s -o /dev/null "$url" 2>/dev/null
    elif [ $((id % 4)) -eq 1 ]; then
        # GET with custom headers
        curl -s -o /dev/null -H "X-Test-ID: $id" -H "User-Agent: LoadTest/1.0" "$url" 2>/dev/null
    elif [ $((id % 4)) -eq 2 ]; then
        # HEAD request
        curl -s -I -o /dev/null "$url" 2>/dev/null
    else
        # GET with query parameters
        curl -s -o /dev/null "${url}?test=$id&timestamp=$(date +%s)" 2>/dev/null
    fi
    
    # Update counter atomically using a lockfile to avoid races
    lockfile="${COUNTER_FILE}.lock"
    (
        flock -x 200
        local count=$(cat "$COUNTER_FILE" 2>/dev/null || echo "0")
        echo $((count + 1)) > "$COUNTER_FILE"
    ) 200>"$lockfile"
}

export -f make_request
export COUNTER_FILE

echo "Starting load test..."
echo "Progress will be displayed below:"
echo ""

# Start time
start_time=$(date +%s)

# Monitor progress in background
monitor_running=true
on_exit() {
    # Called on SIGINT/SIGTERM
    echo ""
    echo "Interrupted. Cleaning up..."
    # Kill child processes spawned by this script (requests)
    pkill -P $$ 2>/dev/null || true
    # Kill the monitor if running
    if [ -n "${MONITOR_PID:-}" ] && kill -0 "$MONITOR_PID" 2>/dev/null; then
        kill "$MONITOR_PID" 2>/dev/null || true
    fi
    final_count=$(cat "$COUNTER_FILE" 2>/dev/null || echo "0")
    printf "\nFinal requests completed: %d / %d (%.1f%%)\n" "$final_count" "$TOTAL_REQUESTS" "$(echo "scale=1; $final_count * 100 / $TOTAL_REQUESTS" | bc 2>/dev/null || echo "N/A")"
    # don't remove counter file so user can inspect or resume
    exit 1
}
trap 'on_exit' INT TERM

(
    while true; do
        count=$(cat "$COUNTER_FILE" 2>/dev/null || echo "0")
        if [ "$count" -ge "$TOTAL_REQUESTS" ]; then
            printf "\rRequests completed: %d / %d (%.1f%%)\n" "$count" "$TOTAL_REQUESTS" "$(echo "scale=1; $count * 100 / $TOTAL_REQUESTS" | bc 2>/dev/null || echo "100.0")"
            break
        fi
        printf "\rRequests completed: %d / %d (%.1f%%)" "$count" "$TOTAL_REQUESTS" "$(echo "scale=1; $count * 100 / $TOTAL_REQUESTS" | bc 2>/dev/null || echo "0.0")"
        sleep 0.5
    done
) &
MONITOR_PID=$!

# Generate requests with controlled concurrency
seq 1 $TOTAL_REQUESTS | xargs -P $CONCURRENT_JOBS -I {} bash -c "make_request {} $TARGET_URL"

# Wait for monitor to finish
wait $MONITOR_PID 2>/dev/null

# End time
end_time=$(date +%s)
duration=$((end_time - start_time))

# Final statistics
echo ""
echo ""
echo "======================================================================"
echo "LOAD TEST COMPLETED"
echo "======================================================================"
echo "Total Requests Sent: $TOTAL_REQUESTS"
echo "Duration: ${duration} seconds"
if [ "$duration" -gt 0 ]; then
    echo "Average Rate: $(echo "scale=2; $TOTAL_REQUESTS / $duration" | bc 2>/dev/null || echo "N/A") requests/second"
else
    echo "Average Rate: N/A (duration too short)"
fi
echo ""
echo "Check the packet sniffer for:"
echo "   ✓ Number of packets captured"
echo "   ✓ Performance stats (packets/second, error rate)"
echo "   ✓ No crashes or errors"
echo "   ✓ Filter functionality still working"
echo "   ✓ Inspection functionality still working"
echo ""
echo "Expected captures: ~$TOTAL_REQUESTS requests (may vary due to caching)"
echo "======================================================================"

# Cleanup
rm -f "$COUNTER_FILE" "${COUNTER_FILE}.lock"
