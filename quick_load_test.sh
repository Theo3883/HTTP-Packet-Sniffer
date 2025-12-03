#!/bin/bash
# Quick load test with 200 requests for performance validation

echo "======================================================================"
echo "QUICK LOAD TEST - 200 Requests"
echo "======================================================================"
echo "This will generate 200 HTTP requests to validate capture performance."
echo ""

TOTAL_REQUESTS=200
CONCURRENT_JOBS=10
TARGET_URL="http://example.com"

echo "Configuration:"
echo "  Total Requests: $TOTAL_REQUESTS"
echo "  Concurrent Jobs: $CONCURRENT_JOBS"
echo "  Target URL: $TARGET_URL"
echo ""

# Counter file
COUNTER_FILE="/tmp/sniffer_quick_test_counter.txt"
echo "0" > "$COUNTER_FILE"

# Function to make HTTP request and update counter
make_request() {
    local id=$1
    local url=$2
    
    # Alternate between different request types
    if [ $((id % 4)) -eq 0 ]; then
        curl -s -o /dev/null "$url" 2>/dev/null
    elif [ $((id % 4)) -eq 1 ]; then
        curl -s -o /dev/null -H "X-Test-ID: $id" "$url" 2>/dev/null
    elif [ $((id % 4)) -eq 2 ]; then
        curl -s -I -o /dev/null "$url" 2>/dev/null
    else
        curl -s -o /dev/null "${url}?test=$id" 2>/dev/null
    fi
    
    # Update counter atomically
    lockfile="${COUNTER_FILE}.lock"
    (
        flock -x 200
        local count=$(cat "$COUNTER_FILE" 2>/dev/null || echo "0")
        echo $((count + 1)) > "$COUNTER_FILE"
    ) 200>"$lockfile"
}

export -f make_request
export COUNTER_FILE

echo "Starting quick load test..."
start_time=$(date +%s)

# Monitor progress
(
    while true; do
        count=$(cat "$COUNTER_FILE" 2>/dev/null || echo "0")
        if [ "$count" -ge "$TOTAL_REQUESTS" ]; then
            printf "\rRequests completed: %d / %d (100.0%%)\n" "$count" "$TOTAL_REQUESTS"
            break
        fi
        printf "\rRequests completed: %d / %d (%.1f%%)" "$count" "$TOTAL_REQUESTS" "$(echo "scale=1; $count * 100 / $TOTAL_REQUESTS" | bc)"
        sleep 0.2
    done
) &
MONITOR_PID=$!

# Cleanup handler
on_exit() {
    echo ""
    echo "Interrupted. Cleaning up..."
    pkill -P $$ 2>/dev/null || true
    if [ -n "${MONITOR_PID:-}" ] && kill -0 "$MONITOR_PID" 2>/dev/null; then
        kill "$MONITOR_PID" 2>/dev/null || true
    fi
    final_count=$(cat "$COUNTER_FILE" 2>/dev/null || echo "0")
    printf "\nFinal requests: %d / %d\n" "$final_count" "$TOTAL_REQUESTS"
    exit 1
}
trap 'on_exit' INT TERM

# Generate requests
seq 1 $TOTAL_REQUESTS | xargs -P $CONCURRENT_JOBS -I {} bash -c "make_request {} $TARGET_URL"

# Wait for monitor
wait $MONITOR_PID 2>/dev/null

end_time=$(date +%s)
duration=$((end_time - start_time))

echo ""
echo "======================================================================"
echo "Duration: ${duration} seconds"
echo "Average Rate: $(echo "scale=2; $TOTAL_REQUESTS / $duration" | bc) req/sec"
echo ""
echo "Expected in GUI: ~$TOTAL_REQUESTS packets (400 total: req + resp)"
echo "Check GUI now and compare Requests + Responses vs $TOTAL_REQUESTS"
echo "======================================================================"

# Cleanup
rm -f "$COUNTER_FILE" "${COUNTER_FILE}.lock"
