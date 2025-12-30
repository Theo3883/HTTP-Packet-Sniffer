#!/bin/bash
# Comprehensive HTTP methods test - Tests all HTTP request types

echo "======================================================================"
echo "HTTP METHODS TEST - All Request Types"
echo "======================================================================"
echo "This will generate various HTTP methods (GET, POST, PUT, DELETE, etc.)"
echo ""

TOTAL_REQUESTS=140
CONCURRENT_JOBS=7
TARGET_URL="http://httpbin.org"

echo "Configuration:"
echo "  Total Requests: $TOTAL_REQUESTS"
echo "  Concurrent Jobs: $CONCURRENT_JOBS"
echo "  Target URL: $TARGET_URL"
echo "  Methods: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS"
echo ""

# Counter file
COUNTER_FILE="/tmp/sniffer_methods_test_counter.txt"
echo "0" > "$COUNTER_FILE"

# Function to make HTTP request based on method type
make_request() {
    local id=$1
    local base_url=$2
    
    # Cycle through 7 different HTTP methods
    local method_type=$((id % 7))
    
    case $method_type in
        0)
            # GET request
            curl -s -o /dev/null -X GET "${base_url}/get?id=$id" 2>/dev/null
            ;;
        1)
            # POST request with JSON data
            curl -s -o /dev/null -X POST "${base_url}/post" \
                -H "Content-Type: application/json" \
                -d "{\"id\":$id,\"test\":\"data\",\"timestamp\":$(date +%s)}" 2>/dev/null
            ;;
        2)
            # PUT request with JSON data
            curl -s -o /dev/null -X PUT "${base_url}/put" \
                -H "Content-Type: application/json" \
                -d "{\"id\":$id,\"action\":\"update\"}" 2>/dev/null
            ;;
        3)
            # DELETE request
            curl -s -o /dev/null -X DELETE "${base_url}/delete?id=$id" 2>/dev/null
            ;;
        4)
            # PATCH request with JSON data
            curl -s -o /dev/null -X PATCH "${base_url}/patch" \
                -H "Content-Type: application/json" \
                -d "{\"id\":$id,\"field\":\"value\"}" 2>/dev/null
            ;;
        5)
            # HEAD request (only headers, no body)
            curl -s -I -o /dev/null "${base_url}/get" 2>/dev/null
            ;;
        6)
            # OPTIONS request
            curl -s -o /dev/null -X OPTIONS "${base_url}/get" \
                -H "Origin: http://example.com" 2>/dev/null
            ;;
    esac
    
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

echo "Starting HTTP methods test..."
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
echo "TEST SUMMARY"
echo "======================================================================"
echo "Duration: ${duration} seconds"
echo "Average Rate: $(echo "scale=2; $TOTAL_REQUESTS / $duration" | bc) req/sec"
echo ""
echo "Method Distribution (approximately):"
echo "  GET:     20 requests"
echo "  POST:    20 requests"
echo "  PUT:     20 requests"
echo "  DELETE:  20 requests"
echo "  PATCH:   20 requests"
echo "  HEAD:    20 requests"
echo "  OPTIONS: 20 requests"
echo ""
echo "Expected in GUI: ~$TOTAL_REQUESTS packets (280 total: req + resp)"
echo "Check GUI now and verify all HTTP methods are captured correctly"
echo "======================================================================"

# Cleanup
rm -f "$COUNTER_FILE" "${COUNTER_FILE}.lock"
