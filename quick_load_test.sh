#!/bin/bash
echo "======================================================================"
echo "HTTP PACKET SNIFFER - QUICK LOAD TEST"
echo "======================================================================"
echo "This script will generate 100 HTTP requests quickly."

# Configuration
TOTAL_REQUESTS=100
CONCURRENT_JOBS=5
TARGET_URL="http://example.com"

echo "Configuration:"
echo "  Total Requests: $TOTAL_REQUESTS"
echo "  Concurrent Jobs: $CONCURRENT_JOBS"
echo "  Target URL: $TARGET_URL"
echo ""

# Counter
counter=0

echo "Generating HTTP requests..."

# Start time
start_time=$(date +%s)

# Make requests with variety
for i in $(seq 1 $TOTAL_REQUESTS); do
    {
        if [ $((i % 4)) -eq 0 ]; then
            curl -s -o /dev/null "$TARGET_URL" 2>/dev/null
        elif [ $((i % 4)) -eq 1 ]; then
            curl -s -o /dev/null -H "X-Test-ID: $i" "$TARGET_URL" 2>/dev/null
        elif [ $((i % 4)) -eq 2 ]; then
            curl -s -I -o /dev/null "$TARGET_URL" 2>/dev/null
        else
            curl -s -o /dev/null "${TARGET_URL}?test=$i" 2>/dev/null
        fi
        
        counter=$((counter + 1))
        if [ $((counter % 10)) -eq 0 ]; then
            printf "\rProgress: %d / %d requests" "$counter" "$TOTAL_REQUESTS"
        fi
    } &
    
    # Limit concurrency
    if [ $((i % CONCURRENT_JOBS)) -eq 0 ]; then
        wait
    fi
done

# Wait for all background jobs to complete
wait

# End time
end_time=$(date +%s)
duration=$((end_time - start_time))

echo ""
echo ""
echo "======================================================================"
echo "QUICK LOAD TEST COMPLETED"
echo "======================================================================"
echo "Total Requests Sent: $TOTAL_REQUESTS"
echo "Duration: ${duration} seconds"
if [ "$duration" -gt 0 ]; then
    echo "Average Rate: $(echo "scale=2; $TOTAL_REQUESTS / $duration" | bc 2>/dev/null || echo "N/A") requests/second"
fi
echo ""
echo "Check your sniffer output for captured HTTP requests!"
echo "======================================================================"
