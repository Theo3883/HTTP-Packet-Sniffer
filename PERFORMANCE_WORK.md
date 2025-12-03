PERFORMANCE WORK — HTTP PACKET SNIFFER
======================================

Overview
--------
This document summarizes all performance and robustness work done in Phases 5–6 for the HTTP packet sniffer. It explains architecture changes, component responsibilities, tuning knobs, how to run tests and load tests, observed benchmarks, and troubleshooting steps.

Goals
-----
- Prevent packet loss under high request rates
- Keep GUI responsive during bursts
PERFORMANCE WORK — HTTP PACKET SNIFFER
======================================

Detailed Performance Deep-Dive
------------------------------
This document expands the high-level summary with a complete, actionable explanation of how the performance subsystem works, where packets can be dropped, how to measure and interpret metrics, and concrete tuning recommendations.

1) End-to-end data flow (step-by-step)
-------------------------------------
- Capture thread (producer)
  - The sniffer opens a raw AF_PACKET socket and calls `recvfrom(SOCKET_BUFFER_SIZE)` to receive frames from the kernel.
  - Immediately after receiving a frame, the sniffer calls `PerformanceMonitor.increment_packets()` so the metric reflects observed frames even if parsing later fails.
  - Frames are passed to parser pipeline: `EthernetParser.parse()` -> `IPv4Parser.parse()` -> `TCPParser.parse()` -> HTTP parser.
  - If HTTP content is detected, the sniffer constructs an `HTTPRequestInfo` or `HTTPResponseInfo` DTO and calls `_send_request()` / `_send_response()`.

- Enqueueing (producer -> queue)
  - `_send_request/_send_response` use `gui_queue.put(..., block=True, timeout=0.1)` by default. This blocks briefly (up to 100 ms) if the queue is full, allowing backpressure without unlimited memory growth.
  - If `put()` times out, the code logs a `queue_full` error through `ErrorHandler` and the packet is dropped.

- GUI queue and consumption (buffer -> consumer)
  - `gui_queue` is created with `queue.Queue(maxsize=5000)` by default and acts as the buffer between capture and UI.
  - The GUI runs `_process_queue()` on a repeating timer (`root.after(GUI_UPDATE_INTERVAL_MS)`), and that function processes up to `max_batch` items per cycle (default 50). Batch processing amortizes the cost of UI updates and increases throughput.

- GUI display and final accounting
  - Each processed DTO updates internal counters (`request_count`, `response_count`) and updates the view.
  - The sniffer also exposes `get_performance_stats()` (reads `PerformanceMonitor` + internal HTTP counters) for external inspection.

2) Where packets are lost (and why)
----------------------------------
- Kernel/driver drops: If the NIC or kernel ring buffer is saturated, frames can be dropped before reaching user space. This will not be visible to `recvfrom()` or `PerformanceMonitor`.
- Application-level drops (intentional protection): If `gui_queue` is full and `queue.put()` times out, the packet is intentionally dropped and `ErrorHandler` logs `queue_full`. This prevents unlimited memory growth while allowing brief blocking.
- Legacy/drop by rate-limiter: Previously a RateLimiter in the sniffer prevented queuing; that pattern was removed to avoid losing packets at the producer. The RateLimiter remains available for GUI-level pacing only.

3) Component internals and concurrency details
--------------------------------------------
- `PerformanceMonitor` (utils/performance.py)
  - Thread-safe via `self.lock`.
  - `increment_packets()` and `increment_errors()` update counters.
  - `get_stats()` computes `packets_per_second = total_packets / elapsed_seconds`.

- `ErrorHandler` (utils/performance.py)
  - Keeps a bounded deque of recent errors and contexts for quick inspection. Use `get_recent_errors(n)` to examine.

- `PacketBuffer` (utils/performance.py)
  - A bounded circular buffer you can optionally use to persist parsed packets asynchronously. `add()` returns False when the buffer is full and increments `dropped_count`.

- `gui_queue` behavior
  - `queue.Queue` is thread-safe; producers block on `put()` if queue is full (with configured timeout), and the consumer (`_process_queue`) uses `get_nowait()` in a loop to drain batches.
  - Using a fixed `maxsize` gives predictable memory bounds; using a too-large `maxsize` can hide spikes but increase memory use.

4) Metrics and formulas
-----------------------
- Core metrics
  - total_packets = PerformanceMonitor.packet_count
  - total_errors = PerformanceMonitor.error_count
  - elapsed_time = now - PerformanceMonitor.start_time
  - packets_per_second = total_packets / elapsed_time
  - error_rate = total_errors / total_packets (guard against division by zero)

- Drop rate estimation
  - queue_full_count = count of `queue_full` errors from `ErrorHandler` (approximate number of dropped events due to queue timeout)
  - drop_rate_app = queue_full_count / total_packets (approximate fraction of packets lost in-app)

5) How to inspect runtime state (quick commands)
-----------------------------------------------
- From a Python REPL inside the running process (or a debug hook):
```python
print(sniffer.get_performance_stats())
print(sniffer.error_handler.get_recent_errors(20))
```

- If you prefer logging to file, add a background thread that periodically calls `get_performance_stats()` and writes JSON lines to disk (example below).

6) Tuning recipes (examples)
----------------------------
Choose parameters based on host capacity and expected rates. These are starting points; measure and tune.

- Low-end laptop (light capture)
  - `GUI_UPDATE_INTERVAL_MS = 200`
  - `gui_queue maxsize = 1000`
  - `max_batch = 10`
  - `queue.put timeout = 0.05`

- Developer desktop (typical)
  - `GUI_UPDATE_INTERVAL_MS = 100`
  - `gui_queue maxsize = 5000`
  - `max_batch = 50`
  - `queue.put timeout = 0.1`

- Capture/analysis host (high throughput)
  - `GUI_UPDATE_INTERVAL_MS = 50`
  - `gui_queue maxsize = 20000`
  - `max_batch = 200`
  - `queue.put timeout = 0.2`
  - Consider running headless capture to disk if sustained high throughput is required.

7) Diagnostics checklist and recommended actions
------------------------------------------------
- GUI shows fewer packets than `sniffer.get_performance_stats()`:
  - `sniffer.get_performance_stats()['total_http']` is authoritative for packets processed by the sniffer. Compare it to GUI counters.
  - Look for `queue_full` errors using `sniffer.error_handler.get_recent_errors()`; many such entries indicate you need a larger queue or faster consumer.

- Producer counters are increasing but GUI not updating:
  - Increase `max_batch` and/or decrease `GUI_UPDATE_INTERVAL_MS` (within CPU limits).
  - Reduce heavy synchronous formatting in `add_request` / `add_response`.

- High memory usage:
  - Reduce `gui_queue maxsize` and `PacketBuffer.maxlen`.
  - Prefer headless capture to pcap for long-duration runs.

8) Persistent metrics example (copyable snippet)
------------------------------------------------
Add a small background thread to persist stats to disk for long runs:

```python
import threading, time, json

def persist_stats(sniffer, path='/tmp/sniffer_stats.log', interval=5):
    def worker():
        with open(path, 'a') as f:
            while True:
                stats = sniffer.get_performance_stats()
                stats['timestamp'] = time.time()
                f.write(json.dumps(stats) + "\n")
                f.flush()
                time.sleep(interval)
    t = threading.Thread(target=worker, daemon=True)
    t.start()

# Usage: persist_stats(sniffer, '/tmp/sniffer_stats.log', interval=2)
```

9) When to switch to offline capture
-----------------------------------
- If packet rates are so high that kernel-level drops appear in interface statistics (e.g., `ifconfig`/`ip -s link`) or you need 100% fidelity, use `tcpdump`/`libpcap` to write to disk and analyze offline.

10) Summary (practical takeaway)
--------------------------------
- Do not drop in the capture path unless absolutely necessary; prefer short blocking puts + bounded queues.
- Use batch consumption in the GUI to boost throughput and reduce the CPU cost per item.
- Instrument producer, buffer, and consumer to compute real drop ratios and prioritize where to tune.

Next actions I can take for you (pick one):
- Add the persistent metrics logger into the codebase under a CLI flag.
- Add a tiny HTTP admin endpoint exposing `get_performance_stats()` for external monitoring.
- Implement an optional headless capture mode that writes pcap output.

