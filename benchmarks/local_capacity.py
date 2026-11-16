#!/usr/bin/env python3
"""Bounded local token smoke: fixed loopback target, 5 offered requests/s, 10 seconds, at most 8 in flight.
Run via tests/backchannel_stack_test.py --mode capacity; no credentials/tokens are printed.
"""
import base64
import concurrent.futures
import datetime
import json
import math
import os
import pathlib
import platform
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    profiled = os.environ.get('IAM_CAPACITY_PROFILE') == 'true'
    target = ROOT / (
        'benchmarks/results/token-local-profiled.json' if profiled else 'benchmarks/results/token-local.json');
    target.unlink(missing_ok=True)
    secret = os.environ['MACHINE_SECRET']
    authorization = 'Basic ' + base64.b64encode(('order-service:' + secret).encode()).decode()
    payload = urllib.parse.urlencode({'grant_type': 'client_credentials', 'scope': 'orders.read'}).encode()

    def token():
        start = time.perf_counter()
        try:
            request = urllib.request.Request('http://localhost:19000/oauth2/token', data=payload,
                                             headers={'Authorization': authorization,
                                                      'Content-Type': 'application/x-www-form-urlencoded'})
            with urllib.request.urlopen(request, timeout=3) as response:
                data = response.read(65537)
                if len(data) > 65536: return 0, (time.perf_counter() - start) * 1000
                body = json.loads(data)
                valid = response.status == 200 and isinstance(body.get('access_token'), str) and body.get('token_type',
                                                                                                          '').lower() == 'bearer'
                return 200 if valid else 0, (time.perf_counter() - start) * 1000
        except urllib.error.HTTPError as response:
            response.close();
            return response.code, (time.perf_counter() - start) * 1000
        except (OSError, ValueError, urllib.error.URLError):
            return 0, (time.perf_counter() - start) * 1000

    for _ in range(3):
        if token()[0] != 200: raise RuntimeError('Warmup token issuance failed')
    gate = threading.BoundedSemaphore(8);
    futures = [];
    dropped = 0;
    lags = [];
    started = datetime.datetime.now(datetime.timezone.utc);
    start = time.perf_counter()

    def work():
        try:
            return token()
        finally:
            gate.release()

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        for index in range(50):
            due = start + index / 5;
            time.sleep(max(0, due - time.perf_counter()));
            lags.append(max(0, time.perf_counter() - due) * 1000)
            if not gate.acquire(blocking=False): dropped += 1;continue
            futures.append(pool.submit(work))
        results = [future.result(timeout=4) for future in futures]
    elapsed = time.perf_counter() - start;
    latencies = sorted(ms for _, ms in results)

    def quantile(q):
        return round(latencies[max(0, math.ceil(q * len(latencies)) - 1)], 3) if latencies else None

    statuses = {str(code): sum(1 for status, _ in results if status == code) for code in
                sorted({s for s, _ in results})}
    successes = sum(1 for status, _ in results if status == 200)
    report = {'kind': 'local-open-loop-client-credentials-smoke',
              'recordedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'startedAt': started.isoformat(),
              'profiled': profiled, 'offeredRatePerSecond': 5, 'offeredRequests': 50, 'durationSeconds': 10,
              'maxConcurrency': 8, 'attempted': len(results), 'successful': successes, 'dropped': dropped,
              'errors': len(results) - successes, 'statuses': statuses, 'elapsedSeconds': round(elapsed, 3),
              'achievedSuccessesPerSecond': round(successes / elapsed, 3),
              'latencyMs': {'p50': quantile(.5), 'p95': quantile(.95), 'p99': quantile(.99)},
              'maxClientSchedulingLagMs': round(max(lags), 3), 'platform': platform.system(),
              'arch': platform.machine(), 'hostLogicalCpus': os.cpu_count(), 'opMaxHeapMiB': 256,
              'limits': ['50 measured requests after 3 warmups; p99 is the observed maximum',
                         'Localhost HTTP, single test client identity, local PostgreSQL/Redis and same-host JVMs',
                         'Client secret validation, signing and database work included; CPU/GC/pool breakdown not instrumented',
                         'Not WebAuthn, MFA, human login, JWT resource validation or PDP throughput',
                         'Not representative production data, TLS/network, saturation, soak or multi-region capacity; no SLO claim']}
    target.parent.mkdir(exist_ok=True);
    target.write_text(json.dumps(report, indent=2) + '\n')
    print('Recorded bounded local token workload: ' + str(successes) + '/' + str(len(results)) + ' successful, ' + str(
        dropped) + ' dropped; report saved')
    if successes != len(results) or dropped: raise RuntimeError('Local workload had errors or dropped work; see report')


if __name__ == '__main__': main()
