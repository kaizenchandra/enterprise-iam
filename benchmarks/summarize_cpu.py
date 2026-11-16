#!/usr/bin/env python3
"""Aggregate CPU stack symbols only; no raw JFR events, environment or request data are published."""
import collections
import datetime
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    source = pathlib.Path(sys.argv[1]);
    if source.stat().st_size > 64 * 1024 * 1024: raise RuntimeError('CPU event export exceeds limit')
    workload = json.loads((ROOT / 'benchmarks/results/token-local-profiled.json').read_text())
    start = datetime.datetime.fromisoformat(workload['startedAt']);
    end = datetime.datetime.fromisoformat(workload['recordedAt']);
    counts = collections.Counter();
    samples = 0
    for event in json.loads(source.read_text()).get('recording', {}).get('events', []):
        values = event.get('values', {});
        stamp = values.get('startTime', '');
        thread = values.get('sampledThread', {}).get('javaName', '')
        if not stamp or '19000-exec-' not in thread: continue
        time = datetime.datetime.fromisoformat(stamp.replace('Z', '+00:00'))
        if not start <= time <= end: continue
        frames = values.get('stackTrace', {}).get('frames', []);
        names = [frame.get('method', {}).get('type', {}).get('name', '').replace('/', '.') for frame in frames]
        category = 'other'
        if any('security.crypto.bcrypt.' in name for name in names):
            category = 'bcrypt-client-authentication'
        elif any(name.startswith('org.postgresql.') for name in names):
            category = 'postgresql-client-stack'
        elif any(name.startswith(('sun.security.', 'java.security.', 'com.nimbusds.')) for name in names):
            category = 'signature-or-security-stack'
        samples += 1;
        counts[category] += 1
    report = {'kind': 'local-token-cpu-sample-summary', 'sampledHttpExecutorEvents': samples,
              'categories': {key: {'samples': value, 'percent': round(100 * value / samples, 2) if samples else 0} for
                             key, value in counts.most_common()},
              'limits': ['CPU sampling during the measured HTTP workload only; not a wall-time decomposition',
                         'Small local run with sampling overhead; not a production bottleneck or SLO certification',
                         'Only aggregate stack categories exported; raw recording and event JSON removed',
                         'Environment/system-property/JVM-argument events disabled in the recording configuration']}
    (ROOT / 'benchmarks/results/token-cpu-profile.json').write_text(json.dumps(report, indent=2) + '\n')
    if samples == 0: raise RuntimeError('No workload CPU samples captured; no attribution claim')
    print('Recorded ' + str(samples) + ' workload CPU samples; sanitized categories saved')


if __name__ == '__main__': main()
