#!/usr/bin/env python3
"""Sequential virtual-device matrix on isolated stacks; requires Chrome, Node and local stores.
Virtual CTAP devices do not establish physical-device or attestation interoperability.
"""
import argparse
import os
import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--benchmark', action='store_true',
                        help='Also measure 20 closed-loop local virtual logins; not production capacity')
    parser.add_argument('--profile', choices=('all', 'platform', 'usb', 'synced'), default='all')
    args = parser.parse_args()
    cases = [('platform', 'ES256', False), ('usb', 'RS256', False), ('synced', 'ES256', False)]
    if args.profile != 'all': cases = [case for case in cases if case[0] == args.profile]
    if args.benchmark: cases.append(('platform', 'ES256', True))
    for index, (profile, algorithm, benchmark) in enumerate(cases):
        if index:
            print('Waiting for public throttle window before the next stack', flush=True);
            time.sleep(30);
            time.sleep(31)
        print('Running ' + profile + ' ' + algorithm + (' local measurement' if benchmark else ' virtual verification'),
              flush=True)
        env = {**os.environ, 'PASSKEY_TEST_PROFILE': profile, 'PASSKEY_TEST_ALGORITHM': algorithm,
               'PASSKEY_BENCHMARK': str(benchmark).lower()}
        subprocess.run([sys.executable, 'tests/backchannel_stack_test.py', '--mode', 'passkey'], cwd=ROOT, env=env,
                       check=True, timeout=240)
    print('PASS: virtual matrix' + (' and bounded local measurement' if args.benchmark else ''), flush=True)


if __name__ == '__main__': main()
