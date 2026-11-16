#!/usr/bin/env python3
"""Reconcile local Compose IAM history only after comparing a fresh migration-built schema.
Default: verify only. --apply: take private backups, repair checksums, validate and prove data unchanged.
Never replays migrations against the existing database and never disables Flyway validation.
"""
import argparse
import difflib
import hashlib
import json
import os
import re
import subprocess
import tempfile
import uuid
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def normalize_dump(value):
    # pg_dump 17 adds random psql restriction tokens; these are not schema definitions.
    return '\n'.join(
        line for line in value.splitlines() if not line.startswith(('\\restrict ', '\\unrestrict ', '-- Dumped ')))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    env = dict(os.environ)
    for line in (ROOT / '.env').read_text().splitlines():
        if line and not line.startswith('#') and '=' in line:
            key, value = line.split('=', 1);
            env[key] = value
    if env.get('DB_URL', 'jdbc:postgresql://localhost:5432/iam') != 'jdbc:postgresql://localhost:5432/iam' or env.get(
            'DB_USER', 'iam') != 'iam':
        raise SystemExit('This helper supports only the local Compose iam database/user.')
    env['PGPASSWORD'] = env['DB_PASSWORD']
    java_home = env.get('JAVA_HOME')
    java = str(Path(java_home) / 'bin/java') if java_home else 'java'
    javac = str(Path(java_home) / 'bin/javac') if java_home else 'javac'

    def run(command, **kwargs):
        return subprocess.run(command, cwd=ROOT, env=env, check=True, **kwargs)

    def sql(database, query):
        return run(['docker', 'compose', 'exec', '-T', 'postgres', 'psql', '-X', '-U', 'iam', '-d', database, '-v',
                    'ON_ERROR_STOP=1', '-At'],
                   input=query, text=True, capture_output=True).stdout

    def dump(database, data=False):
        return run(['docker', 'compose', 'exec', '-T', 'postgres', 'pg_dump', '-U', 'iam', '-d', database,
                    '--no-owner', '--no-privileges', *([] if data else ['--schema-only', '--schema=public'])],
                   capture_output=True).stdout

    history = json.loads(sql('iam', "select json_agg(t order by installed_rank) from public.flyway_schema_history t;"))
    expected = {str(i) for i in range(1, 15)}
    if len(history) != 14 or {row['version'] for row in history} != expected or not all(
            row['success'] for row in history):
        raise SystemExit('Expected exactly successful V1–V14 history; no repair attempted.')
    reference = 'iam_verify_' + uuid.uuid4().hex[:12]
    with tempfile.TemporaryDirectory(prefix='iam-flyway-') as temporary:
        temp = Path(temporary);
        libs = temp / 'lib';
        libs.mkdir();
        migrations = temp / 'migrations';
        migrations.mkdir()
        with zipfile.ZipFile(ROOT / 'iam-server/target/iam-server-0.1.0-SNAPSHOT.jar') as jar:
            for name in jar.namelist():
                if name.startswith('BOOT-INF/lib/') and name.endswith('.jar'):
                    (libs / Path(name).name).write_bytes(jar.read(name))
                if name.startswith('BOOT-INF/classes/db/migration/') and name.endswith('.sql'):
                    value = jar.read(name);
                    source = ROOT / 'iam-server/src/main/resources/db/migration' / Path(name).name
                    if source.read_bytes() != value: raise SystemExit(
                        'JAR/source migration mismatch; rebuild before maintenance.')
                    (migrations / source.name).write_bytes(value)
        scripts = {row['script'] for row in history}
        if scripts != {p.name for p in migrations.glob('*.sql')}:
            raise SystemExit('Applied migration names differ; no repair attempted.')
        cp = str(libs / '*')
        run([javac, '-cp', cp, '-d', str(temp), 'scripts/flyway/LocalFlyway.java'], capture_output=True)
        cp += os.pathsep + str(temp)

        def flyway(action, database):
            completed = run([java, '-cp', cp, 'LocalFlyway', action, 'jdbc:postgresql://localhost:5432/' + database,
                             str(migrations)], capture_output=True, text=True)
            return completed.stdout

        sql('iam', 'create database ' + reference + ';')
        try:
            flyway('migrate', reference)
            actual = normalize_dump(dump('iam').decode())
            fresh = normalize_dump(dump(reference).decode())
            if actual != fresh:
                # Never print business data; this diff contains definitions only.
                print('\n'.join(
                    difflib.unified_diff(actual.splitlines(), fresh.splitlines(), fromfile='existing schema',
                                         tofile='fresh migrations')))
                raise SystemExit('Schema drift detected; no checksum changes made.')
            print('PASS: existing application schema matches a fresh V1–V14 database.')
            if not args.apply:
                print('Verification only. Use --apply to back up and reconcile checksum metadata.');
                return
            directory = ROOT / 'secrets/backups' / ('flyway-' + uuid.uuid4().hex[:12])
            directory.mkdir(parents=True, mode=0o700)
            directory.chmod(0o700)
            # Full private logical backup includes application data and original history.
            backup = directory / 'iam-before-repair.sql'
            with backup.open('xb') as output:
                backup.chmod(0o600);
                output.write(dump('iam', data=True))
            old = directory / 'history-before.json';
            old.write_text(json.dumps(history, indent=2) + '\n');
            old.chmod(0o600)
            print('Private full backup and original history saved to', directory.relative_to(ROOT))
            output = flyway('repair', 'iam')
            if 'VERIFIED:' not in output: raise SystemExit('Missing data-preservation verification.')
            after = json.loads(
                sql('iam', "select json_agg(t order by installed_rank) from public.flyway_schema_history t;"))
            strip_checksum = lambda rows: [{key: value for key, value in row.items() if key != 'checksum'} for row in
                                           rows]
            if strip_checksum(history) != strip_checksum(after): raise SystemExit(
                'Unexpected history change; consult backup.')
            receipt = {'backupSha256': hashlib.sha256(backup.read_bytes()).hexdigest(),
                       'schemaMatchesFreshMigrations': True, 'applicationDataUnchangedDuringRepair': True,
                       'historyChanges': [{'version': a['version'], 'before': a['checksum'], 'after': b['checksum']} for
                                          a, b in zip(history, after) if a['checksum'] != b['checksum']]}
            path = directory / 'verification.json';
            path.write_text(json.dumps(receipt, indent=2) + '\n');
            path.chmod(0o600)
            print('PASS: Flyway repair/validation; application table contents unchanged; only checksums updated.')
        finally:
            sql('iam', 'drop database ' + reference + ';')


if __name__ == '__main__': main()
