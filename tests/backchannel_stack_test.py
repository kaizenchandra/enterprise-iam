#!/usr/bin/env python3
"""Run the actual IAM + two BFF jars on isolated schemas/ports; no token values are printed.
Requires built artifacts, .env from init-local.sh, and Compose PostgreSQL/Redis already running.
"""
import argparse
import base64
import concurrent.futures
import datetime
import http.cookiejar
import http.server
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
ISSUER = 'http://localhost:19000'
PORTAL_PORT = int(os.environ.get('IAM_TEST_PORTAL_BASE_PORT', '18080'))
if not 1024 <= PORTAL_PORT <= 65533 or any(
        port in (19000, 19001, 19003, 19004) for port in range(PORTAL_PORT, PORTAL_PORT + 3)): raise ValueError(
    'Choose three available non-overlapping local portal ports')
A = f'http://localhost:{PORTAL_PORT}';
B = f'http://localhost:{PORTAL_PORT + 1}';
PEER = f'http://localhost:{PORTAL_PORT + 2}'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): return None


class Browser:
    def __init__(self):
        self.cookies = http.cookiejar.CookieJar()
        self.http = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookies), NoRedirect())

    def get(self, url, data=None):
        request = urllib.request.Request(url, data=None if data is None else urllib.parse.urlencode(data).encode())
        try:
            with self.http.open(request, timeout=15) as response:
                return response.status, response.headers, response.read().decode()
        except urllib.error.HTTPError as response:
            with response:
                return response.code, response.headers, response.read().decode()


def require(condition, message):
    if not condition: raise AssertionError(message)


def csrf(html):
    match = re.search(r'name="_csrf"[^>]*value="([^"]+)"', html);
    require(match is not None, 'CSRF form missing');
    return match.group(1)


def op_login(browser, env, username="employee"):
    code, _, html = browser.get(ISSUER + '/login');
    require(code == 200, 'OP login form failed')
    code, _, _ = browser.get(ISSUER + '/login',
                             {'username': username, 'password': env['DEMO_PASSWORD'], '_csrf': csrf(html)})
    require(code == 302, 'OP login failed')


def bff_login(browser, portal):
    code, headers, _ = browser.get(portal + '/oauth2/authorization/iam');
    require(code == 302, 'RP authorization redirect failed')
    location = headers['Location'];
    require(location.startswith(ISSUER + '/'), 'Untrusted issuer redirect')
    code, headers, _ = browser.get(location);
    require(code == 302, 'OP authorization failed')
    require(headers['Location'].startswith(portal + '/login/oauth2/code/iam'), 'Unexpected callback')
    code, _, _ = browser.get(headers['Location']);
    require(code == 302, 'RP callback failed')
    code, _, body = browser.get(portal + '/profile');
    require(code == 200, 'RP authenticated profile failed');
    return json.loads(body)['subject']


def wait_ready(url, process):
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        if process.poll() is not None: raise AssertionError('Application exited during startup')
        try:
            if Browser().get(url + '/actuator/health')[0] == 200: return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(.2)
    raise AssertionError('Application did not become ready')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode',
                        choices=('logout', 'idle', 'absolute', 'ui', 'account', 'passkey', 'capacity', 'physical',
                                 'mds', 'capacity-profile', 'client-auth'), default='logout')
    parser.add_argument('--device-model', default='', help='Physical test model; omit serial numbers')
    parser.add_argument('--device-firmware', default='')
    parser.add_argument('--device-platform', default='', help='OS/browser versions for the evidence record')
    args = parser.parse_args();
    mode = args.mode
    if mode == 'physical':
        require(sys.stdin.isatty(), 'Physical mode requires an interactive terminal and device holder')
        require(all(0 < len(v) <= 128 for v in (args.device_model, args.device_firmware, args.device_platform)),
                'Supply bounded model, firmware and OS/browser labels without device serial numbers')
    env = dict(os.environ)
    for line in (ROOT / '.env').read_text().splitlines():
        key, sep, value = line.partition('=')
        if sep: env[key] = value
    nonce = uuid.uuid4().hex[:12];
    schemas = ['bc_e2e_' + nonce + suffix for suffix in ('_op', '_a', '_b')]
    namespace = 'iam:bc-e2e:' + nonce
    logs = pathlib.Path(tempfile.mkdtemp(prefix='iam-backchannel-e2e-'));
    processes = [];
    files = [];
    chrome_profile = None;
    catalogue_server = None
    java = str(pathlib.Path(env['JAVA_HOME']) / 'bin/java') if env.get('JAVA_HOME') else 'java'

    def start(module, extra):
        log = (logs / (module + str(len(processes)) + '.log')).open('w');
        files.append(log)
        command = [java, '-Xms64m', '-Xmx256m']
        if mode == 'capacity-profile' and module == 'iam-server': command.append(
            '-XX:StartFlightRecording=filename=' + str(logs / 'cpu.jfr') + ',settings=' + str(
                ROOT / 'benchmarks/cpu-only.jfc') + ',dumponexit=true,maxsize=16m,maxage=2m')
        command += ['-jar', str(ROOT / module / 'target' / f'{module}-0.1.0-SNAPSHOT.jar')]
        process = subprocess.Popen(command, cwd=ROOT, env={**env, 'SERVER_ADDRESS': '127.0.0.1', **extra}, stdout=log,
                                   stderr=subprocess.STDOUT)
        processes.append(process);
        return process

    try:
        if mode in ('account', 'passkey'): env.update(
            {'ACCOUNT_ACTIONS_ENABLED': 'true', 'ACCOUNT_PUBLIC_ORIGIN': ISSUER, 'ACCOUNT_ALLOW_HTTP': 'true',
             'SMTP_HOST': 'localhost', 'SMTP_PORT': '2525', 'SMTP_STARTTLS': 'false', 'IAM_ACCOUNT_DELAY_MS': '200',
             'IAM_ACCOUNT_INITIAL_DELAY_MS': '200'})
        if mode == 'passkey': env.update(
            {'PASSKEYS_ENABLED': 'true', 'PASSKEY_RP_ID': 'localhost', 'PASSKEY_ORIGINS': ISSUER,
             'PASSKEY_ALLOW_LOCAL_HTTP': 'true', 'PASSKEY_ATTESTATION_MODE': 'NONE',
             'PASSKEY_METADATA_SOURCE': 'OFFLINE', 'PASSKEY_METADATA_MAXIMUM_AGE': 'PT24H',
             'PASSKEY_ATTESTATION_POLICY_REVISION': '1', 'PASSKEY_METADATA_FILE': '',
             'PASSKEY_METADATA_SIGNING_ROOTS_FILE': '', 'PASSKEY_AUTHENTICATOR_ROOTS_FILE': '',
             'PASSKEY_METADATA_CRLS_FILE': '', 'PASSKEY_METADATA_LEGAL_HEADER': ''})
        if mode in ('mds', 'physical'): env.update(
            {key: value for key, value in os.environ.items() if key.startswith('PASSKEY_')})
        if mode in ('capacity', 'capacity-profile', 'client-auth'): env.update(
            {'PASSKEY_METADATA_SOURCE': 'OFFLINE', 'PASSKEY_METADATA_MAXIMUM_AGE': 'PT24H',
             'PASSKEY_ATTESTATION_MODE': 'NONE', 'PASSKEY_METADATA_FILE': '', 'PASSKEY_METADATA_SIGNING_ROOTS_FILE': '',
             'PASSKEY_AUTHENTICATOR_ROOTS_FILE': '', 'PASSKEY_METADATA_CRLS_FILE': '',
             'PASSKEY_METADATA_LEGAL_HEADER': ''})
        if mode == 'mds' and env.get('PASSKEY_MDS_TEST_CATALOGUE_FILE'):
            candidate = pathlib.Path(env['PASSKEY_MDS_TEST_CATALOGUE_FILE']).read_bytes();
            require(len(candidate) <= 16 * 1024 * 1024, 'Test catalog exceeds limit')

            class Catalogue(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    if self.path != '/metadata': self.send_error(404);return
                    self.send_response(200);
                    self.send_header('Content-Length', str(len(candidate)));
                    self.end_headers();
                    self.wfile.write(candidate)

                def log_message(self, *args): pass

            catalogue_server = http.server.ThreadingHTTPServer(('127.0.0.1', 19004), Catalogue)
            threading.Thread(target=catalogue_server.serve_forever, daemon=True).start()
            env.update({'PASSKEY_MDS_URL': 'http://127.0.0.1:19004/metadata',
                        'PASSKEY_MDS_ORIGINS': 'http://127.0.0.1:19004,https://crl.globalsign.com',
                        'IAM_PASSKEY_ATTESTATION_LIVE_TEST_LOOPBACK': 'true',
                        'IAM_PASSKEY_ATTESTATION_LIVE_SIGNER_NAME': 'mds.fidoalliance.org'})
        if mode == 'mds':
            require(env.get('PASSKEY_METADATA_SOURCE') == 'LIVE',
                    'Configure LIVE metadata source and reviewed roots for the isolated probe')
            env['PASSKEYS_ENABLED'] = 'true'
        if mode == 'physical': env.update(
            {'PASSKEYS_ENABLED': 'true', 'PASSKEY_RP_ID': 'localhost', 'PASSKEY_ORIGINS': ISSUER,
             'PASSKEY_ALLOW_LOCAL_HTTP': 'true'})
        op = start('iam-server', {'SPRING_PROFILES_ACTIVE': 'local', 'SERVER_PORT': '19000', 'IAM_ISSUER': ISSUER,
                                  'PORTAL_A_PORT': str(PORTAL_PORT), 'PORTAL_B_PORT': str(PORTAL_PORT + 1),
                                  'IAM_BACKCHANNEL_ALLOWED_ORIGINS': A + ',' + B,
                                  'IAM_SESSION_EXPIRY_DELAY_MS': '200', 'IAM_SESSION_EXPIRY_INITIAL_DELAY_MS': '200',
                                  'SPRING_FLYWAY_DEFAULT_SCHEMA': schemas[0], 'SPRING_FLYWAY_SCHEMAS': schemas[0],
                                  'SPRING_DATASOURCE_HIKARI_SCHEMA': schemas[0],
                                  'SPRING_SESSION_REDIS_NAMESPACE': namespace})
        wait_ready(ISSUER, op)
        resource = start('sample-resource-server',
                         {'SERVER_PORT': '19001', 'IAM_ISSUER': ISSUER, 'IAM_JWKS': ISSUER + '/oauth2/jwks'})
        wait_ready('http://localhost:19001', resource)
        env['RESOURCE_URL'] = 'http://localhost:19001'
        env['SESSION_COOKIE_SECURE'] = 'false'
        pa = start('sample-web-client', {'PORT': str(PORTAL_PORT), 'IAM_ISSUER': ISSUER, 'CLIENT_ID': 'portal-a',
                                         'CLIENT_SECRET': env['PORTAL_SECRET'], 'CLIENT_SCHEMA': schemas[1],
                                         'SESSION_COOKIE': 'E2E_A'})
        pb = start('sample-web-client', {'PORT': str(PORTAL_PORT + 1), 'IAM_ISSUER': ISSUER, 'CLIENT_ID': 'portal-b',
                                         'CLIENT_SECRET': env['PORTAL_SECRET'], 'CLIENT_SCHEMA': schemas[2],
                                         'SESSION_COOKIE': 'E2E_B'})
        wait_ready(A, pa);
        wait_ready(B, pb)
        peer = start('sample-web-client', {'PORT': str(PORTAL_PORT + 2), 'IAM_ISSUER': ISSUER, 'CLIENT_ID': 'portal-a',
                                           'CLIENT_SECRET': env['PORTAL_SECRET'], 'CLIENT_SCHEMA': schemas[1],
                                           'SESSION_COOKIE': 'E2E_A'})
        wait_ready(PEER, peer)
        if mode == 'passkey':
            chrome = env.get('CHROME_BIN') or (
                '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' if pathlib.Path(
                    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome').exists() else shutil.which(
                    'google-chrome') or shutil.which('chromium'))
            require(chrome is not None, 'Chrome is required for passkey tests')
            chrome_profile = tempfile.mkdtemp(prefix='iam-passkey-chrome-')
            log = (logs / 'chrome.log').open('w');
            files.append(log)
            process = subprocess.Popen(
                [chrome, '--headless=new', '--remote-debugging-port=0', '--remote-debugging-address=127.0.0.1',
                 '--user-data-dir=' + chrome_profile, '--no-first-run', '--no-default-browser-check', '--disable-gpu',
                 'about:blank'], stdout=log, stderr=subprocess.STDOUT)
            processes.append(process)
            deadline = time.monotonic() + 20
            while not (pathlib.Path(chrome_profile) / 'DevToolsActivePort').exists() and time.monotonic() < deadline:
                require(process.poll() is None, 'Chrome exited during startup');
                time.sleep(.1)
            require((pathlib.Path(chrome_profile) / 'DevToolsActivePort').exists(), 'Chrome did not become ready')
            subprocess.run(['node', 'tests/passkeys_browser.mjs'], cwd=ROOT,
                           env={**env, 'PASSKEY_TEST_BASE': ISSUER, 'PASSKEY_TEST_PORTAL_A': A,
                                'PASSKEY_TEST_PORTAL_B': B, 'PASSKEY_TEST_PORTAL_PEER': PEER,
                                'PASSKEY_TEST_SCHEMA': schemas[0], 'PASSKEY_CHROME_PROFILE': chrome_profile},
                           check=True, timeout=180)
            return
        if mode == 'physical':
            chrome = env.get('CHROME_BIN') or (
                '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' if pathlib.Path(
                    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome').exists() else shutil.which(
                    'google-chrome') or shutil.which('chromium'))
            require(chrome is not None, 'Chrome is required')
            chrome_profile = tempfile.mkdtemp(prefix='iam-physical-chrome-');
            log = (logs / 'chrome.log').open('w');
            files.append(log)
            processes.append(subprocess.Popen(
                [chrome, '--user-data-dir=' + chrome_profile, '--no-first-run', '--no-default-browser-check',
                 '--new-window', ISSUER + '/login'], stdout=log, stderr=subprocess.STDOUT))
            print(
                'Use employee with the private .env password. Enroll the physical authenticator, sign in using it, open both portals and their protected APIs, then remove the credential. No virtual authenticator is installed.',
                flush=True)
            print('IAM: ' + ISSUER + '; portals: ' + A + ' and ' + B, flush=True)
            input(
                'After completing the physical flow, press Enter to record server observations and clean up this isolated stack: ')
            sql = f"""SELECT event_type,count(*) FROM \"{schemas[0]}\".security_audit_events WHERE event_type IN ('PASSKEY_ENROLLED','PASSKEY_AUTHENTICATED','PASSKEY_REMOVED') GROUP BY event_type;"""
            result = subprocess.run(
                ['docker', 'compose', 'exec', '-T', 'postgres', 'psql', '-U', 'iam', '-d', 'iam', '-At', '-v',
                 'ON_ERROR_STOP=1'], input=sql.encode(), cwd=ROOT, capture_output=True, check=True, timeout=5)
            counts = {key: int(value) for key, value in
                      (line.split('|', 1) for line in result.stdout.decode().splitlines())}
            report = {'kind': 'interactive-physical-passkey-observations',
                      'recordedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      'operatorLabels': {'model': args.device_model, 'firmware': args.device_firmware,
                                         'platform': args.device_platform},
                      'attestationMode': env.get('PASSKEY_ATTESTATION_MODE', 'NONE'),
                      'metadataSource': env.get('PASSKEY_METADATA_SOURCE', 'OFFLINE'), 'serverEvents': counts,
                      'virtualAuthenticator': False,
                      'limits': ['Operator labels are not authentication authority or certification',
                                 'Server events evidence registration/authentication/removal only; API and device UX require operator review',
                                 'No physical negative-test, OS/browser matrix or hardware laboratory claim']}
            target = ROOT / ('benchmarks/results/physical-' + nonce + '.json');
            target.parent.mkdir(exist_ok=True);
            target.write_text(json.dumps(report, indent=2) + '\n')
            require(all(
                counts.get(event, 0) > 0 for event in ('PASSKEY_ENROLLED', 'PASSKEY_AUTHENTICATED', 'PASSKEY_REMOVED')),
                'Physical flow incomplete; observations recorded')
            print(
                'PASS: physical enrollment/authentication/removal events recorded; review operator observations separately')
            return
        if mode == 'mds':
            peer_op = start('iam-server',
                            {'SPRING_PROFILES_ACTIVE': 'local', 'SERVER_PORT': '19003', 'IAM_ISSUER': ISSUER,
                             'PORTAL_A_PORT': str(PORTAL_PORT), 'PORTAL_B_PORT': str(PORTAL_PORT + 1),
                             'IAM_BACKCHANNEL_ALLOWED_ORIGINS': A + ',' + B,
                             'SPRING_FLYWAY_DEFAULT_SCHEMA': schemas[0], 'SPRING_FLYWAY_SCHEMAS': schemas[0],
                             'SPRING_DATASOURCE_HIKARI_SCHEMA': schemas[0],
                             'SPRING_SESSION_REDIS_NAMESPACE': namespace})
            wait_ready('http://localhost:19003', peer_op)
            require(Browser().get(ISSUER + '/actuator/health')[0] == 200,
                    'Peer evidence publication invalidated primary cache')
            sql = f"""SELECT serial,length(blob),(SELECT count(*) FROM \"{schemas[0]}\".passkey_model_eligibility WHERE eligible) FROM \"{schemas[0]}\".passkey_metadata_state WHERE source='LIVE';"""
            result = subprocess.run(
                ['docker', 'compose', 'exec', '-T', 'postgres', 'psql', '-U', 'iam', '-d', 'iam', '-At', '-v',
                 'ON_ERROR_STOP=1'], input=sql.encode(), cwd=ROOT, capture_output=True, check=True, timeout=5)
            serial, size, eligible = map(int, result.stdout.decode().strip().split('|'))
            report = {'kind': 'isolated-two-node-live-mds-startup',
                      'recordedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'serial': serial,
                      'blobCharacters': size, 'eligibleModels': eligible, 'primaryReady': True, 'peerReady': True,
                      'metadataTransport': 'local mirror of public signed candidate' if env.get(
                          'PASSKEY_MDS_TEST_CATALOGUE_FILE') else 'configured upstream', 'opHeapMiBPerNode': 256,
                      'workerHeapMiB': 256,
                      'limits': ['Isolated temporary schemas and test identities; no production trust publication',
                                 'Ready checks and peer cache warmup only; not authentication throughput or physical-device interoperability']}
            target = ROOT / 'benchmarks/results/live-mds-stack.json';
            target.parent.mkdir(exist_ok=True);
            target.write_text(json.dumps(report, indent=2) + '\n')
            print('PASS: two packaged 256 MiB IAM nodes validated shared live metadata; report saved')
            return
        if mode == 'client-auth':
            subprocess.run(
                [java, '-Xmx128m', '-Dloader.main=com.example.iam.server.client.ClientAuthenticationBenchmark', '-cp',
                 str(ROOT / 'iam-server/target/iam-server-0.1.0-SNAPSHOT.jar'),
                 'org.springframework.boot.loader.launch.PropertiesLauncher',
                 str(ROOT / 'benchmarks/results/token-auth-comparison.json')], cwd=ROOT, env=env, check=True,
                timeout=45)
            return
        if mode in ('capacity', 'capacity-profile'):
            env['IAM_CAPACITY_PROFILE'] = str(mode == 'capacity-profile').lower()
            subprocess.run(['python3', 'benchmarks/local_capacity.py'], cwd=ROOT, env=env, check=True, timeout=45)
            return
        browser = Browser();
        op_login(browser, env);
        if mode == 'ui':
            status, headers, _ = browser.get(A + '/');
            require(
                status == 302 and urllib.parse.urlparse(headers['Location']).path.endswith('/oauth2/authorization/iam'),
                'Initial sign-in did not select business registration: ' + str(status) + ' ' + urllib.parse.urlparse(
                    headers.get('Location', '')).path)
        subject = bff_login(browser, A);
        require(bff_login(browser, B) == subject, 'SSO subjects differ')
        require(browser.get(A + '/orders')[0] == 200 and browser.get(B + '/orders')[0] == 200, 'Protected API failed')
        require(browser.get(PEER + '/orders')[0] == 200, 'Shared RP node could not use session-bound tokens')
        independent = Browser();
        op_login(independent, env);
        require(bff_login(independent, A) == subject, 'Independent session identity differs')
        if mode == 'account':
            email = 'account-' + nonce + '@example.test'

            def send(who, url, data=None, token=None, json_data=None):
                headers = {}
                if token: headers['Authorization'] = 'Bearer ' + token
                payload = None
                if data is not None: payload = urllib.parse.urlencode(data).encode();headers[
                    'Content-Type'] = 'application/x-www-form-urlencoded'
                if json_data is not None: payload = json.dumps(json_data).encode();headers[
                    'Content-Type'] = 'application/json'
                request = urllib.request.Request(url, data=payload, headers=headers)
                try:
                    with who.http.open(request, timeout=15) as response:
                        return response.status, response.headers, response.read().decode()
                except urllib.error.HTTPError as response:
                    with response:
                        return response.code, response.headers, response.read().decode()

            basic = base64.b64encode(('admin-cli:' + env['ADMIN_SECRET']).encode()).decode()
            request = urllib.request.Request(ISSUER + '/oauth2/token', data=urllib.parse.urlencode(
                {'grant_type': 'client_credentials', 'scope': 'iam.admin'}).encode(),
                                             headers={'Authorization': 'Basic ' + basic,
                                                      'Content-Type': 'application/x-www-form-urlencoded'})
            with urllib.request.urlopen(request, timeout=15) as response:
                admin = json.load(response)['access_token']
            require(send(browser, ISSUER + '/api/v1/admin/users/' + subject + '/email', token=admin,
                         json_data={'email': email})[0] == 204, 'Trusted email binding failed')

            def mail_token(kind):
                deadline = time.monotonic() + 25
                while time.monotonic() < deadline:
                    with urllib.request.urlopen('http://localhost:8025/api/v1/messages', timeout=5) as response:
                        messages = json.load(response).get('messages', [])
                    for message in messages:
                        if not any(address.get('Address') == email for address in message.get('To', [])): continue
                        with urllib.request.urlopen('http://localhost:8025/api/v1/message/' + message['ID'],
                                                    timeout=5) as response:
                            body = json.load(response).get('Text', '')
                        match = re.search(re.escape(ISSUER + '/account/' + kind) + r'#token=([A-Za-z0-9_-]{43})', body)
                        if match: return match.group(1)
                    time.sleep(.2)
                raise AssertionError('Account mail not delivered')

            def complete(who, kind, token, password=None):
                code, _, html = who.get(ISSUER + '/account/' + kind);
                require(code == 200, 'Account form unavailable')
                form = {'token': token, '_csrf': csrf(html)}
                if password: form.update({'password': password, 'confirmation': password})
                return who.get(ISSUER + '/account/' + kind, form)[0]

            proof = mail_token('verify');
            require(complete(browser, 'verify', proof) == 200, 'Email verification failed');
            require(complete(browser, 'verify', proof) == 400, 'Verification replay accepted')
            fresh = Browser();
            op_login(fresh, env);
            bff_login(fresh, A);
            bff_login(fresh, B)
            statement = f'''INSERT INTO "{schemas[0]}".users(id,username,password_hash,state) SELECT gen_random_uuid()::text,'other-user',password_hash,'ACTIVE' FROM "{schemas[0]}".users WHERE username='employee';'''
            subprocess.run(['docker', 'compose', 'exec', '-T', 'postgres', 'psql', '-U', 'iam', '-d', 'iam', '-v',
                            'ON_ERROR_STOP=1'], input=statement.encode(), cwd=ROOT, capture_output=True, check=True,
                           timeout=10)
            other = Browser();
            op_login(other, env, 'other-user');
            bff_login(other, A)
            code, _, html = fresh.get(ISSUER + '/account/reset');
            require(code == 200, 'Reset form unavailable')
            require(fresh.get(ISSUER + '/account/reset/request', {'email': email, '_csrf': csrf(html)})[0] == 200,
                    'Reset request failed')
            reset = mail_token('reset');
            password = 'replacement-' + uuid.uuid4().hex
            require(complete(fresh, 'reset', reset, password) == 200, 'Password reset failed');
            require(complete(fresh, 'reset', reset, password) == 400, 'Reset replay accepted')
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline and fresh.get(B + '/profile')[0] == 200: time.sleep(.2)
            require(fresh.get(A + '/profile')[0] != 200 and fresh.get(B + '/profile')[0] != 200,
                    'Reset did not revoke RP sessions')
            require(fresh.get(PEER + '/profile')[0] != 200, 'Peer retained reset session');
            require(other.get(A + '/orders')[0] == 200, 'Other owner was revoked')
            code, _, html = fresh.get(ISSUER + '/login');
            require(code == 200, 'Stale cookie could not reach login')
            code, headers, _ = fresh.get(ISSUER + '/login', {'username': 'employee', 'password': env['DEMO_PASSWORD'],
                                                             '_csrf': csrf(html)});
            require(code == 302 and 'error' in headers['Location'], 'Old password accepted')
            op_login(fresh, {**env, 'DEMO_PASSWORD': password});
            bff_login(fresh, A);
            require(fresh.get(A + '/orders')[0] == 200, 'New password did not authorize protected API')
            print(
                'PASS: account actions; real Mailpit SMTP verification/reset, replay rejection, old-password rejection, new login, shared-node logout and owner isolation')
            return
        if mode == 'ui':
            def sql(statement):
                return subprocess.run(
                    ['docker', 'compose', 'exec', '-T', 'postgres', 'psql', '-U', 'iam', '-d', 'iam', '-v',
                     'ON_ERROR_STOP=1'], input=statement.encode(), cwd=ROOT, capture_output=True, check=True,
                    timeout=10)

            def connect(who):
                code, headers, _ = who.get(A + '/sessions')
                if code == 302:
                    target = headers['Location'];
                    code, headers, _ = who.get(A + target if target.startswith('/') else target)
                    require(code == 302 and headers['Location'].startswith(ISSUER + '/'),
                            'Management authorization redirect missing')
                    code, headers, _ = who.get(headers['Location']);
                    require(code == 302, 'Management authorization failed')
                    require(headers['Location'].startswith(A + '/login/oauth2/code/iam-management'),
                            'Wrong management callback')
                    code, headers, _ = who.get(headers['Location']);
                    require(code == 302, 'Management callback failed')
                code, _, html = who.get(A + '/sessions');
                require(code == 200, 'Session UI failed')
                require('access_token' not in html and 'refresh_token' not in html, 'Credential rendered')
                return html

            def current(html):
                match = re.search(r'data-session-id="([a-f0-9-]+)" data-current="true"', html)
                require(match is not None, 'Current session marker missing');
                return match.group(1)

            html = connect(browser);
            own = current(html);
            other = current(connect(independent))
            require(own != other and other in html, 'Distinct sessions not listed')
            require(browser.get(A + '/orders')[0] == 200, 'Management login replaced orders token')
            require(browser.get(PEER + '/sessions')[0] == 200, 'Shared node could not use server-side management token')
            require(browser.get(A + '/sessions/' + other + '/revoke', {})[0] == 403, 'Missing CSRF accepted')
            require(browser.get(A + '/sessions/' + other + '/revoke')[0] == 405, 'GET performed revocation')
            sql(f'''INSERT INTO "{schemas[0]}".users(id,username,password_hash,state)
                SELECT gen_random_uuid()::text,'other-user',password_hash,'ACTIVE' FROM "{schemas[0]}".users WHERE username='employee';''')
            attacker = Browser();
            op_login(attacker, env, 'other-user');
            bff_login(attacker, A);
            attack_html = connect(attacker)
            require(own not in attack_html and other not in attack_html, 'Other owner sessions leaked')
            require(attacker.get(A + '/sessions/' + other + '/revoke', {'_csrf': csrf(attack_html)})[0] == 404,
                    'Cross-owner revocation accepted')
            # A switched OP account must not replace the signed-in BFF account during management authorization.
            mismatch = Browser();
            op_login(mismatch, env);
            bff_login(mismatch, A)
            for cookie in list(mismatch.cookies):
                if cookie.name == 'IAM_SESSION': mismatch.cookies.clear(cookie.domain, cookie.path, cookie.name)
            op_login(mismatch, env, 'other-user')
            code, headers, _ = mismatch.get(A + '/sessions');
            require(code == 302, 'Mismatch management request failed')
            code, headers, _ = mismatch.get(urllib.parse.urljoin(A, headers['Location']));
            require(code == 302, 'Mismatch authorize redirect failed')
            code, headers, _ = mismatch.get(headers['Location']);
            require(code == 302, 'Mismatch callback redirect failed')
            code, headers, _ = mismatch.get(headers['Location']);
            require(code == 302 and '/sessions' not in headers['Location'], 'Switched OP account accepted')
            code, _, profile = mismatch.get(A + '/profile')
            require(code != 200 or json.loads(profile)['subject'] == subject, 'BFF identity was replaced')
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                results = list(
                    pool.map(lambda _: browser.get(A + '/sessions/' + other + '/revoke', {'_csrf': csrf(html)})[0],
                             range(2)))
            require(results == [302, 302], 'Concurrent owned session revocation failed')
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline and independent.get(A + '/profile')[0] == 200: time.sleep(.2)
            require(independent.get(A + '/profile')[0] != 200, 'Other session survived UI revocation')
            require(browser.get(A + '/orders')[0] == 200 and attacker.get(A + '/orders')[0] == 200,
                    'Unrelated session lost access')
            # Force a management-only grant ineligible; the UI must show a safe reconnect path, never refresh silently.
            sql(f'''UPDATE "{schemas[0]}".authorization_lifecycle SET grant_expires_at=clock_timestamp()-interval '1 second'
                WHERE id IN (SELECT id FROM "{schemas[0]}".oauth2_authorization WHERE authorized_scopes LIKE '%sessions.read%' AND principal_name='{subject}');''')
            code, _, failure = browser.get(A + '/sessions');
            require(code == 409 and 'Reconnect' in failure, 'Revoked management grant did not fail safely')
            html = connect(browser);
            require(current(html) == own, 'Reconnect changed current OP session')
            require(browser.get(A + '/sessions/' + own + '/revoke', {'_csrf': csrf(html)})[0] == 302,
                    'Current session revoke failed')
            require(browser.get(A + '/signed-out')[0] == 200, 'Signed-out page unavailable')
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline and browser.get(B + '/profile')[0] == 200: time.sleep(.2)
            require(browser.get(A + '/profile')[0] != 200 and browser.get(B + '/profile')[0] != 200,
                    'Current session survived')
            require(browser.get(PEER + '/profile')[0] != 200, 'Peer retained revoked session')
            require(attacker.get(A + '/orders')[0] == 200, 'Different owner was revoked')
            print(
                'PASS: session UI; separate server-side grants, listing/current marker, CSRF, ownership, reconnect, individual/current revocation and shared-node logout')
            return
        if mode == 'logout':
            code, _, html = browser.get(A + '/');
            require(code == 200, 'RP home unavailable')
            code, headers, _ = browser.get(A + '/logout', {'_csrf': csrf(html)});
            require(code == 302, 'RP logout failed')
            target = headers['Location'];
            require(target.startswith(ISSUER + '/connect/logout'), 'RP did not initiate OP logout')
            params = {key: values[0] for key, values in
                      urllib.parse.parse_qs(urllib.parse.urlparse(target).query).items()}
            code, _, _ = browser.get(ISSUER + '/connect/logout', params);
            require(code == 302, 'Validated OP logout failed')
        else:
            # Advance only this run's portal-B OP-session deadline; the actual scheduler and HTTP delivery must finish logout.
            column = 'idle_expires_at' if mode == 'idle' else 'expires_at'
            sql = f'''UPDATE "{schemas[0]}".identity_sessions SET {column}=clock_timestamp()-interval '1 second'
                WHERE id IN (SELECT a.session_id FROM "{schemas[0]}".authorization_lifecycle a
                  JOIN "{schemas[0]}".oauth2_registered_client c ON c.id=a.client_id WHERE c.client_id='portal-b');'''
            result = subprocess.run(
                ['docker', 'compose', 'exec', '-T', 'postgres', 'psql', '-U', 'iam', '-d', 'iam', '-v',
                 'ON_ERROR_STOP=1'], input=sql.encode(), cwd=ROOT, capture_output=True, check=True, timeout=10)
            require(result.stdout.strip() == b'UPDATE 1', 'Expected exactly one targeted OP session')
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if browser.get(B + '/profile')[0] != 200: break
            time.sleep(.2)
        else:
            raise AssertionError('Back-channel did not invalidate portal B')
        require(browser.get(A + '/profile')[0] != 200, 'Portal A session survived')
        require(browser.get(PEER + '/profile')[0] != 200, 'Peer RP node retained logged-out session')
        if mode != 'logout': require(browser.get(ISSUER + '/')[0] == 401, 'Expired OP cookie resumed a session')
        require(independent.get(A + '/orders')[0] == 200, 'Independent session protected API failed')
        require(independent.get(A + '/profile')[0] == 200, 'Other OP session was incorrectly invalidated')
        print(
            'PASS: ' + mode + '; two-BFF SSO, protected APIs, shared RP node, automatic back-channel logout, and independent-session isolation')
    except Exception:
        print('Application logs retained in', logs)
        raise
    finally:
        if catalogue_server: catalogue_server.shutdown();catalogue_server.server_close()
        for process in reversed(processes):
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill();
                process.wait(timeout=5)
        profile_failure = None
        if mode == 'capacity-profile' and (logs / 'cpu.jfr').exists():
            output = logs / 'cpu-events.json'
            try:
                jfr = str(pathlib.Path(java).parent / 'jfr') if pathlib.Path(java).is_absolute() else shutil.which(
                    'jfr')
                require(jfr is not None, 'JDK jfr command required')
                with output.open('wb') as stream:
                    subprocess.run([jfr, 'print', '--json', '--events', 'jdk.ExecutionSample', str(logs / 'cpu.jfr')],
                                   stdout=stream, stderr=subprocess.DEVNULL, check=True, timeout=20)
                subprocess.run(['python3', 'benchmarks/summarize_cpu.py', str(output)], cwd=ROOT, check=True,
                               timeout=10)
            except Exception as failure:
                profile_failure = failure
            finally:
                (logs / 'cpu.jfr').unlink(missing_ok=True);
                output.unlink(missing_ok=True)
        for file in files: file.close()
        if chrome_profile: shutil.rmtree(chrome_profile, ignore_errors=True)
        cleanup_failures = []
        try:
            cursor = '0'
            for _ in range(100):
                scan = subprocess.run(
                    ['docker', 'compose', 'exec', '-T', 'redis', 'redis-cli', '--raw', 'SCAN', cursor, 'MATCH',
                     namespace + ':*', 'COUNT', '1000'], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    timeout=5)
                lines = scan.stdout.decode().splitlines()
                if scan.returncode or not lines or not lines[0].isdigit(): raise RuntimeError(
                    'Redis cleanup unavailable')
                cursor = lines[0]
                if len(lines) > 1: subprocess.run(
                    ['docker', 'compose', 'exec', '-T', 'redis', 'redis-cli', 'UNLINK', *lines[1:]], cwd=ROOT,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=5)
                if cursor == '0': break
            else:
                raise RuntimeError('Redis cleanup scan budget exceeded')
        except Exception:
            cleanup_failures.append('Redis namespace ' + namespace)
        # Always attempt SQL cleanup, even if Redis is unavailable. Never mask the test's original failure.
        sql = ''.join('DROP SCHEMA IF EXISTS "' + schema + '" CASCADE;\n' for schema in schemas)
        try:
            subprocess.run(['docker', 'compose', 'exec', '-T', 'postgres', 'psql', '-U', 'iam', '-d', 'iam', '-v',
                            'ON_ERROR_STOP=1'], input=sql.encode(), cwd=ROOT, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, check=True, timeout=15)
        except Exception:
            cleanup_failures.append('PostgreSQL schemas ' + ','.join(schemas))
        if cleanup_failures:
            print('Cleanup incomplete: ' + '; '.join(cleanup_failures), file=sys.stderr)
            if sys.exc_info()[0] is None: raise RuntimeError('Owned test-state cleanup incomplete')
        if profile_failure and sys.exc_info()[0] is None: raise profile_failure


if __name__ == '__main__': main()
