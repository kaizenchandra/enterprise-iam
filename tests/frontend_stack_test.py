#!/usr/bin/env python3
"""Real Next.js + IAM + resource HTTP regression on isolated schemas/namespaces.
Requires built Maven JARs, frontend npm build, root .env and running Compose stores.
No credentials/tokens are printed. Stops only processes and data created by this test.
"""
import http.cookiejar
import json
import os
import pathlib
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
ORIGIN = 'http://localhost:3000'
ISSUER = 'http://localhost:9000'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): return None


class Browser:
    def __init__(self):
        self.cookies = http.cookiejar.CookieJar()
        self.http = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookies), NoRedirect())

    def request(self, path, method='GET', body=None, origin=ORIGIN, form=False):
        url = path if path.startswith('http') else ORIGIN + path
        headers = {'Origin': origin} if method != 'GET' else {}
        if body is not None:
            headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
            body = (urllib.parse.urlencode(body) if form else json.dumps(body)).encode()
        request = urllib.request.Request(url, method=method, data=body, headers=headers)
        try:
            with self.http.open(request, timeout=20) as response:
                return response.status, response.headers, response.read().decode()
        except urllib.error.HTTPError as response:
            with response:
                return response.code, response.headers, response.read().decode()


def require(ok, label):
    if not ok: raise AssertionError(label)


def main():
    env = dict(os.environ)
    for line in (ROOT / '.env').read_text().splitlines():
        key, sep, value = line.partition('=')
        if sep: env[key] = value
    for port in (3000, 9000, 9001):
        with socket.socket() as sock:
            require(sock.connect_ex(('127.0.0.1', port)) != 0,
                    f'Port {port} is occupied; stop your own manual stack first')
    nonce = uuid.uuid4().hex[:12]
    schema = 'frontend_' + nonce
    redis_prefix = 'iam:frontend-test:' + nonce + ':'
    logdir = pathlib.Path(tempfile.mkdtemp(prefix='iam-frontend-test-'))
    processes = [];
    files = []

    def sql(statement):
        subprocess.run(
            ['docker', 'compose', 'exec', '-T', 'postgres', 'psql', '-U', 'iam', '-d', 'iam', '-v', 'ON_ERROR_STOP=1'],
            input=statement, text=True, cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            check=True)

    def start(name, args, extra, cwd=ROOT):
        log = (logdir / (name + '.log')).open('w');
        files.append(log)
        processes.append(subprocess.Popen(args, env={**env, **extra}, cwd=cwd, stdout=log, stderr=subprocess.STDOUT))

    def wait(url):
        for _ in range(120):
            require(all(p.poll() is None for p in processes), 'An owned app exited; inspect temporary log directory')
            try:
                with urllib.request.urlopen(url, timeout=2) as response:
                    if response.status == 200: return
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(.5)
        raise AssertionError('App readiness timeout')

    def expect(browser, path, status=200, method='GET', body=None):
        code, headers, text = browser.request(path, method, body)
        require(code == status, f'{method} {path.split("?")[0]} expected {status}, received {code}')
        return json.loads(text) if text else None

    try:
        sql(f'create schema {schema};')
        java = str(pathlib.Path(env['JAVA_HOME']) / 'bin/java') if env.get('JAVA_HOME') else 'java'
        start('iam', [java, '-Xmx384m', '-jar', 'iam-server/target/iam-server-0.1.0-SNAPSHOT.jar'], {
            'SPRING_PROFILES_ACTIVE': 'local', 'SERVER_ADDRESS': '127.0.0.1',
            'DB_URL': 'jdbc:postgresql://localhost:5432/iam?currentSchema=' + schema,
            'SPRING_FLYWAY_SCHEMAS': schema, 'SPRING_FLYWAY_DEFAULT_SCHEMA': schema,
            'SPRING_SESSION_REDIS_NAMESPACE': redis_prefix + 'op',
            'IAM_BACKCHANNEL_ALLOWED_ORIGINS': ORIGIN,
            'IAM_BACKCHANNEL_INITIAL_DELAY_MS': '500', 'IAM_BACKCHANNEL_DELAY_MS': '500',
        })
        wait(ISSUER + '/.well-known/openid-configuration')
        start('resource',
              [java, '-Xmx192m', '-jar', 'sample-resource-server/target/sample-resource-server-0.1.0-SNAPSHOT.jar'], {
                  'IAM_ISSUER': ISSUER, 'SERVER_ADDRESS': '127.0.0.1',
              })
        start('next', ['node', 'node_modules/next/dist/bin/next', 'start', '--hostname', '127.0.0.1'], {
            'IAM_ISSUER': ISSUER, 'CONSOLE_ORIGIN': ORIGIN, 'CONSOLE_CLIENT_ID': 'next-console',
            'CONSOLE_CLIENT_SECRET': env['PORTAL_SECRET'], 'CONSOLE_COOKIE_SECURE': 'false',
            'CONSOLE_REDIS_URL': 'redis://localhost:6379', 'CONSOLE_REDIS_PREFIX': redis_prefix + 'bff:',
            'CONSOLE_DIAGNOSTICS': 'true',
        }, ROOT / 'frontend')
        wait(ORIGIN)
        wait('http://localhost:9001/actuator/health')
        browser = Browser()
        status, headers, html = browser.request('/login')
        require(status == 200 and 'IAM' in html, 'Console HTML available')
        require(headers.get('X-Frame-Options') == 'DENY', 'Frame protection')
        require(headers.get('Referrer-Policy') == 'no-referrer', 'Referrer protection')
        csp = headers.get('Content-Security-Policy', '')
        require("'nonce-" in csp and "'strict-dynamic'" in csp and "script-src 'self' 'unsafe-inline'" not in csp,
                'Nonce-based script policy')
        require('nonce=' in html, 'Hydration scripts receive a nonce')
        require(env['ADMIN_SECRET'] not in html and env['PORTAL_SECRET'] not in html,
                'No configuration secrets in HTML')

        def sign_in(lane):
            code, headers, _ = browser.request('/api/auth/start?lane=' + lane, 'POST')
            require(code == 303, 'Code+PKCE start')
            url = headers['Location']
            for _ in range(15):
                code, headers, text = browser.request(url)
                if code in (302, 303):
                    url = urllib.parse.urljoin(url, headers['Location'])
                    require(urllib.parse.urlparse(url).netloc in ('localhost:9000', 'localhost:3000'),
                            'Safe auth redirect')
                    continue
                if urllib.parse.urlparse(url).path == '/login':
                    match = re.search(r'name="_csrf"[^>]*value="([^"]+)"', text)
                    require(match is not None, 'Login CSRF token')
                    code, headers, _ = browser.request(ISSUER + '/login', 'POST',
                                                       {'username': 'admin', 'password': env['ADMIN_PASSWORD'],
                                                        '_csrf': match.group(1)}, origin=ISSUER, form=True)
                    require(code == 302, 'Password authentication')
                    url = urllib.parse.urljoin(ISSUER, headers['Location']);
                    continue
                require(code == 200 and url.startswith(ORIGIN + '/'), 'Returned to console after verified callback')
                break
            else:
                raise AssertionError('OAuth redirect loop')
            require(lane in expect(browser, '/api/auth/status')['lanes'], 'OIDC grant saved')

        expect(browser, '/api/backend/api/v1/admin/users', 401)
        require(browser.request('/api/auth/start?lane=admin', 'POST', origin='https://attacker.example')[0] == 403,
                'Reject cross-origin sign-in initiation')
        expect(browser, '/api/auth/connect', 410, 'POST', {})
        sign_in('admin')
        require('admin' in expect(browser, '/api/auth/status')['lanes'], 'Admin exchange and safe session summary')
        cookie = next(c for c in browser.cookies if c.name == 'IAM_CONSOLE_LOCAL')
        require(len(cookie.value) == 43 and 'HttpOnly' in cookie._rest, 'Opaque HttpOnly session cookie')
        user = expect(browser, '/api/backend/api/v1/admin/users', 201, 'POST',
                      {'username': 'console-' + nonce, 'password': 'temporary-' + uuid.uuid4().hex})
        uid = user['id']
        expect(browser, '/api/backend/api/v1/admin/users/' + uid + '/activate', 200, 'POST')
        record = expect(browser, '/api/backend/api/v1/admin/users/' + uid)
        expect(browser, '/api/backend/api/v1/admin/users/' + uid, 200, 'PATCH',
               {'username': 'renamed-' + nonce, 'version': record['version']})
        expect(browser, '/api/backend/api/v1/admin/users/' + uid, 409, 'PATCH',
               {'username': 'stale-' + nonce, 'version': record['version']})
        expect(browser, '/api/backend/api/v1/admin/users?page=21474837', 400)
        expect(browser, '/api/backend/api/v1/admin/users?unexpected=x', 400)
        expect(browser, '/api/backend/oauth2/token', 404, 'POST')
        org = expect(browser, '/api/backend/api/v1/admin/organizations', 201, 'POST', {'name': 'Console regression'})[
            'id']
        expect(browser, f'/api/backend/api/v1/organizations/{org}/members', 201, 'POST', {'userId': uid})
        expect(browser, f'/api/backend/api/v1/organizations/{org}/members', 409, 'POST', {'userId': uid})
        require(len(expect(browser, f'/api/backend/api/v1/organizations/{org}/members')) == 1, 'Member listing')
        role = expect(browser, '/api/backend/api/v1/admin/roles', 201, 'POST', {'name': 'role-' + nonce})['id']
        expect(browser, '/api/backend/api/v1/admin/permissions', 201, 'POST',
               {'roleId': role, 'permission': 'payment:read'})
        assignment = expect(browser, '/api/backend/api/v1/admin/role-assignments', 201, 'POST',
                            {'userId': uid, 'organizationId': org, 'roleId': role})['id']
        expect(browser, '/api/backend/api/v1/admin/role-assignments/' + assignment, 204, 'DELETE')
        client = expect(browser, '/api/backend/api/v1/admin/clients', 201, 'POST',
                        {'clientId': 'test-' + nonce, 'scopes': ['orders.read'],
                         'clientAuthenticationMethod': 'client_secret_basic'})
        require('clientSecret' in client, 'One-time client secret issuance')
        listing = expect(browser, '/api/backend/api/v1/admin/clients')
        require(all('clientSecret' not in entry for entry in listing), 'Ordinary client listing never returns secret')
        rotated = expect(browser, f'/api/backend/api/v1/admin/clients/test-{nonce}/rotate-credentials', 200, 'POST')
        require(rotated['clientSecret'] != client['clientSecret'], 'Secret rotation')

        sign_in('app')
        identity = expect(browser, '/api/resources/identity')
        require(bool(identity.get('sub')), 'OIDC UserInfo')
        expect(browser, '/api/resources/orders')
        expect(browser, f'/api/backend/api/v1/organizations/{org}/members', 201, 'POST', {'userId': identity['sub']})
        resource = 'resource-' + nonce
        sql(f"insert into {schema}.protected_resources values ('{resource}','{org}');")
        expect(browser, '/api/backend/api/v1/admin/role-assignments', 201, 'POST',
               {'userId': identity['sub'], 'organizationId': org, 'roleId': role, 'resourceId': resource})
        decision = {'tenantId': org, 'action': 'payment:read', 'resourceId': resource}
        require(expect(browser, '/api/backend/api/v1/authorization/decisions', 200, 'POST', decision)[
                    'decision'] == 'ALLOW', 'Live PDP allow')
        expect(browser, f'/api/backend/api/v1/organizations/{org}/members/{identity["sub"]}', 204, 'DELETE')
        require(
            expect(browser, '/api/backend/api/v1/authorization/decisions', 200, 'POST', decision)['decision'] == 'DENY',
            'Membership removal denies live PDP')
        sign_in('management')
        sessions = expect(browser, '/api/backend/api/v1/users/me/sessions?limit=20')
        current = next(s for s in sessions['items'] if s['current'])
        expect(browser, '/api/backend/api/v1/users/me/sessions/' + current['id'], 204, 'DELETE')
        for _ in range(60):
            if not expect(browser, '/api/auth/status')['lanes']: break
            time.sleep(.5)
        else:
            raise AssertionError('Signed back-channel logout did not invalidate console session')
        expect(browser, '/api/backend/api/v1/admin/users', 401)
        require(browser.request('/api/auth/callback?state=invalid&code=untrusted')[0] == 303,
                'Invalid callback safely redirects')
        expect(browser, '/api/auth/disconnect', 200, 'POST')
        print(
            'PASS: Next.js/IAM admin lifecycle, membership/RBAC, credentials, Code+PKCE, UserInfo, resource API, PDP and distributed logout',
            flush=True)
        if '--preview' in __import__('sys').argv:
            input('Preview ready at http://localhost:3000. Press Enter to stop owned apps and clean isolated data.\n')
    except Exception as error:
        if '--preview' in __import__('sys').argv:
            print(type(error).__name__ + ': ' + str(error), flush=True)
            input('Failed stack retained for inspection. Press Enter to clean up.\n')
        raise
    finally:
        for process in reversed(processes):
            process.terminate()
        for process in reversed(processes):
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill();
                process.wait()
        for stream in files: stream.close()
        try:
            sql(f'drop schema if exists {schema} cascade;')
        finally:
            # SCAN only this test prefix; never flush shared Redis.
            subprocess.run(['docker', 'compose', 'exec', '-T', 'redis', 'sh', '-c',
                            'redis-cli --scan --pattern "$1*" | while read -r key; do redis-cli DEL "$key" >/dev/null; done',
                            'sh', redis_prefix],
                           cwd=ROOT, env=env, stdout=subprocess.DEVNULL, check=False)
        shutil.rmtree(logdir, ignore_errors=True)


if __name__ == '__main__': main()
