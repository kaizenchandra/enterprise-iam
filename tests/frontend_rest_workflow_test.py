#!/usr/bin/env python3
"""Live JSON IAM APIs through the Next identity proxy, plus Mailpit and OIDC.
No browser automation; uses only its own disposable account for credential changes.
"""
import base64
import hashlib
import hmac
import json
import re
import socket
import struct
import time
import urllib.parse
import urllib.request
import uuid

from frontend_stack_test import Browser, ROOT, ORIGIN, require

resolve = socket.getaddrinfo
socket.getaddrinfo = lambda host, *args, **kwargs: resolve('127.0.0.1' if host == 'iam.localhost' else host, *args,
                                                           **kwargs)
UI = 'http://iam.localhost:3000'
PROVIDER = 'http://iam.localhost:9000'


def api(browser, path, body=None):
    if body is not None:
        status, _, text = browser.request(UI + '/api/iam/session/bootstrap')
        require(status == 200, 'JSON CSRF bootstrap')
        proof = json.loads(text)['csrfToken']
        request = urllib.request.Request(UI + '/api/iam' + path, data=json.dumps(body).encode(),
                                         headers={'Content-Type': 'application/json', 'Origin': UI,
                                                  'X-CSRF-TOKEN': proof})
        try:
            r = browser.http.open(request, timeout=20)
        except urllib.error.HTTPError as error:
            r = error
        return r.status, r.headers, json.loads(r.read().decode() or '{}')
    status, headers, text = browser.request(UI + '/api/iam' + path)
    return status, headers, json.loads(text or '{}')


def login(browser, lane, username, password, recovery=None):
    # Force a new IAM session; preserve only the console's opaque binding cookies.
    for cookie in list(browser.cookies):
        if cookie.name not in ('IAM_CONSOLE_LOCAL', 'IAM_CONSOLE_TX_LOCAL'): browser.cookies.clear(cookie.domain,
                                                                                                   cookie.path,
                                                                                                   cookie.name)
    status, headers, _ = browser.request('/api/auth/start?lane=' + lane, 'POST');
    require(status == 303, 'OIDC start')
    url = headers['Location']
    for _ in range(20):
        path = urllib.parse.urlsplit(url).path
        if url.startswith(UI) and path == '/auth/login':
            status, _, value = api(browser, '/session/login', {'username': username, 'password': password});
            require(status == 200, 'JSON login')
            url = value['redirect'];
            continue
        if url.startswith(UI) and path == '/mfa':
            require(recovery is not None, 'MFA enforced')
            status, _, value = api(browser, '/mfa/recover', {'code': recovery});
            require(status == 200, 'JSON recovery proof')
            url = value['redirect'];
            continue
        status, headers, _ = browser.request(url)
        if status in (302, 303, 307): url = urllib.parse.urljoin(url, headers['Location']);continue
        require(status == 200 and url.startswith(ORIGIN + '/?tab='), 'Frontend console callback');
        break
    else:
        raise AssertionError('Redirect loop')
    require(lane in json.loads(browser.request('/api/auth/status')[2])['lanes'], 'Authenticated console lane')


def mail_token(email, purpose='verify'):
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}));
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        messages = json.load(
            client.open('http://localhost:8025/api/v1/search?' + urllib.parse.urlencode({'query': 'to:' + email})))[
            'messages']
        for summary in messages:
            value = json.load(client.open('http://localhost:8025/api/v1/message/' + summary['ID']))
            match = re.search(re.escape(UI + '/account/' + purpose) + r'#token=([A-Za-z0-9_-]{43})', value['Text'])
            if match: return match.group(1)
        time.sleep(.5)
    raise AssertionError('Mailpit delivery deadline')


def main():
    env = dict(line.split('=', 1) for line in (ROOT / '.env').read_text().splitlines() if
               '=' in line and not line.startswith('#'))
    admin, person = Browser(), Browser();
    login(admin, 'admin', 'admin', env['ADMIN_PASSWORD'])
    require(admin.request('/api/backend/api/v1/admin/users')[0] == 200, 'Admin directory access')
    nonce = uuid.uuid4().hex;
    name = 'rest-' + nonce;
    email = name + '@example.test';
    password = 'temporary-' + nonce
    status, _, page = person.request('/register');
    require(status in (303, 307), 'Frontend register entry')
    require(person.request(UI + '/account/register')[0] == 200, 'Frontend owns registration HTML')
    status, headers, bootstrap = api(person, '/session/bootstrap');
    require(status == 200 and bootstrap['registrationEnabled'], 'REST capabilities')
    bad = person.request(UI + '/api/iam/account/register', 'POST',
                         {'username': name, 'password': password, 'confirmation': password, 'email': email},
                         origin='https://attacker.example')
    require(bad[0] == 403, 'Proxy rejects foreign origins')
    status, _, value = api(person, '/account/register',
                           {'username': name, 'password': password, 'confirmation': password, 'email': email})
    require(status == 200 and value['accepted'], 'REST registration')
    try:
        require(api(person, '/session/login', {'username': name, 'password': password})[0] == 401,
                'Unverified login denied')
        token = mail_token(email)
        require(api(person, '/account/verify', {'token': token})[0] == 200, 'Mailpit verification')
        require(api(person, '/account/verify', {'token': token})[0] == 400, 'Email token replay denied')
        login(person, 'app', name, password)
        require(person.request('/api/resources/identity')[0] == 200, 'Verified OIDC UserInfo')
        require(person.request('/api/backend/api/v1/admin/users')[0] == 401,
                'Registration cannot grant admin privileges')
        status, _, settings = api(person, '/mfa/settings');
        require(status == 200 and not settings['enabled'], 'JSON MFA settings')
        status, _, setup = api(person, '/mfa/enroll', {'password': password});
        require(status == 200, 'MFA setup')
        digest = hmac.new(base64.b32decode(setup['secret']), struct.pack('>Q', int(time.time()) // 30),
                          hashlib.sha1).digest();
        offset = digest[-1] & 15
        otp = str((struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000).zfill(6)
        status, _, result = api(person, '/mfa/verify', {'code': otp});
        require(status == 200 and len(result['recoveryCodes']) == 10, 'Recovery codes returned only in JSON response')
        first = result['recoveryCodes'];
        require(not json.loads(person.request('/api/auth/status')[2])['lanes'], 'MFA change revokes console grant')
        login(person, 'app', name, password, first[0])
        status, _, result = api(person, '/mfa/recovery-codes',
                                {'password': password, 'code': first[1], 'recovery': True});
        require(status == 200, 'Renew recovery codes')
        second = result['recoveryCodes'];
        login(person, 'app', name, password, second[0])
        require(api(person, '/mfa/remove', {'password': password, 'code': first[2], 'recovery': True})[0] == 401,
                'Old recovery code denied')
        require(api(person, '/mfa/remove', {'password': password, 'code': second[1], 'recovery': True})[0] == 200,
                'MFA removal')
        login(person, 'app', name, password)
        status, _, keys = api(person, '/passkeys');
        require(status == 200 and keys['credentials'] == [], 'REST passkey list')
        status, _, options = api(person, '/passkeys/register/options', {'password': password});
        require(status == 200 and options['options']['publicKey']['rp']['id'] == 'iam.localhost',
                'WebAuthn RP preserved')
        require(api(person, '/passkeys/register/finish', {'id': options['id'], 'credential': {}})[0] == 400,
                'Malformed WebAuthn proof denied')
        require(api(person, '/account/reset/request', {'email': email})[0] == 200, 'Password reset request')
        reset = mail_token(email, 'reset');
        new_password = 'changed-' + nonce
        require(api(person, '/account/reset', {'token': reset, 'password': new_password, 'confirmation': new_password})[
                    0] == 200, 'Password reset')
        require(api(person, '/session/login', {'username': name, 'password': password})[0] == 401,
                'Old password denied')
        login(person, 'app', name, new_password)
        require(api(person, '/session/logout', {})[0] == 200, 'JSON IAM logout')
        require(not json.loads(person.request('/api/auth/status')[2])['lanes'], 'Logout revokes frontend grant')
        print(
            'PASS REST frontend proxy: registration, Mailpit verification, JSON login, OIDC, MFA enrollment/recovery/renewal/removal, WebAuthn options/rejection, reset, logout and grant invalidation',
            flush=True)
    finally:
        for page in range(20):
            status, _, text = admin.request('/api/backend/api/v1/admin/users?page=' + str(page));
            require(status == 200, 'Cleanup lookup')
            rows = json.loads(text);
            found = next((row for row in rows if row['username'] == name), None)
            if found:
                require(admin.request('/api/backend/api/v1/admin/users/' + found['id'], 'DELETE')[0] == 204,
                        'Disposable identity cleanup');
                break
            require(len(rows) == 100, 'Cleanup identity exists')


if __name__ == '__main__': main()
