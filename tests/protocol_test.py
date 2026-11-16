#!/usr/bin/env python3
"""Real HTTP tests. Requires the local stack; never prints bearer or credential values."""
import base64
import concurrent.futures
import hashlib
import http.cookiejar
import json
import os
import unittest
import urllib.error
import urllib.parse
import urllib.request

import secrets

ISSUER = os.environ.get('IAM_ISSUER', 'http://localhost:9000')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): return None


class Browser:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.http = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), NoRedirect())

    def request(self, url, data=None, headers=None):
        if url.startswith('/'): url = ISSUER + url
        request = urllib.request.Request(url, data=urllib.parse.urlencode(data).encode() if data is not None else None,
                                         headers=headers or {})
        try:
            with self.http.open(request, timeout=10) as r:
                return r.status, r.headers, r.read().decode()
        except urllib.error.HTTPError as r:
            with r:
                return r.code, r.headers, r.read().decode()


def basic(client, secret): return {
    'Authorization': 'Basic ' + base64.b64encode((client + ':' + secret).encode()).decode()}


def token(data, client='portal-a', secret=None): return Browser().request('/oauth2/token', data, basic(client, secret or
                                                                                                       os.environ[
                                                                                                           'PORTAL_SECRET']))


def csrf(html):
    import re
    return re.search(r'name="_csrf"[^>]*value="([^"]+)"', html).group(1)


def login(browser):
    status, headers, body = browser.request('/login')
    assert status == 200
    status, _, _ = browser.request('/login', {'username': 'employee', 'password': os.environ['DEMO_PASSWORD'],
                                              '_csrf': csrf(body)})
    assert status == 302
    return browser


def code(browser=None, client='portal-a', port=8080, verifier=None):
    browser = browser or login(Browser());
    verifier = verifier or secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    state = secrets.token_urlsafe(16)
    query = urllib.parse.urlencode(
        {'response_type': 'code', 'client_id': client, 'redirect_uri': f'http://localhost:{port}/login/oauth2/code/iam',
         'scope': 'openid profile orders.read', 'state': state, 'nonce': secrets.token_urlsafe(16),
         'code_challenge': challenge, 'code_challenge_method': 'S256'})
    status, headers, body = browser.request('/oauth2/authorize?' + query)
    assert status == 302, (status, body[:200])
    result = urllib.parse.parse_qs(urllib.parse.urlparse(headers['Location']).query)
    assert result.get('state') == [state]
    return result['code'][0], verifier, browser


def exchange(c, v): return token({'grant_type': 'authorization_code', 'code': c, 'code_verifier': v,
                                  'redirect_uri': 'http://localhost:8080/login/oauth2/code/iam'})


class ProtocolTests(unittest.TestCase):
    def test_discovery_jwks(self):
        s, _, body = Browser().request('/.well-known/openid-configuration');
        self.assertEqual(s, 200);
        self.assertEqual(json.loads(body)['issuer'], ISSUER)
        s, _, body = Browser().request('/oauth2/jwks');
        self.assertEqual(s, 200)
        for k in json.loads(body)['keys']: self.assertNotIn('d', k);self.assertIn('kid', k)

    def test_machine_and_resource(self):
        s, _, b = token({'grant_type': 'client_credentials', 'scope': 'orders.read'}, 'order-service',
                        os.environ['MACHINE_SECRET']);
        self.assertEqual(s, 200)
        t = json.loads(b)['access_token'];
        s, _, _ = Browser().request('http://localhost:9001/api/orders', headers={'Authorization': 'Bearer ' + t});
        self.assertEqual(s, 200)
        s, _, _ = Browser().request('http://localhost:9001/api/orders');
        self.assertEqual(s, 401)

    def test_invalid_client_scope(self):
        s, _, _ = token({'grant_type': 'client_credentials'}, 'order-service', 'incorrect');
        self.assertEqual(s, 401)
        s, _, _ = token({'grant_type': 'client_credentials', 'scope': 'iam.admin'}, 'order-service',
                        os.environ['MACHINE_SECRET']);
        self.assertEqual(s, 400)

    def test_pkce_userinfo_code_replay(self):
        c, v, _ = code();
        s, _, body = exchange(c, v);
        self.assertEqual(s, 200, body[:100]);
        t = json.loads(body)
        self.assertIn('id_token', t);
        self.assertIn('refresh_token', t)
        s, _, _ = Browser().request('/userinfo', headers={'Authorization': 'Bearer ' + t['access_token']});
        self.assertEqual(s, 200)
        s, _, _ = exchange(c, v);
        self.assertEqual(s, 400)

    def test_bad_verifier(self):
        c, v, _ = code();
        s, _, _ = exchange(c, secrets.token_urlsafe(48));
        self.assertEqual(s, 400)

    def test_redirect_rejected(self):
        b = login(Browser());
        s, h, _ = b.request('/oauth2/authorize?' + urllib.parse.urlencode(
            {'response_type': 'code', 'client_id': 'portal-a', 'redirect_uri': 'https://attacker.invalid',
             'scope': 'openid'}));
        self.assertNotEqual(s, 302)

    def test_sso(self):
        c, v, b = code();
        c2, v2, _ = code(b, client='portal-b', port=8081);
        self.assertTrue(c2)

    def test_rotation_replay(self):
        c, v, _ = code();
        s, _, b = exchange(c, v);
        self.assertEqual(s, 200);
        r1 = json.loads(b)['refresh_token']
        s, _, b = token({'grant_type': 'refresh_token', 'refresh_token': r1});
        self.assertEqual(s, 200, b[:100]);
        r2 = json.loads(b)['refresh_token'];
        self.assertNotEqual(r1, r2)
        s, _, _ = token({'grant_type': 'refresh_token', 'refresh_token': r1});
        self.assertEqual(s, 400)
        s, _, _ = token({'grant_type': 'refresh_token', 'refresh_token': r2});
        self.assertEqual(s, 400)

    def test_concurrent_refresh(self):
        c, v, _ = code();
        _, _, b = exchange(c, v);
        r = json.loads(b)['refresh_token']
        with concurrent.futures.ThreadPoolExecutor(2) as pool: results = list(
            pool.map(lambda _: token({'grant_type': 'refresh_token', 'refresh_token': r}), range(2)))
        self.assertEqual(sorted(x[0] for x in results), [200, 400])
        new = json.loads(next(x[2] for x in results if x[0] == 200))['refresh_token']
        self.assertEqual(token({'grant_type': 'refresh_token', 'refresh_token': new})[0], 400)

    def test_revocation_introspection(self):
        _, _, b = token({'grant_type': 'client_credentials', 'scope': 'orders.read'}, 'order-service',
                        os.environ['MACHINE_SECRET']);
        t = json.loads(b)['access_token'];
        auth = basic('order-service', os.environ['MACHINE_SECRET'])
        s, _, b = Browser().request('/oauth2/introspect', {'token': t}, auth);
        self.assertEqual(s, 200);
        self.assertTrue(json.loads(b)['active'])
        s, _, _ = Browser().request('/oauth2/revoke', {'token': t}, auth);
        self.assertEqual(s, 200)
        _, _, b = Browser().request('/oauth2/introspect', {'token': t}, auth);
        self.assertFalse(json.loads(b)['active'])

    def test_bff_login_api_and_sso(self):
        b = login(Browser())
        for port in [8080, 8081]:
            status, h, _ = b.request(f'http://localhost:{port}/oauth2/authorization/iam');
            self.assertEqual(status, 302)
            status, h, _ = b.request(h['Location']);
            self.assertEqual(status, 302)
            self.assertIn(f'localhost:{port}/login/oauth2/code/iam', h['Location'])
            status, h, _ = b.request(h['Location']);
            self.assertEqual(status, 302)
            status, _, body = b.request(f'http://localhost:{port}/profile');
            self.assertEqual(status, 200);
            self.assertIn('subject', json.loads(body))
            status, _, body = b.request(f'http://localhost:{port}/orders');
            self.assertEqual(status, 200);
            self.assertIn('orders', json.loads(body))

    def test_pkce_plain_rejected(self):
        b = login(Browser())
        status, h, body = b.request('/oauth2/authorize?' + urllib.parse.urlencode(
            {'response_type': 'code', 'client_id': 'portal-a',
             'redirect_uri': 'http://localhost:8080/login/oauth2/code/iam', 'scope': 'openid',
             'code_challenge': 'a' * 43, 'code_challenge_method': 'plain'}))
        self.assertTrue(status == 400 or (status == 302 and 'error=' in h.get('Location', '')))

    def test_admin_isolation(self):
        _, _, b = token({'grant_type': 'client_credentials'}, 'order-service', os.environ['MACHINE_SECRET']);
        t = json.loads(b)['access_token']
        s, _, _ = Browser().request('/api/v1/admin/users', headers={'Authorization': 'Bearer ' + t});
        self.assertEqual(s, 403)


if __name__ == '__main__': unittest.main(verbosity=2)
