import {test} from 'node:test';
import assert from 'node:assert/strict';
import {NextRequest} from 'next/server';
import {config, digest, failure, HttpError, jsonBody, originGuard, sessionId} from '../src/lib/server';
import nextConfig from '../next.config';
import {proxy} from '../src/proxy';

process.env.CONSOLE_ORIGIN = 'http://localhost:3000';
process.env.CONSOLE_COOKIE_SECURE = 'false';
process.env.IAM_ISSUER = 'http://localhost:9000';

test('CSP allows the configured IAM form redirect and excludes unrelated origins', () => {
    const response = proxy(new NextRequest('http://localhost:3000/login'));
    const csp = response.headers.get('Content-Security-Policy')!;
    assert.equal(csp.split('; ').find(rule => rule.startsWith('form-action')), "form-action 'self' http://localhost:9000");
});

test('browser form policy uses the public issuer rather than its server transport alias', () => {
    const issuer = process.env.IAM_ISSUER, transport = process.env.IAM_TRANSPORT_ORIGIN;
    try {
        process.env.IAM_ISSUER = 'http://iam.localhost:9000';
        process.env.IAM_TRANSPORT_ORIGIN = 'http://127.0.0.1:9000';
        const csp = proxy(new NextRequest('http://localhost:3000/login')).headers.get('Content-Security-Policy')!;
        assert.equal(csp.split('; ').find(rule => rule.startsWith('form-action')), "form-action 'self' http://iam.localhost:9000");
    } finally {
        process.env.IAM_ISSUER = issuer;
        if (transport === undefined) delete process.env.IAM_TRANSPORT_ORIGIN; else process.env.IAM_TRANSPORT_ORIGIN = transport;
    }
});

test('page referrer policy preserves Origin on same-origin login form submissions', async () => {
    const rules = await nextConfig.headers!();
    const headers = rules.find(rule => rule.source === '/:path*')!.headers;
    assert.equal(headers.find(header => header.key === 'Referrer-Policy')?.value, 'same-origin');
});

test('mutation protection requires an exact configured origin', () => {
    for (const origin of [null, 'https://attacker.example', 'http://localhost:3000.evil', 'null']) {
        const req = new NextRequest('http://localhost:3000/api/auth/connect', {
            method: 'POST',
            headers: origin ? {Origin: origin} : {}
        });
        assert.throws(() => originGuard(req), (error: unknown) => error instanceof HttpError && error.status === 403);
    }
    assert.doesNotThrow(() => originGuard(new NextRequest('http://localhost:3000', {headers: {Origin: 'http://localhost:3000'}})));
});
test('configuration disallows remote HTTP, injected paths and insecure remote cookies', () => {
    const original = process.env.CONSOLE_ORIGIN;
    for (const value of ['http://evil.example', 'https://example.com/path', 'https://user:pass@example.com', 'https://example.com']) {
        process.env.CONSOLE_ORIGIN = value;
        assert.throws(config);
    }
    process.env.CONSOLE_ORIGIN = original;
    assert.equal(config().origin, original);
});
test('session cookie parsing accepts only server-generated opaque shape', () => {
    for (const value of ['short', 'a'.repeat(100), '../session', 'abc%00']) assert.equal(sessionId(new NextRequest('http://localhost:3000', {headers: {Cookie: 'IAM_CONSOLE_LOCAL=' + value}})), undefined);
    assert.equal(sessionId(new NextRequest('http://localhost:3000', {headers: {Cookie: 'IAM_CONSOLE_LOCAL=' + 'a'.repeat(43)}})), 'a'.repeat(43));
    assert.notEqual(digest('secret-session'), 'secret-session');
});
test('body reader bounds streamed data without trusting content-length', async () => {
    await assert.rejects(() => jsonBody(new NextRequest('http://localhost:3000', {
        method: 'POST',
        body: 'x'.repeat(65537),
        headers: {'Content-Type': 'application/json'}
    })), (error: unknown) => error instanceof HttpError && error.status === 413);
    await assert.rejects(() => jsonBody(new NextRequest('http://localhost:3000', {
        method: 'POST',
        body: 'bad',
        headers: {'Content-Type': 'application/json'}
    })), (error: unknown) => error instanceof HttpError && error.status === 400);
    assert.deepEqual(await jsonBody(new NextRequest('http://localhost:3000', {
        method: 'POST',
        body: '{"a":1}',
        headers: {'Content-Type': 'application/json'}
    })), {a: 1});
});
test('unexpected failure responses never reflect internal errors or credentials', async () => {
    const response = failure(new Error('SECRET-TOKEN-value SQL password'));
    assert.equal(response.status, 503);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.ok(!(await response.text()).includes('SECRET'));
});

test('explicit loopback transport preserves the Compose issuer for JWT validation', () => {
    process.env.IAM_ISSUER = 'http://iam.localhost:9000';
    process.env.IAM_TRANSPORT_ORIGIN = 'http://127.0.0.1:9000';
    try {
        assert.equal(config().issuer, 'http://iam.localhost:9000');
        assert.equal(config().iamOrigin, 'http://127.0.0.1:9000');
        process.env.IAM_TRANSPORT_ORIGIN = 'http://untrusted.example';
        assert.throws(config);
    } finally {
        process.env.IAM_ISSUER = 'http://localhost:9000';
        delete process.env.IAM_TRANSPORT_ORIGIN;
    }
});

test('loopback aliases redirect before login forms are displayed', () => {
    const response = proxy(new NextRequest('http://127.0.0.1:3000/login?error=authorization', {headers: {host: '127.0.0.1:3000'}}));
    assert.equal(response.status, 307);
    assert.equal(response.headers.get('location'), 'http://localhost:3000/login?error=authorization');
    assert.equal(proxy(new NextRequest('http://localhost:3000/login', {headers: {host: 'localhost:3000'}})).status, 200);
});

test('session status checks authoritative token activity and fails closed on IAM errors', async () => {
    const {grantActive} = await import('../src/lib/server');
    const originalFetch = globalThis.fetch;
    const grant = {
        token: 'test-only-token',
        subject: 'user-id',
        clientId: 'next-console',
        expiresAt: Date.now() + 60000
    };
    try {
        globalThis.fetch = async (url, options) => {
            assert.ok(String(url).endsWith('/oauth2/introspect'));
            assert.equal(options?.redirect, 'error');
            assert.equal(new URLSearchParams(options?.body as URLSearchParams).get('token'), grant.token);
            return Response.json({active: true, sub: grant.subject});
        };
        assert.equal(await grantActive(grant), true);
        globalThis.fetch = async () => Response.json({active: false});
        assert.equal(await grantActive(grant), false);
        globalThis.fetch = async () => Response.json({active: true, sub: 'different-user'});
        assert.equal(await grantActive(grant), false);
        globalThis.fetch = async () => new Response('', {status: 503});
        await assert.rejects(() => grantActive(grant), (e: unknown) => e instanceof HttpError && e.status === 503);
        globalThis.fetch = async () => {
            throw new Error('Expired grants must not be sent');
        };
        assert.equal(await grantActive({...grant, expiresAt: Date.now() - 1}), false);
    } finally {
        globalThis.fetch = originalFetch;
    }
});

test('canonical redirect configuration disables loopback URL normalization', () => {
    assert.equal(nextConfig.skipProxyUrlNormalize, true);
});
