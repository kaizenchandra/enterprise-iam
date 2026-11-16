import {test} from 'node:test';
import assert from 'node:assert/strict';
import {NextRequest} from 'next/server';
import {GET, POST} from '../src/app/api/iam/[...path]/route';

process.env.IAM_ISSUER = 'http://iam.localhost:9000';
process.env.IAM_TRANSPORT_ORIGIN = 'http://127.0.0.1:9000';
process.env.CONSOLE_ORIGIN = 'http://localhost:3000';
process.env.IAM_AUTH_UI_ORIGIN = 'http://iam.localhost:3000';
process.env.CONSOLE_COOKIE_SECURE = 'false';
const ui = 'http://iam.localhost:3000';
const context = (...path: string[]) => ({params: Promise.resolve({path})});

test('identity API proxy forwards only the IAM session and CSRF, and preserves HttpOnly cookies', async () => {
    const original = globalThis.fetch;
    try {
        globalThis.fetch = async (url, options) => {
            assert.equal(String(url), 'http://127.0.0.1:9000/session/login');
            const headers = options?.headers as Record<string, string>;
            assert.equal(headers.Cookie, 'IAM_SESSION=test-session');
            assert.equal(headers['X-CSRF-TOKEN'], 'test-csrf');
            assert.ok(!headers.Authorization);
            assert.equal(options?.redirect, 'error');
            assert.equal(JSON.parse(options?.body as string).username, 'person');
            return Response.json({redirect: 'http://iam.localhost:9000/oauth2/authorize'}, {headers: {'Set-Cookie': 'IAM_SESSION=rotated; Path=/; HttpOnly; SameSite=Lax'}});
        };
        const response = await POST(new NextRequest(ui + '/api/iam/session/login', {
            method: 'POST',
            headers: {
                host: 'iam.localhost:3000',
                origin: ui,
                'Content-Type': 'application/json',
                'X-CSRF-TOKEN': 'test-csrf',
                Cookie: 'IAM_SESSION=test-session; IAM_CONSOLE_LOCAL=private-console-cookie',
                Authorization: 'Bearer untrusted'
            },
            body: JSON.stringify({username: 'person', password: 'test-password'})
        }), context('session', 'login'));
        assert.equal(response.status, 200);
        assert.match(response.headers.get('set-cookie')!, /HttpOnly/);
        assert.equal(response.headers.get('cache-control'), 'no-store');
    } finally {
        globalThis.fetch = original;
    }
});

test('identity proxy rejects foreign origins, console-host mutations, unknown endpoints and non-JSON bodies', async () => {
    const original = globalThis.fetch;
    globalThis.fetch = async () => {
        throw new Error('Rejected requests must not reach IAM');
    };
    try {
        for (const [host, origin] of [['iam.localhost:3000', 'https://attacker.example'], ['localhost:3000', 'http://localhost:3000']]) {
            assert.equal((await POST(new NextRequest(ui + '/api/iam/session/login', {
                method: 'POST',
                headers: {host, origin, 'Content-Type': 'application/json'},
                body: '{}'
            }), context('session', 'login'))).status, 403);
        }
        assert.equal((await GET(new NextRequest(ui + '/api/iam/oauth2/token', {headers: {host: 'iam.localhost:3000'}}), context('oauth2', 'token'))).status, 404);
        assert.equal((await POST(new NextRequest(ui + '/api/iam/session/login', {
            method: 'POST',
            headers: {host: 'iam.localhost:3000', origin: ui},
            body: 'password=secret'
        }), context('session', 'login'))).status, 415);
    } finally {
        globalThis.fetch = original;
    }
});
