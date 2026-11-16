import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {buildRequest, operations, resolveOperation} from '../src/lib/contracts';

test('every implemented bearer API has a matching console operation with the correct lane', () => {
    const spec = JSON.parse(readFileSync(new URL('../../docs/openapi.json', import.meta.url), 'utf8'));
    const expected = Object.entries(spec.paths).flatMap(([path, methods]) => path.startsWith('/api/') ? Object.keys(methods as object).filter(m => ['get', 'post', 'patch', 'delete', 'put'].includes(m)).map(method => method.toUpperCase() + ' ' + path) : []);
    assert.deepEqual(operations.map(op => op.method + ' ' + op.path).sort(), expected.sort());
    for (const op of operations) assert.equal(resolveOperation(op.method, op.path.replace(/\{\w+\}/g, 'test-id'))?.id, op.id);
    assert.equal(resolveOperation('GET', '/api/v1/users/me/sessions')?.lane, 'management');
    assert.equal(resolveOperation('POST', '/api/v1/authorization/decisions')?.lane, 'app');
    assert.equal(resolveOperation('DELETE', '/api/v1/organizations/test/members/user')?.lane, 'admin');
});

test('proxy allowlist rejects traversal, protocol endpoints, unknown paths and wrong methods', () => {
    for (const path of ['/oauth2/token', '//evil.example/api/v1/admin/users', '/api/v1/admin/users/../clients', '/api/v1/admin/users/..', '/api/v1/admin/users/.', '/api/v1/admin/users/%2fsecret', '/api/v1/admin/users/a/b', '/api/v1/admin/users/x?evil=1', '/api/v1/admin/users/x\\z', '/api/v1/admin/unknown']) assert.equal(resolveOperation('GET', path), undefined, path);
    assert.equal(resolveOperation('PUT', '/api/v1/admin/users'), undefined);
});

test('request builder preserves credentials, encodes IDs and converts typed fields', () => {
    const create = operations.find(op => op.method === 'POST' && op.path === '/api/v1/admin/users')!;
    assert.equal(buildRequest(create, {
        username: ' alice ',
        password: ' password with spaces '
    }).body?.password, ' password with spaces ');
    assert.equal(buildRequest(create, {username: ' alice ', password: 'long-password-here'}).body?.username, 'alice');
    const update = operations.find(op => op.method === 'PATCH')!;
    assert.deepEqual(buildRequest(update, {
        id: 'a/b',
        username: 'alice',
        version: '0'
    }), {path: '/api/v1/admin/users/a%2Fb', body: {username: 'alice', version: 0}});
    assert.throws(() => buildRequest(update, {id: 'id', username: 'a', version: '1e999'}));
    assert.throws(() => buildRequest(update, {id: 'id', username: 'a'}));
    const client = operations.find(op => op.method === 'POST' && op.path === '/api/v1/admin/clients')!;
    assert.deepEqual(buildRequest(client, {
        clientId: 'service',
        scopes: 'orders.read, decision.write'
    }).body?.scopes, ['orders.read', 'decision.write']);
});
