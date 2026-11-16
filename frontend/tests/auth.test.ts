import {test} from 'node:test';
import assert from 'node:assert/strict';
import {renderToStaticMarkup} from 'react-dom/server';
import Login from '../src/app/login/page';
import Continue from '../src/app/auth/continue/page';
import {POST} from '../src/app/api/auth/connect/route';

test('the old browser machine-credential endpoint cannot issue any authorization', async () => {
    const response = await POST();
    assert.equal(response.status, 410);
    assert.equal(response.headers.get('Cache-Control'), 'no-store');
    const body = await response.json();
    assert.ok(!('access_token' in body));
    assert.match(body.detail, /username\/password/);
});

test('login offers scoped OIDC entry points without collecting machine or user secrets', async () => {
    const html = renderToStaticMarkup(await Login({searchParams: Promise.resolve({})}));
    assert.match(html, /\/api\/auth\/start\?lane=app/);
    assert.match(html, /\/api\/auth\/start\?lane=admin/);
    assert.match(html, /assigned platform administrator role/);
    assert.match(html, /href="\/register"/);
    assert.ok(!html.includes('client-secret'));
    assert.ok(!html.includes('name="password"')); // Password entry stays on the protected OP origin.
});

test('direct IAM login continues with a protected POST and a fallback button', async () => {
    const html = renderToStaticMarkup(await Continue({searchParams: Promise.resolve({lane: 'admin'})}));
    assert.match(html, /action="\/api\/auth\/start\?lane=admin"/);
    assert.match(html, /method="post"/);
    assert.match(html, /Continue to console/);
    const fallback = renderToStaticMarkup(await Continue({searchParams: Promise.resolve({lane: 'untrusted'})}));
    assert.match(fallback, /lane=app/);
});
