// Real Chromium WebAuthn ceremonies via CDP. No keys/signatures are constructed by this test.
import fs from 'node:fs';
import http from 'node:http';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';

const base = process.env.PASSKEY_TEST_BASE, schema = process.env.PASSKEY_TEST_SCHEMA,
    dir = process.env.PASSKEY_CHROME_PROFILE;
if (!/^bc_e2e_[a-f0-9]{12}_op$/.test(schema)) throw Error('Invalid test schema');
const pw = process.env.DEMO_PASSWORD;
const portalA = process.env.PASSKEY_TEST_PORTAL_A || 'http://localhost:18080',
    portalB = process.env.PASSKEY_TEST_PORTAL_B || 'http://localhost:18081',
    portalPeer = process.env.PASSKEY_TEST_PORTAL_PEER || 'http://localhost:18082';
const profile = process.env.PASSKEY_TEST_PROFILE || 'platform';
const profiles = {
    platform: {transport: 'internal', ctap2Version: 'ctap2_0'},
    usb: {transport: 'usb', ctap2Version: 'ctap2_1'},
    synced: {transport: 'internal', ctap2Version: 'ctap2_1', defaultBackupEligibility: true, defaultBackupState: true}
};
if (!profiles[profile]) throw Error('Unknown virtual profile');
const rsa = process.env.PASSKEY_TEST_ALGORITHM === 'RS256';
const benchmark = process.env.PASSKEY_BENCHMARK === 'true';
if (benchmark) fs.rmSync('benchmarks/results/passkeys-local.json', {force: true});
const check = (condition, message) => {
    if (!condition) throw Error(message);
};
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
let stage = 'startup';
const diagnostics = [];
const [port, path] = fs.readFileSync(dir + '/DevToolsActivePort', 'utf8').trim().split('\n');
const socket = new WebSocket('ws://127.0.0.1:' + port + path);
await new Promise((resolve, reject) => {
    socket.onopen = resolve;
    socket.onerror = () => reject(Error('CDP unavailable'));
});
let seq = 0;
const pending = new Map(), listeners = [];
socket.onmessage = event => {
    const msg = JSON.parse(event.data);
    if (msg.id) {
        const item = pending.get(msg.id);
        if (!item) return;
        pending.delete(msg.id);
        clearTimeout(item.timeout);
        if (msg.error) item.reject(Error('CDP command failed: ' + item.method)); else item.resolve(msg.result);
    } else listeners.forEach(fn => fn(msg));
};
const call = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
    const id = ++seq;
    const timeout = setTimeout(() => {
        pending.delete(id);
        reject(Error('CDP timeout: ' + method));
    }, 20000);
    pending.set(id, {resolve, reject, method, timeout});
    socket.send(JSON.stringify({id, method, params, sessionId}));
});
const evalJS = async (page, expression) => {
    const result = await call('Runtime.evaluate', {
        expression,
        awaitPromise: true,
        returnByValue: true,
        userGesture: true
    }, page.sid);
    if (result.exceptionDetails) throw Error('Browser operation failed during ' + stage);
    return result.result.value;
};

async function waitFor(fn, label) {
    const deadline = Date.now() + 20000;
    while (Date.now() < deadline) {
        try {
            if (await fn()) return;
        } catch {
        }
        await pause(100);
    }
    throw Error('Timed out: ' + label);
}

async function nav(page, url) {
    await call('Page.navigate', {url}, page.sid);
    await waitFor(() => evalJS(page, `document.readyState==='complete' && location.href!== 'about:blank'`), 'navigation');
    await pause(100);
}

async function page() {
    const ctx = await call('Target.createBrowserContext');
    const target = await call('Target.createTarget', {url: 'about:blank', browserContextId: ctx.browserContextId});
    const attached = await call('Target.attachToTarget', {targetId: target.targetId, flatten: true});
    const p = {sid: attached.sessionId, ctx: ctx.browserContextId, payloads: []};
    await call('Page.enable', {}, p.sid);
    await call('Runtime.enable', {}, p.sid);
    await call('Network.enable', {maxPostDataSize: 131072}, p.sid);
    await call('WebAuthn.enable', {enableUI: false}, p.sid);
    const device = await call('WebAuthn.addVirtualAuthenticator', {
        options: {
            protocol: 'ctap2', ...profiles[profile],
            hasResidentKey: true,
            hasUserVerification: true,
            isUserVerified: true,
            automaticPresenceSimulation: true
        }
    }, p.sid);
    p.device = device.authenticatorId;
    listeners.push(msg => {
        if (msg.sessionId === p.sid && msg.method === 'Network.responseReceived') {
            const r = msg.params.response;
            const path = new URL(r.url).pathname;
            if (path.startsWith('/passkeys')) diagnostics.push({path, status: r.status});
        }
        if (msg.sessionId === p.sid && msg.method === 'Network.requestWillBeSent') {
            const r = msg.params.request;
            if (new URL(r.url).pathname.match(/^\/passkeys\/(register|login)\/finish$/) && r.postData) {
                try {
                    p.payloads.push(JSON.parse(r.postData));
                } catch {
                }
            }
        }
    });
    return p;
}

async function post(p, url, body, json = false) {
    return evalJS(p, `(async()=>{const token=document.querySelector('input[name="_csrf"]').value;const r=await fetch(${JSON.stringify(url)},{method:'POST',redirect:'manual',headers:{'X-CSRF-TOKEN':token,'Content-Type':${JSON.stringify(json ? 'application/json' : 'application/x-www-form-urlencoded')}},body:${json ? JSON.stringify(JSON.stringify(body)) : 'new URLSearchParams(' + JSON.stringify(body) + ')'}});let data=null;try{data=await r.json();}catch{}return {status:r.status,data};})()`);
}

async function passwordLogin(p, name = 'employee', password = pw) {
    await nav(p, base + '/login');
    const result = await post(p, '/login', {username: name, password});
    check(result.status === 0 || result.status === 302, 'Password login request failed');
}

async function nativeAssertion(p, options, uv) {
    return evalJS(p, `(async()=>{const options=PublicKeyCredential.parseRequestOptionsFromJSON(${JSON.stringify(options)});${uv ? `options.userVerification=${JSON.stringify(uv)};` : ''}return (await navigator.credentials.get({publicKey:options})).toJSON();})()`);
}

async function authStart(p) {
    await nav(p, base + '/login');
    const response = await post(p, '/passkeys/login/options', {});
    check(response.status === 200, 'Assertion options failed');
    return response.data;
}

async function passkeyLogin(p, expected = '/') {
    await nav(p, base + '/login');
    await evalJS(p, `document.getElementById('passkey-login').click()`);
    await waitFor(() => evalJS(p, `location.origin===${JSON.stringify(base)} && location.pathname===${JSON.stringify(expected)} && document.readyState==='complete'`), 'passkey login');
}

async function cookieFetch(p, url) {
    const cookies = await call('Network.getCookies', {urls: [url]}, p.sid);
    return fetch(url, {
        redirect: 'manual',
        headers: {Cookie: cookies.cookies.map(c => c.name + '=' + c.value).join('; ')}
    });
}

async function bff(p, portal) {
    await nav(p, portal + '/oauth2/authorization/iam');
    await waitFor(() => evalJS(p, `location.origin===${JSON.stringify(portal)} && location.pathname==='/'`), 'OIDC callback');
    check((await cookieFetch(p, portal + '/orders')).status === 200, 'Protected API failed');
}

function sql(statement) {
    const result = spawnSync('docker', ['compose', 'exec', '-T', 'postgres', 'psql', '-U', 'iam', '-d', 'iam', '-At', '-v', 'ON_ERROR_STOP=1'], {
        input: statement,
        encoding: 'utf8'
    });
    if (result.status !== 0) throw Error('Test database operation failed');
    return result.stdout.trim();
}

const owner = sql(`select id
                   from "${schema}".users
                   where username = 'employee'`);
sql(`insert into "${schema}".users(id, username, password_hash, state)
     select gen_random_uuid()::text,'other-user', password_hash, 'ACTIVE'
     from "${schema}".users
     where id = '${owner}';`);
const foreign = http.createServer((req, res) => {
    res.setHeader('Content-Type', 'text/html');
    res.end('<!doctype html><title>Foreign origin test</title>');
});
await new Promise(resolve => foreign.listen(19002, '127.0.0.1', resolve));
try {
    const a = await page(), b = await page(), other = await page();
    stage = 'UI enrollment';
    await passwordLogin(a);
    await nav(a, base + '/passkeys');
    check((await post(a, '/passkeys/register/options', {password: 'wrong-password'})).status === 401, 'Enrollment accepted wrong password');
    if (rsa || benchmark) {
        const request = await post(a, '/passkeys/register/options', {password: pw});
        check(request.status === 200, 'Algorithm enrollment options failed');
        const credential = await evalJS(a, `(async()=>{const options=PublicKeyCredential.parseCreationOptionsFromJSON(${JSON.stringify(request.data.options.publicKey)});options.pubKeyCredParams=options.pubKeyCredParams.filter(p=>p.alg===${rsa ? -257 : -7});return (await navigator.credentials.create({publicKey:options})).toJSON();})()`);
        check((await post(a, '/passkeys/register/finish', {
            id: request.data.id,
            credential
        }, true)).status === 200, 'Algorithm registration failed');
        await nav(a, base + '/login');
    } else {
        await evalJS(a, `document.querySelector('#passkey-enroll input[name="password"]').value=${JSON.stringify(pw)};document.getElementById('passkey-enroll').requestSubmit();`);
        await waitFor(() => evalJS(a, `location.pathname==='/login' && document.readyState==='complete'`), 'enrollment completion');
    }
    check(a.payloads.length > 0, 'Registration was not submitted');
    const enrolled = a.payloads.at(-1);
    check(sql(`select count(*)
               from "${schema}".passkey_credentials
               where user_id = '${owner}'`) === '1', 'Credential not persisted');
    check(sql(`select backup_eligible::text || ':' || backed_up::text
               from "${schema}".passkey_credentials
               where user_id = '${owner}'`) === (profile === 'synced' ? 'true:true' : 'false:false'), 'Backup state was not persisted');
    if (benchmark) {
        stage = 'bounded local measurement';
        const samples = [];
        const start = performance.now();
        for (let i = 0; i < 20; i++) {
            await nav(a, base + '/login');
            const t0 = performance.now();
            const request = await post(a, '/passkeys/login/options', {});
            const t1 = performance.now();
            check(request.status === 200, 'Benchmark options rejected');
            const credential = await nativeAssertion(a, request.data.options.publicKey);
            const t2 = performance.now();
            const result = await post(a, '/passkeys/login/finish', {id: request.data.id, credential}, true);
            const t3 = performance.now();
            check(result.status === 200, 'Benchmark assertion rejected');
            samples.push({optionsMs: t1 - t0, authenticatorMs: t2 - t1, finishMs: t3 - t2, totalMs: t3 - t0});
        }
        const elapsedMs = performance.now() - start;
        const summary = {};
        for (const key of Object.keys(samples[0])) {
            const sorted = samples.map(s => s[key]).sort((a, b) => a - b);
            const quantile = q => Number(sorted[Math.ceil(q * sorted.length) - 1].toFixed(3));
            summary[key] = {p50: quantile(.5), p95: quantile(.95), p99: quantile(.99)};
        }
        const version = await call('Browser.getVersion');
        const report = {
            kind: 'local-closed-loop-virtual-authenticator-smoke',
            recordedAt: new Date().toISOString(),
            samples: samples.length,
            concurrency: 1,
            activeIdentities: 1,
            credentials: 1,
            opMaxHeapMiB: 256,
            failures: 0,
            profile,
            algorithm: rsa ? 'RS256' : 'ES256',
            browser: version.product,
            node: process.version,
            platform: process.platform,
            arch: process.arch,
            elapsedMs: Number(elapsedMs.toFixed(3)),
            achievedCeremoniesPerSecond: Number((samples.length / (elapsedMs / 1000)).toFixed(3)),
            latencyMs: summary,
            limitations: ['20 samples, one active test identity and credential; p99 is the observed maximum, not a reliable tail estimate', 'localhost HTTP, one 256 MiB IAM JVM, local PostgreSQL/Redis and same-host Chrome/CDP', 'native user presence/verification simulated; no physical device, TLS/network, production load or CPU/GC/pool measurements', 'closed loop with navigation between samples; no offered-rate or saturation test', 'options/finish timing includes HTTP, CDP and test-client overhead; no isolated signing/verification CPU claim']
        };
        fs.mkdirSync('benchmarks/results', {recursive: true});
        fs.writeFileSync('benchmarks/results/passkeys-local.json', JSON.stringify(report, null, 2) + '\n');
        console.log('PASS: 20 real signed virtual-authenticator logins; local measurements saved without credential material');
    } else {
        stage = 'primary authentication and saved OIDC authorization';
        await nav(a, portalA + '/oauth2/authorization/iam');
        await waitFor(() => evalJS(a, `location.origin===${JSON.stringify(base)} && location.pathname==='/login' && !!document.getElementById('passkey-login')`), 'OIDC login page');
        await evalJS(a, `document.getElementById('passkey-login').click()`);
        await waitFor(() => evalJS(a, `location.origin===${JSON.stringify(portalA)} && location.pathname==='/'`), 'passkey OIDC callback');
        check((await cookieFetch(a, portalA + '/orders')).status === 200, 'Passkey OIDC protected API failed');
        await nav(a, base + '/passkeys');
        check((await post(a, '/passkeys/register/finish', enrolled, true)).status === 400, 'Registration replay accepted');
        let ids = await evalJS(a, `Array.from(document.querySelectorAll('[data-passkey-id]')).map(e=>e.dataset.passkeyId)`);
        check(ids.length === 1, 'Credential list failed');
        const id = ids[0];
        check((await post(a, '/passkeys/' + id + '/remove', {password: 'wrong'})).status === 401, 'Removal accepted wrong password');
        const noCsrf = await evalJS(a, `fetch('/passkeys/${id}/remove',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({password:${JSON.stringify(pw)}})}).then(r=>r.status)`);
        check(noCsrf === 403, 'Missing CSRF accepted');
        stage = 'exact origin';
        let request = await authStart(a);
        await nav(a, 'http://localhost:19002/');
        const wrongOrigin = await nativeAssertion(a, request.options.publicKey);
        await nav(a, base + '/login');
        check((await post(a, '/passkeys/login/finish', {
            id: request.id,
            credential: wrongOrigin
        }, true)).status === 400, 'Foreign-port origin accepted');
        stage = 'UV downgrade';
        request = await authStart(a);
        await call('WebAuthn.setResponseOverrideBits', {authenticatorId: a.device, isBadUV: true}, a.sid);
        let noUv;
        try {
            noUv = await nativeAssertion(a, request.options.publicKey, 'discouraged');
        } finally {
            await call('WebAuthn.setResponseOverrideBits', {authenticatorId: a.device}, a.sid);
        }
        check((await post(a, '/passkeys/login/finish', {
            id: request.id,
            credential: noUv
        }, true)).status === 400, 'UV downgrade accepted');
        stage = 'signature rejection';
        const sessionsBeforeBogus = sql(`select count(*)
                                         from "${schema}".identity_sessions
                                         where principal_name = '${owner}'`);
        request = await authStart(a);
        await call('WebAuthn.setResponseOverrideBits', {authenticatorId: a.device, isBogusSignature: true}, a.sid);
        let bogus;
        try {
            bogus = await nativeAssertion(a, request.options.publicKey);
        } finally {
            await call('WebAuthn.setResponseOverrideBits', {authenticatorId: a.device}, a.sid);
        }
        const bogusResult = await post(a, '/passkeys/login/finish', {id: request.id, credential: bogus}, true);
        check(bogusResult.status === 400, 'Invalid signature expected 400, received ' + bogusResult.status);
        check(sql(`select count(*)
                   from "${schema}".passkey_challenges
                   where id = '${request.id}'
                     and consumed_at is not null`) === '1', 'Bad signature did not spend challenge');
        check(sql(`select count(*)
                   from "${schema}".identity_sessions
                   where principal_name = '${owner}'`) === sessionsBeforeBogus, 'Bad signature created session');
        stage = 'assertion replay and concurrent finish';
        request = await authStart(a);
        const assertion = await nativeAssertion(a, request.options.publicKey);
        await nav(b, base + '/login');
        check((await post(b, '/passkeys/login/finish', {
            id: request.id,
            credential: assertion
        }, true)).status === 400, 'Other browser accepted bound assertion');
        let results = await Promise.all([post(a, '/passkeys/login/finish', {
            id: request.id,
            credential: assertion
        }, true), post(a, '/passkeys/login/finish', {id: request.id, credential: assertion}, true)]);
        check(results.filter(r => r.status === 200).length === 1, 'Concurrent assertion had multiple/no winners');
        await nav(a, base + '/login');
        check((await post(a, '/passkeys/login/finish', {
            id: request.id,
            credential: assertion
        }, true)).status !== 200, 'Assertion replay accepted');
        stage = 'wrong owner removal';
        await passwordLogin(other, 'other-user');
        await nav(other, base + '/passkeys');
        check((await post(other, '/passkeys/' + id + '/remove', {password: pw})).status === 404, 'Other owner removed credential');
        await bff(other, portalA);
        stage = 'recovery preserves passkey';
        const email = 'pk-' + crypto.randomUUID() + '@example.test';
        const adminResponse = await fetch(base + '/oauth2/token', {
            method: 'POST',
            headers: {
                Authorization: 'Basic ' + Buffer.from('admin-cli:' + process.env.ADMIN_SECRET).toString('base64'),
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: new URLSearchParams({grant_type: 'client_credentials', scope: 'iam.admin'})
        });
        check(adminResponse.status === 200, 'Admin test authorization failed');
        const admin = (await adminResponse.json()).access_token;
        check((await fetch(base + '/api/v1/admin/users/' + owner + '/email', {
            method: 'POST',
            headers: {Authorization: 'Bearer ' + admin, 'Content-Type': 'application/json'},
            body: JSON.stringify({email})
        })).status === 204, 'Email binding failed');

        async function mailToken(kind) {
            let token;
            await waitFor(async () => {
                const messages = await (await fetch('http://localhost:8025/api/v1/messages')).json();
                for (const m of messages.messages || []) {
                    if (!(m.To || []).some(to => to.Address === email)) continue;
                    const content = await (await fetch('http://localhost:8025/api/v1/message/' + m.ID)).json();
                    const match = (content.Text || '').match(new RegExp('/account/' + kind + '#token=([A-Za-z0-9_-]{43})'));
                    if (match) {
                        token = match[1];
                        return true;
                    }
                }
                return false;
            }, 'mail delivery');
            return token;
        }

        await nav(b, base + '/account/verify');
        check((await post(b, '/account/verify', {token: await mailToken('verify')})).status === 200, 'Email proof failed');
        // Seed an enabled factor and hashed recovery codes to test policy preservation without implementing TOTP in the browser harness.
        const recovery1 = crypto.randomUUID(), recovery2 = crypto.randomUUID();
        sql(`insert into "${schema}".mfa_credentials(user_id, secret_encrypted, enabled)
             values ('${owner}', 'test-not-used-for-totp', true);
        insert into "${schema}".recovery_codes(user_id, code_hash)
        values ('${owner}', '${crypto.createHash('sha256').update(recovery1).digest('hex')}'),
               ('${owner}', '${crypto.createHash('sha256').update(recovery2).digest('hex')}');`);
        request = await authStart(a);
        const beforeReset = await nativeAssertion(a, request.options.publicKey);
        await nav(b, base + '/account/reset');
        check((await post(b, '/account/reset/request', {email})).status === 200, 'Reset request failed');
        const reset = await mailToken('reset'), newPassword = 'replacement-' + crypto.randomUUID();
        check((await post(b, '/account/reset', {
            token: reset,
            password: newPassword,
            confirmation: newPassword
        })).status === 200, 'Reset failed');
        check((await post(a, '/passkeys/login/finish', {
            id: request.id,
            credential: beforeReset
        }, true)).status === 400, 'Pre-reset assertion revived session');
        check(sql(`select count(*)
                   from "${schema}".passkey_credentials
                   where user_id = '${owner}'`) === '1', 'Recovery removed passkey');
        stage = 'MFA policy';
        await passkeyLogin(a, '/mfa');
        check(await evalJS(a, `fetch('/passkeys.js').then(r=>r.status===200 && r.headers.get('content-type').includes('javascript'))`), 'Pending MFA blocked passkey script');
        check((await post(a, '/mfa/recover', {code: recovery1})).status === 0, 'Existing MFA recovery failed');
        await bff(a, portalA);
        await bff(a, portalB);
        stage = 'removal racing prepared assertion';
        request = await authStart(a);
        const beforeRemoval = await nativeAssertion(a, request.options.publicKey);
        await passwordLogin(b, 'employee', newPassword);
        await nav(b, base + '/mfa');
        check((await post(b, '/mfa/recover', {code: recovery2})).status === 0, 'Second session MFA failed');
        await nav(b, base + '/passkeys');
        sql(`create function "${schema}".passkey_audit_fail() returns trigger language plpgsql as $$begin if new.event_type='PASSKEY_REMOVED' then raise exception 'simulated audit outage';end if;return new;end$$;create trigger passkey_audit_failure before insert on "${schema}".security_audit_events for each row execute function "${schema}".passkey_audit_fail();`);
        try {
            check((await post(b, '/passkeys/' + id + '/remove', {password: newPassword})).status === 503, 'Audit outage did not fail closed');
            check(sql(`select count(*)
                       from "${schema}".passkey_credentials
                       where user_id = '${owner}'`) === '1', 'Failed removal deleted key');
            check((await cookieFetch(a, portalA + '/orders')).status === 200, 'Failed removal partially revoked sessions');
        } finally {
            sql(`drop trigger passkey_audit_failure on "${schema}".security_audit_events;drop function "${schema}".passkey_audit_fail();`);
        }
        check((await post(b, '/passkeys/' + id + '/remove', {password: newPassword})).status === 0, 'Reauthenticated removal failed');
        check((await post(a, '/passkeys/login/finish', {
            id: request.id,
            credential: beforeRemoval
        }, true)).status === 400, 'Removed credential assertion accepted');
        await waitFor(async () => (await cookieFetch(a, portalB + '/profile')).status !== 200, 'RP invalidation');
        check((await cookieFetch(a, portalA + '/profile')).status !== 200, 'Portal session survived');
        check((await cookieFetch(a, portalPeer + '/profile')).status !== 200, 'Peer session survived');
        check((await cookieFetch(other, portalA + '/orders')).status === 200, 'Other owner lost access');
        check(sql(`select count(*)
                   from "${schema}".passkey_credentials
                   where user_id = '${owner}'`) === '0', 'Credential not removed');
        console.log('PASS: virtual profile ' + profile + ' ' + (rsa ? 'RS256' : 'ES256') + '; real Chromium WebAuthn enrollment/login/removal, replay/concurrency, exact origin, UV, atomic outage rollback, MFA/recovery preservation, stale reset/removal assertions and distributed logout');
    }
} catch (error) {
    console.error('FAIL: passkey browser stage ' + stage + '; ' + error.message + '; passkey HTTP statuses ' + JSON.stringify(diagnostics.slice(-10)));
    process.exitCode = 1;
} finally {
    foreign.close();
    socket.close();
    for (const p of pending.values()) clearTimeout(p.timeout);
}
