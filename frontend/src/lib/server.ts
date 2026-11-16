import {createHash, randomBytes} from 'node:crypto';
import {createClient} from 'redis';
import {createRemoteJWKSet, jwtVerify} from 'jose';
import {NextRequest, NextResponse} from 'next/server';
import type {Lane} from './contracts';

export class HttpError extends Error {
    constructor(public status: number, message: string) {
        super(message);
    }
}

export function config() {
    const issuer = process.env.IAM_ISSUER || 'http://localhost:9000';
    const iamOrigin = process.env.IAM_TRANSPORT_ORIGIN || issuer;
    const origin = process.env.CONSOLE_ORIGIN || 'http://localhost:3000';
    const authUrl = new URL(issuer);
    authUrl.port = new URL(origin).port;
    const authUi = process.env.IAM_AUTH_UI_ORIGIN || authUrl.origin;
    if (new URL(authUi).hostname !== new URL(issuer).hostname) throw new Error('Auth UI must use the IAM hostname for passkeys');
    for (const value of [issuer, iamOrigin, origin, authUi]) {
        const url = new URL(value);
        if (url.origin !== value || url.username || url.password) throw new Error('Configure exact origins without paths');
        if (url.protocol !== 'https:' && !(url.protocol === 'http:' && (['localhost', '127.0.0.1'].includes(url.hostname) || ([issuer, authUi].includes(value) && url.hostname === 'iam.localhost' && new URL(iamOrigin).hostname === '127.0.0.1'))))
            throw new Error('HTTPS required outside loopback');
    }
    const secure = process.env.CONSOLE_COOKIE_SECURE !== 'false';
    if (!secure && !['localhost', '127.0.0.1'].includes(new URL(origin).hostname)) throw new Error('Secure cookies required');
    return {
        issuer,
        iamOrigin,
        authUi,
        origin,
        secure,
        clientId: process.env.CONSOLE_CLIENT_ID || 'next-console',
        secret: process.env.CONSOLE_CLIENT_SECRET || ''
    };
}

export const digest = (value: string) => createHash('sha256').update(value).digest('hex');
const prefix = () => process.env.CONSOLE_REDIS_PREFIX || 'iam:next-console:';
export const storeKey = (suffix: string) => prefix() + suffix;
export const sidKey = (sid: string) => prefix() + 'session:' + digest(sid);
export const newId = () => randomBytes(32).toString('base64url');
const cookieName = () => config().secure ? '__Host-IAM_CONSOLE' : 'IAM_CONSOLE_LOCAL';

export function sessionId(req: NextRequest) {
    const id = req.cookies.get(cookieName())?.value;
    return id && /^[A-Za-z0-9_-]{43}$/.test(id) ? id : undefined;
}

export function setSession(res: NextResponse, sid: string, maxAge = 1800) {
    res.cookies.set(cookieName(), sid, {httpOnly: true, secure: config().secure, sameSite: 'lax', path: '/', maxAge});
}

const globalStore = globalThis as typeof globalThis & {
    consoleRedis?: ReturnType<typeof createClient>;
    consoleRedisConnect?: Promise<unknown>
};

export async function store() {
    if (!globalStore.consoleRedis) {
        globalStore.consoleRedis = createClient({
            url: process.env.CONSOLE_REDIS_URL || 'redis://localhost:6379',
            socket: {connectTimeout: 3000, reconnectStrategy: false},
            disableOfflineQueue: true
        });
        globalStore.consoleRedis.on('error', () => {
        }); // No credential-bearing connection errors in logs.
    }
    const client = globalStore.consoleRedis;
    if (!client.isOpen) {
        globalStore.consoleRedisConnect ??= client.connect().finally(() => {
            globalStore.consoleRedisConnect = undefined;
        });
        await globalStore.consoleRedisConnect;
    }
    if (!client.isReady) throw new HttpError(503, 'Session store unavailable. Try again shortly.');
    return client;
}

export function originGuard(req: NextRequest) {
    if (req.headers.get('origin') !== config().origin) throw new HttpError(403, 'Request origin not allowed.');
}

export async function grantActive(grant: Grant) {
    if (grant.expiresAt <= Date.now()) return false;
    const cfg = config();
    const response = await upstream('/oauth2/introspect', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            Authorization: 'Basic ' + Buffer.from(`${encodeURIComponent(cfg.clientId)}:${encodeURIComponent(cfg.secret)}`).toString('base64')
        },
        body: new URLSearchParams({token: grant.token, token_type_hint: 'access_token'})
    });
    if (!response.ok) throw new HttpError(503, 'Unable to verify your IAM session. Try again shortly.');
    const value = await response.json();
    return value.active === true && value.sub === grant.subject;
}

// Compare-and-delete prevents an old response from deleting a newly connected grant.
export async function discardGrant(sid: string, lane: string, token: string) {
    await (await store()).eval("local raw=redis.call('HGET',KEYS[1],ARGV[1]); if raw and cjson.decode(raw).token==ARGV[2] then return redis.call('HDEL',KEYS[1],ARGV[1]) end; return 0", {
        keys: [sidKey(sid)], arguments: [lane, token]
    });
}

export async function jsonBody(req: NextRequest) {
    if (!req.headers.get('content-type')?.startsWith('application/json')) throw new HttpError(415, 'JSON required.');
    const reader = req.body?.getReader();
    let size = 0;
    const chunks: Uint8Array[] = [];
    if (!reader) throw new HttpError(400, 'Request body required.');
    while (true) {
        const {done, value} = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > 65536) {
            await reader.cancel();
            throw new HttpError(413, 'Request too large.');
        }
        chunks.push(value);
    }
    try {
        return JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch {
        throw new HttpError(400, 'Invalid JSON.');
    }
}

export function result(value: unknown, status = 200) {
    return NextResponse.json(value, {status, headers: {'Cache-Control': 'no-store'}});
}

export function failure(error: unknown) {
    return result({detail: error instanceof HttpError ? error.message : 'Service unavailable. Check the IAM connection and retry.'}, error instanceof HttpError ? error.status : 503);
}

export async function upstream(path: string, options: RequestInit = {}) {
    return fetch(config().iamOrigin + path, {
        ...options,
        redirect: 'error',
        cache: 'no-store',
        signal: AbortSignal.timeout(10000)
    });
}

export async function exchange(form: Record<string, string>, clientId: string, secret: string) {
    const response = await upstream('/oauth2/token', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            Authorization: 'Basic ' + Buffer.from(`${encodeURIComponent(clientId)}:${encodeURIComponent(secret)}`).toString('base64')
        },
        body: new URLSearchParams(form)
    });
    if (!response.ok) throw new HttpError(response.status === 401 || response.status === 400 ? 401 : 502, 'Authorization failed. Check your credentials or sign in again.');
    return response.json() as Promise<{ access_token: string; expires_in: number; id_token?: string }>;
}

let jwks: ReturnType<typeof createRemoteJWKSet> | undefined;

export function keySet() {
    return jwks ??= createRemoteJWKSet(new URL(config().iamOrigin + '/oauth2/jwks'), {
        timeoutDuration: 5000,
        cooldownDuration: 10000
    });
}

export async function verifyAccess(token: string, lane: Lane) {
    const audience = lane === 'admin' ? 'iam-admin' : lane === 'management' ? 'iam-session-management' : 'enterprise-api';
    return (await jwtVerify(token, keySet(), {
        issuer: config().issuer,
        audience,
        algorithms: ['RS256'],
        requiredClaims: ['exp', 'iat', 'sub']
    })).payload;
}

export type Grant = { token: string; expiresAt: number; subject: string; clientId: string; sid?: string };

export async function saveGrant(sid: string, lane: Lane, grant: Grant) {
    const db = await store();
    // A prior back-channel logout fences late callbacks carrying the old OP session.
    if (grant.sid && await db.exists(prefix() + 'ended:' + digest(grant.sid))) throw new HttpError(401, 'This login session has ended.');
    const tx = db.multi().hSet(sidKey(sid), lane, JSON.stringify(grant)).expire(sidKey(sid), 1800);
    if (grant.sid) tx.sAdd(prefix() + 'op:' + digest(grant.sid), sidKey(sid)).expire(prefix() + 'op:' + digest(grant.sid), 3600);
    await tx.exec();
    // Recheck after commit to close the publication/index race against logout.
    if (grant.sid && await db.exists(prefix() + 'ended:' + digest(grant.sid))) {
        await db.del(sidKey(sid));
        throw new HttpError(401, 'This login session has ended.');
    }
}

export async function grantFor(req: NextRequest, lane: Lane): Promise<Grant> {
    const sid = sessionId(req);
    if (!sid) throw new HttpError(401, 'Connect this workspace to continue.');
    const raw = await (await store()).hGet(sidKey(sid), lane);
    if (!raw) throw new HttpError(401, lane === 'admin' ? 'Sign in with a platform administrator account to continue.' : 'Sign in to your IAM account to continue.');
    const grant = JSON.parse(raw) as Grant;
    if (lane === 'admin' && grant.subject.startsWith('client:')) throw new HttpError(401, 'Sign in with a personal administrator account.');
    if (grant.expiresAt <= Date.now()) throw new HttpError(401, 'Authorization expired. Reconnect to continue.');
    return grant;
}

export async function endOpSession(opSid: string, jti: string) {
    const db = await store();
    // Duplicate logout deliveries are idempotent, including retries after a prior success.
    await db.set(prefix() + 'logout:' + digest(jti), '1', {EX: 300, NX: true});
    await db.set(prefix() + 'ended:' + digest(opSid), '1', {EX: 3600});
    const index = prefix() + 'op:' + digest(opSid);
    const sessions = await db.sMembers(index);
    if (sessions.length) await db.del(sessions);
    await db.del(index);
}
