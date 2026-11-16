import {NextRequest, NextResponse} from 'next/server';
import {jwtVerify} from 'jose';
import {
    config,
    digest,
    exchange,
    keySet,
    saveGrant,
    sessionId,
    setSession,
    sidKey,
    store,
    storeKey,
    verifyAccess
} from '@/lib/server';
import type {Lane} from '@/lib/contracts';

export const runtime = 'nodejs';

export async function GET(req: NextRequest) {
    const cfg = config();
    const txCookie = cfg.secure ? '__Host-IAM_CONSOLE_TX' : 'IAM_CONSOLE_TX_LOCAL';
    let verifiedTransaction = false;
    try {
        const state = req.nextUrl.searchParams.get('state'), code = req.nextUrl.searchParams.get('code');
        if (!state || !code || code.length > 2048 || !/^[A-Za-z0-9_-]{43}$/.test(state) || state !== req.cookies.get(txCookie)?.value) throw new Error('State');
        const db = await store();
        const raw = await db.getDel(storeKey('tx:' + digest(state)));
        if (!raw) throw new Error('Expired state');
        const tx = JSON.parse(raw) as { sid: string; lane: Lane; nonce: string; verifier: string };
        if (tx.sid !== sessionId(req)) throw new Error('Browser binding');
        verifiedTransaction = true;
        const token = await exchange({
            grant_type: 'authorization_code',
            code,
            code_verifier: tx.verifier,
            redirect_uri: cfg.origin + '/api/auth/callback'
        }, cfg.clientId, cfg.secret);
        if (!token.id_token) throw new Error('Missing ID token');
        const id = (await jwtVerify(token.id_token, keySet(), {
            issuer: cfg.issuer,
            audience: cfg.clientId,
            algorithms: ['RS256'],
            requiredClaims: ['exp', 'iat', 'sub', 'nonce', 'sid']
        })).payload;
        if (id.nonce !== tx.nonce || typeof id.sid !== 'string' || id.sid.length > 256) throw new Error('Nonce/session');
        const access = await verifyAccess(token.access_token, tx.lane);
        if (access.sub !== id.sub) throw new Error('Subject mismatch');
        // Do not allow two different user identities to share the two delegated lanes.
        const existing = await db.hGetAll(sidKey(tx.sid));
        for (const [lane, raw] of Object.entries(existing)) if (JSON.parse(raw).subject !== id.sub) await db.hDel(sidKey(tx.sid), lane);
        await saveGrant(tx.sid, tx.lane, {
            token: token.access_token,
            expiresAt: Number(access.exp) * 1000,
            subject: id.sub!,
            sid: id.sid,
            clientId: cfg.clientId
        });
        const res = NextResponse.redirect(cfg.origin + '/?tab=' + (tx.lane === 'admin' ? 'overview' : tx.lane === 'management' ? 'sessions' : 'decisions') + '&notice=signed-in', 303);
        setSession(res, tx.sid);
        res.cookies.set(txCookie, '', {path: '/', maxAge: 0, secure: cfg.secure, httpOnly: true, sameSite: 'lax'});
        return res;
    } catch {
        if (verifiedTransaction) {
            try {
                const sid = sessionId(req);
                if (sid) await (await store()).del(sidKey(sid));
            } catch {
            }
        }
        const res = NextResponse.redirect(cfg.origin + '/login?error=authorization', 303);
        res.cookies.set(txCookie, '', {path: '/', maxAge: 0, secure: cfg.secure, httpOnly: true, sameSite: 'lax'});
        return res;
    }
}
