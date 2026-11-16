import {NextRequest, NextResponse} from 'next/server';
import {createHash} from 'node:crypto';
import {config, digest, failure, newId, originGuard, sessionId, setSession, store, storeKey} from '@/lib/server';

export const runtime = 'nodejs';

export async function POST(req: NextRequest) {
    try {
        originGuard(req);
        const cfg = config();
        if (!cfg.secret) throw new Error('OIDC client secret missing');
        const requested = req.nextUrl.searchParams.get('lane');
        const lane = requested === 'admin' ? 'admin' : requested === 'management' ? 'management' : 'app';
        const state = newId(), nonce = newId(), verifier = newId(), sid = sessionId(req) || newId();
        await (await store()).set(storeKey('tx:' + digest(state)), JSON.stringify({
            lane,
            sid,
            nonce,
            verifier
        }), {EX: 300});
        const url = new URL(cfg.issuer + '/oauth2/authorize');
        url.search = new URLSearchParams({
            response_type: 'code',
            client_id: cfg.clientId,
            redirect_uri: cfg.origin + '/api/auth/callback',
            scope: lane === 'admin' ? 'openid profile iam.admin' : lane === 'management' ? 'openid profile sessions.read sessions.write' : 'openid profile orders.read decision.write',
            state,
            nonce,
            code_challenge: createHash('sha256').update(verifier).digest('base64url'),
            code_challenge_method: 'S256'
        }).toString();
        const res = NextResponse.redirect(url, 303);
        setSession(res, sid);
        res.cookies.set(cfg.secure ? '__Host-IAM_CONSOLE_TX' : 'IAM_CONSOLE_TX_LOCAL', state, {
            httpOnly: true,
            secure: cfg.secure,
            sameSite: 'lax',
            path: '/',
            maxAge: 300
        });
        return res;
    } catch (error) {
        return failure(error);
    }
}
