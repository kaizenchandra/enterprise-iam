import {NextRequest} from 'next/server';
import {errors, jwtVerify} from 'jose';
import {config, endOpSession, keySet} from '@/lib/server';

export const runtime = 'nodejs';

export async function POST(req: NextRequest) {
    try {
        if (!req.headers.get('content-type')?.startsWith('application/x-www-form-urlencoded')) return new Response(null, {status: 400});
        if (Number(req.headers.get('content-length') || 0) > 16384) return new Response(null, {status: 400});
        // Bound streaming bodies independently of Content-Length.
        const reader = req.body?.getReader();
        let text = '';
        let size = 0;
        if (!reader) return new Response(null, {status: 400});
        while (true) {
            const {done, value} = await reader.read();
            if (done) break;
            size += value.length;
            if (size > 16384) {
                await reader.cancel();
                return new Response(null, {status: 400});
            }
            text += new TextDecoder().decode(value, {stream: true});
        }
        const params = new URLSearchParams(text);
        if (params.getAll('logout_token').length !== 1) return new Response(null, {status: 400});
        const {
            payload,
            protectedHeader
        } = await jwtVerify(params.get('logout_token')!, keySet(), {
            issuer: config().issuer,
            audience: config().clientId,
            algorithms: ['RS256'],
            maxTokenAge: '3m',
            requiredClaims: ['iat', 'exp', 'jti', 'sid']
        });
        const events = payload.events as Record<string, unknown> | undefined;
        if (protectedHeader.typ !== 'logout+jwt' || payload.nonce !== undefined || typeof payload.sid !== 'string' || payload.sid.length > 256 || typeof payload.jti !== 'string' || !events || !Object.hasOwn(events, 'http://schemas.openid.net/event/backchannel-logout')) return new Response(null, {status: 400});
        await endOpSession(payload.sid, payload.jti);
        return new Response(null, {status: 204, headers: {'Cache-Control': 'no-store'}});
    } catch (error) {
        if (process.env.CONSOLE_DIAGNOSTICS === 'true') console.warn('Logout delivery failed:', error instanceof Error ? error.name : 'UnknownError');
        return new Response(null, {
            status: error instanceof errors.JOSEError && !(error instanceof errors.JWKSTimeout) ? 400 : 503,
            headers: {'Cache-Control': 'no-store'}
        });
    }
}
