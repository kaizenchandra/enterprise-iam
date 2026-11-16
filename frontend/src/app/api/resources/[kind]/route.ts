import {NextRequest} from 'next/server';
import {discardGrant, failure, grantFor, HttpError, result, sessionId, upstream} from '@/lib/server';

export const runtime = 'nodejs';

export async function GET(req: NextRequest, context: { params: Promise<{ kind: string }> }) {
    try {
        const {kind} = await context.params;
        if (!['identity', 'orders'].includes(kind)) throw new HttpError(404, 'Resource not available.');
        const grant = await grantFor(req, 'app');
        const headers = {Authorization: 'Bearer ' + grant.token};
        let response: Response;
        if (kind === 'identity') response = await upstream('/userinfo', {headers});
        else {
            const origin = process.env.RESOURCE_ORIGIN || 'http://localhost:9001';
            const url = new URL(origin);
            if (origin !== url.origin || !(url.protocol === 'https:' || (url.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(url.hostname)))) throw new Error('Invalid resource origin');
            response = await fetch(origin + '/api/orders', {
                headers,
                cache: 'no-store',
                redirect: 'error',
                signal: AbortSignal.timeout(10000)
            });
        }
        const sid = sessionId(req);
        if (response.status === 401 && sid) await discardGrant(sid, 'app', grant.token);
        if (!response.ok) throw new HttpError(response.status, response.status === 401 ? 'Sign in again to access this resource.' : 'The protected resource denied this request or is unavailable.');
        return result(await response.json());
    } catch (error) {
        return failure(error);
    }
}
