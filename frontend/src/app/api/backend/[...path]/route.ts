import {NextRequest} from 'next/server';
import {resolveOperation} from '@/lib/contracts';
import {
    discardGrant,
    failure,
    grantFor,
    HttpError,
    jsonBody,
    originGuard,
    result,
    sessionId,
    upstream
} from '@/lib/server';

export const runtime = 'nodejs';

async function handle(req: NextRequest, context: { params: Promise<{ path: string[] }> }) {
    try {
        const parts = (await context.params).path;
        const path = '/' + parts.join('/');
        const operation = resolveOperation(req.method, path);
        if (!operation) throw new HttpError(404, 'This operation is not available.');
        if (req.method !== 'GET') originGuard(req);
        const allowed = new Set(operation.fields.filter(f => f.location === 'query').map(f => f.name));
        for (const key of req.nextUrl.searchParams.keys()) if (!allowed.has(key)) throw new HttpError(400, 'Unsupported query parameter.');
        const grant = await grantFor(req, operation.lane);
        let body: string | undefined;
        if (req.method !== 'GET' && req.method !== 'DELETE' && req.headers.get('content-type')) body = JSON.stringify(await jsonBody(req));
        const response = await upstream(path + req.nextUrl.search, {
            method: req.method,
            headers: {Authorization: 'Bearer ' + grant.token, ...(body ? {'Content-Type': 'application/json'} : {})},
            body
        });
        if (response.status === 204) return new Response(null, {status: 204, headers: {'Cache-Control': 'no-store'}});
        if (!response.ok) {
            const sid = sessionId(req);
            if (response.status === 401 && sid) await discardGrant(sid, operation.lane, grant.token);
            const messages: Record<number, string> = {
                400: 'Check the highlighted fields and request values.',
                401: 'Authorization expired. Reconnect to continue.',
                403: 'Your authorization does not permit this operation.',
                404: 'The requested record was not found.',
                409: 'The record changed or conflicts with existing data. Refresh and review before retrying.',
                429: 'Too many requests. Wait briefly before retrying.'
            };
            return result({detail: messages[response.status] || 'IAM could not complete this operation. Try again shortly.'}, response.status);
        }
        // Never forward Set-Cookie or arbitrary upstream headers to the browser.
        const text = await response.text();
        return result(text ? JSON.parse(text) : {completed: true}, response.status);
    } catch (error) {
        return failure(error);
    }
}

export {handle as GET, handle as POST, handle as PUT, handle as PATCH, handle as DELETE};
