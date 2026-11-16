import {NextRequest, NextResponse} from 'next/server';
import {config, failure, HttpError, jsonBody, upstream} from '@/lib/server';

export const runtime = 'nodejs';
const routes: Record<string, string[]> = {
    '/session/bootstrap': ['GET'], '/session/login': ['POST'], '/session/logout': ['POST'],
    '/account/register': ['GET', 'POST'], '/account/verify': ['GET', 'POST'], '/account/reset': ['GET', 'POST'],
    '/account/verify/request': ['POST'], '/account/reset/request': ['POST'],
    '/mfa': ['GET'], '/mfa/settings': ['GET'], '/mfa/enroll': ['POST'], '/mfa/verify': ['POST'],
    '/mfa/recover': ['POST'], '/mfa/remove': ['POST'], '/mfa/recovery-codes': ['POST'],
    '/passkeys': ['GET'], '/passkeys/register/options': ['POST'], '/passkeys/register/finish': ['POST'],
    '/passkeys/login/options': ['POST'], '/passkeys/login/finish': ['POST']
};

async function handle(req: NextRequest, context: { params: Promise<{ path: string[] }> }) {
    try {
        const cfg = config();
        if ((req.headers.get('host') || req.nextUrl.host) !== new URL(cfg.authUi).host) throw new HttpError(403, 'Use the configured identity provider frontend.');
        if (req.method !== 'GET' && req.headers.get('origin') !== cfg.authUi) throw new HttpError(403, 'Request origin not allowed.');
        const path = '/' + (await context.params).path.join('/');
        const removal = /^\/passkeys\/[a-f0-9-]{36}\/remove$/.test(path) && req.method === 'POST';
        if (!removal && !routes[path]?.includes(req.method)) throw new HttpError(404, 'Unknown identity operation.');
        if (req.nextUrl.search) throw new HttpError(400, 'Query parameters are not supported.');
        const headers: Record<string, string> = {'Accept': 'application/json'};
        const session = req.cookies.get('IAM_SESSION')?.value;
        if (session && /^[A-Za-z0-9_+=/\-]{1,256}$/.test(session)) headers.Cookie = 'IAM_SESSION=' + session;
        const csrf = req.headers.get('x-csrf-token');
        if (csrf && csrf.length < 1024) headers['X-CSRF-TOKEN'] = csrf;
        let body: string | undefined;
        if (req.method !== 'GET') {
            body = JSON.stringify(await jsonBody(req));
            headers['Content-Type'] = 'application/json';
        }
        const response = await upstream(path, {method: req.method, headers, body});
        const result = new NextResponse(await response.text(), {
            status: response.status,
            headers: {'Content-Type': 'application/json', 'Cache-Control': 'no-store'}
        });
        for (const cookie of response.headers.getSetCookie()) if (cookie.startsWith('IAM_SESSION=')) result.headers.append('Set-Cookie', cookie);
        return result;
    } catch (error) {
        return failure(error);
    }
}

export {handle as GET, handle as POST};
