import {NextRequest, NextResponse} from 'next/server';
import {config as serverConfig} from './lib/server';

export function proxy(req: NextRequest) {
    const cfg = serverConfig();
    if (req.method === 'GET' && ['/', '/login', '/register', '/auth/continue'].includes(req.nextUrl.pathname)
        && (req.headers.get('host') || req.nextUrl.host) !== new URL(cfg.origin).host) {
        return NextResponse.redirect(new URL(req.nextUrl.pathname + req.nextUrl.search, cfg.origin), 307);
    }
    const nonce = Buffer.from(crypto.randomUUID()).toString('base64');
    const csp = `default-src 'self'; script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${process.env.NODE_ENV === 'development' ? " 'unsafe-eval'" : ''}; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self' ${serverConfig().issuer}`;
    const headers = new Headers(req.headers);
    headers.set('x-nonce', nonce);
    headers.set('Content-Security-Policy', csp);
    const res = NextResponse.next({request: {headers}});
    res.headers.set('Content-Security-Policy', csp);
    return res;
}

export const config = {matcher: ['/((?!_next/static|_next/image|favicon.ico).*)']};
