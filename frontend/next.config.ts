import type {NextConfig} from 'next';

const config: NextConfig = {
    poweredByHeader: false,
    // Preserve absolute canonical-origin redirects: NextURL folds loopback aliases together.
    skipProxyUrlNormalize: true,
    async headers() {
        return [{
            source: '/:path*', headers: [
                {key: 'X-Content-Type-Options', value: 'nosniff'},
                // Same-origin form POSTs need a non-null Origin for the CSRF guard.
                // Suppress referrers only when navigating to another origin (including IAM).
                {key: 'Referrer-Policy', value: 'same-origin'},
                {key: 'X-Frame-Options', value: 'DENY'},
                {key: 'Cache-Control', value: 'no-store'},
                {key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()'},
            ]
        }];
    },
};
export default config;
