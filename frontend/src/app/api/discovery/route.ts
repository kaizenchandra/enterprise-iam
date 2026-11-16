import {failure, result, upstream} from '@/lib/server';

export const runtime = 'nodejs';

export async function GET() {
    try {
        const response = await upstream('/.well-known/openid-configuration');
        if (!response.ok) throw new Error();
        const data = await response.json();
        return result({
            issuer: data.issuer,
            authorizationEndpoint: data.authorization_endpoint,
            tokenEndpoint: data.token_endpoint,
            jwksUri: data.jwks_uri,
            scopes: data.scopes_supported,
            grants: data.grant_types_supported
        });
    } catch (error) {
        return failure(error);
    }
}
