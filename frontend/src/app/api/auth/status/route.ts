import {NextRequest} from 'next/server';
import {config, discardGrant, failure, type Grant, grantActive, result, sessionId, sidKey, store} from '@/lib/server';

export const runtime = 'nodejs';

export async function GET(req: NextRequest) {
    try {
        const sid = sessionId(req);
        const grants = sid ? await (await store()).hGetAll(sidKey(sid)) : {};
        const lanes: Record<string, { subject: string; expiresAt: number }> = {};
        await Promise.all(Object.entries(grants).map(async ([lane, raw]) => {
            const grant = JSON.parse(raw) as Grant;
            if (!(lane === 'admin' && grant.subject.startsWith('client:')) && await grantActive(grant)) lanes[lane] = {
                subject: grant.subject,
                expiresAt: grant.expiresAt
            };
            else if (sid) await discardGrant(sid, lane, grant.token);
        }));
        return result({lanes, issuer: config().issuer, authUi: config().authUi});
    } catch (error) {
        return failure(error);
    }
}
