import {NextRequest} from 'next/server';
import {failure, originGuard, result, sessionId, setSession, sidKey, store} from '@/lib/server';

export const runtime = 'nodejs';

export async function POST(req: NextRequest) {
    try {
        originGuard(req);
        const sid = sessionId(req);
        if (sid) await (await store()).del(sidKey(sid));
        const res = result({disconnected: true});
        setSession(res, '', 0);
        return res;
    } catch (error) {
        return failure(error);
    }
}
