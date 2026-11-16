import Console from '@/components/console';
import {cookies} from 'next/headers';
import {redirect} from 'next/navigation';
import {config, type Grant, sidKey, store} from '@/lib/server';

export default async function Page() {
    const name = config().secure ? '__Host-IAM_CONSOLE' : 'IAM_CONSOLE_LOCAL';
    const sid = (await cookies()).get(name)?.value;
    if (!sid || !/^[A-Za-z0-9_-]{43}$/.test(sid)) redirect('/login');
    let authenticated = false;
    try {
        const grants = await (await store()).hGetAll(sidKey(sid));
        authenticated = Object.values(grants).some(raw => {
            const grant = JSON.parse(raw) as Grant;
            return !grant.subject.startsWith('client:') && grant.expiresAt > Date.now();
        });
    } catch {
        return <Console/>;
    } // Render retryable connection error; APIs still fail closed.
    if (!authenticated) redirect('/login');
    return <Console/>;
}
