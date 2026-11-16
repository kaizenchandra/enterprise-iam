import {result} from '@/lib/server';

export async function POST() {
    return result({detail: 'Use username/password sign-in at /login. Browser client-credential login has been removed.'}, 410);
}
