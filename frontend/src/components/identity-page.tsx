import {headers} from 'next/headers';
import {redirect} from 'next/navigation';
import {config} from '@/lib/server';
import IdentityFlow, {type IdentityMode} from './identity-flow';

export default async function IdentityPage({mode, path}: { mode: IdentityMode; path: string }) {
    const cfg = config();
    if ((await headers()).get('host') !== new URL(cfg.authUi).host) redirect(cfg.authUi + path);
    return <IdentityFlow mode={mode} apiOrigin={cfg.issuer} uiOrigin={cfg.authUi} consoleOrigin={cfg.origin}/>;
}
