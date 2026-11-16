'use client';

import {type FormEvent, useEffect, useState} from 'react';

export type IdentityMode = 'login' | 'register' | 'verify' | 'reset' | 'mfa' | 'mfa-settings' | 'passkeys';
type Bootstrap = { csrfToken: string; registrationEnabled: boolean; passkeysEnabled: boolean; signInUrl: string };
type Data = {
    enabled?: boolean;
    removalAllowed?: boolean;
    required?: boolean;
    credentials?: {
        id: string;
        created_at: string;
        hardware_attested: boolean;
        attestation_revoked_at: string | null
    }[];
    attestationRequired?: boolean
};
type Result = {
    redirect?: string;
    requiresSignIn?: boolean;
    recoveryCodes?: string[];
    secret?: string;
    detail?: string
};
const titles: Record<IdentityMode, string> = {
    login: 'Sign in to your account',
    register: 'Create an account',
    verify: 'Verify your email',
    reset: 'Reset your password',
    mfa: 'Verify it’s you',
    'mfa-settings': 'Authenticator settings',
    passkeys: 'Your passkeys'
};

export default function IdentityFlow({mode, apiOrigin, uiOrigin, consoleOrigin}: {
    mode: IdentityMode;
    apiOrigin: string;
    uiOrigin: string;
    consoleOrigin: string
}) {
    const [boot, setBoot] = useState<Bootstrap | null>(null), [data, setData] = useState<Data | null>(null);
    const [error, setError] = useState(''), [message, setMessage] = useState(''), [busy, setBusy] = useState(false);
    const [secret, setSecret] = useState(''), [codes, setCodes] = useState<string[]>([]), [token, setToken] = useState(''), [done, setDone] = useState(false);

    function navigate(target: string) {
        const url = new URL(target, apiOrigin);
        if (![apiOrigin, uiOrigin, consoleOrigin].includes(url.origin)) throw new Error('Invalid identity redirect.');
        window.location.assign(url.toString());
    }

    async function call<T>(path: string, body?: unknown, csrf = boot?.csrfToken): Promise<T> {
        const response = await fetch('/api/iam' + path, {
            method: body === undefined ? 'GET' : 'POST',
            cache: 'no-store',
            redirect: 'error',
            headers: body === undefined ? {} : {'Content-Type': 'application/json', 'X-CSRF-TOKEN': csrf || ''},
            body: body === undefined ? undefined : JSON.stringify(body)
        });
        const value = await response.json().catch(() => ({detail: 'Identity service unavailable. Try again.'}));
        if (!response.ok) {
            if (value.redirect) navigate(value.redirect);
            throw new Error(value.detail || 'This request could not be completed.');
        }
        return value as T;
    }

    useEffect(() => {
        let active = true;
        const fragment = new URLSearchParams(window.location.hash.slice(1)).get('token');
        if (fragment && /^[A-Za-z0-9_-]{43}$/.test(fragment)) setToken(fragment);
        if (window.location.hash) window.history.replaceState({}, '', window.location.pathname);
        call<Bootstrap>('/session/bootstrap').then(async value => {
            if (!active) return;
            setBoot(value);
            if (mode === 'passkeys' && !value.passkeysEnabled) {
                setError('Passkeys are not enabled by this identity provider.');
                return;
            }
            if (mode === 'mfa-settings' || mode === 'passkeys') {
                const result = await call<Data>(mode === 'passkeys' ? '/passkeys' : '/mfa/settings');
                if (active) setData(result);
            }
        }).catch(e => {
            if (active) setError(e.message);
        });
        const wipe = () => {
            setSecret('');
            setCodes([]);
        };
        window.addEventListener('pagehide', wipe);
        return () => {
            active = false;
            window.removeEventListener('pagehide', wipe);
        };
    }, [mode]); // One bootstrap per identity page; mutations remain CSRF protected.
    async function submit(event: FormEvent<HTMLFormElement>, path: string) {
        event.preventDefault();
        setBusy(true);
        setError('');
        setMessage('');
        const form = event.currentTarget, values = Object.fromEntries(new FormData(form).entries());
        const body: Record<string, unknown> = {...values};
        if ('recovery' in values) body.recovery = values.recovery === 'true';
        if ('confirmation' in values && values.password !== values.confirmation) {
            setError('Passwords must match.');
            setBusy(false);
            return;
        }
        try {
            const result = await call<Result>(path, body);
            form.querySelectorAll<HTMLInputElement>('input[type=password]').forEach(input => {
                input.value = '';
            });
            if (result.secret) {
                setSecret(result.secret);
                setMessage('Add this setup key to your authenticator, then confirm a code within 10 minutes.');
            } else if (result.recoveryCodes?.length) {
                setSecret('');
                setCodes(result.recoveryCodes);
                setDone(true);
                setMessage('Save these one-use recovery codes now. They will not be shown again. All sessions have ended.');
            } else if (result.redirect) navigate(result.redirect);
            else if (result.requiresSignIn) {
                setSecret('');
                setDone(true);
                setMessage('Your security settings were updated. Sign in again to continue.');
            } else {
                setDone(true);
                setToken('');
                setMessage('If these details are eligible, an email will arrive shortly. Check your inbox or request a new link if needed.');
            }
        } catch (e) {
            setError((e as Error).message);
        } finally {
            setBusy(false);
        }
    }

    async function passkey(register: boolean, event?: FormEvent<HTMLFormElement>) {
        event?.preventDefault();
        setBusy(true);
        setError('');
        setMessage('Follow the instructions on your device.');
        try {
            if (!window.isSecureContext || !window.PublicKeyCredential || !navigator.credentials) throw new Error('Use a current browser on the configured secure identity URL.');
            const supported = PublicKeyCredential as typeof PublicKeyCredential & {
                parseCreationOptionsFromJSON?: unknown;
                parseRequestOptionsFromJSON?: unknown
            };
            if (typeof (register ? supported.parseCreationOptionsFromJSON : supported.parseRequestOptionsFromJSON) !== 'function') throw new Error('Use a current browser with passkey support.');
            const form = event?.currentTarget, password = form ? new FormData(form).get('password') : undefined;
            if (form) form.querySelectorAll<HTMLInputElement>('input[type=password]').forEach(input => {
                input.value = '';
            });
            const start = await call<{
                id: string;
                options: { publicKey: unknown }
            }>('/passkeys/' + (register ? 'register' : 'login') + '/options', register ? {password} : {});
            const key = PublicKeyCredential as typeof PublicKeyCredential & {
                parseCreationOptionsFromJSON: (x: unknown) => PublicKeyCredentialCreationOptions;
                parseRequestOptionsFromJSON: (x: unknown) => PublicKeyCredentialRequestOptions
            };
            const credential = await (register ? navigator.credentials.create({publicKey: key.parseCreationOptionsFromJSON(start.options.publicKey)}) : navigator.credentials.get({publicKey: key.parseRequestOptionsFromJSON(start.options.publicKey)})) as PublicKeyCredential & {
                toJSON: () => unknown
            };
            if (!credential) throw new Error('No passkey was selected.');
            const result = await call<Result>('/passkeys/' + (register ? 'register' : 'login') + '/finish', {
                id: start.id,
                credential: credential.toJSON()
            });
            if (result.redirect) navigate(result.redirect);
        } catch (e) {
            const problem = e as Error;
            setError(problem.name === 'NotAllowedError' ? 'Passkey operation was cancelled or timed out. You can try again.' : 'Passkey operation could not be completed. Check your password, sign in again if needed, and use a current browser and supported authenticator.');
            setMessage('');
        } finally {
            setBusy(false);
        }
    }

    const disabled = busy || !boot;
    const Password = ({confirmation = false, label = 'Current password'}: { confirmation?: boolean; label?: string }) =>
        <label>{confirmation ? 'Confirm password' : label}<input name={confirmation ? 'confirmation' : 'password'}
                                                                 type="password"
                                                                 autoComplete={confirmation || mode === 'register' || mode === 'reset' ? 'new-password' : 'current-password'}
                                                                 required
                                                                 minLength={mode === 'register' || mode === 'reset' ? 14 : 1}
                                                                 maxLength={mode === 'register' || mode === 'reset' ? 64 : 256}/></label>;
    const Code = () => <label>Authenticator or recovery code<input name="code" autoComplete="one-time-code" required
                                                                   maxLength={64}/></label>;
    const Management = ({remove = false}: { remove?: boolean }) => <form
        onSubmit={e => submit(e, remove ? '/mfa/remove' : '/mfa/recovery-codes')}><Password/><Code/><label
        className="identity-check"><input type="checkbox" name="recovery" value="true"/>This is a recovery code</label>
        <button disabled={disabled}
                className={remove ? 'danger' : ''}>{remove ? 'Remove MFA and end sessions' : 'Renew codes and end sessions'}</button>
    </form>;
    return <main id="main" className="identity-page"><a className="identity-brand" href={consoleOrigin}>◈ IAM
        identity</a>
        <section className="identity-card">
            <p className="identity-eyebrow">ACCOUNT &amp; SECURITY</p><h1>{titles[mode]}</h1>
            {!boot && !error && <p role="status">Connecting to your identity provider…</p>}
            {error && <p className="identity-error" role="alert">{error}</p>}{message &&
            <p className="identity-message" role="status">{message}</p>}
            {done ? <>
                <ul className="identity-codes">{codes.map(code => <li key={code}>{code}</li>)}</ul>
                <a href={boot?.signInUrl || consoleOrigin + '/login'}>Continue to sign
                    in</a>{!codes.length && (mode === 'register' || mode === 'verify' || mode === 'reset') &&
                <p><a href={mode === 'reset' ? '/account/reset' : '/account/verify'}>Request another link</a>
                </p>}</> : <>
                {mode === 'login' && <><p>Use your personal username and password.</p>
                    <form onSubmit={e => submit(e, '/session/login')}><label>Username<input name="username"
                                                                                            autoComplete="username"
                                                                                            required
                                                                                            maxLength={128}/></label><Password
                        label="Password"/>
                        <button disabled={disabled}>Sign in</button>
                    </form>
                    {boot?.passkeysEnabled &&
                        <button disabled={disabled} className="secondary" onClick={() => passkey(false)}>Sign in with a
                            passkey</button>}<p><a href="/account/reset">Forgot password?</a>
                    </p>{boot?.registrationEnabled && <a href="/account/register">Create an account</a>}</>}
                {mode === 'register' && (boot?.registrationEnabled ? <><p>Verify your email before signing in. No
                    administrator access is granted by registration.</p>
                    <form onSubmit={e => submit(e, '/account/register')}><label>Username<input name="username"
                                                                                               autoComplete="username"
                                                                                               required minLength={3}
                                                                                               maxLength={128}
                                                                                               pattern="[A-Za-z0-9][A-Za-z0-9._-]{2,127}"/></label><small>3–128
                        letters, numbers, dots, underscores or hyphens.</small><label>Email address<input name="email"
                                                                                                          type="email"
                                                                                                          autoComplete="email"
                                                                                                          required
                                                                                                          maxLength={254}/></label><Password
                        label="Password"/><small>14–64 characters, at most 72 UTF-8 bytes.</small><Password
                        confirmation/>
                        <button disabled={disabled}>Create account and send verification</button>
                    </form>
                </> : boot && <p>Self-service registration is not enabled. Contact your administrator.</p>)}
                {(mode === 'verify' || mode === 'reset') && <><p>Request a one-use email link. Password recovery
                    preserves MFA and registered passkeys.</p>
                    <form onSubmit={e => submit(e, '/account/' + mode + '/request')}><label>Email address<input
                        type="email" name="email" autoComplete="email" maxLength={254} required/></label>
                        <button disabled={disabled}>Request link</button>
                    </form>
                    <hr/>
                    <h2>Complete your request</h2>
                    <form onSubmit={e => submit(e, '/account/' + mode)}><label>Email token<input name="token"
                                                                                                 autoComplete="off"
                                                                                                 value={token}
                                                                                                 onChange={e => setToken(e.target.value)}
                                                                                                 pattern="[A-Za-z0-9_-]{43}"
                                                                                                 required/></label>{mode === 'reset' && <>
                        <Password label="New password"/><Password confirmation/></>}
                        <button
                            disabled={disabled}>{mode === 'verify' ? 'Verify email' : 'Change password and end sessions'}</button>
                    </form>
                </>}
                {mode === 'mfa' && <><p>Enter a fresh six-digit authenticator code, or choose recovery and enter an
                    unused recovery code.</p>
                    <form onSubmit={e => {
                        const recover = new FormData(e.currentTarget).get('recovery') === 'true';
                        submit(e, recover ? '/mfa/recover' : '/mfa/verify');
                    }}><Code/><label className="identity-check"><input type="checkbox" name="recovery" value="true"/>Use
                        a recovery code</label>
                        <button disabled={disabled}>Verify and continue</button>
                    </form>
                </>}
                {mode === 'mfa-settings' && data && <>{data.enabled ? <><p>Your authenticator is enabled. Renewing codes
                    invalidates all previous codes and ends sessions.</p><h2>Renew recovery codes</h2>
                    <Management/>{data.removalAllowed ? <details>
                        <summary>Remove MFA</summary>
                        <p>Your password and fresh factor proof are required. Sessions will end.</p><Management remove/>
                    </details> : <p>Your organization requires MFA to remain enabled.</p>}</> : <><p>Set up a time-based
                    authenticator (SHA1, six digits, 30-second period).</p>
                    <form onSubmit={e => submit(e, '/mfa/enroll')}><Password/>
                        <button disabled={disabled}>Start authenticator setup</button>
                    </form>
                    {secret && <><code className="identity-secret">{secret}</code><p>Keep this key private. Enter it
                        manually in your authenticator app.</p>
                        <form onSubmit={e => submit(e, '/mfa/verify')}><label>Six-digit code<input name="code"
                                                                                                   inputMode="numeric"
                                                                                                   autoComplete="one-time-code"
                                                                                                   pattern="[0-9]{6}"
                                                                                                   maxLength={6}
                                                                                                   required/></label>
                            <button disabled={disabled}>Enable MFA and end sessions</button>
                        </form>
                    </>}</>}</>}
                {mode === 'passkeys' && data && <><p>Use your device’s fingerprint, face recognition or security key.
                    Adding or removing a passkey ends all sessions. Any enrolled TOTP requirement
                    remains.</p>{data.attestationRequired &&
                    <p>Organization policy requires a trusted device-bound authenticator.</p>}
                    <form onSubmit={e => passkey(true, e)}><Password/>
                        <button disabled={disabled}>Add passkey and end sessions</button>
                    </form>
                    {!data.credentials?.length && <p>No passkeys registered.</p>}{data.credentials?.map(item => <article
                        key={item.id} className="identity-key"><strong>Passkey</strong><code>{item.id}</code>
                        <p>Registered {new Date(item.created_at).toLocaleString()}{item.hardware_attested ? ' · Attested' : ''}{item.attestation_revoked_at ? ' · Revoked by policy' : ''}</p>
                        <form onSubmit={e => submit(e, '/passkeys/' + item.id + '/remove')}><Password/>
                            <button disabled={disabled} className="danger">Remove passkey and end sessions</button>
                        </form>
                    </article>)}</>}
            </>}
            <footer><a href="/auth/login">Identity sign-in</a> · <a href={consoleOrigin}>Back to console</a>{boot &&
                <button disabled={disabled} className="secondary" onClick={async () => {
                    setBusy(true);
                    try {
                        const result = await call<Result>('/session/logout', {});
                        if (result.redirect) navigate(result.redirect);
                    } catch (e) {
                        setError((e as Error).message);
                        setBusy(false);
                    }
                }}>End IAM session</button>}</footer>
        </section>
    </main>;
}
