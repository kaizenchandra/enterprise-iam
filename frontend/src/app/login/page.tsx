import {ArrowRight, KeyRound, ShieldCheck, Users} from 'lucide-react';

export default async function Login({searchParams}: { searchParams: Promise<{ error?: string }> }) {
    const {error} = await searchParams;
    return <main className="login-page"><a className="login-brand" href="/">IAM<span>console</span></a>
        <section className="login-card"><span className="large-icon"><ShieldCheck size={30}/></span><p
            className="eyebrow">ENTERPRISE IDENTITY</p><h1>Welcome back</h1><p>Sign in with your personal username and
            password.<br/>Your account determines your access.</p>{error &&
            <div className="banner error" role="alert">Sign-in could not be authorized. Check your account and access
                role, then try again.</div>}
            <form action="/api/auth/start?lane=app" method="post">
                <button className="login-choice"><Users size={23}/><span><strong>My workspace</strong><small>Account, security and protected applications</small></span><ArrowRight
                    size={18}/></button>
            </form>
            <form action="/api/auth/start?lane=admin" method="post">
                <button className="login-choice"><KeyRound
                    size={23}/><span><strong>Administrator workspace</strong><small>Requires an assigned platform administrator role</small></span><ArrowRight
                    size={18}/></button>
            </form>
            <div className="login-note"><ShieldCheck size={17}/><span>Username/password entry happens on the IAM provider. MFA and passkeys remain enabled where configured.</span>
            </div>
            <p>New here? <a href="/register">Create an account</a></p><a href="/">Back to console</a></section>
    </main>;
}
