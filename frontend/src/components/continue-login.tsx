"use client";

import {useEffect, useRef} from 'react';
import type {Lane} from '@/lib/contracts';

export default function ContinueLogin({lane}: { lane: Lane }) {
    const form = useRef<HTMLFormElement>(null);
    const started = useRef(false);
    useEffect(() => {
        if (!started.current && form.current) {
            started.current = true;
            form.current.requestSubmit();
        }
    }, []);
    return <main className="login-page">
        <section className="login-card">
            <h1>Connecting your workspace</h1>
            <p role="status">Completing secure sign-in. You’ll be redirected to your console.</p>
            <form ref={form} action={'/api/auth/start?lane=' + lane} method="post">
                <button className="button primary">Continue to console</button>
            </form>
        </section>
    </main>;
}
