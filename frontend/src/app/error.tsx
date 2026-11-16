'use client';
export default function ErrorPage({reset}: { reset: () => void }) {
    return <main className="error-page"><h1>Something interrupted this workspace</h1><p>Your changes were not
        automatically retried. Reconnect and review the current record before continuing.</p>
        <button onClick={reset}>Try again</button>
    </main>;
}
