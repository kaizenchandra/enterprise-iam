import type {Metadata} from 'next';
import './globals.css';
import {headers} from 'next/headers';

export const metadata: Metadata = {
    title: 'IAM Console · Enterprise identity',
    description: 'Manage identities, applications, organizations and access from one workspace.'
};
export default async function RootLayout({children}: Readonly<{ children: React.ReactNode }>) {
    await headers(); // A fresh CSP nonce is required for every document.
    return <html lang="en">
    <body><a className="skip-link" href="#main">Skip to content</a>{children}</body>
    </html>;
}
