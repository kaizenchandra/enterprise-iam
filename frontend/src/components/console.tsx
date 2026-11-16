'use client';

import {useCallback, useEffect, useRef, useState} from 'react';
import {
    Activity,
    ArrowDownLeft,
    ArrowRight,
    ArrowUpRight,
    Building2,
    Check,
    ChevronDown,
    ChevronLeft,
    ChevronRight,
    CircleHelp,
    Clock3,
    Copy,
    FileKey2,
    Fingerprint,
    Globe2,
    KeyRound,
    LayoutDashboard,
    Link2,
    LoaderCircle,
    LogOut,
    Menu,
    MoreHorizontal,
    Plus,
    RefreshCw,
    Search,
    Shield,
    ShieldCheck,
    SlidersHorizontal,
    Users,
    X
} from 'lucide-react';
import {buildRequest, type Field, type Lane, type Operation, operations} from '@/lib/contracts';

type Tab = 'overview' | 'users' | 'organizations' | 'applications' | 'policies' | 'sessions' | 'decisions' | 'security';
type Row = Record<string, unknown>;
type Status = { lanes: Partial<Record<Lane, { subject: string; expiresAt: number }>>; issuer: string; authUi?: string };
const sections = [
    {id: 'overview', label: 'Overview', icon: LayoutDashboard, description: 'A clear view of your identity workspace.'},
    {
        id: 'users',
        label: 'Users',
        icon: Users,
        description: 'Manage identities through every stage of their lifecycle.'
    },
    {
        id: 'organizations',
        label: 'Organizations',
        icon: Building2,
        description: 'Keep membership and access boundaries clear.'
    },
    {
        id: 'applications',
        label: 'Applications',
        icon: FileKey2,
        description: 'Connect services with scoped credentials and trusted keys.'
    },
    {
        id: 'policies',
        label: 'Access policies',
        icon: ShieldCheck,
        description: 'Define roles, permissions and resource assignments.'
    },
    {id: 'sessions', label: 'My sessions', icon: Globe2, description: 'Review and revoke your own IAM login sessions.'},
    {
        id: 'decisions',
        label: 'Authorization check',
        icon: SlidersHorizontal,
        description: 'Evaluate your access against current authoritative policy.'
    },
    {
        id: 'security',
        label: 'Account & security',
        icon: Fingerprint,
        description: 'Manage your credentials with the identity provider.'
    },
] as const;
const labels: Record<string, string> = {
    id: 'Record ID',
    userId: 'User ID',
    clientId: 'Client ID',
    sessionId: 'Session ID',
    name: 'Name',
    username: 'Username',
    email: 'Recovery email',
    password: 'Initial password',
    version: 'Current user version',
    organizationId: 'Organization ID',
    roleId: 'Role ID',
    resourceId: 'Resource ID',
    permission: 'Permission',
    scopes: 'Scopes',
    clientAuthenticationMethod: 'Authentication method',
    jwks: 'Public JWKS',
    expectedRevision: 'Expected key revision',
    backchannelLogoutUri: 'Back-channel logout URL',
    tenantId: 'Organization ID',
    action: 'Requested action',
    page: 'Page',
    limit: 'Page size',
    after: 'Next-page cursor'
};
const helpers: Record<string, string> = {
    version: 'Use the version from the latest user record. Stale updates are rejected.',
    password: '14–64 characters; no more than 72 UTF-8 bytes. Share through an approved channel.',
    email: 'A trusted address binding. Binding does not mark the address verified.',
    scopes: 'Comma-separated: orders.read, decision.write',
    jwks: 'Public RS256 keys only. Never paste private key material.',
    expectedRevision: 'Read the current key policy before replacing or disabling it.',
    resourceId: 'An existing protected resource. Leave blank only for an organization-wide assignment.',
    userId: 'The immutable user UUID, not the username.',
    after: 'Use the nextCursor value from the previous response.'
};
const display = (value: unknown) => value === null || value === undefined ? '—' : typeof value === 'object' ? JSON.stringify(value) : String(value);
const titleFor = (op: Operation) => {
    if (op.path.endsWith('/authentication-keys')) return op.method === 'GET' ? 'View authentication keys' : op.method === 'PUT' ? 'Replace authentication keys' : 'Disable authentication keys';
    if (op.path.endsWith('/members')) return op.method === 'GET' ? 'View organization members' : 'Add organization member';
    if (op.path.includes('/members/')) return 'Remove organization member';
    if (op.path.endsWith('/email')) return 'Bind recovery email';
    if (op.path.endsWith('/revoke-sessions')) return 'Revoke all user sessions';
    if (op.path.endsWith('/rotate-credentials')) return 'Rotate client secret';
    if (op.path.endsWith('/backchannel')) return 'Configure back-channel logout';
    if (op.path.endsWith('/decisions')) return 'Evaluate authorization';
    if (op.path.endsWith('/suspend')) return 'Suspend user';
    if (op.path.endsWith('/activate')) return 'Activate user';
    if (op.path.endsWith('/deactivate')) return 'Deactivate user';
    if (op.path.includes('/users/me/sessions/')) return 'Revoke my session';
    const noun = op.group === 'applications' ? 'client' : op.path.includes('/role-assignments') ? 'role assignment' : op.path.endsWith('/permissions') ? 'permission' : op.path.endsWith('/roles') ? 'role' : op.group === 'organizations' ? 'organization' : op.group === 'users' ? 'user' : 'policy';
    return `${op.method === 'GET' ? 'View' : op.method === 'PATCH' ? 'Update' : op.method === 'DELETE' ? 'Delete' : 'Create'} ${noun}`;
};
const lists: Partial<Record<Tab, string>> = {
    users: '/api/v1/admin/users',
    organizations: '/api/v1/admin/organizations',
    applications: '/api/v1/admin/clients',
    policies: '/api/v1/admin/policies',
    sessions: '/api/v1/users/me/sessions'
};

async function api(path: string, options?: RequestInit) {
    const response = await fetch(path, {cache: 'no-store', ...options});
    const body = response.status === 204 ? null : await response.json();
    if (response.status === 401) window.dispatchEvent(new Event('iam-session-changed'));
    if (!response.ok) throw new Error(body?.detail || `Request failed (${response.status}).`);
    return body;
}

export default function Console() {
    const [tab, setTab] = useState<Tab>('overview');
    const [status, setStatus] = useState<Status>({lanes: {}, issuer: ''});
    const [statusError, setStatusError] = useState('');
    const [rows, setRows] = useState<Row[]>([]);
    const [counts, setCounts] = useState<Record<string, number>>({});
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [search, setSearch] = useState('');
    const [page, setPage] = useState(0);
    const [cursors, setCursors] = useState<string[]>(['']);
    const [nextCursor, setNextCursor] = useState('');
    const [operation, setOperation] = useState<Operation | null>(null);
    const [defaults, setDefaults] = useState<Record<string, string>>({});
    const [connect, setConnect] = useState(false);
    const [mobile, setMobile] = useState(false);
    const [toast, setToast] = useState('');
    const [discovery, setDiscovery] = useState<Row | null>(null);
    const [notice, setNotice] = useState('');
    const [refresh, setRefresh] = useState(0);
    const [resource, setResource] = useState<unknown>(undefined);
    const [resourceError, setResourceError] = useState('');
    const [resourceLoading, setResourceLoading] = useState(false);
    const heading = sections.find(s => s.id === tab)!;
    const admin = !!status.lanes.admin;
    const lane = tab === 'sessions' ? 'management' : tab === 'decisions' ? 'app' : 'admin';
    const connected = !!status.lanes[lane];
    const statusGeneration = useRef(0);
    const loadStatus = useCallback(async () => {
        const generation = ++statusGeneration.current;
        try {
            const current = await api('/api/auth/status');
            if (generation !== statusGeneration.current) return;
            setStatus(current);
            setStatusError('');
        } catch (e) {
            if (generation !== statusGeneration.current) return;
            setStatus(previous => ({lanes: {}, issuer: previous.issuer, authUi: previous.authUi}));
            setStatusError((e as Error).message);
        }
    }, []);
    useEffect(() => {
        const params = new URLSearchParams(window.location.search);
        if (sections.some(s => s.id === params.get('tab'))) setTab(params.get('tab') as Tab);
        if (params.get('notice') === 'sign-in-failed') setNotice('Sign-in could not be completed. Please try again; your previous changes were not retried.');
        if (params.get('notice') === 'signed-in') setToast('Your IAM account is connected.');
        window.history.replaceState({}, '', window.location.pathname);
        void loadStatus();
        const sync = () => {
            if (document.visibilityState !== 'hidden') void loadStatus();
        };
        window.addEventListener('focus', sync);
        window.addEventListener('iam-session-changed', sync);
        document.addEventListener('visibilitychange', sync);
        const timer = setInterval(sync, 30000);
        return () => {
            ++statusGeneration.current;
            clearInterval(timer);
            window.removeEventListener('focus', sync);
            window.removeEventListener('iam-session-changed', sync);
            document.removeEventListener('visibilitychange', sync);
        };
    }, [loadStatus]);
    useEffect(() => {
        if (toast) {
            const timer = setTimeout(() => setToast(''), 6000);
            return () => clearTimeout(timer);
        }
    }, [toast]);
    useEffect(() => {
        void api('/api/discovery').then(setDiscovery).catch(() => setDiscovery(null));
    }, [refresh]);
    useEffect(() => {
        const controller = new AbortController();
        setLoading(false);
        setError('');
        setRows([]);
        setNextCursor('');
        if (!lists[tab] || !connected) return;
        setLoading(true);
        const suffix = tab === 'sessions' ? '?limit=20' + (cursors[page] ? '&after=' + encodeURIComponent(cursors[page]) : '') : tab === 'applications' ? '' : '?page=' + page;
        api('/api/backend' + lists[tab] + suffix, {signal: controller.signal}).then(data => {
            if (!controller.signal.aborted) {
                setRows(Array.isArray(data) ? data : data.items || []);
                setNextCursor(data?.nextCursor || '');
            }
        }).catch(e => {
            if (!controller.signal.aborted) setError(e.message);
        }).finally(() => {
            if (!controller.signal.aborted) setLoading(false);
        });
        return () => controller.abort();
    }, [tab, page, refresh, connected, cursors]);
    useEffect(() => {
        let active = true;
        setCounts({});
        if (admin) for (const key of ['users', 'organizations', 'applications']) api('/api/backend' + lists[key as Tab]).then(data => {
            if (active) setCounts(v => ({...v, [key]: data.length}));
        }).catch(() => {
        });
        return () => {
            active = false;
        };
    }, [admin, refresh]);
    useEffect(() => {
        setResource(undefined);
        setResourceError('');
    }, [status.lanes.app?.subject, status.lanes.app?.expiresAt]);
    const navigate = (id: Tab) => {
        window.history.replaceState({}, '', '?tab=' + id);
        setTab(id);
        setPage(0);
        setCursors(['']);
        setSearch('');
        setMobile(false);
        setOperation(null);
    };
    const open = (op: Operation, row?: Row) => {
        const values: Record<string, string> = {};
        if (row) for (const f of op.fields) {
            let value = row[f.name];
            if (f.name === 'id' || f.name === 'sessionId') value = op.path.includes('/role-assignments/') ? undefined : row.id;
            if (f.name === 'userId') value = row.user_id ?? (tab === 'users' ? row.id : undefined);
            if (f.name === 'clientId') value = row.client_id;
            if (f.name === 'organizationId') value = row.organization_id ?? (tab === 'organizations' ? row.id : undefined);
            if (f.name === 'roleId') value = row.role_id ?? (tab === 'policies' ? row.id : undefined);
            if (f.location === 'path' && f.name === 'id' && tab === 'organizations') value = row.id;
            if (value !== undefined && value !== null) values[f.name] = String(value);
        }
        setDefaults(values);
        setOperation(op);
    };
    const available = operations.filter(o => o.group === tab && !(o.method === 'GET' && lists[tab] === o.path));
    const primary = available.find(o => o.method === 'POST' && !o.path.includes('{'));
    const filtered = rows.filter(row => Object.values(row).some(value => display(value).toLowerCase().includes(search.toLowerCase())));
    const refreshAll = () => {
        setRefresh(v => v + 1);
        void loadStatus();
    };

    return <div className="workspace">
        <aside className={'sidebar ' + (mobile ? 'open' : '')} aria-label="Main navigation">
            <a className="brand" href="/" aria-label="IAM Console home"><span className="brand-mark"><Shield size={22}
                                                                                                             strokeWidth={2.3}/></span><span>IAM<span
                className="brand-light">console</span></span><span className="brand-dot"/></a>
            <div className="workspace-switch"><span className="workspace-icon">E</span>
                <div><strong>Enterprise workspace</strong><small>Identity & access</small></div>
                <ChevronDown size={14}/></div>
            <p className="nav-label">WORKSPACE</p>
            <nav>{sections.slice(0, 5).filter(item => item.id === 'overview' || admin).map(item => <button key={item.id}
                                                                                                           className={'nav-item ' + (tab === item.id ? 'selected' : '')}
                                                                                                           onClick={() => navigate(item.id)}
                                                                                                           aria-current={tab === item.id ? 'page' : undefined}>
                <item.icon size={18}/>
                <span>{item.label}</span>{tab === item.id && <span className="nav-active"/>}</button>)}</nav>
            <p className="nav-label personal-label">PERSONAL & TOOLS</p>
            <nav>{sections.slice(5).map(item => <button key={item.id}
                                                        className={'nav-item ' + (tab === item.id ? 'selected' : '')}
                                                        onClick={() => navigate(item.id)}
                                                        aria-current={tab === item.id ? 'page' : undefined}>
                <item.icon size={18}/>
                <span>{item.label}</span></button>)}</nav>
            <div className="sidebar-bottom">
                <div className="security-note"><ShieldCheck size={18}/>
                    <div><strong>Access with intention</strong><p>Scoped credentials.<br/>Explicit, reviewed changes.
                    </p></div>
                </div>
                <a className="help-link"
                   href={status.issuer ? status.issuer + '/.well-known/openid-configuration' : '#main'} target="_blank"
                   rel="noreferrer"><CircleHelp size={17}/> Provider discovery <ArrowUpRight size={14}/></a>
                <button className="operator" onClick={() => setConnect(true)}><span
                    className="avatar">{admin ? 'AD' : 'OP'}</span><span><strong>{admin ? 'Administrator' : 'Your account'}</strong><small>{admin ? 'Platform administrator' : 'Sign-in required'}</small></span><MoreHorizontal
                    size={18}/></button>
            </div>
        </aside>
        {mobile && <button className="sidebar-scrim" aria-label="Close navigation" onClick={() => setMobile(false)}/>}
        <div className="main-shell">
            <header className="topbar">
                <div className="breadcrumb">
                    <button className="icon-button mobile-toggle" aria-label="Open navigation"
                            onClick={() => setMobile(true)}><Menu size={20}/></button>
                    <span>Workspace</span><ChevronRight size={14}/><strong>{heading.label}</strong></div>
                <div className="topbar-right"><span
                    className="environment"><span/>LOCAL DEVELOPMENT</span>{Object.keys(status.lanes).length > 0 &&
                    <button className="text-button" onClick={async () => {
                        try {
                            await api('/api/auth/disconnect', {method: 'POST'});
                            ++statusGeneration.current;
                            setStatus(previous => ({...previous, lanes: {}}));
                            setToast('Console disconnected. Your IAM browser session may still be active.');
                            setRows([]);
                        } catch (e) {
                            setToast((e as Error).message);
                        }
                    }}><LogOut size={15}/> Disconnect</button>}
                    <button className="avatar small" aria-label="Manage administrator connection"
                            onClick={() => setConnect(true)}>{admin ? 'AD' : 'OP'}</button>
                </div>
            </header>
            <main id="main" tabIndex={-1}>
                {(notice || statusError) && <div className="banner error" role="alert">{notice || statusError}
                    <button className="icon-button" aria-label="Dismiss message" onClick={() => {
                        setNotice('');
                        setStatusError('');
                    }}><X size={16}/></button>
                </div>}
                <div className="page-heading">
                    <div>
                        <div className="eyebrow">IDENTITY CONTROL CENTER</div>
                        <h1>{heading.label}</h1><p>{heading.description}</p></div>
                    <div className="heading-actions">
                        <button className="button secondary" onClick={refreshAll}><RefreshCw size={15}/> Refresh
                        </button>
                        {tab === 'overview' ? <button className="button primary" onClick={() => setConnect(true)}><Link2
                            size={16}/> {admin ? 'Manage connection' : 'Sign in as administrator'}</button> : primary &&
                            <button className="button primary" disabled={!connected} onClick={() => open(primary)}><Plus
                                size={17}/>{titleFor(primary)}</button>}</div>
                </div>
                {tab === 'overview' && <>
                    <section className="welcome-panel">
                        <div><span className="panel-kicker"><span className="live-dot"/> YOUR IDENTITY WORKSPACE</span>
                            <h2>Good access starts<br/>with a clear picture.</h2><p>Bring your people, applications and
                                access policies<br className="desktop-break"/> together. Every change, made with
                                confidence.</p>
                            <button className="button dark" onClick={() => navigate('users')}>Manage
                                identities <ArrowRight size={16}/></button>
                        </div>
                        <div className="identity-graphic" aria-hidden="true">
                            <div className="orbit orbit-one"/>
                            <div className="orbit orbit-two"/>
                            <div className="graphic-center"><ShieldCheck size={50} strokeWidth={1.4}/></div>
                            <span className="graphic-node node-one"><Users size={22}/></span><span
                            className="graphic-node node-two"><KeyRound size={22}/></span><span
                            className="graphic-node node-three"><Building2 size={22}/></span><span
                            className="graphic-label">CONNECTED BY TRUST</span></div>
                    </section>
                    <section className="metric-grid" aria-label="Directory summary">{[{
                        key: 'users',
                        title: 'Users',
                        icon: Users,
                        detail: 'Identities in this directory'
                    }, {
                        key: 'organizations',
                        title: 'Organizations',
                        icon: Building2,
                        detail: 'Distinct membership boundaries'
                    }, {
                        key: 'applications',
                        title: 'Applications',
                        icon: FileKey2,
                        detail: 'Registered OAuth clients'
                    }].map(item => <button className="metric-card" key={item.key}
                                           onClick={() => navigate(item.key as Tab)}>
                        <div className="metric-top"><span>{item.title}</span>
                            <item.icon size={19}/>
                        </div>
                        <div className="metric-number">{counts[item.key] ?? '—'}<ArrowUpRight size={20}/></div>
                        <small>{counts[item.key] === undefined ? 'Administrator sign-in required' : counts[item.key] >= 100 ? '100 records on first page · view directory' : item.detail}</small>
                    </button>)}</section>
                    <div className="overview-columns">
                        <section className="card quick-actions">
                            <div className="card-heading">
                                <div><h2>Start with what matters</h2><p>Common tasks, one step away.</p></div>
                                <span className="subtle-icon"><ArrowDownLeft size={20}/></span></div>
                            {[{
                                tab: 'users',
                                title: 'Manage user lifecycle',
                                detail: 'Create, activate, suspend or revoke access.',
                                icon: Users
                            }, {
                                tab: 'applications',
                                title: 'Connect an application',
                                detail: 'Register a scoped service or rotate its keys.',
                                icon: FileKey2
                            }, {
                                tab: 'policies',
                                title: 'Review access policies',
                                detail: 'Keep roles and assignments intentional.',
                                icon: ShieldCheck
                            }].map(item => <button className="action-row" key={item.tab}
                                                   onClick={() => navigate(item.tab as Tab)}><span
                                className="action-icon"><item.icon size={20}/></span><span><strong>{item.title}</strong><small>{item.detail}</small></span><ChevronRight
                                size={17}/></button>)}</section>
                        <section className="card connection-card">
                            <div className="card-heading">
                                <div><h2>Connection health</h2><p>Live state of this console.</p></div>
                                <Activity size={18}/></div>
                            <ConnectionLine name="Identity provider" value={discovery ? 'Reachable' : 'Unavailable'}
                                            good={!!discovery}/><ConnectionLine name="Administrator"
                                                                                value={admin ? 'Connected' : 'Not connected'}
                                                                                good={admin}/><ConnectionLine
                            name="Personal sessions" value={status.lanes.management ? 'Authorized' : 'Sign-in required'}
                            good={!!status.lanes.management}/>
                            <div className="connection-foot"><Clock3 size={15}/><span>Access is checked on every request.</span>
                            </div>
                        </section>
                    </div>
                    <div className="workspace-foot"><Shield size={15}/><span>A development baseline. Production SLOs and complete enterprise capabilities are not yet verified.</span>
                        <button onClick={() => navigate('security')}>View security tools <ArrowRight size={14}/>
                        </button>
                    </div>
                </>}
                {lists[tab] && <>
                    {!connected ? <ConnectionEmpty lane={lane} onConnect={() => setConnect(true)}/> :
                        <section className="card directory">
                            <div className="directory-toolbar">
                                <div className="directory-title">
                                    <h2>{tab === 'policies' ? 'Role permissions' : heading.label}</h2><span
                                    className="count-badge">{rows.length}</span></div>
                                <div className="search-input"><Search size={16}/><input aria-label="Search current page"
                                                                                        placeholder="Search this page…"
                                                                                        value={search}
                                                                                        onChange={e => setSearch(e.target.value)}/>
                                </div>
                            </div>
                            {error ?
                                <div className="empty-state error-state" role="alert"><Shield size={26}/><h3>We couldn’t
                                    load these records</h3><p>{error}</p>
                                    <button className="button secondary" onClick={refreshAll}>Try again</button>
                                </div> : loading ?
                                    <div className="loading-state" role="status"><LoaderCircle className="spin"
                                                                                               size={22}/> Loading live
                                        records…</div> : filtered.length === 0 ? <div className="empty-state">
                                            <heading.icon size={28}/>
                                            <h3>{search ? 'No matching records on this page' : 'No records to show'}</h3>
                                            <p>{search ? 'Try another search or change the page.' : 'New records will appear here as they are created.'}</p>{primary && !search &&
                                            <button className="button primary" onClick={() => open(primary)}><Plus
                                                size={16}/>{titleFor(primary)}</button>}</div> :
                                        <RecordTable tab={tab} rows={filtered}
                                                     available={available.filter(o => o.fields.some(f => f.location === 'path' || f.name === 'roleId'))}
                                                     onOpen={open}/>}
                            <div className="pagination">
                                <span>{tab === 'applications' ? 'Up to 100 registered clients' : `Page ${page + 1} · ${rows.length} records`}<span
                                    className="pagination-note"> · Search applies to this page</span></span>{tab !== 'applications' &&
                                <div>
                                    <button className="icon-button" aria-label="Previous page"
                                            disabled={page === 0 || loading} onClick={() => setPage(v => v - 1)}>
                                        <ChevronLeft size={17}/></button>
                                    <button className="icon-button" aria-label="Next page"
                                            disabled={loading || (tab === 'sessions' ? !nextCursor : rows.length < 100)}
                                            onClick={() => {
                                                if (tab === 'sessions') setCursors(v => [...v.slice(0, page + 1), nextCursor]);
                                                setPage(v => v + 1);
                                            }}><ChevronRight size={17}/></button>
                                </div>}</div>
                        </section>}
                    <section className="operation-section">
                        <div className="section-label">
                            <h2>{tab === 'sessions' ? 'Session tools' : 'Workspace actions'}</h2><span>Explicit changes. Current backend rules.</span>
                        </div>
                        <div className="operation-grid">{available.filter(op => op !== primary).map(op => <button
                            className={'operation-card ' + (op.dangerous ? 'sensitive' : '')} key={op.id}
                            disabled={!connected} onClick={() => open(op)}><span
                            className={'method method-' + op.method.toLowerCase()}>{op.method}</span><strong>{titleFor(op)}</strong><ArrowUpRight
                            size={16}/></button>)}</div>
                    </section>
                    {tab === 'sessions' &&
                        <p className="inline-note"><CircleHelp size={16}/> Revocation ends the selected IAM session and
                            queues participating applications for logout. Existing offline JWTs can remain valid until
                            expiry.</p>}
                </>}
                {tab === 'decisions' && <>
                    <section className="card decision-intro">
                        <div className="large-icon"><SlidersHorizontal size={27}/></div>
                        <h2>Ask before granting access</h2><p>Evaluate the signed-in user’s current permission for an
                        organization, action and resource. The backend derives identity from the token and checks
                        authoritative database records.</p>{status.lanes.app ? <button className="button primary"
                                                                                       onClick={() => open(operations.find(o => o.group === 'decisions')!)}>Run
                            authorization check <ArrowRight size={16}/></button> :
                        <form action="/api/auth/start?lane=app" method="post">
                            <button className="button primary">Sign in to evaluate access <ArrowUpRight size={16}/>
                            </button>
                        </form>}</section>
                    <div className="info-grid"><InfoCard title="Default deny"
                                                         text="Absent membership, inactive users, missing resources and insufficient permissions return DENY."/><InfoCard
                        title="Your identity, verified"
                        text="You cannot enter another user’s subject or self-assert attributes to obtain permission."/><InfoCard
                        title="Current policy snapshot"
                        text="Decisions use the current database statement snapshot. They do not commit a downstream business action."/>
                    </div>
                </>}
                {tab === 'security' && <>
                    <section className="security-hero">
                        <div className="large-icon"><Fingerprint size={30}/></div>
                        <div><h2>Your account. Stronger by design.</h2><p>Sensitive account ceremonies run directly on
                            your IAM provider’s origin. Passwords, recovery tokens and passkey challenges stay in its
                            protected flows.</p></div>
                    </section>
                    <div className="security-grid">{[{
                        title: 'Multi-factor authentication',
                        text: 'Enroll TOTP, verify a second factor or use a recovery code.',
                        path: '/mfa/settings',
                        icon: ShieldCheck,
                        badge: 'IAM provider'
                    }, {
                        title: 'Passkeys',
                        text: 'Enroll, review and remove user-verified credentials.',
                        path: '/passkeys',
                        icon: Fingerprint,
                        badge: 'When enabled'
                    }, {
                        title: 'Password recovery',
                        text: 'Request a single-use reset through your trusted email binding.',
                        path: '/account/reset',
                        icon: KeyRound,
                        badge: 'When enabled'
                    }, {
                        title: 'Email verification',
                        text: 'Verify your email through a purpose-bound, single-use account action.',
                        path: '/account/verify',
                        icon: Check,
                        badge: 'When enabled'
                    }].map(item => <a className="card security-card" key={item.title}
                                      href={status.authUi ? status.authUi + item.path : undefined}
                                      aria-disabled={!status.issuer}>
                        <div className="security-card-top">
                            <item.icon size={24}/>
                            <span className="neutral-badge">{item.badge}</span></div>
                        <h3>{item.title}</h3><p>{item.text}</p><span
                        className="security-link">Continue on IAM <ArrowUpRight size={16}/></span></a>)}</div>
                    <section className="card personal-api-card">
                        <div className="card-heading">
                            <div><h2>My connected identity</h2><p>Read your OIDC identity or call the sample protected
                                orders API.</p></div>
                            <KeyRound size={18}/></div>
                        <div className="personal-api-actions">{status.lanes.app ? <>
                            <button className="button secondary" disabled={resourceLoading} onClick={async () => {
                                setResourceLoading(true);
                                setResourceError('');
                                try {
                                    setResource(await api('/api/resources/identity'));
                                } catch (e) {
                                    setResourceError((e as Error).message);
                                } finally {
                                    setResourceLoading(false);
                                }
                            }}>My identity
                            </button>
                            <button className="button secondary" disabled={resourceLoading} onClick={async () => {
                                setResourceLoading(true);
                                setResourceError('');
                                try {
                                    setResource(await api('/api/resources/orders'));
                                } catch (e) {
                                    setResourceError((e as Error).message);
                                } finally {
                                    setResourceLoading(false);
                                }
                            }}>Protected orders API
                            </button>
                        </> : <form action="/api/auth/start?lane=app" method="post">
                            <button className="button primary">Connect my IAM identity <ArrowUpRight size={16}/>
                            </button>
                        </form>}</div>
                        {resourceLoading &&
                            <p className="inline-note" role="status">Loading protected resource…</p>}{resourceError &&
                        <div className="banner error" role="alert">{resourceError}</div>}{resource !== undefined &&
                        <div className="json-result">
                            <pre>{JSON.stringify(resource, null, 2)}</pre>
                        </div>}</section>
                    <section className="card provider-card">
                        <div className="card-heading">
                            <div><h2>Provider connection</h2><p>Runtime discovery from the configured IAM issuer.</p>
                            </div>
                            <span
                                className={'status-badge ' + (discovery ? 'good' : '')}>{discovery ? 'Reachable' : 'Unavailable'}</span>
                        </div>
                        <dl>{['issuer', 'authorizationEndpoint', 'tokenEndpoint', 'jwksUri'].map(key => <div key={key}>
                            <dt>{key.replace(/([A-Z])/g, ' $1')}</dt>
                            <dd>{discovery ? display(discovery[key]) : 'Not available'}</dd>
                        </div>)}</dl>
                    </section>
                    <p className="inline-note"><CircleHelp size={16}/> Federation, SCIM, mTLS and advanced ABAC controls
                        are not implemented by this backend and are not presented as working controls.</p></>}
                <footer className="page-footer">
                    <span>IAM Console <span> / </span> Enterprise identity workspace</span><span><span
                    className="footer-dot"/> Backend-enforced authorization</span></footer>
            </main>
        </div>
        {operation && <OperationDrawer operation={operation} defaults={defaults} onClose={() => setOperation(null)}
                                       onSuccess={() => {
                                           refreshAll();
                                           setToast('Operation completed. The workspace has been refreshed.');
                                       }}/>}
        {connect && <ConnectDrawer onClose={() => setConnect(false)} onSuccess={() => {
            setConnect(false);
            refreshAll();
            setToast('Administrator connected. Access expires with the backend token.');
        }}/>}
        {toast && <div className="toast" role="status"><Check size={18}/><span>{toast}</span>
            <button className="icon-button" aria-label="Dismiss notification" onClick={() => setToast('')}><X
                size={16}/></button>
        </div>}
    </div>;
}

function ConnectionLine({name, value, good}: { name: string; value: string; good: boolean }) {
    return <div className="connection-line"><span>{name}</span><span className={'status-badge ' + (good ? 'good' : '')}><span/>{value}</span>
    </div>;
}

function InfoCard({title, text}: { title: string; text: string }) {
    return <section className="card info-card"><ShieldCheck size={19}/><h3>{title}</h3><p>{text}</p></section>;
}

function ConnectionEmpty({lane, onConnect}: { lane: Lane; onConnect: () => void }) {
    return <section className="card empty-state connection-empty"><span className="empty-icon">{lane === 'admin' ?
        <KeyRound size={27}/> : <Globe2 size={27}/>}</span>
        <h2>{lane === 'admin' ? 'Administrator access required' : 'Your sessions, under your control'}</h2>
        <p>{lane === 'admin' ? 'Sign in with a platform administrator account to manage this directory.' : 'Sign in with your IAM account to view your own login sessions. Administrator credentials cannot access this owner-only view.'}</p>{lane === 'admin' ?
            <button className="button primary" onClick={onConnect}><Link2 size={16}/>Sign in as administrator</button> :
            <form action="/api/auth/start?lane=management" method="post">
                <button className="button primary">Sign in to manage sessions <ArrowUpRight size={16}/></button>
            </form>}</section>;
}

function RecordTable({tab, rows, available, onOpen}: {
    tab: Tab;
    rows: Row[];
    available: Operation[];
    onOpen: (op: Operation, row?: Row) => void
}) {
    const columns = tab === 'users' ? ['username', 'state', 'id', 'version'] : tab === 'organizations' ? ['name', 'id'] : tab === 'applications' ? ['client_id', 'client_name', 'scopes'] : tab === 'sessions' ? ['id', 'status', 'createdAt', 'lastSeenAt', 'idleExpiresAt', 'absoluteExpiresAt', 'current'] : ['name', 'permission', 'id'];
    return <div className="table-scroll">
        <table>
            <thead>
            <tr>{columns.map(key => <th key={key}>{({
                client_id: 'Client ID',
                client_name: 'Name',
                createdAt: 'Created',
                lastSeenAt: 'Last active',
                idleExpiresAt: 'Idle expiry',
                absoluteExpiresAt: 'Absolute expiry',
                current: 'This login'
            } as Record<string, string>)[key] || key.replaceAll('_', ' ')}</th>)}
                <th className="actions-column"><span className="sr-only">Actions</span></th>
            </tr>
            </thead>
            <tbody>{rows.map((row, index) => <tr
                key={String(row.id ?? row.client_id ?? index) + String(row.permission ?? '')}>{columns.map((key, column) =>
                <td key={key}>{key === 'state' || key === 'status' ? <span
                    className={'state-badge state-' + String(row[key]).toLowerCase()}><span/>{display(row[key]).replaceAll('_', ' ')}</span> : key.endsWith('At') ?
                    <time
                        dateTime={String(row[key])}>{new Date(String(row[key])).toLocaleString()}</time> : key === 'current' ? row[key] ?
                        <span className="neutral-badge">Current</span> : '—' : column === 0 ?
                        <span className="table-identity">{tab !== 'sessions' && <span
                            className={'record-avatar ' + (tab === 'applications' ? 'purple' : '')}>{String(row[key] || '?').slice(0, 2).toUpperCase()}</span>}<strong
                            className={key === 'id' ? 'mono' : ''}>{display(row[key])}</strong></span> :
                        <span className={key === 'id' ? 'mono' : ''}>{display(row[key])}</span>}</td>)}
                <td>
                    <details className="row-menu">
                        <summary
                            aria-label={'Actions for ' + display(row.username ?? row.name ?? row.client_id ?? row.id)}>
                            <MoreHorizontal size={19}/></summary>
                        <div className="row-menu-content">{available.map(op => <button key={op.id}
                                                                                       className={op.dangerous ? 'danger-text' : ''}
                                                                                       onClick={e => {
                                                                                           e.currentTarget.closest('details')?.removeAttribute('open');
                                                                                           onOpen(op, row);
                                                                                       }}>{titleFor(op)}</button>)}</div>
                    </details>
                </td>
            </tr>)}</tbody>
        </table>
    </div>;
}

function Drawer({title, subtitle, children, onClose}: {
    title: string;
    subtitle: string;
    children: React.ReactNode;
    onClose: () => void
}) {
    const ref = useRef<HTMLDivElement>(null);
    const closeRef = useRef(onClose);
    closeRef.current = onClose;
    useEffect(() => {
        const old = document.activeElement as HTMLElement;
        const overflow = document.body.style.overflow;
        document.body.style.overflow = 'hidden';
        ref.current?.focus();
        const keydown = (event: KeyboardEvent) => {
            if (event.key === 'Escape') {
                event.preventDefault();
                closeRef.current();
            }
            if (event.key === 'Tab') {
                const items = ref.current?.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), a[href]');
                if (!items?.length) return;
                const first = items[0], last = items[items.length - 1];
                if (event.shiftKey && (document.activeElement === first || document.activeElement === ref.current)) {
                    event.preventDefault();
                    last.focus();
                } else if (!event.shiftKey && (document.activeElement === last || document.activeElement === ref.current)) {
                    event.preventDefault();
                    first.focus();
                }
            }
        };
        document.addEventListener('keydown', keydown);
        return () => {
            document.removeEventListener('keydown', keydown);
            document.body.style.overflow = overflow;
            old?.focus();
        };
    }, []);
    return <div className="drawer-overlay">
        <div className="drawer-scrim" onClick={onClose}/>
        <div className="drawer" role="dialog" aria-modal="true" aria-labelledby="drawer-title"
             aria-describedby="drawer-subtitle" tabIndex={-1} ref={ref}>
            <div className="drawer-heading">
                <div><span className="eyebrow">WORKSPACE ACTION</span><h2 id="drawer-title">{title}</h2><p
                    id="drawer-subtitle">{subtitle}</p></div>
                <button className="icon-button" aria-label="Close dialog" onClick={onClose}><X size={21}/></button>
            </div>
            {children}</div>
    </div>;
}

function OperationDrawer({operation: op, defaults, onClose, onSuccess}: {
    operation: Operation;
    defaults: Record<string, string>;
    onClose: () => void;
    onSuccess: () => void
}) {
    const [values, setValues] = useState<Record<string, string>>({...(op.path === '/api/v1/admin/clients' ? {clientAuthenticationMethod: 'client_secret_basic'} : {}), ...defaults});
    const [pending, setPending] = useState(false);
    const [error, setError] = useState('');
    const [response, setResponse] = useState<unknown>(undefined);
    const [confirm, setConfirm] = useState(false);
    const [copied, setCopied] = useState(false);
    const complete = response !== undefined;
    const secret = response && typeof response === 'object' && 'clientSecret' in response ? (response as {
        clientSecret: string
    }).clientSecret : null;
    const setValue = (field: string, value: string) => setValues(v => {
        const next = {...v, [field]: value};
        if (field === 'clientAuthenticationMethod' && value !== 'private_key_jwt') delete next.jwks;
        return next;
    });
    const submit = async (event: React.FormEvent) => {
        event.preventDefault();
        setError('');
        setPending(true);
        try {
            const request = buildRequest(op, values);
            const value = await api('/api/backend' + request.path, {
                method: op.method, ...(request.body ? {
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(request.body)
                } : {})
            });
            setResponse(value ?? {completed: true});
            setValues(v => ({...v, password: ''}));
            if (op.method !== 'GET') onSuccess();
        } catch (e) {
            setError((e as Error).message);
        } finally {
            setPending(false);
        }
    };
    return <Drawer title={titleFor(op)}
                   subtitle={op.group === 'sessions' ? 'Owner-only session access' : op.group === 'decisions' ? 'Evaluates the signed-in identity' : 'Requires administrator authorization'}
                   onClose={pending ? () => {
                   } : onClose}>
        <div className="endpoint-label"><span
            className={'method method-' + op.method.toLowerCase()}>{op.method}</span><code>{op.path}</code></div>
        {complete ? <div className="drawer-result">
            <div className="success-heading"><Check size={22}/>
                <h3>{op.method === 'GET' || op.group === 'decisions' ? 'Response received' : 'Operation completed'}</h3>
            </div>
            {secret ?
                <div className="secret-panel"><h3>Save this credential now</h3><p>This secret is shown only for this
                    response. Closing this panel removes it from the console. Store it in your approved secret
                    manager.</p><code>{secret}</code>
                    <button className="button secondary" onClick={async () => {
                        try {
                            await navigator.clipboard.writeText(secret);
                            setCopied(true);
                        } catch {
                            setError('Clipboard unavailable. Select and copy the credential manually.');
                        }
                    }}><Copy size={15}/>{copied ? 'Copied' : 'Copy secret'}</button>
                </div> : <div className="json-result">
                    <pre>{JSON.stringify(response, null, 2)}</pre>
                </div>}{op.method !== 'GET' &&
            <p className="inline-note"><Clock3 size={16}/>Review the refreshed records before making another change.
            </p>}
            <button className="button primary" onClick={onClose}>Done</button>
        </div> : <form className="drawer-form" onSubmit={submit}>
            {op.dangerous && <div className="warning-box"><Shield size={20}/>
                <div><strong>Review this sensitive change</strong>
                    <p>{op.path.includes('/members/') ? 'Removes membership and all role assignments in this organization. Rejoining will not restore them.' : op.method === 'DELETE' && op.group === 'users' ? 'Logical deletion is permanent in this lifecycle. Sessions and grants are revoked; security evidence is retained.' : 'This can change access or invalidate active credentials and sessions. Confirm the target before continuing.'}</p>
                </div>
            </div>}
            {op.fields.filter(field => !(field.name === 'jwks' && op.path === '/api/v1/admin/clients' && values.clientAuthenticationMethod !== 'private_key_jwt')).map(originalField => {
                const field = originalField.name === 'jwks' && values.clientAuthenticationMethod === 'private_key_jwt' ? {
                    ...originalField,
                    required: true
                } : originalField;
                return <FieldInput key={field.location + field.name} field={field} context={op.path}
                                   value={values[field.name] || ''} onChange={value => setValue(field.name, value)}/>;
            })}
            {!op.fields.length &&
                <p className="form-intro">This operation has no additional fields. Continue to submit it to IAM.</p>}
            {op.dangerous && <label className="confirm-check"><input type="checkbox" required checked={confirm}
                                                                     onChange={e => setConfirm(e.target.checked)}/><span>I reviewed the target and understand this change.</span></label>}
            {error && <div className="banner error" role="alert">{error}</div>}
            <div className="drawer-footer">
                <button type="button" className="button secondary" disabled={pending} onClick={onClose}>Cancel</button>
                <button className={'button ' + (op.dangerous ? 'danger' : 'primary')}
                        disabled={pending || (op.dangerous && !confirm)}>{pending ? <><LoaderCircle size={16}
                                                                                                    className="spin"/>Submitting…</> : <>{titleFor(op)}<ArrowRight
                    size={16}/></>}</button>
            </div>
        </form>}
        {complete && error && <div className="banner error" role="alert">{error}</div>}
    </Drawer>;
}

function FieldInput({field, value, onChange, context}: {
    field: Field;
    value: string;
    onChange: (v: string) => void;
    context: string
}) {
    const id = 'field-' + field.name;
    return <div className="form-field"><label
        htmlFor={id}>{field.name === 'id' ? context.includes('/role-assignments/') ? 'Assignment ID' : context.includes('/organizations/') ? 'Organization ID' : 'User ID' : labels[field.name] || field.name} {field.required ?
        <span aria-label="required">*</span> : <small>Optional</small>}</label>{field.enum ?
        <select id={id} value={value} required={field.required} onChange={e => onChange(e.target.value)}>
            <option value="">Select an option</option>
            {field.enum.map(item => <option key={item} value={item}>{item}</option>)}
        </select> : field.type === 'object' ?
            <textarea id={id} required={field.required} value={value} onChange={e => onChange(e.target.value)} rows={7}
                      spellCheck={false} placeholder={'{ "keys": [ … ] }'} aria-describedby={id + '-help'}/> :
            <input id={id}
                   type={field.name === 'password' ? 'password' : field.type === 'integer' ? 'number' : field.format === 'email' ? 'email' : field.format === 'uri' ? 'url' : 'text'}
                   required={field.required} value={value} onChange={e => onChange(e.target.value)}
                   minLength={field.minLength} maxLength={field.maxLength}
                   min={field.minimum ?? (field.type === 'integer' ? 0 : undefined)} max={field.maximum}
                   step={field.type === 'integer' ? 1 : undefined}
                   autoComplete={field.name === 'password' ? 'new-password' : 'off'} spellCheck={false}
                   aria-describedby={id + '-help'}/>}{(helpers[field.name] || field.location === 'path') &&
        <p id={id + '-help'}>{helpers[field.name] || 'Use the immutable identifier from the directory record.'}</p>}
    </div>;
}

function ConnectDrawer({onClose}: { onClose: () => void; onSuccess: () => void }) {
    return <Drawer title="Sign in to your workspace" subtitle="Use your personal IAM username and password."
                   onClose={onClose}>
        <div className="drawer-form">
            <div className="connect-explainer"><span className="large-icon"><ShieldCheck size={25}/></span><h3>One
                identity. The right access.</h3><p>Continue to the secure IAM username/password login. Your assigned
                role determines access.</p></div>
            <a className="button primary" href="/login">Continue to sign in <ArrowRight size={16}/></a></div>
    </Drawer>;
}
