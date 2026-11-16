import ContinueLogin from '@/components/continue-login';

export default async function Continue({searchParams}: { searchParams: Promise<{ lane?: string }> }) {
    const {lane} = await searchParams;
    return <ContinueLogin lane={lane === 'admin' ? 'admin' : lane === 'management' ? 'management' : 'app'}/>;
}
