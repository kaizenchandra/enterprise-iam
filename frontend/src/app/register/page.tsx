import {redirect} from 'next/navigation';
import {config} from '@/lib/server';

export default function Register() {
    redirect(config().authUi + '/account/register');
}
