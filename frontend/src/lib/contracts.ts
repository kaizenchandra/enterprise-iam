import catalog from './operations.json';

export type Lane = 'admin' | 'app' | 'management';
export type Field = {
    name: string;
    type: string;
    required: boolean;
    location: string;
    enum?: string[];
    minimum?: number;
    maximum?: number;
    minLength?: number;
    maxLength?: number;
    pattern?: string;
    format?: string
};
export type Operation = {
    id: string;
    method: string;
    path: string;
    group: string;
    summary: string;
    description: string;
    lane: Lane;
    fields: Field[];
    dangerous: boolean
};
export const operations = catalog as Operation[];

export function resolveOperation(method: string, pathname: string): Operation | undefined {
    if (!pathname.startsWith('/api/v1/') || /[\\%?#]/.test(pathname) || pathname.split('/').some(part => part === '.' || part === '..')) return;
    return operations.find(op => op.method === method && new RegExp('^' + op.path.replace(/\{\w+\}/g, '[a-zA-Z0-9._~-]+') + '$').test(pathname));
}

export function buildRequest(op: Operation, values: Record<string, string>) {
    let path = op.path;
    const query = new URLSearchParams();
    const body: Record<string, unknown> = {};
    for (const field of op.fields) {
        const value = values[field.name]?.trim();
        if (!value) {
            if (field.required) throw new Error(`${field.name} is required`);
            continue;
        }
        if (field.location === 'path') path = path.replace(`{${field.name}}`, encodeURIComponent(value));
        else if (field.location === 'query') query.set(field.name, value);
        else if (field.type === 'object') body[field.name] = JSON.parse(value);
        else if (field.type === 'array') body[field.name] = value.split(',').map(v => v.trim()).filter(Boolean);
        else if (field.type === 'integer') {
            const n = Number(value);
            if (!Number.isSafeInteger(n) || n < 0) throw new Error(`${field.name} must be a nonnegative integer`);
            body[field.name] = n;
        } else body[field.name] = field.name === 'password' ? values[field.name] : value;
    }
    return {path: path + (query.size ? '?' + query.toString() : ''), body: Object.keys(body).length ? body : undefined};
}
