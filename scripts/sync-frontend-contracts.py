#!/usr/bin/env python3
"""Synchronize the console's bounded bearer API catalog with the implemented OpenAPI contract."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'frontend/src/lib/operations.json'
KEYS = ('enum', 'minimum', 'maximum', 'minLength', 'maxLength', 'pattern', 'format')


def fields(schema, name, location, required):
    kind = schema.get('type', 'string')
    if isinstance(kind, list): kind = next(value for value in kind if value != 'null')
    return {'name': name, 'type': kind, 'required': required, 'location': location,
            **{key: schema[key] for key in KEYS if key in schema}}


def generate():
    spec = json.loads((ROOT / 'docs/openapi.json').read_text())
    catalog = []
    for path, methods in spec['paths'].items():
        if not path.startswith('/api/'): continue
        for method, operation in methods.items():
            if method not in ('get', 'post', 'patch', 'put', 'delete'): continue
            schema = operation.get('requestBody', {}).get('content', {}).get('application/json', {}).get('schema', {})
            group = ('users' if '/admin/users' in path else 'organizations' if '/organizations' in path
            else 'applications' if '/clients' in path else 'sessions' if '/users/me/' in path
            else 'decisions' if '/authorization/' in path else 'policies')
            parameters = [fields({}, part[1:-1], 'path', True) for part in path.split('/') if part.startswith('{')]
            seen = set()
            for parameter in operation.get('parameters', []) + methods.get('parameters', []):
                if parameter.get('in') == 'query' and parameter['name'] not in seen:
                    parameters.append(fields(parameter.get('schema', {}), parameter['name'], 'query',
                                             parameter.get('required', False)))
                    seen.add(parameter['name'])
            parameters.extend(fields(value, name, 'body', name in schema.get('required', [])) for name, value in
                              schema.get('properties', {}).items())
            catalog.append({'id': method + ':' + path, 'method': method.upper(), 'path': path, 'group': group,
                            'summary': operation.get('summary', path), 'description': operation.get('description', ''),
                            'lane': 'management' if group == 'sessions' else 'app' if group == 'decisions' else 'admin',
                            'fields': parameters,
                            'dangerous': method == 'delete' or method != 'get' and any(value in path for value in (
                                '/suspend', '/deactivate', '/revoke-sessions', '/rotate-credentials', '/email',
                                '/authentication-keys'))})
    return json.dumps(catalog, indent=2) + '\n'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    generated = generate()
    if args.check:
        if TARGET.read_text() != generated: raise SystemExit(
            'Frontend contracts are stale: run python3 scripts/sync-frontend-contracts.py')
        print('Frontend API catalog matches OpenAPI')
    else:
        TARGET.write_text(generated)
        print('Updated frontend API catalog')
