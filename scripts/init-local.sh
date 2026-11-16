#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
mkdir -p secrets
if [[ ! -f secrets/signing.jwks ]]; then
 java -Dloader.main=com.example.iam.server.security.GenerateDevelopmentKey -cp iam-server/target/iam-server-0.1.0-SNAPSHOT.jar org.springframework.boot.loader.launch.PropertiesLauncher secrets/signing.jwks
fi
if [[ ! -f .env ]]; then
 python3 - <<'PYENV'
import secrets, os
from pathlib import Path
values={k:secrets.token_hex(24) for k in ['DB_PASSWORD','DEMO_PASSWORD','PORTAL_SECRET','MACHINE_SECRET','ADMIN_SECRET','MFA_ENCRYPTION_PASSWORD']}
values['MFA_ENCRYPTION_SALT']=secrets.token_hex(16)
values['LOCAL_UID']=str(os.getuid())
values['LOCAL_GID']=str(os.getgid())
values['SIGNING_KEY_FILE']=str(Path('secrets/signing.jwks').resolve())
Path('.env').write_text(''.join(f'{k}={v}\n' for k,v in values.items()))
PYENV
fi
printf 'Local secrets initialized. Load .env in your shell. Demo username: employee.\n'
# Add account-delivery custody inputs without rotating existing development keys.
python3 - <<'PYACCOUNT'
import secrets
from pathlib import Path
path=Path('.env')
existing={line.partition('=')[0] for line in path.read_text().splitlines()}
extra={k:secrets.token_hex(n) for k,n in [('ACCOUNT_ENCRYPTION_PASSWORD',24),('ACCOUNT_ENCRYPTION_SALT',16)] if k not in existing}
with path.open('a') as stream:
 for key,value in extra.items():stream.write(key+'='+value+'\n')
PYACCOUNT

# Separate human administrator password; does not alter existing users.
python3 - <<'PYADMIN'
import secrets
from pathlib import Path
p=Path('.env')
if not any(line.startswith('ADMIN_PASSWORD=') for line in p.read_text().splitlines()):
 with p.open('a') as stream: stream.write('ADMIN_PASSWORD='+secrets.token_hex(24)+'\n')
PYADMIN
