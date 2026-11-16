#!/usr/bin/env python3
"""Verify local launcher environment precedence without a database or real credentials."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class LauncherTest(unittest.TestCase):
    def test_local_env_replaces_stale_shell_and_spring_settings(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'scripts').mkdir()
            shutil.copyfile(ROOT / 'scripts/run-local.sh', root / 'scripts/run-local.sh')
            (root / '.env').write_text(
                'DB_PASSWORD=test-only-password\nDB_USER=iam\nDB_URL=jdbc:postgresql://localhost:5432/iam\n')
            jar = root / 'iam-server/target/iam-server-0.1.0-SNAPSHOT.jar'
            jar.parent.mkdir(parents=True)
            jar.touch()
            java = root / 'jdk/bin/java'
            java.parent.mkdir(parents=True)
            java.write_text(
                '#!/usr/bin/env python3\nimport os,sys\nassert os.environ["SPRING_DATASOURCE_PASSWORD"] == "test-only-password"\nassert os.environ["DB_PASSWORD"] == "test-only-password"\nassert os.environ["SPRING_DATASOURCE_USERNAME"] == "iam"\nassert os.environ["SPRING_DATASOURCE_URL"] == "jdbc:postgresql://localhost:5432/iam"\nassert os.environ["SPRING_PROFILES_ACTIVE"] == "local"\nassert sys.argv[1:] == ["-jar", "iam-server/target/iam-server-0.1.0-SNAPSHOT.jar"]\nprint("Launcher configuration verified")\n')
            java.chmod(0o700)
            env = {**os.environ, 'JAVA_HOME': str(root / 'jdk'), 'DB_PASSWORD': 'stale',
                   'SPRING_DATASOURCE_PASSWORD': 'stale', 'SPRING_DATASOURCE_URL': 'wrong',
                   'SPRING_DATASOURCE_USERNAME': 'wrong', 'SPRING_PROFILES_ACTIVE': 'wrong'}
            result = subprocess.run(['bash', str(root / 'scripts/run-local.sh')], env=env, capture_output=True,
                                    text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('verified', result.stdout)
            (root / '.env').unlink()
            result = subprocess.run(['bash', str(root / 'scripts/run-local.sh')], env=env, capture_output=True,
                                    text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Missing .env', result.stderr)


if __name__ == '__main__': unittest.main()
