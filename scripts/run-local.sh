#!/usr/bin/env bash
# Local-only launcher. Load credentials explicitly; Spring does not read root .env automatically.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ ! -f .env ]]; then
  printf 'Missing .env. Build the project and run ./scripts/init-local.sh first.\n' >&2
  exit 1
fi
set -a
. ./.env
set +a
: "${DB_PASSWORD:?DB_PASSWORD must be set in .env}"
# Explicitly align Spring's higher-priority environment properties with the local configuration.
export SPRING_DATASOURCE_PASSWORD="$DB_PASSWORD"
export SPRING_DATASOURCE_USERNAME="${DB_USER:-iam}"
export SPRING_DATASOURCE_URL="${DB_URL:-jdbc:postgresql://localhost:5432/iam}"
export SPRING_PROFILES_ACTIVE=local
if [[ -n "${JAVA_HOME:-}" ]]; then
  local_java="$JAVA_HOME/bin/java"
else
  local_java=java
fi
local_jar=iam-server/target/iam-server-0.1.0-SNAPSHOT.jar
if [[ ! -f "$local_jar" ]]; then
  printf 'Missing IAM JAR. Run mvn -B verify with Java 21 first.\n' >&2
  exit 1
fi
exec "$local_java" -jar "$local_jar"
