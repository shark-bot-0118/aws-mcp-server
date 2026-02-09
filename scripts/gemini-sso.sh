#!/usr/bin/env bash
set -euo pipefail

PROFILE="${AWS_SSO_PROFILE:-default}"
START_URL="${AWS_SSO_START_URL:-}"

if [ -z "$START_URL" ]; then
  START_URL="$(PROFILE="$PROFILE" python - <<'PY'
import configparser
import os

profile = os.environ["PROFILE"]
config_path = os.environ.get("AWS_CONFIG_FILE", os.path.expanduser("~/.aws/config"))
config = configparser.ConfigParser()
config.read(config_path)

section = "default" if profile == "default" else f"profile {profile}"
start_url = ""
if config.has_option(section, "sso_start_url"):
    start_url = config.get(section, "sso_start_url").strip()
elif config.has_option(section, "sso_session"):
    session_name = config.get(section, "sso_session").strip()
    session_section = f"sso-session {session_name}"
    if config.has_option(session_section, "sso_start_url"):
        start_url = config.get(session_section, "sso_start_url").strip()

print(start_url)
PY
)"
fi

if [ -z "$START_URL" ]; then
  echo "SSO start URL not found. Set AWS_SSO_START_URL or check profile: $PROFILE"
  exit 1
fi

TOKEN="$(START_URL="$START_URL" python - <<'PY'
import json
import os
import glob
import datetime

start_url = os.environ["START_URL"]
cache_dir = os.path.expanduser("~/.aws/sso/cache")
tokens = []

for path in glob.glob(os.path.join(cache_dir, "*.json")):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if data.get("startUrl") != start_url:
            continue
        token = data.get("accessToken")
        exp = data.get("expiresAt")
        if not token or not exp:
            continue
        exp_dt = datetime.datetime.fromisoformat(exp.replace("Z", "+00:00"))
        if exp_dt > datetime.datetime.now(datetime.timezone.utc):
            tokens.append((exp_dt, token))
    except Exception:
        continue

tokens.sort(reverse=True)
print(tokens[0][1] if tokens else "")
PY
)"

if [ -z "$TOKEN" ]; then
  aws sso login --profile "$PROFILE"
  TOKEN="$(START_URL="$START_URL" python - <<'PY'
import json
import os
import glob
import datetime

start_url = os.environ["START_URL"]
cache_dir = os.path.expanduser("~/.aws/sso/cache")
tokens = []

for path in glob.glob(os.path.join(cache_dir, "*.json")):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if data.get("startUrl") != start_url:
            continue
        token = data.get("accessToken")
        exp = data.get("expiresAt")
        if not token or not exp:
            continue
        exp_dt = datetime.datetime.fromisoformat(exp.replace("Z", "+00:00"))
        if exp_dt > datetime.datetime.now(datetime.timezone.utc):
            tokens.append((exp_dt, token))
    except Exception:
        continue

tokens.sort(reverse=True)
print(tokens[0][1] if tokens else "")
PY
)"
fi

if [ -z "$TOKEN" ]; then
  echo "No valid SSO access token found. Try: aws sso login --profile $PROFILE"
  exit 1
fi

export MCP_SSO_TOKEN="$TOKEN"
exec gemini "$@"
