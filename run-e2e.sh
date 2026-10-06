#!/bin/sh
# Explicit, non-writing smoke checks for a dedicated QA TestRail sandbox.
set -eu

if [ "${QA_SYNC_E2E_CONFIRM_SANDBOX:-}" != "yes" ]; then
  echo "Refusing to run. Set QA_SYNC_E2E_CONFIRM_SANDBOX=yes after confirming the configured TestRail account is a sandbox." >&2
  exit 2
fi
if [ -z "${QA_SYNC_E2E_CASE_ID:-}" ]; then
  echo "Set QA_SYNC_E2E_CASE_ID to the dedicated sandbox case." >&2
  exit 2
fi

export QA_SYNC_E2E=1
export QA_SYNC_WRITE_MODE=review_only
exec python3 -m unittest tests.test_e2e_live -v
