#!/usr/bin/env bash
# Runtime smoke for dar-q95.29.1: single-entry getattrlist/fgetattrlist/
# getattrlistat share the packer for name+objtype, and getattrlistbulk can
# report ATTR_CMN_ERROR records through the same packer.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAUNCH="${DARLING:-darling}"
: "${DPREFIX:?set DPREFIX to a bootable Darling prefix}"

src="$here/getattrlist_shared_packer_test.c"
verdict="/tmp/getattrlist_shared_packer.verdict"
rm -f "$DPREFIX/tmp/getattrlist_shared_packer.verdict" 2>/dev/null || true
cp "$src" "$DPREFIX/tmp/getattrlist_shared_packer_test.c"
env DPREFIX="$DPREFIX" "$LAUNCH" shell /bin/bash --login -c "rm -f '$verdict'" >/dev/null 2>&1 || true

guest_timeout="${GETATTRLIST_PACKER_TIMEOUT:-60}"
env DPREFIX="$DPREFIX" "$LAUNCH" shell /bin/bash --login -c '
  clang -O2 -Wall -Wextra -o /tmp/getattrlist_shared_packer_test /tmp/getattrlist_shared_packer_test.c 2>&1
  /tmp/getattrlist_shared_packer_test > /tmp/getattrlist_shared_packer.verdict 2>&1
  echo "ORACLE_RC=$?" >> /tmp/getattrlist_shared_packer.verdict
' </dev/null > /tmp/getattrlist_shared_packer.runner.log 2>&1 &
shell_pid=$!

deadline=$((SECONDS + guest_timeout))
while [ "$SECONDS" -lt "$deadline" ]; do
  if env DPREFIX="$DPREFIX" "$LAUNCH" shell /bin/bash --login -c \
      "test -f '$verdict' && grep -q '^ORACLE_RC=' '$verdict'" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! env DPREFIX="$DPREFIX" "$LAUNCH" shell /bin/bash --login -c \
    "test -f '$verdict' && grep -q '^ORACLE_RC=' '$verdict'" >/dev/null 2>&1; then
  kill "$shell_pid" 2>/dev/null || true
  wait "$shell_pid" 2>/dev/null || true
  echo "=== runner log ==="
  grep -vE "Xlib|libGL|MESA|X11" /tmp/getattrlist_shared_packer.runner.log 2>/dev/null || true
  echo "no verdict produced before timeout"
  exit 2
fi

kill "$shell_pid" 2>/dev/null || true
wait "$shell_pid" 2>/dev/null || true

echo "=== verdict ==="
guest_verdict="$(env DPREFIX="$DPREFIX" "$LAUNCH" shell /bin/bash --login -c "cat '$verdict'" 2>/dev/null || true)"
printf '%s\n' "$guest_verdict"
grep -q "^GETATTRLIST_SHARED_PACKER_OK" <<<"$guest_verdict" &&
  grep -q "ORACLE_RC=0" <<<"$guest_verdict"
