#!/usr/bin/env bash
# Regression test for dar-cps: abort_with_payload() must NOT broadcast SIGABRT to the
# process group (it must terminate only the calling process, like macOS).
#
# This is a GUEST test: abort_with_payload() must resolve to Darling's libsystem
# sys_abort_with_payload, so it runs inside Darling. It boots a prefix, has the guest
# compile abort_with_payload_no_group_broadcast.c and run it, and asserts GREEN.
#
# Requires a Darling install + a writable prefix. Configure via env:
#   DARLING   = path to the `darling` launcher (default: darling on PATH)
#   DPREFIX   = the prefix to boot (must exist)
# Exit 0 on PASS (GREEN: parent survived). Exit 1 on FAIL (RED: parent got SIGABRT).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAUNCH="${DARLING:-darling}"
: "${DPREFIX:?set DPREFIX to a bootable Darling prefix}"

src="$here/abort_with_payload_no_group_broadcast.c"
verdict="$DPREFIX/tmp/awp_nogroup.verdict"
rm -f "$verdict" 2>/dev/null || true

# Host writes to DPREFIX/tmp are NOT visible to the guest /tmp overlay; only guest
# writes round-trip. So the guest writes its own copy of the source via heredoc.
DPREFIX="$DPREFIX" "$LAUNCH" shell /bin/bash --login -c '
  cat > /tmp/awp_nogroup.c <<"SRCEOF"
'"$(cat "$src")"'
SRCEOF
  clang -O0 -o /tmp/awp_nogroup /tmp/awp_nogroup.c 2>&1
  /tmp/awp_nogroup > /tmp/awp_nogroup.verdict 2>&1
  echo "ORACLE_RC=$?" >> /tmp/awp_nogroup.verdict
' 2>&1 | grep -vE "Xlib|libGL|MESA|X11" || true

echo "=== verdict ==="
cat "$verdict" 2>/dev/null || { echo "no verdict produced"; exit 2; }
grep -q "^GREEN:" "$verdict" && grep -q "ORACLE_RC=0" "$verdict"
