#!/usr/bin/env bash
# Runtime smoke for dar-q95.29.1: single-entry getattrlist/fgetattrlist/
# getattrlistat share the packer for name+objtype, and getattrlistbulk can
# report ATTR_CMN_ERROR records through the same packer.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAUNCH="${DARLING:-darling}"
: "${DPREFIX:?set DPREFIX to a bootable Darling prefix}"

src="$here/getattrlist_shared_packer_test.c"
verdict="$DPREFIX/tmp/getattrlist_shared_packer.verdict"
rm -f "$verdict" 2>/dev/null || true

timeout "${GETATTRLIST_PACKER_TIMEOUT:-60}" env DPREFIX="$DPREFIX" "$LAUNCH" shell /bin/bash --login -c '
  cat > /tmp/getattrlist_shared_packer_test.c <<"SRCEOF"
'"$(cat "$src")"'
SRCEOF
  clang -O2 -Wall -Wextra -o /tmp/getattrlist_shared_packer_test /tmp/getattrlist_shared_packer_test.c 2>&1
  /tmp/getattrlist_shared_packer_test > /tmp/getattrlist_shared_packer.verdict 2>&1
  echo "ORACLE_RC=$?" >> /tmp/getattrlist_shared_packer.verdict
' 2>&1 | grep -vE "Xlib|libGL|MESA|X11" || true

echo "=== verdict ==="
cat "$verdict" 2>/dev/null || { echo "no verdict produced"; exit 2; }
grep -q "^GETATTRLIST_SHARED_PACKER_OK" "$verdict" && grep -q "ORACLE_RC=0" "$verdict"
