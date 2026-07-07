#!/usr/bin/env bash
# Runtime smoke for dar-q95.29.1: single-entry getattrlist/fgetattrlist/
# getattrlistat share the packer for name+objtype, and getattrlistbulk can
# report ATTR_CMN_ERROR records through the same packer.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$here/guest-verdict-test-lib.sh"

guest_verdict_run_c \
	getattrlist_shared_packer \
	"$here/getattrlist_shared_packer_test.c" \
	GETATTRLIST_SHARED_PACKER_OK \
	"${GETATTRLIST_PACKER_TIMEOUT:-60}"
