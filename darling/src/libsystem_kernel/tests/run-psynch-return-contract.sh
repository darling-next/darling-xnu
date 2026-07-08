#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="${XNU_SRC_ROOT:-$(git -C "$here" rev-parse --show-toplevel)}"
src="$here/psynch_return_contract_test.c"
include="$root/darling/src/libsystem_kernel/emulation/include"
out="$(mktemp /tmp/psynch-return-contract.XXXXXX)"
trap 'rm -f "$out"' EXIT

cc -std=c11 -Wall -Wextra -I "$include" "$src" -o "$out"
"$out" | grep -q '^PSYNCH_RETURN_CONTRACT_OK$'
