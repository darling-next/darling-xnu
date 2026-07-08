#!/usr/bin/env bash
set -euo pipefail

cd "${XNU_SRC_ROOT:-$(dirname "$0")/../../../..}"

defs=darling/src/libsystem_kernel/emulation/include/linux_premigration/resources/dserver-rpc-defs.h
sigexc=darling/src/libsystem_kernel/emulation/src/linux_premigration/signal/sigexc.c

fail() {
	echo "rpc_disconnect_status_contract_test: $*" >&2
	exit 1
}

grep -q "dserver_rpc_hooks_is_disconnect_status" "$defs" \
	|| fail "libsystem_kernel RPC hooks do not expose disconnect classification"
for status in LINUX_EBADF LINUX_EPIPE LINUX_ECONNRESET LINUX_ENOTCONN LINUX_ECONNREFUSED; do
	grep -q "status == -$status" "$defs" \
		|| fail "RPC hook does not classify -$status as disconnect"
	grep -q "status == -$status" "$sigexc" \
		|| fail "sigexc does not classify -$status as endpoint unavailable"
done

grep -q "static bool sigexc_rpc_endpoint_unavailable" "$sigexc" \
	|| fail "sigexc has no endpoint-unavailable helper"
grep -q "if (sigexc_rpc_endpoint_unavailable(status))" "$sigexc" \
	|| fail "sigexc does not branch on endpoint-unavailable interrupt_enter failures"

endpoint_line="$(grep -n "if (sigexc_rpc_endpoint_unavailable(status))" "$sigexc" | head -1 | cut -d: -f1)"
abort_line="$(grep -n "dserver_rpc_interrupt_enter failed" "$sigexc" | head -1 | cut -d: -f1)"
if [ -z "$endpoint_line" ] || [ -z "$abort_line" ] || [ "$endpoint_line" -ge "$abort_line" ]; then
	fail "endpoint-unavailable branch must run before abort logging"
fi

echo "RPC_DISCONNECT_STATUS_CONTRACT_OK"
