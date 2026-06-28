#!/usr/bin/env bash
# perf #9-decompose follow-on (dar-dar6x4-perf-5dq): the guest per-callnum reply-wait
# breakdown showed kprintf is 14.5% of a clean build's recvmsg-sleep. Capturing the
# server-side kprintf log during a real build revealed it is almost entirely UNCONDITIONAL
# DEBUG TRACES on the hot path -- each a full synchronous RPC round-trip (~100us sleep)
# with zero value in a normal build:
#   - execve.c:    "execve expand %s -> %s, ret %d"   (fires on EVERY exec; a build is execs)
#   - filio.c:     "dtype for fd %d -> %s"            (fires on a hot ioctl path)
#   - sigexc.c:    "darling_sigexc_self()"            (fires on sigexc init; 43% of the spam)
#
# These should NOT cost an RPC by default. The fix gates them behind a debug macro
# (DARLING_HOTPATH_KPRINTF_DEBUG, default off) so the default build is silent on the hot
# path and the traces are restorable for debugging.
#
# RED->GREEN (source-level, hermetic -- no build, no server): before the fix these are
# bare __simple_kprintf(...) statements (RED); after, each is wrapped so it is compiled
# out unless DARLING_HOTPATH_KPRINTF_DEBUG is defined. We assert (a) the debug macro name
# appears guarding each site, and (b) none of the three trace strings is reachable from a
# bare/unconditional __simple_kprintf line. Exit 0 = GREEN.
set -u

ROOT="$(cd "$(dirname "$0")/../emulation/src" && pwd)"
EXECVE="$ROOT/xnu_syscall/bsd/impl/process/execve.c"
FILIO="$ROOT/xnu_syscall/bsd/helper/ioctl/filio.c"
SIGEXC="$ROOT/linux_premigration/signal/sigexc.c"
fails=0

# A trace is "gated" if its __simple_kprintf is replaced by the debug-only macro
# hotpath_kdebug(...) (which expands to nothing unless DARLING_HOTPATH_KPRINTF_DEBUG).
# RED gate: the original bare __simple_kprintf("execve expand"...) must be GONE.
check_gated() { # $1=file  $2=needle (unique substring of the trace string)
	local f="$1" needle="$2"
	if grep -F "$needle" "$f" | grep -q "__simple_kprintf"; then
		echo "FAIL: $(basename "$f"): trace '$needle' still uses an unconditional __simple_kprintf (hot-path RPC not removed)"
		fails=$((fails+1))
	fi
	if ! grep -F "$needle" "$f" | grep -q "hotpath_kdebug"; then
		echo "FAIL: $(basename "$f"): trace '$needle' is not routed through the gated hotpath_kdebug macro"
		fails=$((fails+1))
	fi
}

check_gated "$EXECVE" "execve expand"
check_gated "$FILIO"  "dtype for fd"

# sigexc.c already has its own gate macro kern_printf (no-op unless DEBUG_SIGEXC). The
# darling_sigexc_self() marker fires on EVERY process startup, so it must route through
# that existing gate rather than a bare __simple_kprintf.
if grep -F "darling_sigexc_self()" "$SIGEXC" | grep -q "__simple_kprintf"; then
	echo "FAIL: sigexc.c: darling_sigexc_self() marker still uses an unconditional __simple_kprintf (hot-path RPC per process)"
	fails=$((fails+1))
fi
if ! grep -F 'kern_printf("darling_sigexc_self()' "$SIGEXC" >/dev/null; then
	echo "FAIL: sigexc.c: darling_sigexc_self() marker is not routed through the gated kern_printf"
	fails=$((fails+1))
fi

# The macro itself must be defined as a no-op by default and only active under the flag.
HDR="$(cd "$(dirname "$0")/../emulation/include/common" && pwd)/simple.h"
if ! grep -q "hotpath_kdebug" "$HDR"; then
	echo "FAIL: hotpath_kdebug macro is not defined in common/simple.h"
	fails=$((fails+1))
fi
if ! grep -q "DARLING_HOTPATH_KPRINTF_DEBUG" "$HDR"; then
	echo "FAIL: simple.h does not key the gate on DARLING_HOTPATH_KPRINTF_DEBUG"
	fails=$((fails+1))
fi

if [ "$fails" -eq 0 ]; then
	echo "GREEN: hot-path kprintf debug traces are gated behind DARLING_HOTPATH_KPRINTF_DEBUG (no RPC by default)"
	exit 0
fi
echo "RED: $fails hot-path kprintf check(s) failed"
exit 1
