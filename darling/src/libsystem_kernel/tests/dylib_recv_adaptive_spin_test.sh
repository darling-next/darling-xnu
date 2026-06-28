#!/usr/bin/env bash
# perf #7-generalize (dar-dar6x4-perf-5dq.14): the perf#6 profile found 57% of a real
# build's guest wall-clock is spent in __skb_wait_for_more_packets -- guest threads
# SLEEPING in recvmsg waiting for an RPC reply. perf#9-decompose attributed that wait
# per call: mach_msg_overwrite 19% + mach_reply_port 8.7% + mach_port_deallocate 8.4%
# + host/thread_self_trap + ... -- the GUEST process's own RPCs, all reply-bearing.
#
# perf#3 (mldr-recv-adaptive-spin) added a bounded non-blocking recvmsg spin before
# blocking, but ONLY to mldr's copy of dserver-rpc-defs.h. The GUEST processes (clang,
# make, sh, ...) issue their RPCs through libsystem_kernel.dylib's SEPARATE copy of
# dserver_rpc_hooks_receive_message, which still does a plain BLOCKING recvmsg with NO
# spin -- so none of the 28%+ above ever gets the spin. This task ports the spin to the
# dylib hook so every synchronous guest RPC reply can be grabbed before sleeping.
#
# The dylib path is libc-free: no glibc recvmsg/getenv -- it uses raw LINUX_SYSCALL with
# LINUX_MSG_DONTWAIT and a CPU pause, with a compile-time budget gate.
#
# RED->GREEN (source-level, hermetic -- no build, no server): before the fix the dylib's
# dserver_rpc_hooks_receive_message has only the unconditional blocking recvmsg (RED);
# after, it spins LINUX_MSG_DONTWAIT polls (capped) before falling through to the blocking
# recvmsg. We assert the spin exists, is non-blocking, is bounded, sits BEFORE the blocking
# recv, and that the spin is absent from mldr-specific reasoning (this is the dylib copy).
# Exit 0 = GREEN.
set -u

HDR="$(cd "$(dirname "$0")/../emulation/include/linux_premigration/resources" && pwd)/dserver-rpc-defs.h"
fails=0

if [ ! -f "$HDR" ]; then
	echo "FAIL: cannot find dylib dserver-rpc-defs.h at $HDR"
	exit 1
fi

# (1) The receive hook must issue a NON-BLOCKING recv (LINUX_MSG_DONTWAIT) -- the spin poll.
if ! grep -q "LINUX_MSG_DONTWAIT" "$HDR"; then
	echo "FAIL: dylib receive hook has no LINUX_MSG_DONTWAIT non-blocking poll (no recv-spin)"
	fails=$((fails+1))
fi

# (2) The spin must be bounded by a compile-time budget gate (never an unbounded busy-wait;
#     symmetric to perf#1/#3). The budget macro keys on DARLING_GUEST_RECVSPIN.
if ! grep -q "DARLING_GUEST_RECVSPIN" "$HDR"; then
	echo "FAIL: dylib recv-spin has no DARLING_GUEST_RECVSPIN budget gate (must be bounded)"
	fails=$((fails+1))
fi

# (3) The non-blocking poll must come BEFORE the blocking recvmsg fallback, inside the
#     receive hook -- i.e. the first recv attempt is the DONTWAIT spin, then we fall back.
#     Assert the DONTWAIT line appears before the plain blocking recvmsg syscall line.
dontwait_ln=$(grep -n "LINUX_MSG_DONTWAIT" "$HDR" | head -1 | cut -d: -f1)
# the blocking fallback is the recvmsg/recvmsg-via-socketcall WITHOUT the DONTWAIT flag,
# i.e. the existing "retry:" path that passes 0 as flags.
block_ln=$(grep -n "__NR_recvmsg" "$HDR" | grep -v "DONTWAIT" | tail -1 | cut -d: -f1)
if [ -n "$dontwait_ln" ] && [ -n "$block_ln" ]; then
	if [ "$dontwait_ln" -ge "$block_ln" ]; then
		echo "FAIL: the LINUX_MSG_DONTWAIT spin (line $dontwait_ln) is not before the blocking recvmsg fallback (line $block_ln)"
		fails=$((fails+1))
	fi
else
	echo "FAIL: could not locate both the DONTWAIT spin and the blocking recvmsg in the hook"
	fails=$((fails+1))
fi

# (4) Must use a CPU pause between polls (not sched_yield as the primary on x86), matching
#     perf#3's reasoning (the reply lands from the server on another core).
if ! grep -Eq "ia32_pause|__asm__.*pause|\"yield\"" "$HDR"; then
	echo "FAIL: dylib recv-spin does not pause/relax between polls (would burn the core hot)"
	fails=$((fails+1))
fi

# (5) On a non-EAGAIN error during the spin, it must bail (return the error), not loop --
#     guard against turning a real recv error into a spin.
if ! grep -q "LINUX_EAGAIN" "$HDR"; then
	echo "FAIL: dylib recv-spin does not distinguish LINUX_EAGAIN from real errors"
	fails=$((fails+1))
fi

if [ "$fails" -eq 0 ]; then
	echo "GREEN: dylib RPC receive hook does a bounded LINUX_MSG_DONTWAIT recv-spin before blocking (covers all guest RPCs)"
	exit 0
fi
echo "RED: $fails dylib recv-spin check(s) failed"
exit 1
