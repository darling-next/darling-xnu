#include <darling/emulation/xnu_syscall/bsd/impl/unistd/exit.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/linux_premigration/elfcalls_wrapper.h>

#ifdef DARLING_RPC_SLEEP_ACCOUNT
// perf #9-decompose: flush the per-callnum recvmsg-sleep table on the clean exit path
// (in addition to the destructor), so the dump is robust even if fini handlers don't
// run for this -nostdlib dylib. Defined in the generated-wrapper TU via the accountant.
extern void __darling_rpc_sleep_dump(void);
#endif

#ifdef DARLING_RING_TRANSPORT
// perf #18 D17 (dar-1il.12): flush this process's per-thread ring lane stats on the clean exit path
// (RECON-only; strict no-op unless DARLING_GUEST_LANE_STATS=1). Robust without a dylib fini handler.
#include <darling/emulation/linux_premigration/resources/dserver-ring.h>
#endif

long sys_exit(int status)
{
	int ret;

#ifdef DARLING_RPC_SLEEP_ACCOUNT
	__darling_rpc_sleep_dump();
#endif
#ifdef DARLING_RING_TRANSPORT
	__dserver_ring_lane_stats_dump();
#endif

	native_exit(status);

	ret = LINUX_SYSCALL1(__NR_exit_group, status);
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
}
