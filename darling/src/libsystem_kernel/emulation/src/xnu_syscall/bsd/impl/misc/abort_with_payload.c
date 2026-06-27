#include <darling/emulation/xnu_syscall/bsd/impl/misc/abort_with_payload.h>

#include <sys/signal.h>

#include <darling/emulation/xnu_syscall/bsd/impl/signal/kill.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/signal/duct_signals.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

long sys_abort_with_payload(unsigned int reason_namespace, unsigned long long reason_code, void *payload, unsigned int payload_size, const char *reason_string, unsigned long long reason_flags)
{
	__simple_printf("abort_with_payload: reason: %s; code: %lu\n", reason_string, reason_code);

	// macOS abort_with_payload terminates ONLY the calling process. Do NOT use
	// kill(0, SIGABRT): kill(0, sig) targets the caller's ENTIRE PROCESS GROUP,
	// so a conftest aborting (e.g. gnulib via os/assumes.c -> abort_with_payload)
	// would broadcast SIGABRT to its parent/sibling processes sharing the pgid and
	// kill them too -- observed taking down the parent brew Ruby with a spurious
	// SI_USER SIGABRT (dar-cps; same family as dar-gwn.1.5 / dar-gwn.6.4). Re-raise
	// to THIS thread (raise() semantics) via tgkill(pid, tid, SIGABRT) so only this
	// process is affected.
	int self_pid = LINUX_SYSCALL(__NR_getpid);
	int self_tid = LINUX_SYSCALL(__NR_gettid);
	LINUX_SYSCALL(__NR_tgkill, self_pid, self_tid, signum_bsd_to_linux(SIGABRT));
	return 0;
}
