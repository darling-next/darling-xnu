#include <darling/emulation/xnu_syscall/bsd/impl/psynch/psynch_mutexwait.h>


#include <darling/emulation/common/base.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/duct_errno.h>

#include <darlingserver/rpc.h>

long sys_psynch_mutexwait(void* mutex, uint32_t mgen, uint32_t ugen, uint64_t tid, uint32_t flags)
{
	uint32_t retval;
	int ret = dserver_rpc_psynch_mutexwait(mutex, mgen, ugen, tid, flags, &retval);

	if (ret < 0) {
		if (ret == -LINUX_EINTR) {
			return -EINTR;
		}
		__simple_printf("psynch_mutexwait failed internally: %d", ret);
		__simple_abort();
	}

	// Non-zero result code is a BSD error (EINTR/ETIMEDOUT) from
	// psynch_mtxcontinue; return it negated so it reaches libpthread as a
	// negative value (this emulated BSD syscall does NOT route it through
	// cerror -> errno; it arrives directly in the return register, where the
	// mutex wait loop decodes (int32_t)ret < 0 and retries the kernel wait).
	// Returning it positively would make libpthread treat the error as a
	// successful mutex updateval, defeating the EINTR retry / kw_intr
	// interrupted-wakeup redirection and stranding a contended-mutex handoff.
	// See psynch_cvwait.c for the full analysis.
	return (ret) ? -ret : retval;
}
