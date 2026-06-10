#include <darling/emulation/xnu_syscall/bsd/impl/psynch/psynch_cvwait.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/duct_errno.h>

#include <darlingserver/rpc.h>

long sys_psynch_cvwait(void* cv, uint64_t cvlsgen, uint32_t cvugen, void * mutex, uint64_t mugen, 
		uint32_t flags, int64_t sec, uint32_t nsec)
{
	uint32_t retval;
	int ret = dserver_rpc_psynch_cvwait(cv, cvlsgen, cvugen, mutex, mugen, flags, sec, nsec, &retval);

	if (ret < 0) {
		if (ret == -LINUX_EINTR) {
			return -EINTR;
		}
		__simple_printf("psynch_cvwait failed internally: %d", ret);
		__simple_abort();
	}

	// A non-zero result code is the BSD error returned by psynch_cvcontinue
	// (EINTR/ETIMEDOUT, possibly OR'd with the cvar ECVCLEARED/ECVPREPOST
	// status bits). Return it *negated* so it reaches libpthread as a negative
	// value. NOTE: unlike a real macOS syscall this emulated BSD syscall does
	// NOT route the negative return through cerror -> errno; the value arrives
	// directly in libpthread's return register, where _pthread_psynch_cond_wait
	// decodes it ((int32_t)ret < 0 -> err = -ret) to run the EINTR / prepost
	// recovery. Returning it positively would make libpthread treat the error
	// as a successful updateval, leaving an orphaned prepost that permanently
	// strands a later condvar wakeup.
	return (ret) ? -ret : retval;
}
