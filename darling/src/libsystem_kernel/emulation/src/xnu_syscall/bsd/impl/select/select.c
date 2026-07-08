#include <darling/emulation/xnu_syscall/bsd/impl/select/select.h>

#include <stddef.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/bsdthread/cancelable.h>

#include "fdset.h"

long sys_select(int nfds, void* rfds, void* wfds, void* efds, struct bsd_timeval* timeout)
{
	CANCELATION_POINT();
	return sys_select_nocancel(nfds, rfds, wfds, efds, timeout);
}

long sys_select_nocancel(int nfds, void* rfds, void* wfds, void* efds, struct bsd_timeval* timeout)
{
	#if defined(__NR__newselect) || defined(__NR_select)
		int ret;
		struct linux_timeval ltv;
		size_t words = linux_fdset_words(nfds);
		unsigned long* linux_rfds = (rfds != NULL) ? __builtin_alloca(words * sizeof(*linux_rfds)) : NULL;
		unsigned long* linux_wfds = (wfds != NULL) ? __builtin_alloca(words * sizeof(*linux_wfds)) : NULL;
		unsigned long* linux_efds = (efds != NULL) ? __builtin_alloca(words * sizeof(*linux_efds)) : NULL;

		if (timeout != NULL)
		{
			ltv.tv_sec = timeout->tv_sec;
			ltv.tv_usec = timeout->tv_usec;
		}

		bsd_fdset_to_linux(nfds, rfds, linux_rfds);
		bsd_fdset_to_linux(nfds, wfds, linux_wfds);
		bsd_fdset_to_linux(nfds, efds, linux_efds);

		#if defined(__NR__newselect)
			ret = LINUX_SYSCALL(__NR__newselect, nfds, linux_rfds, linux_wfds, linux_efds,
					(timeout != NULL) ? &ltv : NULL);
		#else
			ret = LINUX_SYSCALL(__NR_select, nfds, linux_rfds, linux_wfds, linux_efds,
					(timeout != NULL) ? &ltv : NULL);
		#endif
		if (ret < 0)
			ret = errno_linux_to_bsd(ret);
		else {
			linux_fdset_to_bsd(nfds, linux_rfds, rfds);
			linux_fdset_to_bsd(nfds, linux_wfds, wfds);
			linux_fdset_to_bsd(nfds, linux_efds, efds);
		}

		return ret;
	#else
		return sys_pselect_nocancel(nfds, rfds, wfds, efds, timeout, NULL);
	#endif
}
