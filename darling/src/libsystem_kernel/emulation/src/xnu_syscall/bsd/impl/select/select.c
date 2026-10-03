#include <darling/emulation/xnu_syscall/bsd/impl/select/select.h>

#include <stddef.h>
#include <time.h>

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
		darwin_fdset_adapter_t readfds;
		darwin_fdset_adapter_t writefds;
		darwin_fdset_adapter_t exceptfds;

		ret = darwin_fdset_validate_nfds(nfds);
		if (ret < 0)
			return ret;

		if (timeout != NULL)
		{
			ltv.tv_sec = timeout->tv_sec;
			ltv.tv_usec = timeout->tv_usec;
		}

		darwin_fdset_prepare(&readfds, nfds, rfds);
		darwin_fdset_prepare(&writefds, nfds, wfds);
		darwin_fdset_prepare(&exceptfds, nfds, efds);

		#if defined(__NR__newselect)
			ret = LINUX_SYSCALL(__NR__newselect, nfds,
					darwin_fdset_linux_ptr(&readfds),
					darwin_fdset_linux_ptr(&writefds),
					darwin_fdset_linux_ptr(&exceptfds),
					(timeout != NULL) ? &ltv : NULL);
		#else
			ret = LINUX_SYSCALL(__NR_select, nfds,
					darwin_fdset_linux_ptr(&readfds),
					darwin_fdset_linux_ptr(&writefds),
					darwin_fdset_linux_ptr(&exceptfds),
					(timeout != NULL) ? &ltv : NULL);
		#endif
		if (ret < 0)
			ret = errno_linux_to_bsd(ret);
		else {
			darwin_fdset_copyback(&readfds, nfds);
			darwin_fdset_copyback(&writefds, nfds);
			darwin_fdset_copyback(&exceptfds, nfds);
		}

		return ret;
	#else
		if (timeout != NULL)
		{
			struct timespec ts = {
				.tv_sec = timeout->tv_sec,
				.tv_nsec = timeout->tv_usec * 1000,
			};

			return sys_pselect_nocancel(nfds, rfds, wfds, efds, &ts, NULL);
		}

		return sys_pselect_nocancel(nfds, rfds, wfds, efds, NULL, NULL);
	#endif
}
