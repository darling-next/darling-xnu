#include <darling/emulation/xnu_syscall/bsd/impl/select/pselect.h>

#include <stddef.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/bsdthread/cancelable.h>

#include "fdset.h"

long sys_pselect(int nfds, void* rfds, void* wfds, void* efds, const struct timespec* timeout, const sigset_t* mask)
{
	CANCELATION_POINT();
	return sys_pselect_nocancel(nfds, rfds, wfds, efds, timeout, mask);
}

long sys_pselect_nocancel(int nfds, void* rfds, void* wfds, void* efds, const struct timespec* timeout, const sigset_t* mask)
{
	int ret;
	struct timespec lts;
	linux_sigset_t lmask;
	long data[2];
	darwin_fdset_adapter_t readfds;
	darwin_fdset_adapter_t writefds;
	darwin_fdset_adapter_t exceptfds;

	ret = darwin_fdset_validate_nfds(nfds);
	if (ret < 0)
		return ret;

	if (timeout != NULL)
	{
		lts.tv_sec = timeout->tv_sec;
		lts.tv_nsec = timeout->tv_nsec;
	}
	if (mask != NULL)
	{
		sigset_bsd_to_linux(mask, &lmask);

		data[0] = (long)&lmask;
		data[1] = sizeof(lmask);
	}

	darwin_fdset_prepare(&readfds, nfds, rfds);
	darwin_fdset_prepare(&writefds, nfds, wfds);
	darwin_fdset_prepare(&exceptfds, nfds, efds);

	ret = LINUX_SYSCALL(__NR_pselect6, nfds,
			darwin_fdset_linux_ptr(&readfds),
			darwin_fdset_linux_ptr(&writefds),
			darwin_fdset_linux_ptr(&exceptfds),
			(timeout != NULL) ? &lts : NULL,
			(mask != NULL) ? data : NULL);

	if (ret < 0)
		ret = errno_linux_to_bsd(ret);
	else {
		darwin_fdset_copyback(&readfds, nfds);
		darwin_fdset_copyback(&writefds, nfds);
		darwin_fdset_copyback(&exceptfds, nfds);
	}

	return ret;
}
