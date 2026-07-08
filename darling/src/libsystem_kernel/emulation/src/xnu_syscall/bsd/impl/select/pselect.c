#include <darling/emulation/xnu_syscall/bsd/impl/select/pselect.h>

#include <stddef.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/bsdthread/cancelable.h>

#include "fdset.h"

long sys_pselect(int nfds, void* rfds, void* wfds, void* efds, struct bsd_timeval* timeout, const sigset_t* mask)
{
	CANCELATION_POINT();
	return sys_pselect_nocancel(nfds, rfds, wfds, efds, timeout, mask);
}

long sys_pselect_nocancel(int nfds, void* rfds, void* wfds, void* efds, struct bsd_timeval* timeout, const sigset_t* mask)
{
	int ret;
	struct linux_timeval ltv;
	long data[2];
	size_t words = linux_fdset_words(nfds);
	unsigned long* linux_rfds = (rfds != NULL) ? __builtin_alloca(words * sizeof(*linux_rfds)) : NULL;
	unsigned long* linux_wfds = (wfds != NULL) ? __builtin_alloca(words * sizeof(*linux_wfds)) : NULL;
	unsigned long* linux_efds = (efds != NULL) ? __builtin_alloca(words * sizeof(*linux_efds)) : NULL;

	if (timeout != NULL)
	{
		ltv.tv_sec = timeout->tv_sec;
		ltv.tv_usec = timeout->tv_usec;
	}
	if (mask != NULL)
	{
		linux_sigset_t lmask;

		sigset_bsd_to_linux(mask, &lmask);

		data[0] = (long)lmask;
		data[1] = 65/8; // _NSIG / 8
	}

	bsd_fdset_to_linux(nfds, rfds, linux_rfds);
	bsd_fdset_to_linux(nfds, wfds, linux_wfds);
	bsd_fdset_to_linux(nfds, efds, linux_efds);

	ret = LINUX_SYSCALL(__NR_pselect6, nfds, linux_rfds, linux_wfds, linux_efds,
			(timeout != NULL) ? &ltv : NULL,
			(mask != NULL) ? data : NULL);

	if (ret < 0)
		ret = errno_linux_to_bsd(ret);
	else {
		linux_fdset_to_bsd(nfds, linux_rfds, rfds);
		linux_fdset_to_bsd(nfds, linux_wfds, wfds);
		linux_fdset_to_bsd(nfds, linux_efds, efds);
	}

	return ret;
}
