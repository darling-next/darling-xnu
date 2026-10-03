#include <darling/emulation/xnu_syscall/bsd/impl/process/wait4.h>

#include <darling/emulation/common/simple.h>

static int emitted_wait4 = 0;

#include <sys/signal.h>
#include <stddef.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/process/wait4.h>
#include <darling/emulation/conversion/signal/duct_signals.h>
#include <darling/emulation/linux_premigration/signal/sigexc.h>
#include <darling/emulation/xnu_syscall/bsd/impl/misc/ptrace.h>
#include <darling/emulation/other/mach/lkm.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/bsdthread/cancelable.h>

extern int getpid(void);

long sys_wait4(int pid, int* status, int options, void* rusage)
{
	CANCELATION_POINT();
	return sys_wait4_nocancel(pid, status, options, rusage);
}

long sys_wait4_nocancel(int pid, int* status, int options, void* rusage)
{
	int ret, linux_options;
	int mystatus;

	// We always need status even if the caller doesn't
	if (status == NULL)
		status = &mystatus;

	linux_options = waitopts_bsd_to_linux(options);

restart:
	ret = LINUX_SYSCALL(__NR_wait4, pid, status, linux_options, rusage);
	// REAP PROBE. MEASURED NEED: for the fatal SIGSEGV the kernel enters neither the guest's handler wrapper nor the
	// loader's host probe, although the guest installed a handler for SIGSEGV and never blocks it -- so the process
	// that dies is NOT the one that installed them. This prints the pid the host reaped and the RAW host status, so
	// the dying process is named instead of inferred: a signaled status is (signum | 0x80) and the pid can be
	// matched against the pid-tagged lines of the same log. Bounded.
	if (ret > 0 && emitted_wait4 < 40) {
		++emitted_wait4;
		__simple_fprintf(2, "[wait4 pid=%d raw=0x%x]\n", ret, (unsigned)*status);
	}
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	if ((*status & 0x7f) != 0x7f) // process terminated
	{
		int signum;

		signum = *status & 0x7f;
		*status &= ~0x7f;
		*status |= signum_linux_to_bsd(signum);
	}
	else if (*status == 0xffff) // Linux: __W_CONTINUED
		*status = 0x7f | (0x13 << 8);
	else if ((*status & 0x7f) == 0x7f) // process stopped
	{
		int signal = *status >> 8;
		signal = signum_linux_to_bsd(signal);
		*status = (*status & 0x7f) | (signal << 8);
	}

	return ret;
}
