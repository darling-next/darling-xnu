#include <darling/emulation/xnu_syscall/bsd/impl/signal/sigprocmask.h>

#include <stddef.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/signal/duct_signals.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

static inline int spchow_bsd_to_linux(int how) { return how-1; }

long sys_sigprocmask(int how, const sigset_t* set, sigset_t* oldset)
{
	int ret, linux_how;
	linux_sigset_t in, out;

	linux_how = spchow_bsd_to_linux(how);

	if (set != NULL)
		sigset_bsd_to_linux(set, &in);

	// SIGNAL-MASK PROBE, FOR SIGSEGV ONLY. A hardware fault whose signal is BLOCKED takes the DEFAULT action even
	// when a handler is installed, which is the only remaining explanation for a real SIGSEGV that reaches neither
	// the guest's crash handler nor the loader's host probe. This prints every mask transition that carries bit 10
	// (Darwin's SIGSEGV bit), so a block with no matching unblock before the death is the answer. Bounded.
	if (set != NULL && ((((const unsigned int*)(const void*)set)[0]) & (1u << (11 - 1)))) {
		static int emitted = 0;
		if (emitted < 40) {
			++emitted;
			__simple_fprintf(2, "[sigsegv-mask how=%d ra=%p]\n", how, __builtin_return_address(0));
		}
	}

	ret = LINUX_SYSCALL(__NR_rt_sigprocmask, linux_how,
			(set != NULL) ? &in : NULL, &out, sizeof(linux_sigset_t));
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);
	else if (oldset != NULL)
		sigset_linux_to_bsd(&out, oldset);

	return ret;
}
