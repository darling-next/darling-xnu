#if defined(__x86_64__)
#define DSERVER_URGENT_ARCH 2u
#elif defined(__i386__)
#define DSERVER_URGENT_ARCH 1u
#elif defined(__aarch64__) || defined(__arm64__)
#define DSERVER_URGENT_ARCH 4u
#elif defined(__arm__)
#define DSERVER_URGENT_ARCH 3u
#else
#define DSERVER_URGENT_ARCH 0u
#endif
#include <darling/emulation/xnu_syscall/bsd/impl/signal/sigaction.h>

#include <stddef.h>
#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/linux_premigration/signal/sigexc.h>

#include <darlingserver/rpc.h>
#include <darlingserver/rpc-supplement.h>
#include <darling/emulation/linux_premigration/elfcalls_wrapper.h>
// perf#30 (directive sections 19-21): the interrupt calls ride the URGENT pool -- signal-safe, non-blocking.
// Only when there is no transport or no free slot does the datagram path run.
static inline int __dserver_urgent_enter(void) {
	if (__dserver_plane_urgent_publish(DSERVER_PROCESS_CONTROL_OP_INTERRUPT_ENTER, 0, 0, 0, DSERVER_URGENT_ARCH) == 0) {
		return 0;
	}
	return dserver_rpc_interrupt_enter();
}
static inline int __dserver_urgent_exit(void) {
	if (__dserver_plane_urgent_publish(DSERVER_PROCESS_CONTROL_OP_INTERRUPT_EXIT, 0, 0, 0, DSERVER_URGENT_ARCH) == 0) {
		return 0;
	}
	return dserver_rpc_interrupt_exit();
}


static int sigflags_bsd_to_linux(int flags);
static int sigflags_linux_to_bsd(int flags);
extern void sig_restorer(void);

extern void* memcpy(void* dest, const void* src, __SIZE_TYPE__ len);
extern void* memset(void* dest, int v, __SIZE_TYPE__ len);

static void handler_linux_to_bsd_wrapper(int linux_signum, struct linux_siginfo* info, void* ctxt);

// Libc uses only one trampoline
void (*sa_tramp)(void*, int, int, struct bsd_siginfo*, void*) = 0;
bsd_sig_handler* sig_handlers[32] = {
	[LINUX_SIGWINCH] = (bsd_sig_handler*) SIG_IGN,
	[LINUX_SIGURG] = (bsd_sig_handler*) SIG_IGN,
};
int sig_flags[32];
unsigned int sig_masks[32];

long sys_sigaction(int signum, const struct bsd___sigaction* nsa, struct bsd_sigaction* osa)
{
	int ret, linux_signum;
	struct linux_sigaction sa, olsa;

	linux_signum = signum_bsd_to_linux(signum);
	if (linux_signum == 0)
	{
		// Some software (e.g. Node.js) tries to set up handlers for all signals by
		// walking through all signal numbers incrementally. They end up hitting
		// signals that don't exist on Linux and then bail out if they receive
		// an error.
		// Fake that everyting is all right.

		if (osa != NULL)
			memset(osa, 0, sizeof(*osa));
		
		return 0;
	}

	// SIGACTION PROBE, FOR SIGSEGV ONLY. MEASURED NEED: the workload dies of a REAL SIGSEGV (the guest's wait4 is a
	// raw host wait4, so the status the shell prints comes from the host kernel) and neither the guest's crash
	// handler nor the loader's host probe fires -- which means the host disposition was the DEFAULT at the fault.
	// Every transition of SIGSEGV's disposition therefore names the actor: req=0 is SIG_DFL and req=1 is SIG_IGN,
	// and the return address names who asked. Bounded, and only for signal 11 so the log stays readable.
	if (signum == 11 || linux_signum == 11) {
		static int emitted = 0;
		if (emitted < 32) {
			++emitted;
			// pid and tid are printed because the KEY question is whether the process that installs the SIGSEGV
			// handler is the process that dies: if it is not, the fatal SIGSEGV meets a DEFAULT disposition and the
			// silent, handler-less death is fully explained without any delivery failure.
			__simple_fprintf(2, "[sigact pid=%d tid=%d bsd=%d linux=%d req=%p flags=0x%x ra=%p]\n",
				(int)LINUX_SYSCALL(__NR_getpid), (int)LINUX_SYSCALL(__NR_gettid), signum, linux_signum,
				(nsa != NULL) ? (const void*)nsa->sa_sigaction : (const void*)-1,
				(nsa != NULL) ? nsa->sa_flags : 0, __builtin_return_address(0));
		}
	}

	if (nsa != NULL && (linux_signum == LINUX_SIGCHLD || linux_signum == LINUX_SIGTTOU))
	{
		sa_tramp = nsa->sa_tramp;
		if (nsa->sa_sigaction != XNU_SIG_DFL && nsa->sa_sigaction != XNU_SIG_IGN
				&& nsa->sa_sigaction != XNU_SIG_ERR)
		{
			sa.sa_sigaction = &handler_linux_to_bsd_wrapper;
		}
		else
			sa.sa_sigaction = (linux_sig_handler*) nsa->sa_sigaction;

		sigset_bsd_to_linux(&nsa->sa_mask, &sa.sa_mask);
		sa.sa_flags = sigflags_bsd_to_linux(nsa->sa_flags) | LINUX_SA_RESTORER;
		sa.sa_restorer = sig_restorer;

		ret = LINUX_SYSCALL(__NR_rt_sigaction, linux_signum,
			(nsa != NULL) ? &sa : NULL, &olsa,
			sizeof(sa.sa_mask));

		if (ret < 0)
			return errno_linux_to_bsd(ret);

		if (osa != NULL)
		{
			if (olsa.sa_sigaction == handler_linux_to_bsd_wrapper)
				osa->sa_sigaction = sig_handlers[linux_signum];
			else // values such as SIG_DFL
				osa->sa_sigaction = (bsd_sig_handler*) olsa.sa_sigaction;
			sigset_linux_to_bsd(&olsa.sa_mask, &osa->sa_mask);
			osa->sa_flags = sigflags_linux_to_bsd(olsa.sa_flags);
		}
	}
	else
	{
		ret = 0;

		if (nsa != NULL)
		{
			bool restart = nsa->sa_sigaction == XNU_SIG_IGN
				|| (nsa->sa_flags & BSD_SA_RESTART);
			ret = sigexc_set_restart(linux_signum, restart);
			if (ret < 0)
				return errno_linux_to_bsd(ret);
		}

		if (osa != NULL)
		{
			osa->sa_sigaction = sig_handlers[linux_signum];
			osa->sa_flags = sig_flags[linux_signum];
			osa->sa_mask = sig_masks[linux_signum];
		}

		if (nsa != NULL && linux_signum != LINUX_SIGKILL && linux_signum != LINUX_SIGSTOP
				&& (nsa->sa_sigaction == XNU_SIG_IGN || sig_handlers[linux_signum] == XNU_SIG_IGN))
		{
			// Ignoring only in sigexc_handler leaves blocked signals pending.
			// Let Linux discard them, retaining the internal mask, flags and restorer.
			ret = LINUX_SYSCALL(__NR_rt_sigaction, linux_signum, NULL, &sa,
				sizeof(sa.sa_mask));
			if (ret < 0)
				return errno_linux_to_bsd(ret);

			// Both a user handler and SIG_DFL must return through sigexc when
			// leaving ignore, rather than keeping Linux's SIG_IGN disposition.
			sa.sa_sigaction = nsa->sa_sigaction == XNU_SIG_IGN
				? (linux_sig_handler*) XNU_SIG_IGN : (linux_sig_handler*) sigexc_handler;
			ret = LINUX_SYSCALL(__NR_rt_sigaction, linux_signum, &sa, NULL,
				sizeof(sa.sa_mask));
			if (ret < 0)
				return errno_linux_to_bsd(ret);
		}
	}
	
	if (nsa != NULL && ret >= 0)
	{
		// __simple_printf("Saving handler for signal %d: %p\n", linux_signum, nsa->sa_sigaction);
		sig_handlers[linux_signum] = nsa->sa_sigaction;
		sig_flags[linux_signum] = nsa->sa_flags;
		sig_masks[linux_signum] = nsa->sa_mask;
	}

	return 0;
}

#if 0
long sys_sigaction(int signum, const struct bsd___sigaction* nsa, struct bsd_sigaction* osa)
{
	int ret, linux_signum;
	struct linux_sigaction sa, olsa;

	linux_signum = signum_bsd_to_linux(signum);
	if (linux_signum == 0)
	{
		// Some software (e.g. Node.js) tries to set up handlers for all signals by
		// walking through all signal numbers incrementally. They end up hitting
		// signals that don't exist on Linux and then bail out if they receive
		// an error.
		// Fake that everyting is all right.

		if (osa != NULL)
			memset(osa, 0, sizeof(*osa));
		
		return 0;
	}

	if (nsa != NULL)
	{
		sa_tramp = nsa->sa_tramp;
		/*if (darling_am_i_ptraced())
		{
			sa.sa_sigaction = &sigexc_handler;
		}
		else*/ if (nsa->sa_sigaction != SIG_DFL && nsa->sa_sigaction != SIG_IGN
				&& nsa->sa_sigaction != SIG_ERR)
		{
			sa.sa_sigaction = &handler_linux_to_bsd;
		}
		else
			sa.sa_sigaction = (linux_sig_handler*) nsa->sa_sigaction;

		sigset_bsd_to_linux(&nsa->sa_mask, &sa.sa_mask);
		sa.sa_flags = sigflags_bsd_to_linux(nsa->sa_flags) | LINUX_SA_RESTORER;
		sa.sa_restorer = sig_restorer;
	}

	ret = LINUX_SYSCALL(__NR_rt_sigaction, linux_signum,
			(nsa != NULL) ? &sa : NULL, &olsa,
			sizeof(sa.sa_mask));
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	if (osa != NULL)
	{
		if (olsa.sa_sigaction == handler_linux_to_bsd)
			osa->sa_sigaction = sig_handlers[linux_signum];
		else // values such as SIG_DFL
			osa->sa_sigaction = (bsd_sig_handler*) olsa.sa_sigaction;
		sigset_linux_to_bsd(&olsa.sa_mask, &osa->sa_mask);
		osa->sa_flags = sigflags_linux_to_bsd(olsa.sa_flags);
	}
	
	if (nsa != NULL && ret >= 0)
	{
		//  __simple_printf("Saving handler for signal %d: %d\n", linux_signum, nsa->sa_sigaction);
		sig_handlers[linux_signum] = nsa->sa_sigaction;
		sig_flags[linux_signum] = sa.sa_flags;
		sig_masks[linux_signum] = sa.sa_mask;
	}

	return 0;
}
#endif

static void handler_linux_to_bsd_wrapper(int linux_signum, struct linux_siginfo* info, void* ctxt) {
	// GUEST-HANDLER ENTRY PROBE. This wrapper is what the kernel calls for a SELF-INFLICTED signal, so a line here
	// means the fault REACHED the guest's own handler; its absence, given that the guest installed handlers for
	// SIGSEGV and never blocks it, means the kernel invoked nothing at all. Bounded.
	{
		static int emitted = 0;
		if (emitted < 24) {
			++emitted;
			// The mask matters as much as the entry: a hardware fault whose signal is masked -- and a handler's
			// own sa_mask masks it for the duration of that handler, invisibly to any sigprocmask API probe --
			// takes the DEFAULT action, which is a silent death with no second handler entry.
			linux_sigset_t cur;
			long mq = LINUX_SYSCALL(__NR_rt_sigprocmask, 0, NULL, &cur, sizeof(cur));
			// Bit (11-1) of the LINUX mask, read byte-wise so the struct's field name is irrelevant.
			int segv_masked = (mq == 0)
				? (int)((((const unsigned char*)&cur)[(11 - 1) >> 3] >> ((11 - 1) & 7)) & 1) : -1;
			__simple_fprintf(2, "[guest-handler linux_sig=%d segv_masked=%d]\n", linux_signum, segv_masked);
		}
	}
	(void)__dserver_urgent_enter();
	handler_linux_to_bsd(linux_signum, info, ctxt);
	(void)__dserver_urgent_exit();
};

// Published so another translation unit can say WHICH handler the host disposition holds: without the comparison
// "a real handler is installed" cannot be told from "the wrapper that runs the guest's handler is installed".
void* dw_sig_wrapper_addr = (void*) &handler_linux_to_bsd_wrapper;

static int sigflags_bsd_to_linux(int flags)
{
	int linux_flags = LINUX_SA_SIGINFO;

	if (flags & BSD_SA_NOCLDSTOP)
		linux_flags |= LINUX_SA_NOCLDSTOP;
	if (flags & BSD_SA_NOCLDWAIT)
		linux_flags |= LINUX_SA_NOCLDWAIT;
	if (flags & BSD_SA_ONSTACK)
		linux_flags |= LINUX_SA_ONSTACK;
	if (flags & BSD_SA_NODEFER)
		linux_flags |= LINUX_SA_NODEFER;
	if (flags & BSD_SA_RESETHAND)
		linux_flags |= LINUX_SA_RESETHAND;
	if (flags & BSD_SA_RESTART)
		linux_flags |= LINUX_SA_RESTART;

	return linux_flags;
}

static int sigflags_linux_to_bsd(int flags)
{
	int bsd_flags = 0;

	if (flags & LINUX_SA_NOCLDSTOP)
		bsd_flags |= BSD_SA_NOCLDSTOP;
	if (flags & LINUX_SA_NOCLDWAIT)
		bsd_flags |= BSD_SA_NOCLDWAIT;
	if (flags & LINUX_SA_ONSTACK)
		bsd_flags |= BSD_SA_ONSTACK;
	if (flags & LINUX_SA_NODEFER)
		bsd_flags |= BSD_SA_NODEFER;
	if (flags & LINUX_SA_RESETHAND)
		bsd_flags |= BSD_SA_RESETHAND;
	if (flags & LINUX_SA_RESTART)
		bsd_flags |= BSD_SA_RESTART;

	return bsd_flags;
}
