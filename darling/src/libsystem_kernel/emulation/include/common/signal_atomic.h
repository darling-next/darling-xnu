#ifndef DARLING_EMULATION_COMMON_SIGNAL_ATOMIC_H
#define DARLING_EMULATION_COMMON_SIGNAL_ATOMIC_H

#include <stddef.h>
#include <darling/emulation/xnu_syscall/bsd/impl/signal/sigprocmask.h>

static inline void signal_atomic_begin(sigset_t* saved_mask) {
	// Defer standard Unix handlers without blocking runtime real-time signals.
	sigset_t set = 0x7fffffff;
	sys_sigprocmask(SIG_BLOCK, &set, saved_mask);
}

static inline void signal_atomic_end(const sigset_t* saved_mask) {
	sys_sigprocmask(SIG_SETMASK, saved_mask, NULL);
}

#endif
