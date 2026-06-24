#include <darling/emulation/xnu_syscall/bsd/impl/psynch/ulock_wait.h>

#include <sys/errno.h>
#include <stdbool.h>
#include <stddef.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

struct timespec
{
	long tv_sec;
	long tv_nsec;
};

// timeout is in us
long sys_ulock_wait(uint32_t operation, void* addr, uint64_t value, uint32_t timeout)
{
	int ret, op;
	struct timespec ts;


	// char dbg[100];
	// __simple_sprintf(dbg, "ulock_wait on %p for %d ns", addr, timeout / 1000);
	// lkm_call(0x1028, dbg);

	if (timeout > 0)
	{
		ts.tv_sec = timeout / (1000*1000);
		ts.tv_nsec = (timeout % (1000*1000)) * 1000;
	}

	op = operation & XNU_UL_OPCODE_MASK;
	if (op == XNU_UL_COMPARE_AND_WAIT || op == XNU_UL_UNFAIR_LOCK)
	{
		// dar-gwn.6: retry on EINTR instead of returning it.
		//
		// Darling's BSD-syscall stub treats ANY return in the errno range
		// [-4095,-1] as a failed syscall and routes it through cerror, which
		// returns -1 to the caller. But os_unfair_lock's slow path passes
		// ULF_NO_ERRNO and expects __ulock_wait to return a raw negated errno
		// (it does `switch (-ret)` and only EINTR/EFAULT/EOWNERDEAD are
		// non-fatal -- anything else, including the cerror'd -1, falls into
		// _os_unfair_lock_corruption_abort -> ud2 -> SIGILL). There is no way
		// to smuggle a small -errno back through the generic cerror stub, and
		// the previous `ret &= ~0x800` hack just mangled the value further.
		//
		// Under a fork/exec signal storm futex(FUTEX_WAIT) is constantly woken
		// early with -EINTR while a thread holds e.g. the malloc magazine
		// os_unfair_lock, so this misfires and aborts the process. Since the
		// caller would only re-read the lock word and re-wait on EINTR anyway
		// (and macOS's ulock_wait restarts internally across signals), just
		// retry the futex here. This keeps the contended-wait blocking until a
		// real wake/contention change, and never hands a spurious errno to the
		// corruption-abort path.
		do {
			ret = LINUX_SYSCALL(__NR_futex, addr, FUTEX_WAIT | FUTEX_PRIVATE_FLAG,
				value, (timeout != 0) ? & ts : NULL);
		} while (ret == -LINUX_EINTR && timeout == 0);

		// unlike ulock_wait(), futex(FUTEX_WAIT) does not return how many
		// other threads are now (still) waiting for the lock.
		//
		// This hack makes userspace believe that there are other pending threads
		// and always take the slow path, which is the safe thing to do if
		// we are unsure.
		if (ret == 0 || ret == -LINUX_EAGAIN)
			ret = 1;
	}
	else
		return -EINVAL;

	if (ret < 0)
	{
		// Map any remaining error to a negated BSD errno (e.g. ETIMEDOUT for a
		// timed wait). EINTR on an untimed wait was already retried above.
		ret = errno_linux_to_bsd(ret);
	}

	return ret;
}
