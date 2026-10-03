#include <darling/emulation/xnu_syscall/bsd/impl/bsdthread/bsdthread_terminate.h>

#include <sys/errno.h>
#include <stddef.h>
#include <stdint.h>

#include <darling/emulation/xnu_syscall/bsd/impl/bsdthread/bsdthread_register.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/linux_premigration/elfcalls_wrapper.h>
#include <darling/emulation/common/guarded/table.h>
#include <darling/emulation/other/mach/lkm.h>
#ifdef DARLING_RING_TRANSPORT
// perf#27 lane lifecycle: give this thread's ring lane slot back to the catalog on the way out.
#include <darling/emulation/linux_premigration/resources/dserver-ring.h>
#endif

int bsdthread_terminate_trap(
                uintptr_t stackaddr,
                unsigned long freesize,
                int thread,
                int sem);
int semaphore_signal_trap_impl(int signal_name);

extern void _xtrace_thread_exit(void);

long sys_bsdthread_terminate(void* stackaddr, unsigned long freesize, int port,
		int join_sem)
{
#ifndef VARIANT_DYLD
#ifdef DARLING_RING_TRANSPORT
	// perf#27: this OS thread is about to stop existing, so its lane must stop existing too. Before the
	// point of no return below, release the catalog slot and hand the loader-owned wake descriptor back
	// (the loader must forget the number, not just close it -- see __mldr_release_ring_fd). Nothing here
	// needs the server: it retires its own RingBuffer when the Thread dies, and an in-flight Call holds its
	// own shared_ptr, so recycling the slot cannot hand a new lane a stale completion.
	__dserver_ring_release_current_lane();
#endif
#ifdef BSDTHREAD_WRAP_LINUX_PTHREAD
	// Implemented in libdyld
	extern int __darling_thread_terminate(void* stackaddr,
			unsigned long freesize, unsigned long pthobj_size);

	semaphore_signal_trap_impl(join_sem);

	// point of no return; let xtrace know
	_xtrace_thread_exit();

	// perf#30 REMOVAL STEP 3c: there is no guarded per-thread RPC fd to unguard -- a thread never had one.

	return __darling_thread_terminate(stackaddr, freesize, pthread_obj_size);
#else
	return bsdthread_terminate_trap((uintptr_t) stackaddr, freesize,
			port, join_sem);
#endif
#else
	return -ENOSYS;
#endif
}
