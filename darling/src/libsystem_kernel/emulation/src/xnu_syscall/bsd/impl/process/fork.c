#include <darling/emulation/xnu_syscall/bsd/impl/process/fork.h>

#include <_libkernel_init.h>
#include <stddef.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/signal/duct_signals.h>
#include <darling/emulation/common/bsdthread/per_thread_wd.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/fchdir.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/common/simple.h>
#include <darlingserver/rpc-supplement.h>
#include <darlingserver/rpc-supplement.h>   // perf#30: the process-control page protocol (OP_CHECKIN, states)
#include <darling/emulation/linux_premigration/elfcalls_wrapper.h>
#include <darling/emulation/linux_premigration/elfcalls_wrapper.h>
#include <darling/emulation/other/mach/lkm.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>
#include <darling/emulation/common/guarded/table.h>
#include <darling/emulation/linux_premigration/resources/dserver-ring.h>

#include <darlingserver/rpc.h>

extern _libkernel_functions_t _libkernel_functions;

#define LINUX_CLONE_PIDFD 0x00001000

// perf#30: the architecture byte the checkin must carry -- the SAME mapping
// dserver_rpc_hooks_get_architecture() (resources/dserver-rpc-defs.h) produces: 1 = i386, 2 = x86_64,
// 3 = arm32, 4 = arm64. Computed locally because including that header in this translation unit
// conflicts with its own memcpy declaration.
#if defined(__x86_64__)
	#define DSERVER_GUEST_ARCH_BYTE 2u
#elif defined(__i386__)
	#define DSERVER_GUEST_ARCH_BYTE 1u
#elif defined(__aarch64__) || defined(__arm64__)
	#define DSERVER_GUEST_ARCH_BYTE 4u
#elif defined(__arm__)
	#define DSERVER_GUEST_ARCH_BYTE 3u
#else
	#define DSERVER_GUEST_ARCH_BYTE 0u
#endif

static long fork_with_exit_signal(int exit_signal, int* pidfd)
{
	int ret;
	int wdfd = get_perthread_wd();
	__mldr_prefork_prepare();

	if (pidfd != NULL) {
		/*
		 * parent_tid is argument 3 on x86_64, i386 and arm64. The last two
		 * arguments (child_tid/tls) differ in order but are both unused.
		 * Only the parent receives the new CLOEXEC descriptor.
		 */
		*pidfd = -1;
		ret = LINUX_SYSCALL(__NR_clone, exit_signal | LINUX_CLONE_PIDFD,
			0, pidfd, 0, 0);
	} else {
#ifdef SYS_fork
		ret = LINUX_SYSCALL(__NR_fork);
#else
		ret = LINUX_SYSCALL(__NR_clone, exit_signal, 0);
#endif
	}
	if (ret != 0) {
		__mldr_postfork_parent();
	}
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);
	else if (ret == 0)
	{
		// in the child

		__mldr_postfork_child();

		// the old RPC FD will be closed in `guard_table_postfork_child`;
		// we don't need to close it ourselves.
		// that should also take care of closing descriptors for any other threads.
		guard_table_postfork_child();

		// perf#30 (directive sections 2/3, doc section 206): NO eager per-thread RPC socket in the child. The old
		// descriptor is closed by guard_table_postfork_child above, and the loader has already invalidated its
		// cached number __mldr_postfork_child; the child's transport is the process Ring, which it re-adopts here.
		// MEASURED: creating it here -- with no RPC behind it -- was the denial the hard oracle reported, labelled
		// with the stale name of the last call the child had made before forking.
		// The loader already closed both images' inherited ring FDs. Drop this
		// image's mappings without closing numbers the new RPC socket may reuse.
		__dserver_ring_postfork_reset();
		int newReadFd = __dserver_process_lifetime_pipe_refresh();

		// perf#30: nothing to guard -- no socket was created, so no descriptor can be inherited into a grandchild
		// (an inherited one is already handled by guard_table_postfork_child), and creating a socket purely to
		// guard it is exactly the eager creation this work removes.
		guard_entry_options_t options;

		// only guard the lifetime pipe if it's used.
		if (newReadFd != -1)
		{
			options.close = __dserver_close_process_lifetime_pipe;
			guard_table_add(__dserver_get_process_lifetime_pipe(), guard_flag_prevent_close | guard_flag_close_on_fork, &options);
		}

		int dummy_stack_variable;
		// perf#30 CHECKIN ON THE PAGE (fork child): the child's checkin is ordered against its parent's
		// checkout in the exec/fork handshake, and the page gives that ordering explicitly -- the child
		// waits for the server's completion before returning, which is exactly what the datagram gave for
		// free. The lifetime descriptor (when there is one) rides the process courier with the kind the
		// server's OP_CHECKIN already resolves, so no datagram is needed for either half. MEASURED: this
		// call site was the whole of the remaining checkin UDS traffic.
		int child_checked_in = 0;
		{
			struct dserver_process_control* page =
				(struct dserver_process_control*)__dserver_process_control_page();
			// A forked child gets a FRESH page (the accessor abandons the parent's, which is the fix for
			// the inherited-page hang), so its transport is not established yet at this instant. Waiting
			// here is a TRANSPORT wait, bounded, and it is what keeps the child's checkin on the page
			// instead of falling back to the datagram.
			if (page != NULL) {
				for (int w = 0; w < 200 && __atomic_load_n(&page->transport_ready, __ATOMIC_ACQUIRE) == 0; ++w) {
					long ts[2] = {0, 1000000L};
					(void)LINUX_SYSCALL6(__NR_nanosleep, ts, 0, 0, 0, 0, 0);
				}
			}
			if (page != NULL && __atomic_load_n(&page->transport_ready, __ATOMIC_ACQUIRE) != 0) {
				uint64_t token = 0;
				if (newReadFd != -1) {
					token = __dserver_fd_courier_send(newReadFd, DSERVER_FD_COURIER_KIND_CHECKIN_FD);
				}
				int slot = 0;
				for (int t = 0; t < 2000 && !slot; ++t) {
					uint32_t expect = DSERVER_PROCESS_CONTROL_IDLE;
					if (__atomic_compare_exchange_n(&page->request_state, &expect,
					        DSERVER_PROCESS_CONTROL_PENDING, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
						slot = 1;
						break;
					}
					{
						long ts[2] = {0, 1000000L};
						(void)LINUX_SYSCALL6(__NR_nanosleep, ts, 0, 0, 0, 0, 0);
					}
				}
				if (slot) {
					static uint32_t fork_checkin_seq = 0;
					// ATOMIC (doc section 70): see execve.c -- a plain ++ can collide between threads.
					uint32_t mine = __atomic_add_fetch(&fork_checkin_seq, 1, __ATOMIC_RELAXED);
					page->reply_state = DSERVER_PROCESS_CONTROL_IDLE;
					page->request_op = DSERVER_PROCESS_CONTROL_OP_CHECKIN;
					// perf#30 (directive D1): THREAD IDENTITY travels with every request, including this
					// hand-rolled publisher: a management request that carries no identity is refused
					// (-ESRCH), never serviced against whatever thread the pid resolves to.
					page->request_tid = (int32_t)LINUX_SYSCALL(__NR_gettid);
					page->request_seq = mine;
					// perf#30 THE DUPLICATE-CHECKIN DEFECT (doc section 57): `1u` is i386, not this image's
					// architecture, and the server throws on the mismatch -- the page route answered
					// -EINVAL, the guest repeated the checkin on the datagram, and half of all checkins
					// were duplicates. Ask the same hook the datagram path asks.
					page->request_payload[0] = (uint64_t)DSERVER_GUEST_ARCH_BYTE | (1u << 8);  // arch | is_fork
					page->request_payload[1] = (uint64_t)LINUX_SYSCALL(__NR_gettid);
					page->request_payload[2] = token;
					page->request_payload[3] = (uint64_t)(uintptr_t)&dummy_stack_variable;
					__atomic_store_n(&page->request_state, DSERVER_PROCESS_CONTROL_PENDING, __ATOMIC_RELEASE);
					{
						int courier = __dserver_fd_courier_socket();
						if (courier >= 0) {
							char wake = 0;
							(void)LINUX_SYSCALL6(__NR_sendto, courier, &wake, 1, 0x40, 0, 0);
						}
					}
					int spins = 0, claimed = 0;
					while (__atomic_load_n(&page->reply_state, __ATOMIC_ACQUIRE) != DSERVER_PROCESS_CONTROL_DONE) {
						if (__atomic_load_n(&page->reply_state, __ATOMIC_ACQUIRE) == DSERVER_PROCESS_CONTROL_CLAIMED) {
							claimed = 1;
						}
						if (++spins < 20000) { continue; }
						{
							uint32_t seen = page->futex;
							long ts[2] = {0, claimed ? 2000000L : 1000000L};
							if (page->reply_state == DSERVER_PROCESS_CONTROL_DONE) { break; }
							(void)LINUX_SYSCALL6(__NR_futex, &page->futex, 0, seen, ts, 0, 0);
						}
					}
					// read before release (doc 71): releasing first lets the next thread overwrite the fields.
					uint32_t seenState = __atomic_load_n(&page->reply_state, __ATOMIC_ACQUIRE);
					uint32_t seenSeq = page->reply_seq;
					int32_t seenStatus = page->reply_status;
	{ uint32_t _st = __atomic_load_n(&(page)->request_state, __ATOMIC_ACQUIRE); if (_st == DSERVER_PROCESS_CONTROL_PENDING) { static const char _m[] = "[release-drops-pending] site=fork.c:184\n"; long _a = 1, _d = 2, _s = (long)_m, _n = sizeof(_m) - 1; __asm__ volatile("syscall" : "+a"(_a), "+D"(_d), "+S"(_s), "+d"(_n) : : "rcx", "r11", "memory"); } }
					DSERVER_PROCESS_CONTROL_RELEASE(page);
					if (seenState == DSERVER_PROCESS_CONTROL_DONE && seenSeq == mine && seenStatus == 0) {
						child_checked_in = 1;
					} else if (claimed) {
						child_checked_in = 1;  // the server owns the same operation
					}
				}
			}
		}
		if (!child_checked_in && dserver_rpc_checkin(true, &dummy_stack_variable, newReadFd) < 0) {
			// we can't do ANYTHING if darlingserver fails to acknowledge us
			__simple_printf("Failed to checkin with darlingserver after fork\n");
			__simple_abort();
		}
		if (wdfd >= 0)
			sys_fchdir(wdfd);

		__dserver_close_process_lifetime_pipe(newReadFd);
	}

	return ret;
}

long sys_fork(void)
{
	return fork_with_exit_signal(LINUX_SIGCHLD, NULL);
}

long fork_for_spawn(int* pidfd)
{
	/* Linux exec resets the exit signal to SIGCHLD before closing CLOEXEC fds. */
	return fork_with_exit_signal(0, pidfd);
}
