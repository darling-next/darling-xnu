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
#include <darling/emulation/linux_premigration/elfcalls_wrapper.h>
#include <darling/emulation/other/mach/lkm.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>
#include <darling/emulation/common/guarded/table.h>
#include <darling/emulation/linux_premigration/resources/dserver-ring.h>

#include <darlingserver/rpc.h>

extern _libkernel_functions_t _libkernel_functions;

#define LINUX_CLONE_PIDFD 0x00001000

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

		// create a new dserver RPC socket
		__dserver_per_thread_socket_refresh();
		// The loader already closed both images' inherited ring FDs. Drop this
		// image's mappings without closing numbers the new RPC socket may reuse.
		__dserver_ring_postfork_reset();
		int newReadFd = __dserver_process_lifetime_pipe_refresh();

		// guard it
		guard_entry_options_t options;
		options.close = __dserver_close_socket;
		guard_table_add(__dserver_per_thread_socket(), guard_flag_prevent_close | guard_flag_close_on_fork, &options);

		// only guard the lifetime pipe if it's used.
		if (newReadFd != -1)
		{
			options.close = __dserver_close_process_lifetime_pipe;
			guard_table_add(__dserver_get_process_lifetime_pipe(), guard_flag_prevent_close | guard_flag_close_on_fork, &options);
		}

		int dummy_stack_variable;
		if (dserver_rpc_checkin(true, &dummy_stack_variable, newReadFd) < 0) {
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
