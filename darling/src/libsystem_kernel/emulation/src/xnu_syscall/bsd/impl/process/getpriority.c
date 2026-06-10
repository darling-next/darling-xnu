#include <darling/emulation/xnu_syscall/bsd/impl/process/getpriority.h>
#include <errno.h>

int sys_getpriority(int which, id_t who) {
	if (which == PRIO_DARWIN_THREAD) {
		if (who != 0) {
			return EINVAL;
		}

		return 0;
	}

	if (which == PRIO_DARWIN_PROCESS) {
		return 0;
	}

	return LINUX_SYSCALL(__NR_getpriority, which, who);

	// TODO: Errors
}
