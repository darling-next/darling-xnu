#include <darling/emulation/xnu_syscall/bsd/impl/process/setpriority.h>
#include <errno.h>

int sys_setpriority(int which, int who, int prio) {
	if (which == PRIO_DARWIN_THREAD) {
		if (who != 0) {
			return -EINVAL;
		}

		if (prio == 0 || prio == PRIO_DARWIN_BG || prio == PRIO_DARWIN_NONUI) {
			return 0;
		}

		return -EINVAL;
	}

	if (which == PRIO_DARWIN_PROCESS) {
		if (prio == 0 || prio == PRIO_DARWIN_BG || prio == PRIO_DARWIN_NONUI) {
			return 0;
		}

		return -EINVAL;
	}

	return LINUX_SYSCALL(__NR_setpriority, which, who, prio);

	// TODO: Errors
}
