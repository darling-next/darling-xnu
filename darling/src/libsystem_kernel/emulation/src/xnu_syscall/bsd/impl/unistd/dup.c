#include <darling/emulation/xnu_syscall/bsd/impl/unistd/dup.h>

#include <sys/errno.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/common/guarded/table.h>

__attribute__((weak))
__attribute__((visibility("default")))
void kqueue_dup(int oldfd, int newfd) { }

long sys_dup(int fd)
{
	int ret;

	// dar-6x4.1: a reserved darlingserver RPC fd is out-of-range to the guest;
	// duplicating it must look like an invalid fd (EBADF), not expose the socket.
	if (guard_table_check(fd, guard_flag_prevent_close)) {
		return -EBADF;
	}

	ret = LINUX_SYSCALL1(__NR_dup, fd);
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);
	else
		kqueue_dup(fd, ret);

	return ret;
}
