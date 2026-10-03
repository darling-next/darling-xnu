#include <darling/emulation/xnu_syscall/bsd/impl/unistd/lseek.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#ifdef EUNION
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#define LINUX_SEEK_SET 0
#endif

long long sys_lseek(int fd, long long offset, int whence)
{
	long long ret;

#ifdef SYS__llseek
	long long roff;
	ret = LINUX_SYSCALL(__NR__llseek, fd, (unsigned int)offset >> 32,
			(unsigned int)offset, &roff, whence);

	if (ret >= 0)
		ret = roff;
#else
	ret = LINUX_SYSCALL(__NR_lseek, fd, offset, whence);
#endif
#ifdef EUNION
	if (ret >= 0 && offset == 0 && whence == LINUX_SEEK_SET)
		vchroot_dir_rewind(fd);
#endif
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
}
