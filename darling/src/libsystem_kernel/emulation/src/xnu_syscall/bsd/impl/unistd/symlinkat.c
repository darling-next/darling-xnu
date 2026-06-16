#include <darling/emulation/xnu_syscall/bsd/impl/unistd/symlinkat.h>

#include <sys/errno.h>

#include <darling/emulation/other/mach/lkm.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/common/bsdthread/per_thread_wd.h>

long sys_symlinkat(const char* path, int fd, const char* link)
{
	int ret;
	struct vchroot_expand_args vc;

	vc.flags = 0;
	vc.dfd = get_perthread_wd();

#ifdef EUNION
	// creating a symlink at `link`: copy up its parent dir (so the link lands in
	// the upper layer, not the shared template) and clear any whiteout at the name.
	if (link[0] == '/') {
		int wr = vchroot_prepare_create(link);
		if (wr < 0)
			return errno_linux_to_bsd(wr);
	}
#endif

	strcpy(vc.path, link);

	ret = vchroot_expand(&vc);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	ret = LINUX_SYSCALL(__NR_symlinkat, path, vc.dfd, vc.path);
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
}
