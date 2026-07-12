#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/openat.h>

#include <sys/fcntl.h>

#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/open.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/fcntl/open.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/xnu_syscall/bsd/helper/bsdthread/cancelable.h>

#include <darlingserver/rpc.h>

#ifndef O_NOFOLLOW
#	define O_NOFOLLOW 0x0100
#endif
#ifndef O_CLOEXEC
#	define O_CLOEXEC 0x1000000
#endif
#ifndef O_DIRECTORY
#	define O_DIRECTORY 0x100000
#endif

extern int strcmp(const char *s1, const char *s2);
extern char* strcpy(char* dst, const char* src);

long sys_openat(int fd, const char* filename, int flags, unsigned int mode)
{
	CANCELATION_POINT();
	return sys_openat_nocancel(fd, filename, flags, mode);
}

long sys_openat_nocancel(int fd, const char* filename, int flags, unsigned int mode)
{
	int ret, linux_flags;
	if (!filename)
		return -EFAULT;

	linux_flags = oflags_bsd_to_linux(flags);

	if (sizeof(void*) == 4)
	{
		linux_flags |= LINUX_O_LARGEFILE;
	}

	// XNU /dev/random behaves like Linux /dev/urandom
	if (strcmp(filename, "/dev/random") == 0)
		filename = "/dev/urandom";
	// Expected by launchd and CF
	else if (strcmp(filename, "/dev/autofs_nowait") == 0)
		filename = "/dev/null";
	else if (strcmp(filename, "/dev/console") == 0) {
		// redirect console output to darlingserver
		int err = dserver_rpc_console_open(&ret);
		if (err < 0) {
			__simple_printf("dserver_rpc_console_open failed internally: %d", err);
			__simple_abort();
		}
		if (err > 0) {
			ret = errno_linux_to_bsd(-err);
		}
		return ret;
	}

	struct vchroot_expand_args vc;
	int use_upper_path = 0;

#ifdef EUNION
	// E-UNION: if this open writes/creates/truncates, materialize the target in
	// the writable upper layer BEFORE expand so the real syscall never mutates the
	// shared read-only template. Handles BOTH absolute paths and dirfd-relative
	// paths (openat into a lower-only dir): prepare_write_at resolves the dirfd to
	// a guest path and joins the relative target. (Read-only opens are left alone.)
	int union_path = 1;
	char guest_path[4096];
	char upper_path[4096];
	int mutating = ((flags & 0x3) == BSD_O_WRONLY || (flags & 0x3) == BSD_O_RDWR ||
		(flags & BSD_O_CREAT) || (flags & BSD_O_TRUNC));
	if (mutating || filename[0] != '/') {
		union_path = vchroot_canonical_guest_path(atfd(fd), filename,
			guest_path, sizeof(guest_path));
		if (union_path < 0)
			return errno_linux_to_bsd(union_path);
	}
	if (union_path == 0 && mutating) {
		int wr = vchroot_prepare_write(guest_path);
		if (wr < 0)
			return errno_linux_to_bsd(wr);
		if (flags & BSD_O_CREAT) {
			wr = vchroot_prepare_create_path(guest_path, upper_path, sizeof(upper_path));
			if (wr < 0)
				return errno_linux_to_bsd(wr);
			if (wr > 0) {
				strcpy(vc.path, upper_path);
				vc.dfd = LINUX_AT_FDCWD;
				use_upper_path = 1;
			}
		}
	}
#endif

	vc.flags = (flags & BSD_O_SYMLINK || flags & BSD_O_NOFOLLOW) ? 0 : VCHROOT_FOLLOW;
	vc.dfd = atfd(fd);

	if (!use_upper_path) {
#ifdef EUNION
		if (union_path == 0) {
			strcpy(vc.path, guest_path);
			vc.dfd = LINUX_AT_FDCWD;
		} else
#endif
			strcpy(vc.path, filename);
		ret = vchroot_expand(&vc);
	} else {
		ret = 0;
	}
	if (ret < 0) {
		return errno_linux_to_bsd(ret);
	}

	// when we're given O_SYMLINK, `oflags_bsd_to_linux` translates it into
	// O_NOFOLLOW and O_PATH
	// this is the only way to open the symlink itself on Linux
	// unfortunately, this presents additional challenges
	// only a select few Linux syscalls support O_PATH descriptors, which means
	// that for other syscalls, we either have to check for this and use an
	// `l` variant (e.g. `llistxattr` instead of `listxatrr`) or we're screwed

	ret = LINUX_SYSCALL(__NR_openat, vc.dfd, vc.path, linux_flags, mode);
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
}
