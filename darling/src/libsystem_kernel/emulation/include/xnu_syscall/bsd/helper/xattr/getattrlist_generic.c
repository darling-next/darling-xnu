#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/conversion/dirent/getdirentries.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/fcntl/open.h>
#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/xnu_syscall/bsd/helper/xattr/getattrlist_pack.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/fdpath.h>
#include <darling/emulation/xnu_syscall/bsd/impl/dirent/getdirentries.h>
#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/open.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/dup.h>

#ifndef LINUX_AT_SYMLINK_NOFOLLOW
#define LINUX_AT_SYMLINK_NOFOLLOW 0x100
#endif

#define XATTR_FINDER_INFO "com.apple.FinderInfo"
#define XATTR_RESOURCE_FORK "com.apple.ResourceFork"

#define FSOPT_NOFOLLOW 1

#ifndef LINUX_O_RDONLY
#define LINUX_O_RDONLY    0
#endif
#define LINUX_O_DIRECTORY 0200000

#define min(a,b) (((a) < (b)) ? (a) : (b))

static int darling_getattr_is_dot_or_dotdot(const char* name)
{
	if (name[0] != '.')
		return 0;
	if (name[1] == '\0')
		return 1;
	if (name[1] == '.' && name[2] == '\0')
		return 1;
	return 0;
}

static uint32_t darling_count_dir_entries(int fd)
{
	uint32_t count = 0;
	char buf[2048];

	while (1) {
		long rv = LINUX_SYSCALL(__NR_getdents64, fd, buf, sizeof(buf));
		if (rv <= 0)
			break;

		for (char* iter = buf; iter < buf + rv; iter += ((struct linux_dirent64*)iter)->d_reclen) {
			if (!darling_getattr_is_dot_or_dotdot(((struct linux_dirent64*)iter)->d_name))
				++count;
		}
	}

	return count;
}

static uint32_t darling_getattr_dir_entrycount(int fd
#if HAS_PATH
	, const struct vchroot_expand_args* vc
#endif
)
{
	int tmp_fd;

#if HAS_PATH
	tmp_fd = LINUX_SYSCALL(__NR_openat, vc->dfd, vc->path, LINUX_O_RDONLY | LINUX_O_DIRECTORY, 0);
#else
	tmp_fd = sys_dup(fd);
#endif
	if (tmp_fd < 0)
		return 0;

	uint32_t count = darling_count_dir_entries(tmp_fd);
	close_internal(tmp_fd);
	return count;
}

static void darling_getattr_basename(char* out, size_t out_size, int fd
#if HAS_PATH
	, const char* path
#endif
)
{
#if HAS_PATH
	const char* p = path;
#else
	if (fdpath(fd, out, out_size) < 0)
		out[0] = '\0';
	const char* p = out;
#endif

	size_t plen = strlen(p);
	while (plen > 1 && p[plen - 1] == '/')
		--plen;

	if (plen == 1 && p[0] == '/') {
		if (out_size > 1) {
			out[0] = '/';
			out[1] = '\0';
		}
		return;
	}

	size_t start = 0;
	for (size_t i = plen; i > 0; --i) {
		if (p[i - 1] == '/') {
			start = i;
			break;
		}
	}

	size_t len = plen - start;
	if (len > out_size - 1)
		len = out_size - 1;

	char tmpname[256];
	if (len > sizeof(tmpname) - 1)
		len = sizeof(tmpname) - 1;
	memcpy(tmpname, p + start, len);
	tmpname[len] = '\0';
	memcpy(out, tmpname, len + 1);
}

long
FUNC_NAME(int fd,

#if HAS_PATH
const char* path,
#endif

struct xnu_attrlist* alist, void *attributeBuffer, __SIZE_TYPE__ bufferSize, unsigned long options)
{
	int rv = darling_attrlist_validate(alist, 0);
	if (rv < 0)
		return rv;
	if (!attributeBuffer)
		return -EFAULT;

#if HAS_PATH
	if (!path)
		return -EFAULT;

	struct vchroot_expand_args vc;
	vc.flags = (options & FSOPT_NOFOLLOW) ? 0 : VCHROOT_FOLLOW;
	vc.dfd = atfd(fd);
	strcpy(vc.path, path);

	rv = vchroot_expand(&vc);
	if (rv < 0)
		return rv;
#endif

	struct darling_attrpack_entry entry;
	memset(&entry, 0, sizeof(entry));

	char name_buf[256];
	if (alist->commonattr & DARLING_ATTR_CMN_NAME) {
		darling_getattr_basename(name_buf, sizeof(name_buf), fd
#if HAS_PATH
			, path
#endif
		);
		entry.name = name_buf;
		entry.name_len = strlen(name_buf);
	}

	struct linux_stat lst;
	long stat_rv = 0;
	int need_stat = darling_attr_wants_objtype(alist);
	if (need_stat) {
		int lflags = (options & FSOPT_NOFOLLOW) ? LINUX_AT_SYMLINK_NOFOLLOW : 0;
#if HAS_PATH
#ifdef __NR_newfstatat
		stat_rv = LINUX_SYSCALL(__NR_newfstatat, vc.dfd, vc.path, &lst, lflags);
#else
		stat_rv = LINUX_SYSCALL(__NR_fstatat64, vc.dfd, vc.path, &lst, lflags);
#endif
#else
		stat_rv = LINUX_SYSCALL(__NR_fstat, fd, &lst);
#endif
	}

	if (alist->commonattr & DARLING_ATTR_CMN_OBJTYPE) {
		entry.has_objtype = 1;
		entry.objtype = (stat_rv >= 0) ? darling_objtype_from_mode(lst.st_mode) : DARLING_DTAPE_VNON;
	}
	if (alist->commonattr & DARLING_ATTR_CMN_OBJTAG) {
		entry.has_objtag = 1;
		entry.objtag = DARLING_VT_UNKNOWN;
	}
	if (alist->commonattr & DARLING_ATTR_CMN_FNDRINFO) {
		static const char zero_finderinfo[32] = {0};
		char finderinfo[32];
#if HAS_PATH
		long xr = LINUX_SYSCALL(__NR_getxattr, vc.path, XATTR_FINDER_INFO, finderinfo, sizeof(finderinfo));
#else
		long xr = LINUX_SYSCALL(__NR_fgetxattr, fd, XATTR_FINDER_INFO, finderinfo, sizeof(finderinfo));
#endif
		entry.has_finderinfo = 1;
		entry.finderinfo = xr >= 0 ? finderinfo : zero_finderinfo;
	}
	if (alist->commonattr & DARLING_ATTR_CMN_ERROR) {
		entry.has_error = 1;
		entry.error = 0;
	}
	if (alist->dirattr & DARLING_ATTR_DIR_ENTRYCOUNT) {
		entry.has_dir_entrycount = 1;
		if (stat_rv >= 0 && darling_objtype_from_mode(lst.st_mode) == DARLING_DTAPE_VDIR) {
			entry.dir_entrycount = darling_getattr_dir_entrycount(fd
#if HAS_PATH
				, &vc
#endif
			);
		}
	}
	if (alist->fileattr & DARLING_ATTR_FILE_RSRCLENGTH) {
		long xr;
#if HAS_PATH
		xr = LINUX_SYSCALL(__NR_getxattr, vc.path, XATTR_RESOURCE_FORK, 0, 0);
#else
		xr = LINUX_SYSCALL(__NR_fgetxattr, fd, XATTR_RESOURCE_FORK, 0, 0);
#endif
		entry.has_file_rsrclength = 1;
		entry.file_rsrclength = xr > 0 ? (uint64_t)xr : 0;
	}

	size_t space_needed = darling_attrpack_entry_size(alist, &entry);
	char* out = (char*)__builtin_alloca(space_needed);
	darling_attrpack_entry(out, alist, &entry);

	if (bufferSize < space_needed && !(options & DARLING_FSOPT_REPORT_FULLSIZE))
		return -ERANGE;

	memcpy(attributeBuffer, out, min(bufferSize, space_needed));
	return 0;
}
