#include <stddef.h>
#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/dirent/getdirentries.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/fcntl/open.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/xnu_syscall/bsd/impl/dirent/getdirentries.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/dup.h>
#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/open.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

#define ATTR_BIT_MAP_COUNT 5

#define COMMON_SUPPORTED (ATTR_CMN_NAME | ATTR_CMN_OBJTYPE | ATTR_CMN_FNDRINFO | ATTR_CMN_OBJTAG)
#define VOLUME_SUPPORTED 0
#define DIR_SUPPORTED (ATTR_DIR_ENTRYCOUNT)
#define FILE_SUPPORTED (ATTR_FILE_RSRCLENGTH)
#define FORK_SUPPORTED 0

#define ATTR_CMN_NAME 0x00000001
#define ATTR_CMN_OBJTYPE 0x00000008
#define ATTR_CMN_FNDRINFO 0x4000
#define ATTR_FILE_RSRCLENGTH 0x1000
#define ATTR_CMN_OBJTAG 0x00000010
#define ATTR_DIR_ENTRYCOUNT 0x00000002

// fsobj_type_t values (sys/vnode.h) returned for ATTR_CMN_OBJTYPE.
#define DTAPE_VNON  0
#define DTAPE_VREG  1
#define DTAPE_VDIR  2
#define DTAPE_VBLK  3
#define DTAPE_VCHR  4
#define DTAPE_VLNK  5
#define DTAPE_VSOCK 6
#define DTAPE_VFIFO 7

#define LINUX_S_IFMT   0170000
#define LINUX_S_IFSOCK 0140000
#define LINUX_S_IFLNK  0120000
#define LINUX_S_IFREG  0100000
#define LINUX_S_IFBLK  0060000
#define LINUX_S_IFDIR  0040000
#define LINUX_S_IFCHR  0020000
#define LINUX_S_IFIFO  0010000

#ifndef LINUX_AT_SYMLINK_NOFOLLOW
#define LINUX_AT_SYMLINK_NOFOLLOW 0x100
#endif

// attrreference_t as packed by getattrlist for variable-length attributes
// (e.g. ATTR_CMN_NAME). attr_dataoffset is relative to the reference itself.
struct dtape_attrreference {
	int attr_dataoffset;
	unsigned int attr_length;
};

#define XATTR_FINDER_INFO "com.apple.FinderInfo"
#define XATTR_RESOURCE_FORK "com.apple.ResourceFork"

#define FSOPT_NOFOLLOW 1
#define FSOPT_REPORT_FULLSIZE 4

#define VT_HFS 16

#define min(a,b) (((a) < (b)) ? (a) : (b))

extern void *memcpy(void *dest, const void *src, __SIZE_TYPE__ n);
extern void *memset(void *s, int c, __SIZE_TYPE__ n);
extern char *strcpy(char *dest, const char *src);
extern __SIZE_TYPE__ strlen(const char *s);

long
FUNC_NAME(int fd,

#if HAS_PATH
const char* path,
#endif

struct xnu_attrlist* alist, void *attributeBuffer, __SIZE_TYPE__ bufferSize, unsigned long options)
{
	int rv;
	char *ourBuffer, *next;
	__SIZE_TYPE__ spaceNeeded = 4; // 4 bytes for the length header

	if (!alist)
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

	if (alist->bitmapcount < ATTR_BIT_MAP_COUNT)
		return -EINVAL;

	if ((alist->commonattr & COMMON_SUPPORTED) != alist->commonattr)
		return -EINVAL;
	if ((alist->volattr & VOLUME_SUPPORTED) != alist->volattr)
		return -EINVAL;
	if ((alist->dirattr & DIR_SUPPORTED) != alist->dirattr)
		return -EINVAL;
	if ((alist->fileattr & FILE_SUPPORTED) != alist->fileattr)
		return -EINVAL;
	if ((alist->forkattr & FORK_SUPPORTED) != alist->forkattr)
		return -EINVAL;

	// ATTR_CMN_NAME: the entry's on-disk name. For the path variants this is the
	// basename of the supplied path; for fgetattrlist we resolve the fd through
	// /proc/self/fd. Ruby's Dir.glob (replace_real_basename) requests this for
	// every literal path component, so without it glob silently returns nothing.
	char nameBuf[256];
	const char *theName = nameBuf;
	__SIZE_TYPE__ nameFieldLen = 0; // strlen + 1 (NUL)
	__SIZE_TYPE__ nameAligned = 0;
	if (alist->commonattr & ATTR_CMN_NAME)
	{
#if HAS_PATH
		const char *p = path;
#else
		// resolve the fd to a path via /proc/self/fd/<fd>, then take its basename
		char fdlink[64];
		static const char pfx[] = "/proc/self/fd/";
		__SIZE_TYPE__ k = 0;
		for (const char *s = pfx; *s; ++s)
			fdlink[k++] = *s;
		if (fd == 0)
			fdlink[k++] = '0';
		else
		{
			int v = fd;
			char tmp[16];
			int t = 0;
			if (v < 0) { fdlink[k++] = '-'; v = -v; }
			while (v > 0 && t < (int) sizeof(tmp)) { tmp[t++] = (char) ('0' + (v % 10)); v /= 10; }
			while (t > 0)
				fdlink[k++] = tmp[--t];
		}
		fdlink[k] = '\0';
		long rl = LINUX_SYSCALL(__NR_readlinkat, -100 /* AT_FDCWD */, fdlink, nameBuf, sizeof(nameBuf) - 1);
		if (rl < 0)
			rl = 0;
		nameBuf[rl] = '\0';
		const char *p = nameBuf;
#endif
		// strip trailing slashes, then isolate the basename
		__SIZE_TYPE__ pl = strlen(p);
		while (pl > 1 && p[pl - 1] == '/')
			--pl;
		__SIZE_TYPE__ start = 0;
		for (__SIZE_TYPE__ i = pl; i > 0; --i)
		{
			if (p[i - 1] == '/') { start = i; break; }
		}
		__SIZE_TYPE__ bl = pl - start;
		char tmpname[256];
		if (bl > sizeof(tmpname) - 1)
			bl = sizeof(tmpname) - 1;
		memcpy(tmpname, p + start, bl);
		tmpname[bl] = '\0';
		memcpy(nameBuf, tmpname, bl + 1); // p may alias nameBuf (fd case); copy via tmp first
		theName = nameBuf;
		nameFieldLen = bl + 1;
		nameAligned = (nameFieldLen + 3) & ~(__SIZE_TYPE__) 3;
		spaceNeeded += sizeof(struct dtape_attrreference) + nameAligned;
	}

	// ATTR_CMN_OBJTYPE: the vnode type (VREG/VDIR/VLNK/...). Ruby's glob requests
	// this together with ATTR_CMN_NAME and uses it to decide whether a plain path
	// component is a directory to descend into; getattrlist failing here makes
	// glob treat the component as non-existent.
	unsigned int objType = DTAPE_VNON;
	if (alist->commonattr & ATTR_CMN_OBJTYPE)
	{
		struct linux_stat lst;
		long sr;
		int lflags = (options & FSOPT_NOFOLLOW) ? LINUX_AT_SYMLINK_NOFOLLOW : 0;
#if HAS_PATH
#ifdef __NR_newfstatat
		sr = LINUX_SYSCALL(__NR_newfstatat, vc.dfd, vc.path, &lst, lflags);
#else
		sr = LINUX_SYSCALL(__NR_fstatat64, vc.dfd, vc.path, &lst, lflags);
#endif
#else
		sr = LINUX_SYSCALL(__NR_fstat, fd, &lst);
#endif
		if (sr >= 0)
		{
			unsigned int fmt = lst.st_mode & LINUX_S_IFMT;
			if (fmt == LINUX_S_IFREG) objType = DTAPE_VREG;
			else if (fmt == LINUX_S_IFDIR) objType = DTAPE_VDIR;
			else if (fmt == LINUX_S_IFLNK) objType = DTAPE_VLNK;
			else if (fmt == LINUX_S_IFBLK) objType = DTAPE_VBLK;
			else if (fmt == LINUX_S_IFCHR) objType = DTAPE_VCHR;
			else if (fmt == LINUX_S_IFSOCK) objType = DTAPE_VSOCK;
			else if (fmt == LINUX_S_IFIFO) objType = DTAPE_VFIFO;
		}
		spaceNeeded += sizeof(uint32_t); // fsobj_type_t
	}

	if (alist->commonattr & ATTR_CMN_FNDRINFO)
		spaceNeeded += 32;
	if (alist->fileattr & ATTR_FILE_RSRCLENGTH)
		spaceNeeded += 8; // off_t
	if (alist->commonattr & ATTR_CMN_OBJTAG)
		spaceNeeded += sizeof(uint32_t); // fsobj_tag_t
	if (alist->dirattr & ATTR_DIR_ENTRYCOUNT)
		spaceNeeded += sizeof(uint32_t);

	ourBuffer = (char*) __builtin_alloca(spaceNeeded);
	next = ourBuffer + 4;

	// ATTR_CMN_NAME is the lowest common-attr bit, so its fixed-size reference is
	// packed first; the name string itself goes into the variable-data area after
	// all fixed attributes (filled in below once `next` reaches that area).
	char *nameRef = 0;
	if (alist->commonattr & ATTR_CMN_NAME)
	{
		nameRef = next;
		next += sizeof(struct dtape_attrreference);
	}

	// ATTR_CMN_OBJTYPE (bit 0x8) is packed right after the name reference, matching
	// the field order Ruby's replace_real_basename expects (ref then objtype).
	if (alist->commonattr & ATTR_CMN_OBJTYPE)
	{
		*((uint32_t*) next) = objType;
		next += sizeof(uint32_t);
	}

	if (alist->commonattr & ATTR_CMN_FNDRINFO)
	{
#if HAS_PATH
		rv = LINUX_SYSCALL(__NR_getxattr, vc.path, XATTR_FINDER_INFO, next, 32);
#else
		rv = LINUX_SYSCALL(__NR_fgetxattr, fd, XATTR_FINDER_INFO, next, 32);
#endif
		if (rv < 0)
			memset(next, 0, 32);
		next += 32;
	}
	if (alist->fileattr & ATTR_FILE_RSRCLENGTH)
	{
#if HAS_PATH
		rv = LINUX_SYSCALL(__NR_getxattr, vc.path, XATTR_FINDER_INFO, NULL, 0);
#else
		rv = LINUX_SYSCALL(__NR_fgetxattr, fd, XATTR_FINDER_INFO, NULL, 0);
#endif
		if (rv < 0)
			*((uint32_t*) next) = 0;
		else
			*((uint32_t*) next) = rv;
		next += 4;
	}

	if (alist->commonattr & ATTR_CMN_OBJTAG) {
		// pretend we're always on HFS
		*((uint32_t*)next) = VT_HFS;
		next += 4;
	}

	if (alist->dirattr & ATTR_DIR_ENTRYCOUNT) {
		char buf[1024]; // maybe this should be smaller?
		int tmp_fd;

		*((uint32_t*)next) = 0;

#if HAS_PATH
		tmp_fd = LINUX_SYSCALL(__NR_openat, vc.dfd, vc.path, LINUX_O_RDONLY | LINUX_O_DIRECTORY, 0);
		if (tmp_fd < 0) {
			rv = -EIO; // translate all errors into EIO (to avoid confusing our caller)
			goto attr_dir_entrycount_out_no_fd;
		}
#else
		// dupe it to avoid advancing the internal `getdents` position if our caller is using that
		tmp_fd = sys_dup(fd);
		if (tmp_fd < 0) {
			rv = -EIO; // see above
			goto attr_dir_entrycount_out_no_fd;
		}
#endif

		while (1) {
			// there's basically no other way to do this (at least none that either i or the internet know of)
			rv = LINUX_SYSCALL(__NR_getdents64, tmp_fd, buf, sizeof(buf));
			if (rv < 0) {
				rv = -EIO; // same as before: avoid confusing our caller with unexepected errnos
				goto attr_dir_entrycount_out;
			} else if (rv == 0) {
				break;
			}

			for (char* iter = buf; iter < buf + rv; iter += ((struct linux_dirent64*)iter)->d_reclen) {
				++(*((uint32_t*)next));
			}
		}

attr_dir_entrycount_out:
		close_internal(tmp_fd);
attr_dir_entrycount_out_no_fd:
		next += 4;
	}

	if (nameRef)
	{
		// `next` now points at the variable-data area (after every fixed attr).
		struct dtape_attrreference *ref = (struct dtape_attrreference*) nameRef;
		ref->attr_dataoffset = (int) (next - nameRef);
		ref->attr_length = (unsigned int) nameFieldLen;
		memcpy(next, theName, nameFieldLen);
		next += nameAligned;
	}

	if (!(options & FSOPT_REPORT_FULLSIZE) && bufferSize < spaceNeeded)
		bufferSize = spaceNeeded;

	*((uint32_t*) ourBuffer) = bufferSize;

	memcpy(attributeBuffer, ourBuffer, min(bufferSize, spaceNeeded));
	
	return 0;
}
