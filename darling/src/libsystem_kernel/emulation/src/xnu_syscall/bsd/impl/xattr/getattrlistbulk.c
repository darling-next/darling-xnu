#include <darling/emulation/xnu_syscall/bsd/impl/xattr/getattrlistbulk.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/dirent/getdirentries.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/xattr/getattrlist_pack.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/lseek.h>

#ifndef LINUX_AT_SYMLINK_NOFOLLOW
#define LINUX_AT_SYMLINK_NOFOLLOW 0x100
#endif

#ifndef LINUX_O_RDONLY
#define LINUX_O_RDONLY    0
#endif
#define LINUX_O_DIRECTORY 0200000
#define LINUX_SEEK_SET 0

static int is_dot_or_dotdot(const char* name)
{
	if (name[0] != '.')
		return 0;
	if (name[1] == '\0')
		return 1;
	if (name[1] == '.' && name[2] == '\0')
		return 1;
	return 0;
}

static unsigned int dir_entry_count(int dirfd, const char* name)
{
	int subfd = LINUX_SYSCALL(__NR_openat, dirfd, name, LINUX_O_RDONLY | LINUX_O_DIRECTORY, 0);
	if (subfd < 0)
		return 0;

	unsigned int n = 0;
	char buf[2048];
	while (1) {
		long r = LINUX_SYSCALL(__NR_getdents64, subfd, buf, sizeof(buf));
		if (r <= 0)
			break;
		for (char* it = buf; it < buf + r; it += ((struct linux_dirent64*) it)->d_reclen) {
			if (!is_dot_or_dotdot(((struct linux_dirent64*) it)->d_name))
				++n;
		}
	}

	close_internal(subfd);
	return n;
}

long sys_getattrlistbulk(int fd, struct xnu_attrlist* alist, void* attributeBuffer, __SIZE_TYPE__ bufferSize, unsigned long options)
{
	(void)options;

	if (!attributeBuffer)
		return -EFAULT;

	int rv = darling_attrlist_validate(alist, 1);
	if (rv < 0)
		return rv;

	const int need_type = darling_attr_wants_objtype(alist);
	char* outp = (char*)attributeBuffer;
	size_t out_remaining = bufferSize;
	int count = 0;

	while (1) {
		char dbuf[4096];
		long n = LINUX_SYSCALL(__NR_getdents64, fd, dbuf, sizeof(dbuf));
		if (n < 0)
			return errno_linux_to_bsd(n);
		if (n == 0)
			return count;

		long long committed_off = -1;
		int stopped_early = 0;

		for (char* iter = dbuf; iter < dbuf + n; ) {
			struct linux_dirent64* de = (struct linux_dirent64*)iter;
			char* de_next = iter + de->d_reclen;

			if (is_dot_or_dotdot(de->d_name)) {
				committed_off = (long long)de->d_off;
				iter = de_next;
				continue;
			}

			struct darling_attrpack_entry entry;
			memset(&entry, 0, sizeof(entry));

			entry.name = de->d_name;
			entry.name_len = strlen(de->d_name);

			unsigned int objtype = DARLING_DTAPE_VNON;
			if (need_type) {
				objtype = darling_objtype_from_dtype(de->d_type);
				if (objtype == DARLING_DTAPE_VNON) {
					struct linux_stat lst;
					long sr;
#ifdef __NR_newfstatat
					sr = LINUX_SYSCALL(__NR_newfstatat, fd, de->d_name, &lst, LINUX_AT_SYMLINK_NOFOLLOW);
#else
					sr = LINUX_SYSCALL(__NR_fstatat64, fd, de->d_name, &lst, LINUX_AT_SYMLINK_NOFOLLOW);
#endif
					if (sr >= 0)
						objtype = darling_objtype_from_mode(lst.st_mode);
				}
			}

			if (alist->commonattr & DARLING_ATTR_CMN_OBJTYPE) {
				entry.has_objtype = 1;
				entry.objtype = objtype;
			}
			if (alist->commonattr & DARLING_ATTR_CMN_OBJTAG) {
				entry.has_objtag = 1;
				entry.objtag = DARLING_VT_UNKNOWN;
			}
			if (alist->commonattr & DARLING_ATTR_CMN_FNDRINFO) {
				static const char zero_finderinfo[32] = {0};
				entry.has_finderinfo = 1;
				entry.finderinfo = zero_finderinfo;
			}
			if (alist->commonattr & DARLING_ATTR_CMN_ERROR) {
				entry.has_error = 1;
				entry.error = 0;
			}
			if ((alist->dirattr & DARLING_ATTR_DIR_ENTRYCOUNT) && objtype == DARLING_DTAPE_VDIR) {
				entry.has_dir_entrycount = 1;
				entry.dir_entrycount = dir_entry_count(fd, de->d_name);
			}
			if ((alist->fileattr & DARLING_ATTR_FILE_RSRCLENGTH) && objtype == DARLING_DTAPE_VREG) {
				entry.has_file_rsrclength = 1;
				entry.file_rsrclength = 0;
			}

			size_t space_needed = darling_attrpack_entry_size(alist, &entry);
			if (space_needed > out_remaining) {
				stopped_early = 1;
				break;
			}

			size_t packed = darling_attrpack_entry(outp, alist, &entry);
			outp += packed;
			out_remaining -= packed;
			committed_off = (long long)de->d_off;
			++count;
			iter = de_next;
		}

		if (stopped_early) {
			if (committed_off >= 0)
				sys_lseek(fd, committed_off, LINUX_SEEK_SET);
			if (count == 0)
				return -EINVAL;
			return count;
		}

		if (count > 0)
			return count;
	}
}
