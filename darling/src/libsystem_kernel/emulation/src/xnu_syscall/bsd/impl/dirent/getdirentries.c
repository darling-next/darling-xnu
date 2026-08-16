#include <darling/emulation/xnu_syscall/bsd/impl/dirent/getdirentries.h>

#include <sys/dirent.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/dirent/getdirentries.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/linux_premigration/guest_namespace_authority.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/fdpath.h>
#ifdef EUNION
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#endif

#define LINUX_SEEK_SET 0
#define LINUX_SEEK_CUR 1

extern __SIZE_TYPE__ strlen(const char* s);
extern char* strcpy(char* dest, const char* src);
extern int strcmp(const char* str1, const char* str2);

#ifndef min
#	define min(a,b) ((a) < (b)) ? (a) : (b)
#endif

#define ALIGN(x, alignment) (((x) + (alignment - 1)) & ~(alignment - 1))
#define BSD_DIRENT_MIN_SIZE ALIGN(sizeof(struct bsd_dirent) + 2, 4)
#define BSD_DIRENT64_MIN_SIZE ALIGN(sizeof(struct bsd_dirent64) + 2, 4)
#define LINUX_DIRENT64_MIN_SIZE ALIGN(sizeof(struct linux_dirent64) + 2, 8)

static int protected_fd_directory(int fd) {
	char path[1024];
	if (darling_guest_namespace_state() != DARLING_GUEST_NAMESPACE_REQUIRED ||
		fdpath(fd, path, sizeof(path)) < 0) return 0;
	int length = (int)strlen(path);
	return length >= 9 && path[0] == '/' && path[1] == 'p' && path[2] == 'r' &&
		path[3] == 'o' && path[4] == 'c' && path[length - 3] == '/' &&
		path[length - 2] == 'f' && path[length - 1] == 'd';
}

static int hidden_capability_name(const char* name) {
	if (!name || !*name) return 0;
	int value = 0;
	for (const char* cursor = name; *cursor; ++cursor) {
		if (*cursor < '0' || *cursor > '9') return 0;
		value = value * 10 + (*cursor - '0');
	}
	for (unsigned int index = 0; index < 5; ++index)
		if (darling_guest_namespace_protected_fd(index) == value) return 1;
	return 0;
}

static inline void round_to_4(unsigned short* reclen)
{
	if (*reclen & 3)
	{
		*reclen += 3;
		*reclen /= 4;
		*reclen *= 4;
	}
}

long sys_getdirentries(int fd, char* ibuf, unsigned int len, long* basep)
{
	int ret, bpos = 0, opos = 0;
	unsigned int hidden_only_pages = 0;

	unsigned int max_entry_count = len / BSD_DIRENT_MIN_SIZE;

	// don't want to blow up the stack
	if (max_entry_count > 20)
		max_entry_count = 20;

	char buf[max_entry_count * LINUX_DIRENT64_MIN_SIZE];

	if (basep)
		*basep = 0;

read_next_page:
	bpos = 0;
#ifdef EUNION
	// E-UNION: merged listing (upper + lower template, whiteouts subtracted,
	// opaque honoured). Per-fd state is freed by close() via vchroot_dir_closed.
	ret = vchroot_getdents_merge(fd, buf, sizeof(buf));
#else
	ret = LINUX_SYSCALL(__NR_getdents64, fd, buf, sizeof(buf));
#endif
	if (ret < 0)
		return errno_linux_to_bsd(ret);
	int hide_capabilities = protected_fd_directory(fd);

	while (bpos < ret && opos < len)
	{
		struct linux_dirent64* l64;
		struct bsd_dirent* bsd;
		int slen;

		l64 = (struct linux_dirent64*) (buf + bpos);
		if (hide_capabilities && hidden_capability_name(l64->d_name)) {
			bpos += l64->d_reclen;
			continue;
		}
		bsd = (struct bsd_dirent*) (ibuf + opos);
		slen = strlen(l64->d_name);

		if (len-opos < sizeof(struct bsd_dirent) + slen + 1)
			break;

		bsd->d_ino = l64->d_ino;
		bsd->d_type = l64->d_type;
		strcpy(bsd->d_name, l64->d_name);

		bsd->d_reclen = sizeof(struct bsd_dirent) + slen + 1;
		bsd->d_namlen = slen;

		round_to_4(&bsd->d_reclen);

		opos += bsd->d_reclen;
		bpos += l64->d_reclen;
	}
	/* A Linux page containing only protected internal descriptors is not EOF.
	 * Continue to the actual EOF (or a bounded fail-closed error). */
	if (ret > 0 && opos == 0 && bpos >= ret) {
		if (++hidden_only_pages > 64)
			return errno_linux_to_bsd(-LINUX_EIO);
		goto read_next_page;
	}

	return opos;
}

struct dirent64 __DARWIN_STRUCT_DIRENTRY;

long sys_getdirentries64(int fd, char* ibuf, unsigned int len, long* basep)
{
	int ret, bpos = 0, opos = 0;
	unsigned int hidden_only_pages = 0;

	unsigned int max_entry_count = len / BSD_DIRENT64_MIN_SIZE;

	// don't want to blow up the stack
	if (max_entry_count > 20)
		max_entry_count = 20;

	char buf[max_entry_count * LINUX_DIRENT64_MIN_SIZE];

	if (basep)
		*basep = 0;

read_next_page64:
	bpos = 0;
#ifdef EUNION
	ret = vchroot_getdents_merge(fd, buf, sizeof(buf));
#else
	ret = LINUX_SYSCALL(__NR_getdents64, fd, buf, sizeof(buf));
#endif
	if (ret < 0)
		return errno_linux_to_bsd(ret);
	int hide_capabilities = protected_fd_directory(fd);

	while (bpos < ret && opos < len)
	{
		struct linux_dirent64* l64;
		struct bsd_dirent64* bsd;
		int slen;

		l64 = (struct linux_dirent64*) (buf + bpos);
		if (hide_capabilities && hidden_capability_name(l64->d_name)) {
			bpos += l64->d_reclen;
			continue;
		}
		bsd = (struct bsd_dirent64*) (ibuf + opos);
		slen = strlen(l64->d_name);

		if (len-opos < sizeof(struct bsd_dirent64) + slen + 1)
			break;

		bsd->d_ino = l64->d_ino;
		bsd->d_type = l64->d_type;
		strcpy(bsd->d_name, l64->d_name);

		bsd->d_reclen = sizeof(struct bsd_dirent64) + slen + 1;
		bsd->d_namlen = slen;
		bsd->d_seekoff = 0;

		round_to_4(&bsd->d_reclen);

		opos += bsd->d_reclen;
		bpos += l64->d_reclen;
	}
	if (ret > 0 && opos == 0 && bpos >= ret) {
		if (++hidden_only_pages > 64)
			return errno_linux_to_bsd(-LINUX_EIO);
		goto read_next_page64;
	}

	/*
	if (bpos < ret) {
		__simple_printf("bpos < ret; %d < %d", bpos, ret);
	}
	*/

	return opos;
}
