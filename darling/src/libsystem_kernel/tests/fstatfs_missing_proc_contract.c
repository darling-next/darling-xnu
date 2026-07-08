#include "fstatfs_missing_proc_stubs.h"

#include <stdio.h>
#include <string.h>

static int saw_mounts_open;

long fake_linux_fstatfs64(int fd, unsigned long size, struct linux_statfs64* buf)
{
	if (fd != 42 || size != sizeof(*buf) || buf == NULL)
		return -22;
	memset(buf, 0, sizeof(*buf));
	buf->f_type = 0x1234;
	return 0;
}

int fdpath(int fd, char* path, unsigned long size)
{
	if (fd != 42 || path == NULL || size < 5)
		return -22;
	strcpy(path, "/tmp");
	return 0;
}

long sys_open(const char* path, int flags, int mode)
{
	(void)flags;
	(void)mode;
	if (strcmp(path, "/proc/self/mounts") != 0)
		return -2;
	saw_mounts_open = 1;
	return -2;
}

unsigned long strlcpy(char* dst, const char* src, unsigned long size)
{
	unsigned long len = strlen(src);
	if (size != 0) {
		unsigned long copy = len < size - 1 ? len : size - 1;
		memcpy(dst, src, copy);
		dst[copy] = '\0';
	}
	return len;
}

extern long sys_fstatfs64(int fd, struct bsd_statfs64* buf);

int main(void)
{
	struct bsd_statfs64 buf;
	memset(&buf, 0xa5, sizeof(buf));

	long rc = sys_fstatfs64(42, &buf);
	if (rc != 0) {
		fprintf(stderr, "sys_fstatfs64 returned %ld when /proc/self/mounts is absent\n", rc);
		return 1;
	}
	if (!saw_mounts_open) {
		fprintf(stderr, "test did not exercise /proc/self/mounts open path\n");
		return 1;
	}
	if (buf.converted_from_linux != 1 || buf.f_iosize != 512) {
		fprintf(stderr, "statfs conversion fields were not preserved\n");
		return 1;
	}
	if (buf.f_mntonname[0] != '\0' || buf.f_fstypename[0] != '\0' || buf.f_mntfromname[0] != '\0') {
		fprintf(stderr, "missing mounts should leave cosmetic mount names empty\n");
		return 1;
	}

	puts("PASS fstatfs_missing_proc_contract");
	return 0;
}
