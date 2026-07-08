#ifndef FSTATFS_MISSING_PROC_STUBS_H
#define FSTATFS_MISSING_PROC_STUBS_H

struct bsd_statfs {
	int unused;
};

struct bsd_statfs64 {
	char f_mntonname[1024];
	char f_fstypename[16];
	char f_mntfromname[1024];
	long f_iosize;
	int converted_from_linux;
};

struct linux_statfs64 {
	unsigned long f_type;
};

struct simple_readline_buf {
	int unused;
};

long sys_fstatfs64(int fd, struct bsd_statfs64* buf);
int fdpath(int fd, char* path, unsigned long size);
long sys_open(const char* path, int flags, int mode);
long fake_linux_fstatfs64(int fd, unsigned long size, struct linux_statfs64* buf);

#define __NR_fstatfs64 1
#define LINUX_SYSCALL3(nr, fd, size, buf) fake_linux_fstatfs64((fd), (size), (buf))

#endif
