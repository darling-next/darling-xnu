#ifdef TEST
#define _GNU_SOURCE
#include "guest_namespace_authority.h"
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <poll.h>
#include <sched.h>
#include <unistd.h>
#define CAP_FD(index) test_capabilities[(index)]
#define CAP_FCNTL(fd, cmd, arg) fcntl((fd), (cmd), (arg))
#define CAP_FSTAT(fd, st) fstat((fd), (st))
#define CAP_FSTATAT(fd, path, st, flags) fstatat((fd), (path), (st), (flags))
#define CAP_FLOCK(fd, op) flock((fd), (op))
#define CAP_MMAP(fd, size) mmap(NULL, (size), PROT_READ, MAP_SHARED, (fd), 0)
#define CAP_MUNMAP(ptr, size) munmap((ptr), (size))
#define CAP_CLOSE(fd) close((fd))
#define CAP_OPENAT(fd, path, flags, mode) openat((fd), (path), (flags), (mode))
#define CAP_MKDIRAT(fd, path, mode) mkdirat((fd), (path), (mode))
#define CAP_UNLINKAT(fd, path, flags) unlinkat((fd), (path), (flags))
#define CAP_RENAMEAT(oldfd, old, newfd, new) renameat((oldfd), (old), (newfd), (new))
#define CAP_RENAMEAT2(oldfd, old, newfd, new, flags) syscall(SYS_renameat2, (oldfd), (old), (newfd), (new), (flags))
#define CAP_FSETXATTR(fd, name, value, size) fsetxattr((fd), (name), (value), (size), 0)
#define CAP_POLL(capfd) ({ struct pollfd p = {.fd = (capfd), .events = POLLIN | POLLHUP | POLLERR}; poll(&p, 1, 0); })
#define CAP_YIELD() sched_yield()
typedef struct stat cap_stat_t;
static int test_capabilities[5] = {-1, -1, -1, -1, -1};
#else
#include <darling/emulation/linux_premigration/guest_namespace_authority.h>
#include <darling/emulation/linux_premigration/elfcalls_wrapper.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/common/base.h>
#include <stdatomic.h>
#include <stddef.h>
#define CAP_FD(index) __mldr_guest_namespace_capability_fd((index))
#define CAP_FCNTL(fd, cmd, arg) ((int)LINUX_SYSCALL(__NR_fcntl, (fd), (cmd), (arg)))
#define CAP_FSTAT(fd, st) ((int)LINUX_SYSCALL(__NR_fstat, (fd), (st)))
#define CAP_FSTATAT(fd, path, st, flags) ((int)LINUX_SYSCALL(__NR_newfstatat, (fd), (path), (st), (flags)))
#define CAP_FLOCK(fd, op) ((int)LINUX_SYSCALL(__NR_flock, (fd), (op)))
#define CAP_MMAP(fd, size) ((void*)LINUX_SYSCALL(__NR_mmap, 0, (size), 1, 1, (fd), 0))
#define CAP_MUNMAP(ptr, size) ((int)LINUX_SYSCALL(__NR_munmap, (ptr), (size)))
#define CAP_CLOSE(fd) ((int)LINUX_SYSCALL(__NR_close, (fd)))
#define CAP_OPENAT(fd, path, flags, mode) ((int)LINUX_SYSCALL(__NR_openat, (fd), (path), (flags), (mode)))
#define CAP_MKDIRAT(fd, path, mode) ((int)LINUX_SYSCALL(__NR_mkdirat, (fd), (path), (mode)))
#define CAP_UNLINKAT(fd, path, flags) ((int)LINUX_SYSCALL(__NR_unlinkat, (fd), (path), (flags)))
#define CAP_RENAMEAT(oldfd, old, newfd, new) ((int)LINUX_SYSCALL(__NR_renameat, (oldfd), (old), (newfd), (new)))
#define CAP_RENAMEAT2(oldfd, old, newfd, new, flags) ((int)LINUX_SYSCALL(__NR_renameat2, (oldfd), (old), (newfd), (new), (flags)))
#define CAP_FSETXATTR(fd, name, value, size) ((int)LINUX_SYSCALL(__NR_fsetxattr, (fd), (name), (value), (size), 0))
#define CAP_POLL(fd) ((int)LINUX_SYSCALL(__NR_poll, &(struct { int fd; short events; short revents; }){(fd), 0x19, 0}, 1, 0))
#define CAP_YIELD() ((int)LINUX_SYSCALL(__NR_sched_yield))
#define F_DUPFD_CLOEXEC 1030
#define LOCK_SH 1
#define LOCK_NB 4
typedef struct linux_stat cap_stat_t;
extern int memcmp(const void*, const void*, __SIZE_TYPE__);
#endif

#ifndef O_PATH
#define O_PATH 010000000
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY 0200000
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0400000
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 02000000
#endif

extern __SIZE_TYPE__ strlen(const char*);
extern void* memcpy(void*, const void*, __SIZE_TYPE__);

#define CAPABILITY_COUNT 5
#define LEASE_INDEX 0
#define GATE_INDEX 1
#define PREFIX_INDEX 2
#define LOCK_INDEX 3
#define CONTROLLER_PIDFD_INDEX 4
#define ACTIVE 1u

struct cap_identity { uint64_t device; uint64_t inode; };
struct lease_page {
	unsigned char magic[8];
	uint32_t version;
	_Atomic uint32_t state;
	uint64_t generation;
	struct cap_identity prefix;
	struct cap_identity lock;
	struct cap_identity gate;
	int32_t controller_pid;
};

enum initialization_state { INIT_UNINITIALIZED, INIT_INITIALIZING, INIT_OFF, INIT_REQUIRED, INIT_INVALID };
static _Atomic int initialized = INIT_UNINITIALIZED;
static _Atomic int session_state = DARLING_GUEST_NAMESPACE_OFF;
static struct lease_page* lease_page;
static int capabilities[CAPABILITY_COUNT] = {-1, -1, -1, -1, -1};

static int same_identity(int fd, struct cap_identity expected) {
	cap_stat_t value;
	return fd >= 0 && CAP_FSTAT(fd, &value) == 0 && expected.inode != 0 &&
		(uint64_t)value.st_dev == expected.device && (uint64_t)value.st_ino == expected.inode;
}

static int same_named_identity(int parent, const char* name, struct cap_identity expected) {
	cap_stat_t value;
	return CAP_FSTATAT(parent, name, &value, 0x100) == 0 && expected.inode != 0 &&
		(uint64_t)value.st_dev == expected.device && (uint64_t)value.st_ino == expected.inode;
}

int darling_guest_namespace_initialize(void) {
	int expected = INIT_UNINITIALIZED;
	if (!atomic_compare_exchange_strong_explicit(&initialized, &expected, INIT_INITIALIZING,
		memory_order_acq_rel, memory_order_acquire)) {
		for (unsigned int spin = 0; spin < 4096 && expected == INIT_INITIALIZING; ++spin) {
			CAP_YIELD();
			expected = atomic_load_explicit(&initialized, memory_order_acquire);
		}
		if (expected == INIT_REQUIRED) return DARLING_GUEST_NAMESPACE_REQUIRED;
		if (expected == INIT_OFF) return DARLING_GUEST_NAMESPACE_OFF;
		return DARLING_GUEST_NAMESPACE_INVALID;
	}
	int present = 0;
	for (unsigned int index = 0; index < CAPABILITY_COUNT; ++index) {
		capabilities[index] = CAP_FD(index);
		present += capabilities[index] >= 0;
	}
	if (present == 0) {
		atomic_store_explicit(&initialized, INIT_OFF, memory_order_release);
		return DARLING_GUEST_NAMESPACE_OFF;
	}
	if (present != CAPABILITY_COUNT) {
		atomic_store(&session_state, DARLING_GUEST_NAMESPACE_INVALID);
		atomic_store_explicit(&initialized, INIT_INVALID, memory_order_release);
		return DARLING_GUEST_NAMESPACE_INVALID;
	}
	lease_page = CAP_MMAP(capabilities[LEASE_INDEX], sizeof(*lease_page));
	if ((long)lease_page < 0 || !lease_page ||
		memcmp(lease_page->magic, "DLGNSA2", 8) != 0 || lease_page->version != 2 ||
		lease_page->generation == 0 || lease_page->controller_pid <= 0 ||
		atomic_load_explicit(&lease_page->state, memory_order_acquire) != ACTIVE ||
		!same_identity(capabilities[PREFIX_INDEX], lease_page->prefix) ||
		!same_identity(capabilities[LOCK_INDEX], lease_page->lock) ||
		!same_identity(capabilities[GATE_INDEX], lease_page->gate) ||
		CAP_POLL(capabilities[CONTROLLER_PIDFD_INDEX]) != 0) {
		atomic_store(&session_state, DARLING_GUEST_NAMESPACE_INVALID);
		atomic_store_explicit(&initialized, INIT_INVALID, memory_order_release);
		return DARLING_GUEST_NAMESPACE_INVALID;
	}
	atomic_store_explicit(&session_state, DARLING_GUEST_NAMESPACE_REQUIRED, memory_order_release);
	atomic_store_explicit(&initialized, INIT_REQUIRED, memory_order_release);
	return DARLING_GUEST_NAMESPACE_REQUIRED;
}

int darling_guest_namespace_state(void) {
	int state = atomic_load_explicit(&initialized, memory_order_acquire);
	return state == INIT_UNINITIALIZED || state == INIT_INITIALIZING
		? darling_guest_namespace_initialize() : atomic_load_explicit(&session_state, memory_order_acquire);
}

int darling_guest_namespace_protected_fd(unsigned int index) {
	return index < CAPABILITY_COUNT && darling_guest_namespace_state() == DARLING_GUEST_NAMESPACE_REQUIRED
		? capabilities[index] : -1;
}

int darling_guest_namespace_begin(struct darling_guest_namespace_mutation* mutation) {
	if (!mutation) return -1;
	mutation->gate_fd = mutation->prefix_fd = -1;
	mutation->generation = 0;
	int state = darling_guest_namespace_state();
	if (state == DARLING_GUEST_NAMESPACE_OFF) return 0;
	if (state != DARLING_GUEST_NAMESPACE_REQUIRED ||
		atomic_load_explicit(&lease_page->state, memory_order_acquire) != ACTIVE ||
		CAP_POLL(capabilities[CONTROLLER_PIDFD_INDEX]) != 0) return -1;
	char gate_path[64] = "/proc/self/fd/";
	int value = capabilities[GATE_INDEX], digits = 0;
	do { ++digits; value /= 10; } while (value);
	value = capabilities[GATE_INDEX];
	for (int index = digits - 1; index >= 0; --index) { gate_path[14 + index] = (char)('0' + value % 10); value /= 10; }
	gate_path[14 + digits] = 0;
	int gate = CAP_OPENAT(-100, gate_path, 02 | O_CLOEXEC, 0);
	int prefix = CAP_FCNTL(capabilities[PREFIX_INDEX], F_DUPFD_CLOEXEC, 3);
	if (gate < 0 || prefix < 0 || CAP_FLOCK(gate, LOCK_SH | LOCK_NB) < 0 ||
		atomic_load_explicit(&lease_page->state, memory_order_acquire) != ACTIVE ||
		CAP_POLL(capabilities[CONTROLLER_PIDFD_INDEX]) != 0 ||
		!same_identity(prefix, lease_page->prefix) ||
		!same_named_identity(prefix, ".lifecycle.lock", lease_page->lock)) {
		if (prefix >= 0) CAP_CLOSE(prefix);
		if (gate >= 0) CAP_CLOSE(gate);
		return -1;
	}
	mutation->gate_fd = gate;
	mutation->prefix_fd = prefix;
	mutation->generation = lease_page->generation;
	return 1;
}

void darling_guest_namespace_end(struct darling_guest_namespace_mutation* mutation) {
	if (!mutation) return;
	if (mutation->prefix_fd >= 0) CAP_CLOSE(mutation->prefix_fd);
	if (mutation->gate_fd >= 0) CAP_CLOSE(mutation->gate_fd);
	mutation->prefix_fd = mutation->gate_fd = -1;
	mutation->generation = 0;
}

void darling_guest_namespace_resolved_close(struct darling_guest_namespace_resolved* resolved) {
	if (resolved && resolved->parent_fd >= 0) CAP_CLOSE(resolved->parent_fd);
	if (resolved) resolved->parent_fd = -1;
}

int darling_guest_namespace_resolve(struct darling_guest_namespace_mutation* mutation,
	const char* path, struct darling_guest_namespace_resolved* resolved) {
	if (!mutation || mutation->prefix_fd < 0 || !path || path[0] != '/' || !resolved)
		return -22;
	resolved->parent_fd = -1;
	const char* cursor = path + 1;
	int parent = CAP_FCNTL(mutation->prefix_fd, F_DUPFD_CLOEXEC, 3);
	if (parent < 0) return parent;
	for (;;) {
		const char* slash = cursor;
		while (*slash && *slash != '/') ++slash;
		__SIZE_TYPE__ length = (__SIZE_TYPE__)(slash - cursor);
		if (length == 0 || length >= sizeof(resolved->leaf) ||
			(length == 1 && cursor[0] == '.') ||
			(length == 2 && cursor[0] == '.' && cursor[1] == '.')) {
			CAP_CLOSE(parent); return -22;
		}
		if (!*slash) {
			memcpy(resolved->leaf, cursor, length);
			resolved->leaf[length] = 0;
			cap_stat_t identity;
			if (CAP_FSTAT(parent, &identity) < 0) { CAP_CLOSE(parent); return -5; }
			resolved->parent_fd = parent;
			resolved->layer = DARLING_GUEST_NAMESPACE_UPPER;
			resolved->parent_device = (uint64_t)identity.st_dev;
			resolved->parent_inode = (uint64_t)identity.st_ino;
			return 0;
		}
		char component[256];
		if (length >= sizeof(component)) { CAP_CLOSE(parent); return -36; }
		memcpy(component, cursor, length); component[length] = 0;
		int next = CAP_OPENAT(parent, component,
			O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, 0);
		CAP_CLOSE(parent);
		if (next < 0) return next;
		parent = next;
		cursor = slash + 1;
	}
}

static int mutation_still_valid(struct darling_guest_namespace_mutation* mutation) {
	return mutation && mutation->generation == lease_page->generation &&
		atomic_load_explicit(&lease_page->state, memory_order_acquire) == ACTIVE &&
		CAP_POLL(capabilities[CONTROLLER_PIDFD_INDEX]) == 0 &&
		same_identity(mutation->prefix_fd, lease_page->prefix) &&
		same_named_identity(mutation->prefix_fd, ".lifecycle.lock", lease_page->lock);
}

long darling_guest_namespace_mkdir(const char* path, unsigned int mode) {
	struct darling_guest_namespace_mutation mutation;
	int active = darling_guest_namespace_begin(&mutation);
	if (active <= 0) return active;
	(void)path; (void)mode;
	(void)mutation_still_valid(&mutation);
	darling_guest_namespace_end(&mutation);
	return -95;
}

long darling_guest_namespace_create(const char* path, int flags, unsigned int mode) {
	struct darling_guest_namespace_mutation mutation;
	int active = darling_guest_namespace_begin(&mutation);
	if (active <= 0) return active;
	(void)path; (void)flags; (void)mode;
	(void)mutation_still_valid(&mutation);
	darling_guest_namespace_end(&mutation);
	return -95;
}

long darling_guest_namespace_unlink(const char* path, int flags) {
	struct darling_guest_namespace_mutation mutation;
	int active = darling_guest_namespace_begin(&mutation);
	if (active <= 0) return active;
	(void)path; (void)flags;
	(void)mutation_still_valid(&mutation);
	darling_guest_namespace_end(&mutation);
	return -95;
}

long darling_guest_namespace_rename(const char* source, const char* destination) {
	struct darling_guest_namespace_mutation mutation;
	int active = darling_guest_namespace_begin(&mutation);
	if (active <= 0) return active;
	(void)source; (void)destination;
	(void)mutation_still_valid(&mutation);
	darling_guest_namespace_end(&mutation);
	return -95;
}

#ifdef TEST
void darling_guest_namespace_test_set_capability(unsigned int index, int fd) {
	if (index < CAPABILITY_COUNT) test_capabilities[index] = fd;
}
void darling_guest_namespace_test_reset(void) {
	if (lease_page && (long)lease_page > 0) CAP_MUNMAP(lease_page, sizeof(*lease_page));
	lease_page = 0;
	for (unsigned int index = 0; index < CAPABILITY_COUNT; ++index) {
		test_capabilities[index] = -1;
		capabilities[index] = -1;
	}
	atomic_store(&session_state, DARLING_GUEST_NAMESPACE_OFF);
	atomic_store(&initialized, INIT_UNINITIALIZED);
}
#endif
