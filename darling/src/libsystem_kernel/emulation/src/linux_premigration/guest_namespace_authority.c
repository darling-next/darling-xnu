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
#define CAP_READ(fd, buffer, size) read((fd), (buffer), (size))
#define CAP_WRITE(fd, buffer, size) write((fd), (buffer), (size))
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
#include <darling/emulation/conversion/stat/common.h>
#include <darlingserver/rpc.h>
#include <stdatomic.h>
#include <stddef.h>
#define DARLING_GUEST_NAMESPACE_RETAINED_FD_BASE 1008
static int cap_fd(unsigned int index);
#define CAP_FD(index) cap_fd((index))
#define CAP_FCNTL(fd, cmd, arg) ((int)LINUX_SYSCALL(__NR_fcntl, (fd), (cmd), (arg)))
#define CAP_FSTAT(fd, st) ((int)LINUX_SYSCALL(__NR_fstat, (fd), (st)))
#ifdef __NR_newfstatat
#define CAP_FSTATAT(fd, path, st, flags) ((int)LINUX_SYSCALL4(__NR_newfstatat, (fd), (path), (st), (flags)))
#else
#define CAP_FSTATAT(fd, path, st, flags) ((int)LINUX_SYSCALL4(__NR_fstatat64, (fd), (path), (st), (flags)))
#endif
#define CAP_FLOCK(fd, op) ((int)LINUX_SYSCALL(__NR_flock, (fd), (op)))
#ifdef __NR_mmap2
#define CAP_MMAP_FLAGS 1
#define CAP_MMAP(fd, size) ((void*)LINUX_SYSCALL6(__NR_mmap2, 0, (size), 1, CAP_MMAP_FLAGS, (fd), 0))
#else
#define CAP_MMAP(fd, size) ((void*)LINUX_SYSCALL6(__NR_mmap, 0, (size), 1, 1, (fd), 0))
#endif
#define CAP_MUNMAP(ptr, size) ((int)LINUX_SYSCALL(__NR_munmap, (ptr), (size)))
#define CAP_CLOSE(fd) ((int)LINUX_SYSCALL(__NR_close, (fd)))
#define CAP_OPENAT(fd, path, flags, mode) ((int)LINUX_SYSCALL(__NR_openat, (fd), (path), (flags), (mode)))
#define CAP_READ(fd, buffer, size) ((long)LINUX_SYSCALL(__NR_read, (fd), (buffer), (size)))
#define CAP_WRITE(fd, buffer, size) ((long)LINUX_SYSCALL(__NR_write, (fd), (buffer), (size)))
#define CAP_MKDIRAT(fd, path, mode) ((int)LINUX_SYSCALL(__NR_mkdirat, (fd), (path), (mode)))
#define CAP_UNLINKAT(fd, path, flags) ((int)LINUX_SYSCALL(__NR_unlinkat, (fd), (path), (flags)))
#define CAP_RENAMEAT(oldfd, old, newfd, new) ((int)LINUX_SYSCALL(__NR_renameat, (oldfd), (old), (newfd), (new)))
#define CAP_RENAMEAT2(oldfd, old, newfd, new, flags) ((int)LINUX_SYSCALL(__NR_renameat2, (oldfd), (old), (newfd), (new), (flags)))
#define CAP_FSETXATTR(fd, name, value, size) ((int)LINUX_SYSCALL(__NR_fsetxattr, (fd), (name), (value), (size), 0))
#define CAP_YIELD() ((int)LINUX_SYSCALL(__NR_sched_yield))
#define F_DUPFD_CLOEXEC 1030
#define F_SETFD 2
#define FD_CLOEXEC 1
#define LOCK_SH 1
#define LOCK_NB 4
typedef struct linux_stat cap_stat_t;
struct cap_pollfd { int fd; short events; short revents; };
static int cap_poll(int fd) {
	struct cap_pollfd descriptor = {fd, 0x19, 0};
	return (int)LINUX_SYSCALL3(__NR_poll, &descriptor, 1, 0);
}
#define CAP_POLL(fd) cap_poll((fd))
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

static __SIZE_TYPE__ cap_strlen(const char* value) {
	__SIZE_TYPE__ length = 0;
	while (value[length]) ++length;
	return length;
}

static int cap_bytes_equal(const void* left, const void* right, __SIZE_TYPE__ size) {
	const unsigned char* lhs = left;
	const unsigned char* rhs = right;
	for (__SIZE_TYPE__ index = 0; index < size; ++index)
		if (lhs[index] != rhs[index]) return 0;
	return 1;
}

static void cap_copy(void* destination, const void* source, __SIZE_TYPE__ size) {
	unsigned char* output = destination;
	const unsigned char* input = source;
	for (__SIZE_TYPE__ index = 0; index < size; ++index) output[index] = input[index];
}

#define CAPABILITY_COUNT 5
#define LEASE_INDEX 0
#define GATE_INDEX 1
#define PREFIX_INDEX 2
#define LOCK_INDEX 3
#define CONTROLLER_PIDFD_INDEX 4
#define ACTIVE 1u

#ifndef TEST
static int cap_fd(unsigned int index) {
	if (index >= CAPABILITY_COUNT)
		return -1;
	int fd = DARLING_GUEST_NAMESPACE_RETAINED_FD_BASE + (int)index;
	return CAP_FCNTL(fd, 1 /* F_GETFD */, 0) >= 0 ? fd : -1;
}
#endif

static int guest_effective_mode(uint32_t requested, uint32_t* effective) {
	char status[4097];
	int fd = CAP_OPENAT(-100, "/proc/self/status", O_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	long size = CAP_READ(fd, status, sizeof(status) - 1);
	CAP_CLOSE(fd);
	if (size <= 0 || size >= (long)sizeof(status))
		return -1;
	status[size] = 0;
	for (long index = 0; index + 6 < size; ++index) {
		if ((index == 0 || status[index - 1] == '\n') &&
			status[index] == 'U' && status[index + 1] == 'm' &&
			status[index + 2] == 'a' && status[index + 3] == 's' &&
			status[index + 4] == 'k' && status[index + 5] == ':') {
			uint32_t mask = 0;
			long cursor = index + 6;
			while (cursor < size && (status[cursor] == ' ' || status[cursor] == '\t'))
				++cursor;
			int digits = 0;
			while (cursor < size && status[cursor] >= '0' && status[cursor] <= '7') {
				mask = (mask << 3) | (uint32_t)(status[cursor++] - '0');
				++digits;
			}
			if (digits == 0 || mask > 07777 || (requested & ~07777u) != 0)
				return -1;
			*effective = (requested & 07777u) & ~mask;
			return 0;
		}
	}
	return -1;
}

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
#ifdef TEST
static darling_guest_namespace_test_transaction_fn test_transaction;
#endif

static uint32_t bounded_guest_path_length(const char* path) {
	uint32_t length = 0;
	if (!path)
		return 0;
	while (length <= 1024 && path[length])
		++length;
	return length <= 1024 ? length : 0;
}

static int invalid_bootstrap(const char* reason) {
	static const char prefix[] = "invalid guest namespace bootstrap: ";
	CAP_WRITE(2, prefix, sizeof(prefix) - 1);
	CAP_WRITE(2, reason, cap_strlen(reason));
	CAP_WRITE(2, "\n", 1);
	atomic_store(&session_state, DARLING_GUEST_NAMESPACE_INVALID);
	atomic_store_explicit(&initialized, INIT_INVALID, memory_order_release);
	return DARLING_GUEST_NAMESPACE_INVALID;
}

static long transaction_rpc(uint32_t operation, const char* source,
	const char* destination, int flags, uint32_t mode) {
	if (!source || source[0] != '/' || source[1] == 0)
		return -22;
	uint32_t source_length = bounded_guest_path_length(source + 1);
	uint32_t destination_length = destination ? bounded_guest_path_length(destination + 1) : 0;
	if (source_length == 0 || (destination && destination_length == 0))
		return -36;
	if (operation == 1 || operation == 2) {
		uint32_t effective = 0;
		if (guest_effective_mode(mode, &effective) != 0)
			return -5;
		mode = effective;
	}
#ifdef TEST
	long result = test_transaction ? test_transaction(operation, source, destination, flags, mode) : -95;
	if (result < 0 && test_transaction)
		result = test_transaction(operation, source, destination, flags, mode);
	return result;
#else
	uint64_t low = 0;
	if (LINUX_SYSCALL(__NR_getrandom, &low, sizeof(low), 0) != (long)sizeof(low) || low == 0)
		return -5;
	uint32_t disposition = 0;
	uint64_t device = 0;
	uint64_t inode = 0;
	int created_fd = -1;
	int result = dserver_rpc_guest_namespace_transaction(
		operation, lease_page->generation, low,
		source + 1, source_length,
		destination ? destination + 1 : 0, destination_length, flags, mode,
		&disposition, &device, &inode, &created_fd);
	/* The transaction ID is deliberately stable across the one bounded replay.
	 * Rust returns the cached outcome and duplicates the same retained inode. */
	if (result < 0)
		result = dserver_rpc_guest_namespace_transaction(
			operation, lease_page->generation, low,
			source + 1, source_length,
			destination ? destination + 1 : 0, destination_length, flags, mode,
			&disposition, &device, &inode, &created_fd);
	if (result != 0)
		return result;
	if (operation == 1) {
		if (created_fd < 0 || CAP_FCNTL(created_fd, F_SETFD, FD_CLOEXEC) < 0) {
			if (created_fd >= 0)
				CAP_CLOSE(created_fd);
			return -5;
		}
		return created_fd;
	}
	if (created_fd >= 0)
		CAP_CLOSE(created_fd);
	return 0;
#endif
}

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
	if ((unsigned long)lease_page >= (unsigned long)-4095 || !lease_page)
		return invalid_bootstrap("lease mapping");
	if (!cap_bytes_equal(lease_page->magic, "DLGNSA2", 8) || lease_page->version != 2 ||
		lease_page->generation == 0 || lease_page->controller_pid <= 0)
		return invalid_bootstrap("lease envelope");
	if (atomic_load_explicit(&lease_page->state, memory_order_acquire) != ACTIVE)
		return invalid_bootstrap("lease revoked");
	if (!same_identity(capabilities[PREFIX_INDEX], lease_page->prefix))
		return invalid_bootstrap("prefix identity");
	if (!same_identity(capabilities[LOCK_INDEX], lease_page->lock))
		return invalid_bootstrap("lock identity");
	if (!same_identity(capabilities[GATE_INDEX], lease_page->gate))
		return invalid_bootstrap("gate identity");
	if (CAP_POLL(capabilities[CONTROLLER_PIDFD_INDEX]) != 0)
		return invalid_bootstrap("controller death");
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
			cap_copy(resolved->leaf, cursor, length);
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
		cap_copy(component, cursor, length); component[length] = 0;
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
	long result = mutation_still_valid(&mutation) ?
		transaction_rpc(2, path, 0, 0, mode) : -116;
	darling_guest_namespace_end(&mutation);
	return result;
}

long darling_guest_namespace_create(const char* path, int flags, unsigned int mode) {
	struct darling_guest_namespace_mutation mutation;
	int active = darling_guest_namespace_begin(&mutation);
	if (active <= 0) return active;
	long result = mutation_still_valid(&mutation) ?
		transaction_rpc(1, path, 0, flags, mode) : -116;
	darling_guest_namespace_end(&mutation);
	return result;
}

long darling_guest_namespace_unlink(const char* path, int flags) {
	struct darling_guest_namespace_mutation mutation;
	int active = darling_guest_namespace_begin(&mutation);
	if (active <= 0) return active;
	long result = mutation_still_valid(&mutation) ?
		transaction_rpc(3, path, 0, flags, 0) : -116;
	darling_guest_namespace_end(&mutation);
	return result;
}

long darling_guest_namespace_rename(const char* source, const char* destination) {
	struct darling_guest_namespace_mutation mutation;
	int active = darling_guest_namespace_begin(&mutation);
	if (active <= 0) return active;
	long result = mutation_still_valid(&mutation) ?
		transaction_rpc(4, source, destination, 0, 0) : -116;
	darling_guest_namespace_end(&mutation);
	return result;
}

#ifdef TEST
void darling_guest_namespace_test_set_capability(unsigned int index, int fd) {
	if (index < CAPABILITY_COUNT) test_capabilities[index] = fd;
}
void darling_guest_namespace_test_set_transaction(
	darling_guest_namespace_test_transaction_fn transaction) {
	test_transaction = transaction;
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
	test_transaction = 0;
}
#endif
