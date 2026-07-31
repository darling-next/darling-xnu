#include <linux_premigration/eunion_sidecar.h>

#ifdef TEST
#	define _GNU_SOURCE
#	include <errno.h>
#	include <fcntl.h>
#	include <string.h>
#	include <sys/file.h>
#	include <sys/stat.h>
#	include <sys/syscall.h>
#	include <sys/types.h>
#	include <unistd.h>
#	define SIDECAR_SYSCALL(number, ...) \
		(eunion_sidecar_test_should_fail(number) \
			? -eunion_test_sidecar_fail_errno \
			: eunion_sidecar_test_syscall( \
				syscall(number, __VA_ARGS__)))
typedef struct stat sidecar_stat_t;
#else
#	include <stdbool.h>
#	include <stddef.h>
#	include <string.h>
#	include <darling/emulation/common/base.h>
#	include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#	include <darling/emulation/conversion/stat/common.h>
#	define SIDECAR_SYSCALL(...) LINUX_SYSCALL(__VA_ARGS__)
typedef struct linux_stat sidecar_stat_t;
#endif

#include <errno.h>

#ifndef LINUX_AT_FDCWD
#define LINUX_AT_FDCWD -100
#endif
#ifndef LINUX_AT_SYMLINK_NOFOLLOW
#define LINUX_AT_SYMLINK_NOFOLLOW 0x100
#endif
#ifndef __NR_fchmodat2
#define __NR_fchmodat2 452
#endif
#if !defined(__NR_newfstatat) && defined(__NR_fstatat64)
#define __NR_newfstatat __NR_fstatat64
#endif
#ifndef LINUX_O_RDONLY
#define LINUX_O_RDONLY 0
#endif
#ifndef LINUX_O_WRONLY
#define LINUX_O_WRONLY 01
#endif
#ifndef LINUX_O_RDWR
#define LINUX_O_RDWR 02
#endif
#ifndef LINUX_O_CREAT
#define LINUX_O_CREAT 0100
#endif
#ifndef LINUX_O_EXCL
#define LINUX_O_EXCL 0200
#endif
#ifndef LINUX_O_DIRECTORY
#define LINUX_O_DIRECTORY 0200000
#endif
#ifndef LINUX_O_NOFOLLOW
#define LINUX_O_NOFOLLOW 0400000
#endif
#ifndef LINUX_O_CLOEXEC
#define LINUX_O_CLOEXEC 02000000
#endif
#ifndef LINUX_O_PATH
#define LINUX_O_PATH 010000000
#endif
#ifndef LINUX_LOCK_SH
#define LINUX_LOCK_SH 1
#endif
#ifndef LINUX_LOCK_EX
#define LINUX_LOCK_EX 2
#endif
#ifndef LINUX_LOCK_UN
#define LINUX_LOCK_UN 8
#endif
#ifndef LINUX_S_IFMT
#define LINUX_S_IFMT 00170000
#endif
#ifndef LINUX_S_IFDIR
#define LINUX_S_IFDIR 0040000
#endif
#ifndef LINUX_AF_UNIX
#define LINUX_AF_UNIX 1
#endif
#ifndef LINUX_S_IFREG
#define LINUX_S_IFREG 0100000
#endif
#ifndef LINUX_S_IFLNK
#define LINUX_S_IFLNK 0120000
#endif
#ifndef LINUX_EBUSY
#define LINUX_EBUSY 16
#endif
#ifndef LINUX_EPERM
#define LINUX_EPERM 1
#endif
#ifndef LINUX_EEXIST
#define LINUX_EEXIST 17
#endif
#ifndef LINUX_ENOENT
#define LINUX_ENOENT 2
#endif
#ifndef LINUX_EIO
#define LINUX_EIO 5
#endif
#ifndef LINUX_EACCES
#define LINUX_EACCES 13
#endif
#ifndef LINUX_ENOMEM
#define LINUX_ENOMEM 12
#endif
#ifndef LINUX_EINVAL
#define LINUX_EINVAL 22
#endif
#ifndef LINUX_ENOTDIR
#define LINUX_ENOTDIR 20
#endif
#ifndef LINUX_EISDIR
#define LINUX_EISDIR 21
#endif
#ifndef LINUX_ELOOP
#define LINUX_ELOOP 40
#endif
#ifndef LINUX_ENOTEMPTY
#define LINUX_ENOTEMPTY 39
#endif
#ifndef LINUX_EAGAIN
#define LINUX_EAGAIN 11
#endif
#ifndef LINUX_ENAMETOOLONG
#define LINUX_ENAMETOOLONG 36
#endif
#ifndef LINUX_RENAME_NOREPLACE
#define LINUX_RENAME_NOREPLACE 1
#endif
#ifndef LINUX_RENAME_EXCHANGE
#define LINUX_RENAME_EXCHANGE 2
#endif

#define EUNION_SIDECAR_FORMAT_VERSION 1U
#define EUNION_SIDECAR_FORMAT_MAGIC 0x45555343464d5431ULL
#define EUNION_SIDECAR_NODE_MAGIC 0x455553434e4f4431ULL
#define EUNION_SIDECAR_JOURNAL_MAGIC 0x455553434a4e4c31ULL
#define EUNION_SIDECAR_ACTIVATION_MAGIC 0x4555534341435431ULL

struct eunion_sidecar_format_disk {
	uint64_t magic;
	uint32_t version;
	uint32_t size;
	uint64_t uuid[2];
	uint64_t key[2];
	struct eunion_sidecar_identity upper_root;
	struct eunion_sidecar_identity lower_root;
	uint64_t checksum;
};

struct eunion_sidecar_activation_disk {
	uint64_t magic;
	uint32_t version;
	uint32_t size;
	uint64_t uuid[2];
	struct eunion_sidecar_identity upper_root;
	struct eunion_sidecar_identity lower_root;
	struct eunion_sidecar_identity sidecar_root;
	uint64_t checksum;
};

struct eunion_sidecar_node_disk {
	uint64_t magic;
	uint32_t version;
	uint32_t size;
	uint32_t kind;
	uint32_t name_length;
	uint64_t generation;
	uint64_t parent_generation;
	struct eunion_sidecar_identity upper;
	struct eunion_sidecar_identity lower;
	char name[EUNION_SIDECAR_NAME_MAX + 1];
	uint64_t checksum;
};

struct eunion_sidecar_journal_disk {
	uint64_t magic;
	uint32_t version;
	uint32_t size;
	uint32_t phase;
	uint32_t operation;
	uint32_t remove_directory;
	uint32_t recursive_tree;
	uint32_t path_length;
	uint32_t secondary_path_length;
	uint32_t old_record_valid;
	uint32_t new_record_valid;
	uint32_t secondary_old_record_valid;
	uint32_t secondary_new_record_valid;
	struct eunion_sidecar_identity upper;
	struct eunion_sidecar_identity lower;
	struct eunion_sidecar_identity secondary_upper;
	struct eunion_sidecar_identity secondary_lower;
	struct eunion_sidecar_identity backing_new;
	struct eunion_sidecar_node_disk old_record;
	struct eunion_sidecar_node_disk new_record;
	struct eunion_sidecar_node_disk secondary_old_record;
	struct eunion_sidecar_node_disk secondary_new_record;
	char path[EUNION_SIDECAR_PATH_MAX];
	char secondary_path[EUNION_SIDECAR_PATH_MAX];
	uint64_t checksum;
};

struct eunion_sidecar_dirent64 {
	uint64_t inode;
	int64_t offset;
	unsigned short record_length;
	unsigned char type;
	char name[];
};

union eunion_sidecar_transaction_intent {
	struct {
		uint32_t remove_directory;
	} remove;
	struct {
		uint32_t kind;
	} create;
	struct {
		uint32_t directory;
	} copy_up;
	struct {
		uint32_t two_path;
	} rename;
};

struct eunion_sidecar_transaction_storage {
	uintptr_t owner;
	enum eunion_sidecar_phase phase;
	enum eunion_sidecar_operation operation;
	union eunion_sidecar_transaction_intent intent;
	struct eunion_sidecar_view_storage view;
};

typedef struct eunion_sidecar_transaction_storage
	eunion_sidecar_transaction[1];

static int eunion_sidecar_recover_locked(eunion_sidecar_view view);
static int eunion_sidecar_dispose_partial_node(
	int parent, const char* name);
static int eunion_sidecar_cleanup_copyup_stage(
	eunion_sidecar_view view);
static int eunion_sidecar_materialize_merged_tree(
	eunion_sidecar_view view, int upper_directory, int lower_directory,
	const char* guest_path);

static int eunion_sidecar_transaction_validate(
	eunion_sidecar_transaction transaction)
{
	if (!transaction ||
		transaction->owner != (uintptr_t)transaction ||
		transaction->operation < EUNION_SIDECAR_OPERATION_REMOVE ||
		transaction->operation >= EUNION_SIDECAR_OPERATION_INVALID ||
		transaction->phase < EUNION_SIDECAR_PHASE_EMPTY ||
		transaction->phase >= EUNION_SIDECAR_PHASE_INVALID)
		return -LINUX_EINVAL;
	return 0;
}

static int eunion_sidecar_transaction_transition(
	eunion_sidecar_transaction transaction,
	enum eunion_sidecar_phase next)
{
	int result = eunion_sidecar_transaction_validate(transaction);
	if (result < 0)
		return result;
	result = eunion_sidecar_operation_transition_allowed(
		transaction->operation, transaction->phase, next);
	if (result < 0)
		return -LINUX_EINVAL;
	transaction->phase = next;
	return 0;
}

static int eunion_sidecar_transaction_begin(
	eunion_sidecar_transaction transaction,
	const struct eunion_sidecar_runtime* runtime,
	enum eunion_sidecar_operation operation,
	union eunion_sidecar_transaction_intent intent)
{
	if (!transaction || transaction->owner != 0 ||
		transaction->phase != EUNION_SIDECAR_PHASE_EMPTY ||
		operation < EUNION_SIDECAR_OPERATION_REMOVE ||
		operation >= EUNION_SIDECAR_OPERATION_INVALID)
		return -LINUX_EINVAL;
	transaction->owner = (uintptr_t)transaction;
	transaction->operation = operation;
	transaction->intent = intent;
	int result = eunion_sidecar_transaction_transition(
		transaction, EUNION_SIDECAR_PHASE_RESOLVED);
	if (result < 0)
		return result;
	result = eunion_sidecar_view_open(
		&transaction->view, runtime, EUNION_SIDECAR_ACCESS_EXCLUSIVE);
	if (result < 0) {
		(void)eunion_sidecar_transaction_transition(
			transaction, EUNION_SIDECAR_PHASE_RELEASED);
		return result;
	}
	result = eunion_sidecar_transaction_transition(
		transaction, EUNION_SIDECAR_PHASE_LOCKED);
	if (result < 0)
		(void)eunion_sidecar_view_close(&transaction->view);
	return result;
}

static int eunion_sidecar_transaction_release(
	eunion_sidecar_transaction transaction, int primary_result)
{
	int validation = eunion_sidecar_transaction_validate(transaction);
	if (validation < 0)
		return primary_result < 0 ? primary_result : validation;
	if (primary_result < 0 &&
		(transaction->phase == EUNION_SIDECAR_PHASE_LOGICALLY_PUBLISHED ||
		 transaction->phase == EUNION_SIDECAR_PHASE_BACKING_COMMITTED)) {
		(void)eunion_sidecar_transaction_transition(transaction,
			EUNION_SIDECAR_PHASE_RECOVERY_DELEGATED);
	}
	int close_result = eunion_sidecar_view_close(&transaction->view);
	int release_result = eunion_sidecar_transaction_transition(
		transaction, EUNION_SIDECAR_PHASE_RELEASED);
	if (primary_result < 0)
		return primary_result;
	if (close_result < 0)
		return close_result;
	return release_result < 0 ? release_result : primary_result;
}

/*
 * E-UNION is anchored before libsystem has installed libplatform's optimized
 * string-function table.  In that window libsystem_kernel's public memcmp()
 * dispatcher has no generic implementation and calling it jumps through a
 * null function pointer.  Keep sidecar validation self-contained so both the
 * dyld and non-dyld anchors can inspect the same published format safely.
 */
static int eunion_sidecar_bytes_equal(
	const void* left, const void* right, size_t length)
{
	const unsigned char* left_bytes = left;
	const unsigned char* right_bytes = right;
	for (size_t index = 0; index < length; ++index) {
		if (left_bytes[index] != right_bytes[index])
			return 0;
	}
	return 1;
}

#ifdef TEST
int eunion_sidecar_test_transaction_guards(
	const struct eunion_sidecar_runtime* runtime)
{
	eunion_sidecar_transaction transaction = {{0}};
	union eunion_sidecar_transaction_intent intent = {
		.remove = {
			.remove_directory = 0,
		},
	};
	int result = eunion_sidecar_transaction_begin(transaction, runtime,
		EUNION_SIDECAR_OPERATION_REMOVE, intent);
	if (result < 0)
		return result;
	eunion_sidecar_transaction copied;
	memcpy(copied, transaction, sizeof(copied));
	if (eunion_sidecar_transaction_validate(copied) != -LINUX_EINVAL)
		result = -LINUX_EIO;
	if (result >= 0 &&
		eunion_sidecar_transaction_begin(transaction, runtime,
			EUNION_SIDECAR_OPERATION_REMOVE, intent) != -LINUX_EINVAL)
		result = -LINUX_EIO;
	return eunion_sidecar_transaction_release(transaction, result);
}
#endif

#ifdef TEST
uint64_t eunion_test_sidecar_key[2] = {
	0x0706050403020100ULL,
	0x0f0e0d0c0b0a0908ULL,
};
uint64_t eunion_test_sidecar_uuid[2] = {
	0x1716151413121110ULL,
	0x1f1e1d1c1b1a1918ULL,
};
void (*eunion_test_sidecar_checkpoint_hook)(
	enum eunion_sidecar_test_checkpoint checkpoint,
	const char* guest_path);
long eunion_test_sidecar_fail_syscall = -1;
unsigned int eunion_test_sidecar_fail_after;
int eunion_test_sidecar_fail_errno = EINTR;

static int eunion_sidecar_test_should_fail(long number)
{
	if (number != eunion_test_sidecar_fail_syscall ||
		eunion_test_sidecar_fail_after == 0)
		return 0;
	--eunion_test_sidecar_fail_after;
	if (eunion_test_sidecar_fail_after != 0)
		return 0;
	eunion_test_sidecar_fail_syscall = -1;
	return 1;
}

static int eunion_sidecar_test_syscall(long result)
{
	return result == -1 ? -errno : (int)result;
}
#endif

static uint64_t eunion_sidecar_checksum(const void* data, size_t size)
{
	const unsigned char* bytes = data;
	uint64_t value = 1469598103934665603ULL;
	for (size_t index = 0; index < size; ++index) {
		value ^= bytes[index];
		value *= 1099511628211ULL;
	}
	return value;
}

static int eunion_sidecar_write_all(int descriptor, const void* data,
	size_t size)
{
	const unsigned char* bytes = data;
	size_t offset = 0;
	while (offset < size) {
		int result = SIDECAR_SYSCALL(__NR_write, descriptor,
			bytes + offset, size - offset);
		if (result < 0)
			return result;
		if (result == 0)
			return -LINUX_EIO;
		offset += (size_t)result;
	}
	return 0;
}

static int eunion_sidecar_read_exact(int descriptor, void* data, size_t size)
{
	unsigned char* bytes = data;
	size_t offset = 0;
	while (offset < size) {
		int result = SIDECAR_SYSCALL(__NR_read, descriptor,
			bytes + offset, size - offset);
		if (result < 0)
			return result;
		if (result == 0)
			return -LINUX_EIO;
		offset += (size_t)result;
	}
	char extra;
	int result = SIDECAR_SYSCALL(__NR_read, descriptor, &extra, 1);
	if (result < 0)
		return result;
	return result == 0 ? 0 : -LINUX_EIO;
}

static int eunion_sidecar_identity_from_stat(const sidecar_stat_t* status,
	struct eunion_sidecar_identity* identity)
{
	if (!status || !identity)
		return -LINUX_EINVAL;
	*identity = (struct eunion_sidecar_identity) {
		.present = 1,
		.mode = (uint32_t)status->st_mode,
		.device = (uint64_t)status->st_dev,
		.inode = (uint64_t)status->st_ino,
#ifdef TEST
		.ctime_seconds = (int64_t)status->st_ctim.tv_sec,
		.ctime_nanoseconds = (int64_t)status->st_ctim.tv_nsec,
#else
		.ctime_seconds = (int64_t)status->st_ctime,
		.ctime_nanoseconds = (int64_t)status->st_ctime_nsec,
#endif
	};
	return 0;
}

static int eunion_sidecar_fstat_identity(int descriptor,
	struct eunion_sidecar_identity* identity)
{
	sidecar_stat_t status;
	int result = SIDECAR_SYSCALL(__NR_fstat, descriptor, &status);
	if (result < 0)
		return result;
	return eunion_sidecar_identity_from_stat(&status, identity);
}

static int eunion_sidecar_identity_equal(
	const struct eunion_sidecar_identity* left,
	const struct eunion_sidecar_identity* right)
{
	return left->present == right->present &&
		left->mode == right->mode &&
		left->device == right->device &&
		left->inode == right->inode &&
		left->ctime_seconds == right->ctime_seconds &&
		left->ctime_nanoseconds == right->ctime_nanoseconds;
}

static int eunion_sidecar_same_object(
	const struct eunion_sidecar_identity* left,
	const struct eunion_sidecar_identity* right)
{
	return left->present == right->present &&
		(!left->present ||
		 (left->device == right->device &&
		  left->inode == right->inode &&
		  (left->mode & LINUX_S_IFMT) == (right->mode & LINUX_S_IFMT)));
}

static int eunion_sidecar_open_absolute_directory(const char* path)
{
	if (!path || path[0] != '/')
		return -LINUX_EINVAL;
	int descriptor = SIDECAR_SYSCALL(__NR_openat, LINUX_AT_FDCWD, "/",
		LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
		LINUX_O_CLOEXEC, 0);
	if (descriptor < 0)
		return descriptor;
	const char* cursor = path;
	while (*cursor == '/')
		++cursor;
	while (*cursor) {
		const char* end = cursor;
		while (*end && *end != '/')
			++end;
		size_t length = (size_t)(end - cursor);
		if (length == 0 || length > EUNION_SIDECAR_NAME_MAX ||
			(length == 1 && cursor[0] == '.') ||
			(length == 2 && cursor[0] == '.' && cursor[1] == '.')) {
			SIDECAR_SYSCALL(__NR_close, descriptor);
			return -LINUX_EINVAL;
		}
		char component[EUNION_SIDECAR_NAME_MAX + 1];
		memcpy(component, cursor, length);
		component[length] = '\0';
		int next = SIDECAR_SYSCALL(__NR_openat, descriptor, component,
			LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
			LINUX_O_CLOEXEC, 0);
		if (next < 0) {
			SIDECAR_SYSCALL(__NR_close, descriptor);
			return next;
		}
		SIDECAR_SYSCALL(__NR_close, descriptor);
		descriptor = next;
		cursor = end;
		while (*cursor == '/')
			++cursor;
	}
	return descriptor;
}

static int eunion_sidecar_open_runtime_directory(
	const struct eunion_sidecar_runtime* runtime,
	int anchored_descriptor,
	const char* path)
{
	if (!runtime->anchored) {
#ifdef TEST
		return eunion_sidecar_open_absolute_directory(path);
#else
		(void)path;
		return -LINUX_EINVAL;
#endif
	}
	if (anchored_descriptor < 0)
		return -LINUX_EINVAL;
	/* Linux F_DUPFD_CLOEXEC; kept local to avoid Darwin fcntl values. */
	int descriptor = SIDECAR_SYSCALL(
		__NR_fcntl, anchored_descriptor, 1030, 0);
	if (descriptor < 0)
		return descriptor;
	sidecar_stat_t status;
	int result = SIDECAR_SYSCALL(__NR_fstat, descriptor, &status);
	if (result < 0 || (status.st_mode & LINUX_S_IFMT) != LINUX_S_IFDIR) {
		SIDECAR_SYSCALL(__NR_close, descriptor);
		return result < 0 ? result : -LINUX_ENOTDIR;
	}
	return descriptor;
}

static int eunion_sidecar_open_regular(int parent, const char* name,
	int flags)
{
	int descriptor = SIDECAR_SYSCALL(__NR_openat, parent, name,
		flags | LINUX_O_NOFOLLOW | LINUX_O_CLOEXEC, 0);
	if (descriptor < 0)
		return descriptor;
	sidecar_stat_t status;
	int result = SIDECAR_SYSCALL(__NR_fstat, descriptor, &status);
	if (result < 0 || ((unsigned int)status.st_mode & LINUX_S_IFMT) !=
		LINUX_S_IFREG) {
		SIDECAR_SYSCALL(__NR_close, descriptor);
		return result < 0 ? result : -LINUX_EIO;
	}
	return descriptor;
}

static int eunion_sidecar_close_fd(int* descriptor, int result)
{
	if (*descriptor >= 0) {
		int close_result = SIDECAR_SYSCALL(__NR_close, *descriptor);
		*descriptor = -1;
		if (result >= 0 && close_result < 0)
			result = close_result;
	}
	return result;
}

int eunion_sidecar_runtime_anchor(struct eunion_sidecar_runtime* runtime,
	int upper_descriptor, const char* lower_root, const char* sidecar_root)
{
	if (!runtime || runtime->anchored || upper_descriptor < 0 ||
		!lower_root || lower_root[0] != '/' ||
		!sidecar_root || sidecar_root[0] != '/')
		return -LINUX_EINVAL;
	memset(runtime, 0, sizeof(*runtime));
	runtime->upper_descriptor = -1;
	runtime->lower_descriptor = -1;
	runtime->sidecar_descriptor = -1;
	struct eunion_sidecar_runtime source = {
		.anchored = 1,
	};
	runtime->upper_descriptor = eunion_sidecar_open_runtime_directory(
		&source, upper_descriptor, NULL);
	if (runtime->upper_descriptor < 0)
		return runtime->upper_descriptor;
	runtime->lower_descriptor =
		eunion_sidecar_open_absolute_directory(lower_root);
	if (runtime->lower_descriptor < 0) {
		int result = runtime->lower_descriptor;
		eunion_sidecar_close_fd(&runtime->upper_descriptor, 0);
		return result;
	}
	runtime->sidecar_descriptor =
		eunion_sidecar_open_absolute_directory(sidecar_root);
	if (runtime->sidecar_descriptor < 0) {
		int result = runtime->sidecar_descriptor;
		eunion_sidecar_close_fd(&runtime->lower_descriptor, 0);
		eunion_sidecar_close_fd(&runtime->upper_descriptor, 0);
		return result;
	}
	runtime->anchored = 1;
	return 0;
}

int eunion_sidecar_runtime_release(struct eunion_sidecar_runtime* runtime)
{
	if (!runtime || !runtime->anchored)
		return -LINUX_EINVAL;
	int result = eunion_sidecar_close_fd(
		&runtime->sidecar_descriptor, 0);
	result = eunion_sidecar_close_fd(
		&runtime->lower_descriptor, result);
	result = eunion_sidecar_close_fd(
		&runtime->upper_descriptor, result);
	memset(runtime, 0, sizeof(*runtime));
	return result;
}

static int eunion_sidecar_mkdir_private(int parent, const char* name)
{
	int result = SIDECAR_SYSCALL(__NR_mkdirat, parent, name, 0700);
	if (result < 0)
		return result;
	result = SIDECAR_SYSCALL(__NR_fchmodat2, parent, name, 0700,
		LINUX_AT_SYMLINK_NOFOLLOW);
	if (result < 0) {
		SIDECAR_SYSCALL(__NR_unlinkat, parent, name, 0x200);
		return result;
	}
	return 0;
}

static int eunion_sidecar_write_format(int sidecar,
	const struct eunion_sidecar_identity* upper,
	const struct eunion_sidecar_identity* lower,
	struct eunion_sidecar_format_disk* written)
{
	struct eunion_sidecar_format_disk format;
	memset(&format, 0, sizeof(format));
	format.magic = EUNION_SIDECAR_FORMAT_MAGIC;
	format.version = EUNION_SIDECAR_FORMAT_VERSION;
	format.size = (uint32_t)sizeof(format);
#ifdef TEST
	memcpy(format.uuid, eunion_test_sidecar_uuid, sizeof(format.uuid));
	memcpy(format.key, eunion_test_sidecar_key, sizeof(format.key));
#else
	int random_result = SIDECAR_SYSCALL(__NR_getrandom,
		format.uuid, sizeof(format.uuid), 0);
	if (random_result != (int)sizeof(format.uuid))
		return random_result < 0 ? random_result : -LINUX_EIO;
	random_result = SIDECAR_SYSCALL(__NR_getrandom,
		format.key, sizeof(format.key), 0);
	if (random_result != (int)sizeof(format.key))
		return random_result < 0 ? random_result : -LINUX_EIO;
#endif
	format.upper_root = *upper;
	format.lower_root = *lower;
	format.checksum = eunion_sidecar_checksum(&format,
		offsetof(struct eunion_sidecar_format_disk, checksum));
	int descriptor = SIDECAR_SYSCALL(__NR_openat, sidecar, "format-v1",
		LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_EXCL |
		LINUX_O_NOFOLLOW | LINUX_O_CLOEXEC, 0600);
	if (descriptor < 0)
		return descriptor;
	int result = SIDECAR_SYSCALL(__NR_fchmod, descriptor, 0600);
	if (result >= 0)
		result = eunion_sidecar_write_all(descriptor, &format, sizeof(format));
	if (result >= 0)
		result = SIDECAR_SYSCALL(__NR_fsync, descriptor);
	result = eunion_sidecar_close_fd(&descriptor, result);
	if (result >= 0 && written)
		*written = format;
	return result;
}

static int eunion_sidecar_write_journal(eunion_sidecar_view view,
	struct eunion_sidecar_journal_disk* journal)
{
	journal->magic = EUNION_SIDECAR_JOURNAL_MAGIC;
	journal->version = EUNION_SIDECAR_FORMAT_VERSION;
	journal->size = (uint32_t)sizeof(*journal);
	journal->checksum = eunion_sidecar_checksum(journal,
		offsetof(struct eunion_sidecar_journal_disk, checksum));
	int descriptor = SIDECAR_SYSCALL(__NR_openat,
		view->sidecar_descriptor, "journal-v1.tmp",
		LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_EXCL |
		LINUX_O_NOFOLLOW | LINUX_O_CLOEXEC, 0600);
	if (descriptor < 0)
		return descriptor;
	int result = SIDECAR_SYSCALL(__NR_fchmod, descriptor, 0600);
	if (result >= 0)
		result = eunion_sidecar_write_all(
			descriptor, journal, sizeof(*journal));
	if (result >= 0)
		result = SIDECAR_SYSCALL(__NR_fsync, descriptor);
	result = eunion_sidecar_close_fd(&descriptor, result);
	if (result >= 0)
		result = SIDECAR_SYSCALL(__NR_renameat,
			view->sidecar_descriptor, "journal-v1.tmp",
			view->sidecar_descriptor, "journal-v1");
	if (result >= 0)
		result = SIDECAR_SYSCALL(__NR_fsync, view->sidecar_descriptor);
	if (result < 0)
		SIDECAR_SYSCALL(__NR_unlinkat,
			view->sidecar_descriptor, "journal-v1.tmp", 0);
	return result;
}

static int eunion_sidecar_read_journal(int sidecar,
	struct eunion_sidecar_journal_disk* journal)
{
	int descriptor = eunion_sidecar_open_regular(
		sidecar, "journal-v1", LINUX_O_RDONLY);
	if (descriptor < 0)
		return descriptor;
	int result = eunion_sidecar_read_exact(
		descriptor, journal, sizeof(*journal));
	result = eunion_sidecar_close_fd(&descriptor, result);
	if (result < 0)
		return result;
	if (journal->magic != EUNION_SIDECAR_JOURNAL_MAGIC ||
		journal->version != EUNION_SIDECAR_FORMAT_VERSION ||
		journal->size != sizeof(*journal) ||
		journal->phase < EUNION_SIDECAR_JOURNAL_PREPARED ||
		journal->phase > EUNION_SIDECAR_JOURNAL_DURABLE ||
		(journal->operation != EUNION_SIDECAR_OPERATION_REMOVE &&
		 journal->operation != EUNION_SIDECAR_OPERATION_CREATE &&
		 journal->operation != EUNION_SIDECAR_OPERATION_COPY_UP &&
		 journal->operation != EUNION_SIDECAR_OPERATION_RENAME) ||
		journal->remove_directory > 1 ||
		journal->recursive_tree > 1 ||
		(journal->recursive_tree &&
		 journal->operation != EUNION_SIDECAR_OPERATION_COPY_UP) ||
		journal->path_length == 0 ||
		journal->path_length >= EUNION_SIDECAR_PATH_MAX ||
		journal->path[0] != '/' ||
		journal->path[journal->path_length] != '\0' ||
		(journal->operation == EUNION_SIDECAR_OPERATION_RENAME &&
		 (journal->secondary_path_length == 0 ||
		  journal->secondary_path_length >= EUNION_SIDECAR_PATH_MAX ||
		  journal->secondary_path[0] != '/' ||
		  journal->secondary_path[
			journal->secondary_path_length] != '\0')) ||
		journal->old_record_valid > 1 ||
		journal->new_record_valid > 1 ||
		journal->secondary_old_record_valid > 1 ||
		journal->secondary_new_record_valid > 1 ||
		journal->checksum != eunion_sidecar_checksum(journal,
			offsetof(struct eunion_sidecar_journal_disk, checksum)))
		return -LINUX_EIO;
	return 0;
}

static int eunion_sidecar_remove_journal(eunion_sidecar_view view)
{
	int result = SIDECAR_SYSCALL(__NR_unlinkat,
		view->sidecar_descriptor, "journal-v1", 0);
	if (result == -LINUX_ENOENT)
		return 0;
	if (result < 0)
		return result;
	return SIDECAR_SYSCALL(__NR_fsync, view->sidecar_descriptor);
}

static int eunion_sidecar_directory_empty(int descriptor, int* empty)
{
	char buffer[4096];
	*empty = 1;
	for (;;) {
		int length = SIDECAR_SYSCALL(__NR_getdents64,
			descriptor, buffer, sizeof(buffer));
		if (length < 0)
			return length;
		if (length == 0)
			return 0;
		int offset = 0;
		while (offset < length) {
			struct eunion_sidecar_dirent64* entry =
				(struct eunion_sidecar_dirent64*)(buffer + offset);
			if (entry->record_length == 0 ||
				offset + entry->record_length > length)
				return -LINUX_EIO;
			offset += entry->record_length;
			if (strcmp(entry->name, ".") != 0 &&
				strcmp(entry->name, "..") != 0) {
				*empty = 0;
				return 0;
			}
		}
	}
}

static int eunion_sidecar_write_activation(int sidecar,
	const struct eunion_sidecar_format_disk* format)
{
	struct eunion_sidecar_activation_disk activation;
	memset(&activation, 0, sizeof(activation));
	activation.magic = EUNION_SIDECAR_ACTIVATION_MAGIC;
	activation.version = EUNION_SIDECAR_FORMAT_VERSION;
	activation.size = (uint32_t)sizeof(activation);
	memcpy(activation.uuid, format->uuid, sizeof(activation.uuid));
	activation.upper_root = format->upper_root;
	activation.lower_root = format->lower_root;
	int result = eunion_sidecar_fstat_identity(
		sidecar, &activation.sidecar_root);
	if (result < 0)
		return result;
	activation.checksum = eunion_sidecar_checksum(&activation,
		offsetof(struct eunion_sidecar_activation_disk, checksum));
	int descriptor = SIDECAR_SYSCALL(__NR_openat, sidecar,
		EUNION_SIDECAR_ACTIVATION_NAME ".tmp",
		LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_EXCL |
		LINUX_O_NOFOLLOW | LINUX_O_CLOEXEC, 0600);
	if (descriptor < 0)
		return descriptor;
	result = SIDECAR_SYSCALL(__NR_fchmod, descriptor, 0600);
	if (result >= 0)
		result = eunion_sidecar_write_all(
			descriptor, &activation, sizeof(activation));
	if (result >= 0)
		result = SIDECAR_SYSCALL(__NR_fsync, descriptor);
	result = eunion_sidecar_close_fd(&descriptor, result);
	if (result >= 0)
		result = SIDECAR_SYSCALL(__NR_renameat2, sidecar,
			EUNION_SIDECAR_ACTIVATION_NAME ".tmp", sidecar,
			EUNION_SIDECAR_ACTIVATION_NAME, LINUX_RENAME_NOREPLACE);
	if (result >= 0)
		result = SIDECAR_SYSCALL(__NR_fsync, sidecar);
	if (result < 0)
		SIDECAR_SYSCALL(__NR_unlinkat, sidecar,
			EUNION_SIDECAR_ACTIVATION_NAME ".tmp", 0);
	return result;
}

static int eunion_sidecar_read_activation(int sidecar,
	struct eunion_sidecar_activation_disk* activation)
{
	int descriptor = eunion_sidecar_open_regular(sidecar,
		EUNION_SIDECAR_ACTIVATION_NAME, LINUX_O_RDONLY);
	if (descriptor < 0)
		return descriptor;
	int result = eunion_sidecar_read_exact(
		descriptor, activation, sizeof(*activation));
	result = eunion_sidecar_close_fd(&descriptor, result);
	if (result < 0)
		return result;
	if (activation->magic != EUNION_SIDECAR_ACTIVATION_MAGIC ||
		activation->version != EUNION_SIDECAR_FORMAT_VERSION ||
		activation->size != sizeof(*activation) ||
		activation->checksum != eunion_sidecar_checksum(activation,
			offsetof(struct eunion_sidecar_activation_disk, checksum)))
		return -LINUX_EIO;
	return 0;
}

static int eunion_sidecar_write_root_node(int tree,
	const struct eunion_sidecar_identity* upper,
	const struct eunion_sidecar_identity* lower)
{
	int root = eunion_sidecar_mkdir_private(tree, "root-v1");
	if (root < 0)
		return root;
	int root_descriptor = SIDECAR_SYSCALL(__NR_openat, tree, "root-v1",
		LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
		LINUX_O_CLOEXEC, 0);
	if (root_descriptor < 0)
		return root_descriptor;
	int result = SIDECAR_SYSCALL(__NR_fchmod, root_descriptor, 0700);
	if (result >= 0)
		result = eunion_sidecar_mkdir_private(root_descriptor, "children");
	if (result >= 0) {
		struct eunion_sidecar_node_disk node;
		memset(&node, 0, sizeof(node));
		node.magic = EUNION_SIDECAR_NODE_MAGIC;
		node.version = EUNION_SIDECAR_FORMAT_VERSION;
		node.size = (uint32_t)sizeof(node);
		node.kind = EUNION_SIDECAR_RECORD_INDEX;
		node.name_length = 1;
		node.generation = 1;
		node.name[0] = '/';
		node.upper = *upper;
		node.lower = *lower;
		node.checksum = eunion_sidecar_checksum(&node,
			offsetof(struct eunion_sidecar_node_disk, checksum));
		int descriptor = SIDECAR_SYSCALL(__NR_openat, root_descriptor,
			"node-v1", LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_EXCL |
			LINUX_O_NOFOLLOW | LINUX_O_CLOEXEC, 0600);
		if (descriptor < 0)
			result = descriptor;
		else {
			result = SIDECAR_SYSCALL(__NR_fchmod, descriptor, 0600);
			if (result >= 0)
				result = eunion_sidecar_write_all(descriptor,
					&node, sizeof(node));
			if (result >= 0)
				result = SIDECAR_SYSCALL(__NR_fsync, descriptor);
			result = eunion_sidecar_close_fd(&descriptor, result);
		}
	}
	if (result >= 0)
		result = SIDECAR_SYSCALL(__NR_fsync, root_descriptor);
	result = eunion_sidecar_close_fd(&root_descriptor, result);
	if (result >= 0)
		result = SIDECAR_SYSCALL(__NR_fsync, tree);
	return result;
}

static int eunion_sidecar_cleanup_failed_initialize(int upper, int sidecar)
{
	int result = 0;
	int tree = SIDECAR_SYSCALL(__NR_openat, sidecar, "tree-v1",
		LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
		LINUX_O_CLOEXEC, 0);
	if (tree >= 0) {
		int root = SIDECAR_SYSCALL(__NR_openat, tree, "root-v1",
			LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
			LINUX_O_CLOEXEC, 0);
		if (root >= 0) {
			int cleanup = SIDECAR_SYSCALL(__NR_unlinkat,
				root, "node-v1", 0);
			if (cleanup < 0 && cleanup != -LINUX_ENOENT)
				result = cleanup;
			cleanup = SIDECAR_SYSCALL(__NR_unlinkat,
				root, "children", 0x200);
			if (result >= 0 && cleanup < 0 &&
				cleanup != -LINUX_ENOENT)
				result = cleanup;
			eunion_sidecar_close_fd(&root, 0);
		}
		int cleanup = SIDECAR_SYSCALL(__NR_unlinkat,
			tree, "root-v1", 0x200);
		if (result >= 0 && cleanup < 0 && cleanup != -LINUX_ENOENT)
			result = cleanup;
		eunion_sidecar_close_fd(&tree, 0);
	}
	const char* sidecar_names[] = {
		"staging-v1", "tree-v1", "format-v1",
		"journal-v1.tmp", "journal-v1",
		EUNION_SIDECAR_ACTIVATION_NAME ".tmp",
		EUNION_SIDECAR_ACTIVATION_NAME,
	};
	const int sidecar_flags[] = { 0x200, 0x200, 0, 0, 0, 0, 0 };
	for (size_t index = 0;
		index < sizeof(sidecar_names) / sizeof(sidecar_names[0]);
		++index) {
		int cleanup = SIDECAR_SYSCALL(__NR_unlinkat, sidecar,
			sidecar_names[index], sidecar_flags[index]);
		if (result >= 0 && cleanup < 0 && cleanup != -LINUX_ENOENT)
			result = cleanup;
	}
	int sync_result = SIDECAR_SYSCALL(__NR_fsync, sidecar);
	if (result >= 0 && sync_result < 0)
		result = sync_result;
	sync_result = SIDECAR_SYSCALL(__NR_fsync, upper);
	if (result >= 0 && sync_result < 0)
		result = sync_result;
	return result;
}

static int eunion_sidecar_initialization_layout(
	int sidecar, int* recovery_required)
{
	if (!recovery_required)
		return -LINUX_EINVAL;
	*recovery_required = 0;
	int cursor = SIDECAR_SYSCALL(__NR_openat, sidecar, ".",
		LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
		LINUX_O_CLOEXEC, 0);
	if (cursor < 0)
		return cursor;
	char buffer[1024];
	int found_lock = 0;
	int result = 0;
	for (;;) {
		int length = SIDECAR_SYSCALL(
			__NR_getdents64, cursor, buffer, sizeof(buffer));
		if (length < 0) {
			result = length;
			break;
		}
		if (length == 0)
			break;
		int offset = 0;
		while (offset < length) {
			struct eunion_sidecar_dirent64* entry =
				(struct eunion_sidecar_dirent64*)(buffer + offset);
			if (entry->record_length == 0 ||
				offset + entry->record_length > length) {
				result = -LINUX_EIO;
				break;
			}
			offset += entry->record_length;
			if (strcmp(entry->name, ".") == 0 ||
				strcmp(entry->name, "..") == 0)
				continue;
			if (strcmp(entry->name, "lock-v1") == 0) {
				if (found_lock) {
					result = -LINUX_EIO;
					break;
				}
				found_lock = 1;
				continue;
			}
			if (strcmp(entry->name, "format-v1") == 0 ||
				strcmp(entry->name, "tree-v1") == 0 ||
				strcmp(entry->name, "staging-v1") == 0 ||
				strcmp(entry->name,
					EUNION_SIDECAR_ACTIVATION_NAME ".tmp") == 0) {
				*recovery_required = 1;
				continue;
			}
			{
				result = -LINUX_ENOTEMPTY;
				break;
			}
		}
		if (result < 0)
			break;
	}
	result = eunion_sidecar_close_fd(&cursor, result);
	return result < 0 ? result : (found_lock ? 0 : -LINUX_EIO);
}

static int eunion_sidecar_validate_named_lock(int sidecar, int lock)
{
	sidecar_stat_t opened_status;
	sidecar_stat_t named_status;
	int result = SIDECAR_SYSCALL(__NR_fstat, lock, &opened_status);
	if (result >= 0 &&
		((unsigned int)opened_status.st_mode & LINUX_S_IFMT) !=
			LINUX_S_IFREG)
		result = -LINUX_EIO;
	if (result >= 0)
		result = SIDECAR_SYSCALL(__NR_newfstatat,
			sidecar, "lock-v1", &named_status,
			LINUX_AT_SYMLINK_NOFOLLOW);
	if (result >= 0 &&
		(((unsigned int)named_status.st_mode & LINUX_S_IFMT) !=
			LINUX_S_IFREG ||
		 opened_status.st_dev != named_status.st_dev ||
		 opened_status.st_ino != named_status.st_ino))
		result = -LINUX_EBUSY;
	return result;
}

int eunion_sidecar_initialize(const struct eunion_sidecar_runtime* runtime)
{
	if (!runtime || (!runtime->anchored &&
			(!runtime->upper_root || !runtime->lower_root ||
			 !runtime->sidecar_root)))
		return -LINUX_EINVAL;
	int upper = eunion_sidecar_open_runtime_directory(runtime,
		runtime->upper_descriptor, runtime->upper_root);
	if (upper < 0)
		return upper;
	int lower = eunion_sidecar_open_runtime_directory(runtime,
		runtime->lower_descriptor, runtime->lower_root);
	if (lower < 0) {
		eunion_sidecar_close_fd(&upper, 0);
		return lower;
	}
	int sidecar = eunion_sidecar_open_runtime_directory(runtime,
		runtime->sidecar_descriptor, runtime->sidecar_root);
	if (sidecar < 0) {
		eunion_sidecar_close_fd(&lower, 0);
		eunion_sidecar_close_fd(&upper, 0);
		return sidecar;
	}
	struct eunion_sidecar_runtime anchored = {
		.anchored = 1,
		.upper_descriptor = upper,
		.lower_descriptor = lower,
		.sidecar_descriptor = sidecar,
	};
	int state_result =
		eunion_sidecar_prefix_state_v3_valid(&anchored);
	if (state_result < 0) {
		eunion_sidecar_close_fd(&sidecar, 0);
		eunion_sidecar_close_fd(&lower, 0);
		eunion_sidecar_close_fd(&upper, 0);
		return state_result;
	}
	int result = 0;
	struct eunion_sidecar_identity upper_identity;
	struct eunion_sidecar_identity lower_identity;
	if (result >= 0)
		result = eunion_sidecar_fstat_identity(upper, &upper_identity);
	if (result >= 0)
		result = eunion_sidecar_fstat_identity(lower, &lower_identity);
	if (result >= 0) {
#ifdef TEST
		if (eunion_test_sidecar_checkpoint_hook)
			eunion_test_sidecar_checkpoint_hook(
				EUNION_SIDECAR_TEST_INITIALIZE_READY, "/");
#endif
	}
	int lock = -1;
	if (result >= 0) {
		lock = SIDECAR_SYSCALL(__NR_openat, sidecar, "lock-v1",
			LINUX_O_RDWR | LINUX_O_CREAT |
			LINUX_O_NOFOLLOW | LINUX_O_CLOEXEC, 0600);
		if (lock < 0)
			result = lock;
		else {
			result = SIDECAR_SYSCALL(
				__NR_flock, lock, LINUX_LOCK_EX);
			if (result >= 0)
				result = eunion_sidecar_validate_named_lock(
					sidecar, lock);
			if (result >= 0)
				result = SIDECAR_SYSCALL(__NR_fchmod, lock, 0600);
			if (result >= 0)
				result = SIDECAR_SYSCALL(__NR_fsync, lock);
#ifdef TEST
			if (result >= 0 && eunion_test_sidecar_checkpoint_hook)
				eunion_test_sidecar_checkpoint_hook(
					EUNION_SIDECAR_TEST_INITIALIZE_LOCKED, "/");
#endif
		}
	}
	int recovery_required = 0;
	if (result >= 0) {
		struct eunion_sidecar_activation_disk activation;
		int activation_result =
			eunion_sidecar_read_activation(sidecar, &activation);
		if (activation_result >= 0) {
			struct eunion_prefix_format_inspection inspection;
			int inspect_result =
				eunion_sidecar_inspect_prefix(&anchored, &inspection);
			result = inspect_result < 0
				? inspect_result
				: inspection.verdict == EUNION_PREFIX_FORMAT_VALID
					? 1 : -LINUX_EIO;
		} else if (activation_result != -LINUX_ENOENT)
			result = activation_result;
		else
			result = eunion_sidecar_initialization_layout(
				sidecar, &recovery_required);
	}
	if (result >= 0 && result != 1 && recovery_required) {
		result = eunion_sidecar_cleanup_failed_initialize(upper, sidecar);
		if (result >= 0) {
			int unexpected_recovery = 0;
			result = eunion_sidecar_initialization_layout(
				sidecar, &unexpected_recovery);
			if (result >= 0 && unexpected_recovery)
				result = -LINUX_EIO;
		}
	}
	int already_initialized = result == 1;
	int initialization_owned =
		result == 0 && !already_initialized;
	if (already_initialized)
		result = 0;
	struct eunion_sidecar_format_disk format;
	if (result >= 0 && !already_initialized)
		result = eunion_sidecar_write_format(sidecar,
			&upper_identity, &lower_identity, &format);
#ifdef TEST
	if (result >= 0 && !already_initialized &&
		eunion_test_sidecar_checkpoint_hook)
		eunion_test_sidecar_checkpoint_hook(
			EUNION_SIDECAR_TEST_INITIALIZE_FORMAT, "/");
#endif
	if (result >= 0 && !already_initialized)
		result = eunion_sidecar_mkdir_private(sidecar, "tree-v1");
	int tree = -1;
	if (result >= 0 && !already_initialized) {
		tree = SIDECAR_SYSCALL(__NR_openat, sidecar, "tree-v1",
			LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
			LINUX_O_CLOEXEC, 0);
		result = tree < 0 ? tree : 0;
	}
	if (result >= 0 && !already_initialized)
		result = SIDECAR_SYSCALL(__NR_fchmod, tree, 0700);
	if (result >= 0 && !already_initialized)
		result = eunion_sidecar_write_root_node(tree,
			&upper_identity, &lower_identity);
#ifdef TEST
	if (result >= 0 && !already_initialized &&
		eunion_test_sidecar_checkpoint_hook)
		eunion_test_sidecar_checkpoint_hook(
			EUNION_SIDECAR_TEST_INITIALIZE_TREE, "/");
#endif
	if (result >= 0 && !already_initialized)
		result = eunion_sidecar_mkdir_private(sidecar, "staging-v1");
#ifdef TEST
	if (result >= 0 && !already_initialized &&
		eunion_test_sidecar_checkpoint_hook)
		eunion_test_sidecar_checkpoint_hook(
			EUNION_SIDECAR_TEST_INITIALIZE_STAGING, "/");
#endif
	if (result >= 0 && !already_initialized)
		result = SIDECAR_SYSCALL(__NR_fsync, sidecar);
	if (result >= 0 && !already_initialized)
		result = eunion_sidecar_write_activation(sidecar, &format);
#ifdef TEST
	if (result >= 0 && !already_initialized &&
		eunion_test_sidecar_checkpoint_hook)
		eunion_test_sidecar_checkpoint_hook(
			EUNION_SIDECAR_TEST_INITIALIZE_ACTIVATED, "/");
#endif
	result = eunion_sidecar_close_fd(&tree, result);
	if (result < 0 && initialization_owned) {
		int cleanup = eunion_sidecar_cleanup_failed_initialize(
			upper, sidecar);
		if (cleanup < 0)
			result = cleanup;
	}
	if (lock >= 0) {
		int unlock = SIDECAR_SYSCALL(
			__NR_flock, lock, LINUX_LOCK_UN);
		if (result >= 0 && unlock < 0)
			result = unlock;
	}
	result = eunion_sidecar_close_fd(&lock, result);
	result = eunion_sidecar_close_fd(&sidecar, result);
	result = eunion_sidecar_close_fd(&lower, result);
	return eunion_sidecar_close_fd(&upper, result);
}

static int eunion_sidecar_read_format(int sidecar,
	struct eunion_sidecar_format_disk* format)
{
	int descriptor = eunion_sidecar_open_regular(sidecar, "format-v1",
		LINUX_O_RDONLY);
	if (descriptor < 0)
		return descriptor;
	int result = eunion_sidecar_read_exact(descriptor, format, sizeof(*format));
	result = eunion_sidecar_close_fd(&descriptor, result);
	if (result < 0)
		return result;
	if (format->magic != EUNION_SIDECAR_FORMAT_MAGIC ||
		format->version != EUNION_SIDECAR_FORMAT_VERSION ||
		format->size != sizeof(*format) ||
		format->checksum != eunion_sidecar_checksum(format,
			offsetof(struct eunion_sidecar_format_disk, checksum)))
		return -LINUX_EIO;
	return 0;
}

static int eunion_sidecar_line_equals(
	const char* line, size_t length, const char* expected)
{
	size_t expected_length = strlen(expected);
	return length == expected_length &&
		eunion_sidecar_bytes_equal(line, expected, length);
}

static int eunion_sidecar_parse_field_u64(
	const char* line, size_t length, const char* key, uint64_t* value)
{
	size_t key_length = strlen(key);
	if (length <= key_length ||
		!eunion_sidecar_bytes_equal(line, key, key_length))
		return -LINUX_EIO;
	uint64_t parsed = 0;
	for (size_t index = key_length; index < length; ++index) {
		unsigned char character = (unsigned char)line[index];
		if (character < '0' || character > '9' ||
			parsed > (UINT64_MAX - (character - '0')) / 10)
			return -LINUX_EIO;
		parsed = parsed * 10 + (character - '0');
	}
	*value = parsed;
	return 0;
}

int eunion_sidecar_prefix_state_v3_valid(
	const struct eunion_sidecar_runtime* runtime)
{
	if (!runtime || !runtime->anchored)
		return -LINUX_EINVAL;
	int descriptor = eunion_sidecar_open_regular(
		runtime->upper_descriptor, ".darling-prefix-state-v3",
		LINUX_O_RDONLY);
	if (descriptor < 0)
		return descriptor == -LINUX_ENOENT
			? -EUNION_PREFIX_RECREATE_REQUIRED_ERROR : descriptor;
	sidecar_stat_t metadata;
	int result = SIDECAR_SYSCALL(__NR_fstat, descriptor, &metadata);
	if (result >= 0 &&
		(((unsigned int)metadata.st_mode & LINUX_S_IFMT) != LINUX_S_IFREG ||
		 ((unsigned int)metadata.st_mode & 07777) != 0600 ||
		 metadata.st_size <= 0 || metadata.st_size >= 1024))
		result = -LINUX_EIO;
	char content[1024];
	if (result >= 0)
		result = eunion_sidecar_read_exact(
			descriptor, content, (size_t)metadata.st_size);
	result = eunion_sidecar_close_fd(&descriptor, result);
	if (result < 0)
		return result;
	if (memchr(content, '\0', (size_t)metadata.st_size) != NULL)
		return -LINUX_EIO;
	const char* lines[11];
	size_t lengths[11];
	size_t offset = 0;
	for (size_t index = 0; index < 11; ++index) {
		lines[index] = content + offset;
		const char* newline = memchr(content + offset, '\n',
			(size_t)metadata.st_size - offset);
		if (!newline)
			return -LINUX_EIO;
		lengths[index] = (size_t)(newline - (content + offset));
		offset = (size_t)(newline - content) + 1;
	}
	if (offset != (size_t)metadata.st_size ||
		!eunion_sidecar_line_equals(lines[0], lengths[0],
			"DARLING_PREFIX_STATE_V3") ||
		!eunion_sidecar_line_equals(lines[1], lengths[1],
			"schema_version=3") ||
		!eunion_sidecar_line_equals(lines[10], lengths[10],
			"provenance=darling-runtime-prefix-sidecar-v1"))
		return -LINUX_EIO;
	static const char* modes[] = {
		"runtime_mode=privileged-overlay",
		"runtime_mode=privileged-copy",
		"runtime_mode=privileged-eunion",
		"runtime_mode=rootless-eunion",
	};
	int valid_mode = 0;
	for (size_t index = 0;
		index < sizeof(modes) / sizeof(modes[0]); ++index)
		valid_mode |= eunion_sidecar_line_equals(
			lines[2], lengths[2], modes[index]);
	if (!valid_mode)
		return -LINUX_EIO;
	uint64_t generation;
	uint64_t prefix_device;
	uint64_t prefix_inode;
	uint64_t sidecar_device;
	uint64_t sidecar_inode;
	uint64_t owner_uid;
	uint64_t owner_gid;
	if (eunion_sidecar_parse_field_u64(lines[3], lengths[3],
			"generation=", &generation) < 0 ||
		eunion_sidecar_parse_field_u64(lines[4], lengths[4],
			"prefix_device=", &prefix_device) < 0 ||
		eunion_sidecar_parse_field_u64(lines[5], lengths[5],
			"prefix_inode=", &prefix_inode) < 0 ||
		eunion_sidecar_parse_field_u64(lines[6], lengths[6],
			"sidecar_device=", &sidecar_device) < 0 ||
		eunion_sidecar_parse_field_u64(lines[7], lengths[7],
			"sidecar_inode=", &sidecar_inode) < 0 ||
		eunion_sidecar_parse_field_u64(lines[8], lengths[8],
			"owner_uid=", &owner_uid) < 0 ||
		eunion_sidecar_parse_field_u64(lines[9], lengths[9],
			"owner_gid=", &owner_gid) < 0 ||
		generation == 0)
		return -LINUX_EIO;
	sidecar_stat_t prefix_status;
	sidecar_stat_t sidecar_status;
	if (SIDECAR_SYSCALL(__NR_fstat, runtime->upper_descriptor,
			&prefix_status) < 0 ||
		SIDECAR_SYSCALL(__NR_fstat, runtime->sidecar_descriptor,
			&sidecar_status) < 0 ||
		prefix_device != (uint64_t)prefix_status.st_dev ||
		prefix_inode != (uint64_t)prefix_status.st_ino ||
		sidecar_device != (uint64_t)sidecar_status.st_dev ||
		sidecar_inode != (uint64_t)sidecar_status.st_ino ||
		owner_uid != (uint64_t)prefix_status.st_uid ||
		owner_gid != (uint64_t)prefix_status.st_gid ||
		owner_uid != (uint64_t)sidecar_status.st_uid ||
		owner_gid != (uint64_t)sidecar_status.st_gid)
		return -LINUX_EIO;
	return 0;
}

int eunion_sidecar_inspect_prefix(
	const struct eunion_sidecar_runtime* runtime,
	struct eunion_prefix_format_inspection* inspection)
{
	if (!runtime || (!runtime->anchored &&
			(!runtime->upper_root || !runtime->lower_root ||
			 !runtime->sidecar_root)) || !inspection)
		return -LINUX_EINVAL;
	memset(inspection, 0, sizeof(*inspection));
	inspection->verdict = EUNION_PREFIX_FORMAT_CORRUPT;
	int upper = eunion_sidecar_open_runtime_directory(runtime,
		runtime->upper_descriptor, runtime->upper_root);
	if (upper < 0)
		return upper;
	int sidecar = eunion_sidecar_open_runtime_directory(runtime,
		runtime->sidecar_descriptor, runtime->sidecar_root);
	if (sidecar == -LINUX_ENOENT || sidecar == -LINUX_ENOTDIR) {
		inspection->verdict = EUNION_PREFIX_RECREATE_REQUIRED;
		eunion_sidecar_close_fd(&upper, 0);
		return 0;
	}
	if (sidecar < 0) {
		eunion_sidecar_close_fd(&upper, 0);
		return sidecar;
	}
	struct eunion_sidecar_activation_disk activation;
	int result = eunion_sidecar_read_activation(sidecar, &activation);
	if (result == -LINUX_ENOENT) {
		int empty = 0;
		int empty_result =
			eunion_sidecar_directory_empty(sidecar, &empty);
		struct eunion_sidecar_runtime inspected = {
			.anchored = 1,
			.upper_descriptor = upper,
			.lower_descriptor = -1,
			.sidecar_descriptor = sidecar,
		};
		int state_result = empty_result >= 0 && empty
			? eunion_sidecar_prefix_state_v3_valid(&inspected)
			: -LINUX_EIO;
		if (empty_result < 0)
			inspection->verdict = EUNION_PREFIX_FORMAT_CORRUPT;
		else if (!empty)
			inspection->verdict = EUNION_PREFIX_FORMAT_CORRUPT;
		else if (state_result >= 0)
			inspection->verdict = EUNION_PREFIX_FORMAT_UNINITIALIZED;
		else
			inspection->verdict = EUNION_PREFIX_RECREATE_REQUIRED;
		eunion_sidecar_close_fd(&sidecar, 0);
		eunion_sidecar_close_fd(&upper, 0);
		return 0;
	}
	if (result < 0) {
		eunion_sidecar_close_fd(&sidecar, 0);
		eunion_sidecar_close_fd(&upper, 0);
		return 0;
	}
	int lower = eunion_sidecar_open_runtime_directory(runtime,
		runtime->lower_descriptor, runtime->lower_root);
	if (lower < 0) {
		eunion_sidecar_close_fd(&sidecar, 0);
		eunion_sidecar_close_fd(&upper, 0);
		return 0;
	}
	struct eunion_sidecar_format_disk format;
	struct eunion_sidecar_identity upper_identity;
	struct eunion_sidecar_identity lower_identity;
	struct eunion_sidecar_identity sidecar_identity;
	result = eunion_sidecar_read_format(sidecar, &format);
	if (result >= 0)
		result = eunion_sidecar_fstat_identity(upper, &upper_identity);
	if (result >= 0)
		result = eunion_sidecar_fstat_identity(lower, &lower_identity);
	if (result >= 0)
		result = eunion_sidecar_fstat_identity(sidecar, &sidecar_identity);
	if (result >= 0 &&
		(!eunion_sidecar_bytes_equal(
			activation.uuid, format.uuid, sizeof(format.uuid)) ||
		 !eunion_sidecar_same_object(
			&activation.upper_root, &upper_identity) ||
		 !eunion_sidecar_same_object(
			&activation.lower_root, &lower_identity) ||
		 !eunion_sidecar_same_object(
			&activation.sidecar_root, &sidecar_identity) ||
		 !eunion_sidecar_same_object(
			&format.upper_root, &upper_identity) ||
		 !eunion_sidecar_same_object(
			&format.lower_root, &lower_identity)))
		result = -LINUX_EIO;
	if (result >= 0) {
		inspection->verdict = EUNION_PREFIX_FORMAT_VALID;
		inspection->format_version = format.version;
		memcpy(inspection->uuid, format.uuid, sizeof(inspection->uuid));
	}
	eunion_sidecar_close_fd(&sidecar, 0);
	eunion_sidecar_close_fd(&lower, 0);
	eunion_sidecar_close_fd(&upper, 0);
	return 0;
}

static int eunion_sidecar_read_node(int node,
	struct eunion_sidecar_node_disk* record)
{
	int descriptor = eunion_sidecar_open_regular(node, "node-v1",
		LINUX_O_RDONLY);
	if (descriptor < 0)
		return descriptor;
	int result = eunion_sidecar_read_exact(descriptor, record, sizeof(*record));
	result = eunion_sidecar_close_fd(&descriptor, result);
	if (result < 0)
		return result;
	if (record->magic != EUNION_SIDECAR_NODE_MAGIC ||
		record->version != EUNION_SIDECAR_FORMAT_VERSION ||
		record->size != sizeof(*record) ||
		record->kind <= EUNION_SIDECAR_RECORD_NONE ||
		record->kind >= EUNION_SIDECAR_RECORD_INVALID ||
		record->name_length == 0 ||
		record->name_length > EUNION_SIDECAR_NAME_MAX ||
		record->name[record->name_length] != '\0' ||
		record->checksum != eunion_sidecar_checksum(record,
			offsetof(struct eunion_sidecar_node_disk, checksum)))
		return -LINUX_EIO;
	return 0;
}

static int eunion_sidecar_validate_view(eunion_sidecar_view view)
{
	return view && view->owner == (uintptr_t)view &&
		view->phase == EUNION_SIDECAR_VIEW_OPEN &&
		view->access < EUNION_SIDECAR_ACCESS_INVALID
			? 0 : -LINUX_EINVAL;
}

int eunion_sidecar_view_open(eunion_sidecar_view view,
	const struct eunion_sidecar_runtime* runtime,
	enum eunion_sidecar_access access)
{
	if (!view || !runtime || (!runtime->anchored &&
			(!runtime->upper_root || !runtime->lower_root ||
			 !runtime->sidecar_root)) ||
		access < EUNION_SIDECAR_ACCESS_SHARED ||
		access >= EUNION_SIDECAR_ACCESS_INVALID ||
		view->phase != EUNION_SIDECAR_VIEW_EMPTY)
		return -LINUX_EINVAL;
	memset(view, 0, sizeof(*view));
	view->owner = (uintptr_t)view;
	view->phase = EUNION_SIDECAR_VIEW_EMPTY;
	view->access = access;
	view->upper_descriptor = -1;
	view->lower_descriptor = -1;
	view->sidecar_descriptor = -1;
	view->lock_descriptor = -1;
	view->tree_descriptor = -1;
	view->root_descriptor = -1;
	int result = 0;
	view->upper_descriptor =
		eunion_sidecar_open_runtime_directory(runtime,
			runtime->upper_descriptor, runtime->upper_root);
	if (view->upper_descriptor < 0)
		result = view->upper_descriptor;
	if (result >= 0) {
		view->lower_descriptor =
			eunion_sidecar_open_runtime_directory(runtime,
				runtime->lower_descriptor, runtime->lower_root);
		if (view->lower_descriptor < 0)
			result = view->lower_descriptor;
	}
	if (result >= 0) {
		view->sidecar_descriptor =
			eunion_sidecar_open_runtime_directory(runtime,
				runtime->sidecar_descriptor, runtime->sidecar_root);
		if (view->sidecar_descriptor < 0)
			result = view->sidecar_descriptor;
	}
	if (result >= 0) {
		view->lock_descriptor = eunion_sidecar_open_regular(
			view->sidecar_descriptor, "lock-v1", LINUX_O_RDWR);
		if (view->lock_descriptor < 0)
			result = view->lock_descriptor;
	}
	if (result >= 0)
		result = SIDECAR_SYSCALL(__NR_flock, view->lock_descriptor,
			access == EUNION_SIDECAR_ACCESS_SHARED
				? LINUX_LOCK_SH : LINUX_LOCK_EX);
	if (result >= 0) {
		struct eunion_sidecar_identity opened;
		struct eunion_sidecar_identity named;
		sidecar_stat_t status;
		result = eunion_sidecar_fstat_identity(view->lock_descriptor, &opened);
		if (result >= 0)
			result = SIDECAR_SYSCALL(__NR_newfstatat,
				view->sidecar_descriptor, "lock-v1", &status,
				LINUX_AT_SYMLINK_NOFOLLOW);
		if (result >= 0)
			result = eunion_sidecar_identity_from_stat(&status, &named);
		if (result >= 0 && !eunion_sidecar_identity_equal(&opened, &named))
			result = -LINUX_EBUSY;
	}
	struct eunion_sidecar_format_disk format;
	if (result >= 0)
		result = eunion_sidecar_read_format(view->sidecar_descriptor, &format);
	struct eunion_sidecar_activation_disk activation;
	if (result >= 0)
		result = eunion_sidecar_read_activation(
			view->sidecar_descriptor, &activation);
	if (result >= 0) {
		struct eunion_sidecar_identity upper;
		struct eunion_sidecar_identity lower;
		struct eunion_sidecar_identity sidecar;
		result = eunion_sidecar_fstat_identity(
			view->upper_descriptor, &upper);
		if (result >= 0)
			result = eunion_sidecar_fstat_identity(
				view->lower_descriptor, &lower);
		if (result >= 0)
			result = eunion_sidecar_fstat_identity(
				view->sidecar_descriptor, &sidecar);
		if (result >= 0 &&
			(!eunion_sidecar_same_object(&upper, &format.upper_root) ||
			 !eunion_sidecar_same_object(&lower, &format.lower_root) ||
			 !eunion_sidecar_bytes_equal(
				activation.uuid, format.uuid, sizeof(format.uuid)) ||
			 !eunion_sidecar_same_object(
				&upper, &activation.upper_root) ||
			 !eunion_sidecar_same_object(
				&lower, &activation.lower_root) ||
			 !eunion_sidecar_same_object(
				&sidecar, &activation.sidecar_root)))
			result = -LINUX_EIO;
	}
	if (result >= 0) {
		view->tree_descriptor = SIDECAR_SYSCALL(__NR_openat,
			view->sidecar_descriptor, "tree-v1",
			LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
			LINUX_O_CLOEXEC, 0);
		if (view->tree_descriptor < 0)
			result = view->tree_descriptor;
	}
	if (result >= 0) {
		view->root_descriptor = SIDECAR_SYSCALL(__NR_openat,
			view->tree_descriptor, "root-v1",
			LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
			LINUX_O_CLOEXEC, 0);
		if (view->root_descriptor < 0)
			result = view->root_descriptor;
	}
	struct eunion_sidecar_node_disk root_record;
	if (result >= 0)
		result = eunion_sidecar_read_node(view->root_descriptor, &root_record);
	if (result >= 0 &&
		(root_record.kind != EUNION_SIDECAR_RECORD_INDEX ||
		 root_record.name_length != 1 || root_record.name[0] != '/' ||
		 !eunion_sidecar_same_object(
			&root_record.upper, &format.upper_root) ||
		 !eunion_sidecar_same_object(
			&root_record.lower, &format.lower_root)))
		result = -LINUX_EIO;
	if (result >= 0) {
		memcpy(view->uuid, format.uuid, sizeof(view->uuid));
		memcpy(view->key, format.key, sizeof(view->key));
		view->root_generation = root_record.generation;
		view->phase = EUNION_SIDECAR_VIEW_OPEN;
		sidecar_stat_t temporary;
		int temporary_result = SIDECAR_SYSCALL(__NR_newfstatat,
			view->sidecar_descriptor, "journal-v1.tmp", &temporary,
			LINUX_AT_SYMLINK_NOFOLLOW);
		if (temporary_result != -LINUX_ENOENT) {
			if (temporary_result < 0)
				result = temporary_result;
			else if (access == EUNION_SIDECAR_ACCESS_SHARED)
				result = -LINUX_EBUSY;
			else {
				result = SIDECAR_SYSCALL(__NR_unlinkat,
					view->sidecar_descriptor, "journal-v1.tmp", 0);
				if (result >= 0)
					result = SIDECAR_SYSCALL(__NR_fsync,
						view->sidecar_descriptor);
			}
		}
		sidecar_stat_t journal;
		int journal_result = result < 0 ? -LINUX_ENOENT :
			SIDECAR_SYSCALL(__NR_newfstatat,
				view->sidecar_descriptor, "journal-v1", &journal,
				LINUX_AT_SYMLINK_NOFOLLOW);
		if (result >= 0 && journal_result != -LINUX_ENOENT) {
			if (journal_result < 0)
				result = journal_result;
			else if (access == EUNION_SIDECAR_ACCESS_SHARED)
				result = -LINUX_EBUSY;
			else
				result = eunion_sidecar_recover_locked(view);
		}
		if (result >= 0)
			return 0;
	}
	eunion_sidecar_view_close(view);
	return result;
}

int eunion_sidecar_view_close(eunion_sidecar_view view)
{
	if (!view || view->owner != (uintptr_t)view ||
		(view->phase != EUNION_SIDECAR_VIEW_EMPTY &&
		 view->phase != EUNION_SIDECAR_VIEW_OPEN))
		return -LINUX_EINVAL;
	int result = 0;
	result = eunion_sidecar_close_fd(&view->root_descriptor, result);
	result = eunion_sidecar_close_fd(&view->tree_descriptor, result);
	if (view->lock_descriptor >= 0) {
		int unlock = SIDECAR_SYSCALL(__NR_flock,
			view->lock_descriptor, LINUX_LOCK_UN);
		if (result >= 0 && unlock < 0)
			result = unlock;
	}
	result = eunion_sidecar_close_fd(&view->lock_descriptor, result);
	result = eunion_sidecar_close_fd(&view->sidecar_descriptor, result);
	result = eunion_sidecar_close_fd(&view->lower_descriptor, result);
	result = eunion_sidecar_close_fd(&view->upper_descriptor, result);
	view->phase = EUNION_SIDECAR_VIEW_RELEASED;
	return result;
}

static uint64_t eunion_sidecar_rotate_left(uint64_t value, unsigned int bits)
{
	return (value << bits) | (value >> (64 - bits));
}

#define EUNION_SIDECAR_SIPROUND() do { \
	v0 += v1; v1 = eunion_sidecar_rotate_left(v1, 13); v1 ^= v0; \
	v0 = eunion_sidecar_rotate_left(v0, 32); \
	v2 += v3; v3 = eunion_sidecar_rotate_left(v3, 16); v3 ^= v2; \
	v0 += v3; v3 = eunion_sidecar_rotate_left(v3, 21); v3 ^= v0; \
	v2 += v1; v1 = eunion_sidecar_rotate_left(v1, 17); v1 ^= v2; \
	v2 = eunion_sidecar_rotate_left(v2, 32); \
} while (0)

static uint64_t eunion_sidecar_component_hash(
	const uint64_t key[2], const char* bytes, size_t length)
{
	uint64_t v0 = 0x736f6d6570736575ULL ^ key[0];
	uint64_t v1 = 0x646f72616e646f6dULL ^ key[1];
	uint64_t v2 = 0x6c7967656e657261ULL ^ key[0];
	uint64_t v3 = 0x7465646279746573ULL ^ key[1];
	size_t offset = 0;
	while (offset + 8 <= length) {
		uint64_t message = 0;
		for (unsigned int index = 0; index < 8; ++index)
			message |= (uint64_t)(unsigned char)bytes[offset + index]
				<< (8 * index);
		v3 ^= message;
		EUNION_SIDECAR_SIPROUND();
		EUNION_SIDECAR_SIPROUND();
		v0 ^= message;
		offset += 8;
	}
	uint64_t tail = (uint64_t)length << 56;
	for (size_t index = 0; offset + index < length; ++index)
		tail |= (uint64_t)(unsigned char)bytes[offset + index] << (8 * index);
	v3 ^= tail;
	EUNION_SIDECAR_SIPROUND();
	EUNION_SIDECAR_SIPROUND();
	v0 ^= tail;
	v2 ^= 0xff;
	EUNION_SIDECAR_SIPROUND();
	EUNION_SIDECAR_SIPROUND();
	EUNION_SIDECAR_SIPROUND();
	EUNION_SIDECAR_SIPROUND();
	return v0 ^ v1 ^ v2 ^ v3;
}

#undef EUNION_SIDECAR_SIPROUND

static void eunion_sidecar_hash_name(uint64_t value, char output[17])
{
	static const char hex[] = "0123456789abcdef";
	for (int index = 15; index >= 0; --index) {
		output[index] = hex[value & 15];
		value >>= 4;
	}
	output[16] = '\0';
}

static int eunion_sidecar_next_component(const char** cursor,
	char component[EUNION_SIDECAR_NAME_MAX + 1], size_t* length)
{
	while (**cursor == '/')
		++*cursor;
	if (**cursor == '\0')
		return 0;
	const char* end = *cursor;
	while (*end && *end != '/')
		++end;
	*length = (size_t)(end - *cursor);
	if (*length == 0 || *length > EUNION_SIDECAR_NAME_MAX ||
		(*length == 1 && (*cursor)[0] == '.') ||
		(*length == 2 && (*cursor)[0] == '.' && (*cursor)[1] == '.'))
		return -LINUX_EINVAL;
	memcpy(component, *cursor, *length);
	component[*length] = '\0';
	*cursor = end;
	return 1;
}

static int eunion_sidecar_open_children(int node)
{
	return SIDECAR_SYSCALL(__NR_openat, node, "children",
		LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
		LINUX_O_CLOEXEC, 0);
}

static int eunion_sidecar_open_child(eunion_sidecar_view view, int parent,
	uint64_t parent_generation, const char* component, size_t length,
	int* child, struct eunion_sidecar_node_disk* record)
{
	char hash[17];
	eunion_sidecar_hash_name(eunion_sidecar_component_hash(
		view->key, component, length), hash);
	int children = eunion_sidecar_open_children(parent);
	if (children < 0)
		return children;
	*child = SIDECAR_SYSCALL(__NR_openat, children, hash,
		LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
		LINUX_O_CLOEXEC, 0);
	int result = *child;
	eunion_sidecar_close_fd(&children, 0);
	if (result < 0)
		return result;
	result = eunion_sidecar_read_node(*child, record);
	if (result >= 0 &&
		(record->parent_generation != parent_generation ||
		 record->name_length != length ||
		 !eunion_sidecar_bytes_equal(record->name, component, length)))
		result = -LINUX_EIO;
	if (result < 0)
		eunion_sidecar_close_fd(child, 0);
	return result;
}

static int eunion_sidecar_fstatat_identity_or_absent(int parent,
	const char* component, struct eunion_sidecar_identity* identity)
{
	sidecar_stat_t status;
	int result = SIDECAR_SYSCALL(__NR_newfstatat, parent, component,
		&status, LINUX_AT_SYMLINK_NOFOLLOW);
	if (result == -LINUX_ENOENT) {
		memset(identity, 0, sizeof(*identity));
		return 0;
	}
	if (result == -LINUX_EACCES) {
		memset(identity, 0, sizeof(*identity));
		identity->present = 2;
		return 0;
	}
	if (result < 0)
		return result;
	return eunion_sidecar_identity_from_stat(&status, identity);
}

static int eunion_sidecar_open_path_child(int parent, const char* component,
	const struct eunion_sidecar_identity* identity)
{
	if (!identity->present ||
		(identity->mode & LINUX_S_IFMT) != LINUX_S_IFDIR)
		return -LINUX_ENOENT;
	return SIDECAR_SYSCALL(__NR_openat, parent, component,
		LINUX_O_PATH | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
		LINUX_O_CLOEXEC, 0);
}

static int eunion_sidecar_validate_record_identities(
	const struct eunion_sidecar_node_disk* record,
	const struct eunion_sidecar_identity* upper,
	const struct eunion_sidecar_identity* lower)
{
	switch ((enum eunion_sidecar_record_kind)record->kind)
	{
		case EUNION_SIDECAR_RECORD_INDEX:
			if ((record->upper.present &&
				 !eunion_sidecar_same_object(&record->upper, upper)) ||
				(record->lower.present &&
				 !eunion_sidecar_same_object(&record->lower, lower)))
				return -LINUX_EIO;
			return 0;
		case EUNION_SIDECAR_RECORD_WHITEOUT:
			if ((upper->present != 2 &&
				 upper->present != record->upper.present) ||
				(upper->present &&
				 upper->present != 2 &&
				 !eunion_sidecar_identity_equal(&record->upper, upper)) ||
				!eunion_sidecar_identity_equal(&record->lower, lower))
				return -LINUX_EIO;
			return 0;
		case EUNION_SIDECAR_RECORD_OPAQUE:
			if (!eunion_sidecar_same_object(&record->upper, upper) ||
				!eunion_sidecar_same_object(&record->lower, lower))
				return -LINUX_EIO;
			return 0;
		case EUNION_SIDECAR_RECORD_NONE:
		case EUNION_SIDECAR_RECORD_INVALID:
		default:
			return -LINUX_EIO;
	}
}

static int eunion_sidecar_walk(eunion_sidecar_view view,
	const char* guest_path, int create_missing,
	enum eunion_sidecar_record_kind leaf_kind,
	int* node_result, struct eunion_sidecar_node_disk* record_result);

struct eunion_sidecar_path_component {
	size_t length;
	char name[EUNION_SIDECAR_NAME_MAX + 1];
};

struct eunion_sidecar_path {
	struct eunion_sidecar_path_component* component;
	int count;
};

extern void* malloc(size_t size);
extern void free(void* pointer);

static int eunion_sidecar_parse_path(
	const char* guest_path, struct eunion_sidecar_path* path);

static void eunion_sidecar_path_release(struct eunion_sidecar_path* path)
{
	if (!path)
		return;
	free(path->component);
	path->component = NULL;
	path->count = 0;
}

#define EUNION_SIDECAR_AUTO_PATH(name) \
	struct eunion_sidecar_path name \
		__attribute__((cleanup(eunion_sidecar_path_release))) = {0}

int eunion_sidecar_lookup_path(eunion_sidecar_view view,
	const char* guest_path, struct eunion_sidecar_lookup* result)
{
	if (eunion_sidecar_validate_view(view) < 0 || !guest_path ||
		guest_path[0] != '/' || !result)
		return -LINUX_EINVAL;
	if (guest_path[1] == '\0') {
		struct eunion_sidecar_node_disk root;
		int read_result = eunion_sidecar_read_node(
			view->root_descriptor, &root);
		if (read_result < 0)
			return read_result;
		*result = (struct eunion_sidecar_lookup) {
			.kind = (enum eunion_sidecar_record_kind)root.kind,
			.generation = root.generation,
			.upper = root.upper,
			.lower = root.lower,
		};
		return 0;
	}
	int node = -1;
	struct eunion_sidecar_node_disk record;
	int walk_result = eunion_sidecar_walk(view, guest_path, 0,
		EUNION_SIDECAR_RECORD_NONE, &node, &record);
	if (walk_result == -LINUX_ENOENT) {
		*result = (struct eunion_sidecar_lookup) {
			.kind = EUNION_SIDECAR_RECORD_NONE,
		};
		return 0;
	}
	if (walk_result < 0)
		return walk_result;
	*result = (struct eunion_sidecar_lookup) {
		.kind = record.kind == EUNION_SIDECAR_RECORD_INDEX
			? EUNION_SIDECAR_RECORD_NONE
			: (enum eunion_sidecar_record_kind)record.kind,
		.generation = record.generation,
		.upper = record.upper,
		.lower = record.lower,
	};
	return eunion_sidecar_close_fd(&node, 0);
}

static int eunion_sidecar_write_node_file(int node,
	struct eunion_sidecar_node_disk* record, int replace)
{
	record->magic = EUNION_SIDECAR_NODE_MAGIC;
	record->version = EUNION_SIDECAR_FORMAT_VERSION;
	record->size = (uint32_t)sizeof(*record);
	record->checksum = eunion_sidecar_checksum(record,
		offsetof(struct eunion_sidecar_node_disk, checksum));
	const char* name = replace ? "node-v1.tmp" : "node-v1";
	int descriptor = SIDECAR_SYSCALL(__NR_openat, node, name,
		LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_EXCL |
		LINUX_O_NOFOLLOW | LINUX_O_CLOEXEC, 0600);
	if (descriptor < 0)
		return descriptor;
	int result = SIDECAR_SYSCALL(__NR_fchmod, descriptor, 0600);
	if (result >= 0)
		result = eunion_sidecar_write_all(descriptor, record, sizeof(*record));
	if (result >= 0)
		result = SIDECAR_SYSCALL(__NR_fsync, descriptor);
	result = eunion_sidecar_close_fd(&descriptor, result);
	if (result < 0) {
		SIDECAR_SYSCALL(__NR_unlinkat, node, name, 0);
		return result;
	}
	if (replace) {
		result = SIDECAR_SYSCALL(__NR_renameat, node, "node-v1.tmp",
			node, "node-v1");
		if (result < 0) {
			SIDECAR_SYSCALL(__NR_unlinkat, node, "node-v1.tmp", 0);
			return result;
		}
	}
	return SIDECAR_SYSCALL(__NR_fsync, node);
}

static int eunion_sidecar_create_child(eunion_sidecar_view view,
	int parent, uint64_t parent_generation, const char* component,
	size_t length, enum eunion_sidecar_record_kind kind,
	const struct eunion_sidecar_identity* upper,
	const struct eunion_sidecar_identity* lower,
	int* child, struct eunion_sidecar_node_disk* record)
{
	char hash[17];
	char temporary[22] = ".tmp-";
	eunion_sidecar_hash_name(eunion_sidecar_component_hash(
		view->key, component, length), hash);
	memcpy(temporary + 5, hash, sizeof(hash));
	int children = eunion_sidecar_open_children(parent);
	if (children < 0)
		return children;
	int result = eunion_sidecar_mkdir_private(children, temporary);
	if (result < 0) {
		eunion_sidecar_close_fd(&children, 0);
		return result;
	}
	int temporary_node = SIDECAR_SYSCALL(__NR_openat, children, temporary,
		LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
		LINUX_O_CLOEXEC, 0);
	if (temporary_node < 0) {
		SIDECAR_SYSCALL(__NR_unlinkat, children, temporary, 0x200);
		eunion_sidecar_close_fd(&children, 0);
		return temporary_node;
	}
	result = SIDECAR_SYSCALL(__NR_fchmod, temporary_node, 0700);
	if (result >= 0)
		result = eunion_sidecar_mkdir_private(temporary_node, "children");
	if (result >= 0) {
		memset(record, 0, sizeof(*record));
		record->kind = (uint32_t)kind;
		record->name_length = (uint32_t)length;
		record->generation = parent_generation + 1;
		record->parent_generation = parent_generation;
		record->upper = *upper;
		record->lower = *lower;
		memcpy(record->name, component, length);
		record->name[length] = '\0';
		result = eunion_sidecar_write_node_file(temporary_node, record, 0);
	}
	if (result >= 0)
		result = SIDECAR_SYSCALL(__NR_fsync, temporary_node);
	if (result >= 0)
		result = SIDECAR_SYSCALL(__NR_fsync, children);
	if (result >= 0)
		result = SIDECAR_SYSCALL(__NR_renameat2, children, temporary,
			children, hash, LINUX_RENAME_NOREPLACE);
	if (result >= 0)
		result = SIDECAR_SYSCALL(__NR_fsync, children);
	eunion_sidecar_close_fd(&temporary_node, 0);
	if (result < 0) {
		int cleanup = eunion_sidecar_dispose_partial_node(
			children, temporary);
		eunion_sidecar_close_fd(&children, 0);
		return cleanup < 0 ? cleanup : result;
	}
	*child = SIDECAR_SYSCALL(__NR_openat, children, hash,
		LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
		LINUX_O_CLOEXEC, 0);
	result = *child < 0 ? *child : 0;
	eunion_sidecar_close_fd(&children, 0);
	return result;
}

static int eunion_sidecar_walk(eunion_sidecar_view view,
	const char* guest_path, int create_missing,
	enum eunion_sidecar_record_kind leaf_kind,
	int* node_result, struct eunion_sidecar_node_disk* record_result)
{
	if (!guest_path || guest_path[0] != '/' || !node_result || !record_result)
		return -LINUX_EINVAL;
	char component[EUNION_SIDECAR_NAME_MAX + 1];
	size_t length = 0;
	const char* cursor = guest_path;
	int next = eunion_sidecar_next_component(
		&cursor, component, &length);
	if (next <= 0)
		return next < 0 ? next : -LINUX_EINVAL;

	int sidecar_node = view->root_descriptor;
	int upper_parent = view->upper_descriptor;
	int lower_parent = view->lower_descriptor;
	uint64_t parent_generation = view->root_generation;
	int own_sidecar_node = 0;
	int own_upper_parent = 0;
	int own_lower_parent = 0;
	int result = 0;
	for (;;) {
		const char* remaining = cursor;
		while (*remaining == '/')
			++remaining;
		const int is_leaf = *remaining == '\0';
		struct eunion_sidecar_identity upper;
		struct eunion_sidecar_identity lower;
		if (upper_parent >= 0)
			result = eunion_sidecar_fstatat_identity_or_absent(
				upper_parent, component, &upper);
		else {
			memset(&upper, 0, sizeof(upper));
			result = 0;
		}
		if (result >= 0 && lower_parent >= 0)
			result = eunion_sidecar_fstatat_identity_or_absent(
				lower_parent, component, &lower);
		else if (result >= 0)
			memset(&lower, 0, sizeof(lower));
		if (result < 0)
			break;

		int child = -1;
		struct eunion_sidecar_node_disk record;
		result = eunion_sidecar_open_child(view, sidecar_node,
			parent_generation, component, length,
			&child, &record);
		enum eunion_sidecar_record_kind expected_kind =
			is_leaf && leaf_kind != EUNION_SIDECAR_RECORD_NONE
				? leaf_kind : EUNION_SIDECAR_RECORD_INDEX;
		if (result == -LINUX_ENOENT && create_missing) {
			if (expected_kind == EUNION_SIDECAR_RECORD_WHITEOUT &&
				!lower.present)
				result = -LINUX_EINVAL;
			else if (expected_kind == EUNION_SIDECAR_RECORD_OPAQUE &&
				(!upper.present || !lower.present ||
				 (upper.mode & LINUX_S_IFMT) != LINUX_S_IFDIR ||
				 (lower.mode & LINUX_S_IFMT) != LINUX_S_IFDIR))
				result = -LINUX_EINVAL;
			else
				result = eunion_sidecar_create_child(view, sidecar_node,
					parent_generation, component, length,
					expected_kind, &upper, &lower, &child, &record);
		}
		if (result < 0)
			break;
		result = eunion_sidecar_validate_record_identities(
			&record, &upper, &lower);
		if (result < 0) {
			eunion_sidecar_close_fd(&child, 0);
			break;
		}
		if (is_leaf && create_missing &&
			record.kind != (uint32_t)expected_kind) {
			record.kind = (uint32_t)expected_kind;
			record.generation++;
			record.upper = upper;
			record.lower = lower;
			result = eunion_sidecar_write_node_file(child, &record, 1);
			if (result < 0) {
				eunion_sidecar_close_fd(&child, 0);
				break;
			}
		}

		int next_upper = !is_leaf
			? eunion_sidecar_open_path_child(
				upper_parent, component, &upper) : -1;
		int next_lower = !is_leaf
			? eunion_sidecar_open_path_child(
				lower_parent, component, &lower) : -1;
		if (own_sidecar_node)
			eunion_sidecar_close_fd(&sidecar_node, 0);
		if (own_upper_parent)
			eunion_sidecar_close_fd(&upper_parent, 0);
		if (own_lower_parent)
			eunion_sidecar_close_fd(&lower_parent, 0);
		sidecar_node = child;
		own_sidecar_node = 1;
		parent_generation = record.generation;
		if (!is_leaf) {
			upper_parent = next_upper >= 0 ? next_upper : -1;
			lower_parent = next_lower >= 0 ? next_lower : -1;
			own_upper_parent = upper_parent >= 0;
			own_lower_parent = lower_parent >= 0;
		}
		*record_result = record;
		if (is_leaf)
			break;
		next = eunion_sidecar_next_component(
			&cursor, component, &length);
		if (next <= 0) {
			result = next < 0 ? next : -LINUX_EINVAL;
			break;
		}
	}
	if (own_upper_parent)
		eunion_sidecar_close_fd(&upper_parent, 0);
	if (own_lower_parent)
		eunion_sidecar_close_fd(&lower_parent, 0);
	if (result < 0) {
		if (own_sidecar_node)
			eunion_sidecar_close_fd(&sidecar_node, 0);
		return result;
	}
	*node_result = sidecar_node;
	return 0;
}

static int eunion_sidecar_require_exclusive(eunion_sidecar_view view)
{
	int result = eunion_sidecar_validate_view(view);
	if (result < 0)
		return result;
	return view->access == EUNION_SIDECAR_ACCESS_EXCLUSIVE
		? 0 : -LINUX_EBUSY;
}

int eunion_sidecar_publish_whiteout(eunion_sidecar_view view,
	const char* guest_path)
{
	int result = eunion_sidecar_require_exclusive(view);
	if (result < 0)
		return result;
	int node = -1;
	struct eunion_sidecar_node_disk record;
	result = eunion_sidecar_walk(view, guest_path, 1,
		EUNION_SIDECAR_RECORD_WHITEOUT, &node, &record);
	return eunion_sidecar_close_fd(&node, result);
}

static int eunion_sidecar_dispose_node(int parent, const char* name);
static int eunion_sidecar_dispose_partial_node(
	int parent, const char* name);

static int eunion_sidecar_dispose_children(int node)
{
	int children = eunion_sidecar_open_children(node);
	int result = children < 0 ? children : 0;
	if (result >= 0) {
		char buffer[4096];
		for (;;) {
			int length = SIDECAR_SYSCALL(__NR_getdents64,
				children, buffer, sizeof(buffer));
			if (length < 0) {
				result = length;
				break;
			}
			if (length == 0)
				break;
			int offset = 0;
			while (offset < length) {
				struct eunion_sidecar_dirent64* entry =
					(struct eunion_sidecar_dirent64*)(buffer + offset);
				if (entry->record_length == 0 ||
					offset + entry->record_length > length) {
					result = -LINUX_EIO;
					break;
				}
				offset += entry->record_length;
				if (strcmp(entry->name, ".") == 0 ||
					strcmp(entry->name, "..") == 0)
					continue;
				result = eunion_sidecar_dispose_node(
					children, entry->name);
				if (result < 0)
					break;
			}
			if (result < 0)
				break;
		}
	}
	eunion_sidecar_close_fd(&children, 0);
	return result;
}

static int eunion_sidecar_dispose_node(int parent, const char* name)
{
	int node = SIDECAR_SYSCALL(__NR_openat, parent, name,
		LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
		LINUX_O_CLOEXEC, 0);
	if (node < 0)
		return node;
	int result = eunion_sidecar_dispose_children(node);
	if (result >= 0)
		result = SIDECAR_SYSCALL(__NR_unlinkat, node, "node-v1", 0);
	if (result >= 0)
		result = SIDECAR_SYSCALL(__NR_unlinkat, node, "children", 0x200);
	eunion_sidecar_close_fd(&node, 0);
	if (result >= 0)
		result = SIDECAR_SYSCALL(__NR_unlinkat, parent, name, 0x200);
	if (result >= 0)
		result = SIDECAR_SYSCALL(__NR_fsync, parent);
	return result;
}

static int eunion_sidecar_unlink_if_present(
	int parent, const char* name, int flags)
{
	int result = SIDECAR_SYSCALL(__NR_unlinkat, parent, name, flags);
	return result == -LINUX_ENOENT ? 0 : result;
}

static int eunion_sidecar_dispose_partial_node(
	int parent, const char* name)
{
	int node = SIDECAR_SYSCALL(__NR_openat, parent, name,
		LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
		LINUX_O_CLOEXEC, 0);
	if (node == -LINUX_ENOENT)
		return 0;
	if (node < 0)
		return node;
	int children = eunion_sidecar_open_children(node);
	int result = 0;
	if (children >= 0) {
		result = eunion_sidecar_dispose_children(node);
		eunion_sidecar_close_fd(&children, 0);
	} else if (children != -LINUX_ENOENT) {
		result = children;
	}
	if (result >= 0)
		result = eunion_sidecar_unlink_if_present(
			node, "node-v1.tmp", 0);
	if (result >= 0)
		result = eunion_sidecar_unlink_if_present(
			node, "node-v1", 0);
	if (result >= 0)
		result = eunion_sidecar_unlink_if_present(
			node, "children", 0x200);
	eunion_sidecar_close_fd(&node, 0);
	if (result >= 0)
		result = eunion_sidecar_unlink_if_present(parent, name, 0x200);
	if (result >= 0)
		result = SIDECAR_SYSCALL(__NR_fsync, parent);
	return result;
}

static int eunion_sidecar_replace_with_empty_index(
	eunion_sidecar_view view, const char* guest_path,
	const struct eunion_sidecar_node_disk* old_record)
{
	struct eunion_sidecar_path path;
	int result = eunion_sidecar_parse_path(guest_path, &path);
	if (result < 0)
		return result;
	int parent_node = view->root_descriptor;
	int own_parent = 0;
	uint64_t parent_generation = view->root_generation;
	for (int index = 0; index < path.count - 1; ++index) {
		int child = -1;
		struct eunion_sidecar_node_disk record;
		result = eunion_sidecar_open_child(view, parent_node,
			parent_generation, path.component[index].name,
			path.component[index].length,
			&child, &record);
		if (result < 0)
			goto done;
		if (own_parent)
			eunion_sidecar_close_fd(&parent_node, 0);
		parent_node = child;
		own_parent = 1;
		parent_generation = record.generation;
	}
	int children = eunion_sidecar_open_children(parent_node);
	if (children < 0) {
		result = children;
		goto done;
	}
	char hash[17];
	char temporary[22] = ".new-";
	eunion_sidecar_hash_name(eunion_sidecar_component_hash(
		view->key, path.component[path.count - 1].name,
		path.component[path.count - 1].length), hash);
	memcpy(temporary + 5, hash, sizeof(hash));
	result = eunion_sidecar_mkdir_private(children, temporary);
	if (result < 0) {
		eunion_sidecar_close_fd(&children, 0);
		goto done;
	}
	int replacement = SIDECAR_SYSCALL(__NR_openat, children, temporary,
		LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
		LINUX_O_CLOEXEC, 0);
	if (replacement < 0)
		result = replacement;
	if (result >= 0)
		result = eunion_sidecar_mkdir_private(replacement, "children");
	struct eunion_sidecar_node_disk new_record = *old_record;
	new_record.kind = EUNION_SIDECAR_RECORD_INDEX;
	new_record.generation++;
	new_record.parent_generation = parent_generation;
	if (result >= 0)
		result = eunion_sidecar_write_node_file(
			replacement, &new_record, 0);
	if (result >= 0)
		result = SIDECAR_SYSCALL(__NR_fsync, replacement);
	eunion_sidecar_close_fd(&replacement, 0);
	if (result >= 0)
		result = SIDECAR_SYSCALL(__NR_renameat2, children, temporary,
			children, hash, LINUX_RENAME_EXCHANGE);
	if (result >= 0)
		result = SIDECAR_SYSCALL(__NR_fsync, children);
	if (result >= 0)
		result = eunion_sidecar_dispose_node(children, temporary);
	if (result < 0)
		eunion_sidecar_dispose_node(children, temporary);
	eunion_sidecar_close_fd(&children, 0);
done:
	if (own_parent)
		eunion_sidecar_close_fd(&parent_node, 0);
	eunion_sidecar_path_release(&path);
	return result;
}

int eunion_sidecar_clear_whiteout(eunion_sidecar_view view,
	const char* guest_path)
{
	int result = eunion_sidecar_require_exclusive(view);
	if (result < 0)
		return result;
	int node = -1;
	struct eunion_sidecar_node_disk record;
	result = eunion_sidecar_walk(view, guest_path, 0,
		EUNION_SIDECAR_RECORD_NONE, &node, &record);
	if (result < 0)
		return result;
	if (record.kind != EUNION_SIDECAR_RECORD_WHITEOUT) {
		eunion_sidecar_close_fd(&node, 0);
		return -LINUX_EINVAL;
	}
	eunion_sidecar_close_fd(&node, 0);
	return eunion_sidecar_replace_with_empty_index(
		view, guest_path, &record);
}

int eunion_sidecar_publish_opaque(eunion_sidecar_view view,
	const char* guest_path)
{
	int result = eunion_sidecar_require_exclusive(view);
	if (result < 0)
		return result;
	int node = -1;
	struct eunion_sidecar_node_disk record;
	result = eunion_sidecar_walk(view, guest_path, 1,
		EUNION_SIDECAR_RECORD_OPAQUE, &node, &record);
	return eunion_sidecar_close_fd(&node, result);
}

static int eunion_sidecar_parse_path(
	const char* guest_path, struct eunion_sidecar_path* path)
{
	if (!guest_path || guest_path[0] != '/' || !path)
		return -LINUX_EINVAL;
	memset(path, 0, sizeof(*path));
	char component[EUNION_SIDECAR_NAME_MAX + 1];
	size_t length;
	const char* cursor = guest_path;
	for (;;) {
		int result = eunion_sidecar_next_component(&cursor,
			component, &length);
		if (result < 0)
			return result;
		if (result == 0)
			break;
		if (path->count == 0x7fffffff)
			return -LINUX_ENAMETOOLONG;
		++path->count;
	}
	if (path->count == 0)
		return -LINUX_EINVAL;
	if ((size_t)path->count >
		(size_t)-1 / sizeof(*path->component))
		return -LINUX_ENAMETOOLONG;
	path->component = malloc(
		(size_t)path->count * sizeof(*path->component));
	if (!path->component)
		return -LINUX_ENOMEM;
	cursor = guest_path;
	for (int index = 0; index < path->count; ++index) {
		int result = eunion_sidecar_next_component(&cursor,
			path->component[index].name,
			&path->component[index].length);
		if (result != 1) {
			eunion_sidecar_path_release(path);
			return result < 0 ? result : -LINUX_EIO;
		}
	}
	return 0;
}

static int eunion_sidecar_open_parent(
	int root, const struct eunion_sidecar_path* path, int readable)
{
	int descriptor = SIDECAR_SYSCALL(__NR_dup, root);
	if (descriptor < 0)
		return descriptor;
	for (int index = 0; index < path->count - 1; ++index) {
		int flags = (readable ? LINUX_O_RDONLY : LINUX_O_PATH) |
			LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW | LINUX_O_CLOEXEC;
		int next = SIDECAR_SYSCALL(__NR_openat, descriptor,
			path->component[index].name, flags, 0);
		if (next < 0) {
			eunion_sidecar_close_fd(&descriptor, 0);
			return next;
		}
		eunion_sidecar_close_fd(&descriptor, 0);
		descriptor = next;
	}
	return descriptor;
}

static int eunion_sidecar_directory_has_entry(int descriptor, int* nonempty)
{
	char buffer[4096];
	*nonempty = 0;
	for (;;) {
		int length = SIDECAR_SYSCALL(__NR_getdents64, descriptor,
			buffer, sizeof(buffer));
		if (length < 0)
			return length;
		if (length == 0)
			return 0;
		int offset = 0;
		while (offset < length) {
			struct eunion_sidecar_dirent64* entry =
				(struct eunion_sidecar_dirent64*)(buffer + offset);
			if (entry->record_length == 0 ||
				offset + entry->record_length > length)
				return -LINUX_EIO;
			offset += entry->record_length;
			if (strcmp(entry->name, ".") != 0 &&
				strcmp(entry->name, "..") != 0) {
				*nonempty = 1;
				return 0;
			}
		}
	}
}

static int eunion_sidecar_join_child(const char* parent, const char* child,
	char output[EUNION_SIDECAR_PATH_MAX])
{
	size_t parent_length = strlen(parent);
	size_t child_length = strlen(child);
	int separator = parent_length > 1;
	if (parent_length + (size_t)separator + child_length + 1 >
		EUNION_SIDECAR_PATH_MAX)
		return -LINUX_EINVAL;
	memcpy(output, parent, parent_length);
	if (separator)
		output[parent_length++] = '/';
	memcpy(output + parent_length, child, child_length + 1);
	return 0;
}

static int eunion_sidecar_lower_directory_nonempty(
	eunion_sidecar_view view, int descriptor, const char* guest_path,
	int* nonempty)
{
	char buffer[4096];
	*nonempty = 0;
	for (;;) {
		int length = SIDECAR_SYSCALL(__NR_getdents64, descriptor,
			buffer, sizeof(buffer));
		if (length < 0)
			return length;
		if (length == 0)
			return 0;
		int offset = 0;
		while (offset < length) {
			struct eunion_sidecar_dirent64* entry =
				(struct eunion_sidecar_dirent64*)(buffer + offset);
			if (entry->record_length == 0 ||
				offset + entry->record_length > length)
				return -LINUX_EIO;
			offset += entry->record_length;
			if (strcmp(entry->name, ".") == 0 ||
				strcmp(entry->name, "..") == 0)
				continue;
			char child[EUNION_SIDECAR_PATH_MAX];
			int result = eunion_sidecar_join_child(
				guest_path, entry->name, child);
			if (result < 0)
				return result;
			struct eunion_sidecar_lookup lookup;
			result = eunion_sidecar_lookup_path(view, child, &lookup);
			if (result < 0)
				return result;
			if (lookup.kind != EUNION_SIDECAR_RECORD_WHITEOUT) {
				*nonempty = 1;
				return 0;
			}
		}
	}
}

static int eunion_sidecar_open_record_path(
	eunion_sidecar_view view, const char* guest_path, int* node_result,
	struct eunion_sidecar_node_disk* record_result)
{
	struct eunion_sidecar_path path;
	int result = eunion_sidecar_parse_path(guest_path, &path);
	if (result < 0)
		return result;
	int node = view->root_descriptor;
	int own_node = 0;
	uint64_t parent_generation = view->root_generation;
	for (int index = 0; index < path.count; ++index) {
		int child = -1;
		struct eunion_sidecar_node_disk record;
		result = eunion_sidecar_open_child(view, node,
			parent_generation, path.component[index].name,
			path.component[index].length,
			&child, &record);
		if (result < 0)
			break;
		if (own_node)
			eunion_sidecar_close_fd(&node, 0);
		node = child;
		own_node = 1;
		parent_generation = record.generation;
		*record_result = record;
	}
	if (result < 0) {
		if (own_node)
			eunion_sidecar_close_fd(&node, 0);
		eunion_sidecar_path_release(&path);
		return result;
	}
	*node_result = node;
	eunion_sidecar_path_release(&path);
	return 0;
}

#ifdef TEST
int eunion_sidecar_test_corrupt_record(
	const struct eunion_sidecar_runtime* runtime,
	const char* guest_path,
	enum eunion_sidecar_test_corruption corruption)
{
	eunion_sidecar_view view = {{0}};
	int result = eunion_sidecar_view_open(view, runtime,
		EUNION_SIDECAR_ACCESS_EXCLUSIVE);
	if (result < 0)
		return result;
	int node = -1;
	struct eunion_sidecar_node_disk record;
	result = eunion_sidecar_open_record_path(
		view, guest_path, &node, &record);
	if (result < 0)
		goto done;
	int descriptor = SIDECAR_SYSCALL(__NR_openat, node, "node-v1",
		LINUX_O_RDWR | LINUX_O_NOFOLLOW | LINUX_O_CLOEXEC, 0);
	if (descriptor < 0) {
		result = descriptor;
		goto done;
	}
	switch (corruption) {
	case EUNION_SIDECAR_TEST_CORRUPT_TRUNCATE:
		result = SIDECAR_SYSCALL(__NR_ftruncate, descriptor,
			(off_t)sizeof(record) - 1);
		break;
	case EUNION_SIDECAR_TEST_CORRUPT_VERSION:
		record.version++;
		result = SIDECAR_SYSCALL(__NR_pwrite64, descriptor,
			&record, sizeof(record), 0);
		break;
	case EUNION_SIDECAR_TEST_CORRUPT_CHECKSUM:
		record.checksum ^= UINT64_C(1);
		result = SIDECAR_SYSCALL(__NR_pwrite64, descriptor,
			&record, sizeof(record), 0);
		break;
	default:
		result = -LINUX_EINVAL;
		break;
	}
	if (result == (int)sizeof(record))
		result = 0;
	if (result >= 0)
		result = SIDECAR_SYSCALL(__NR_fsync, descriptor);
	result = eunion_sidecar_close_fd(&descriptor, result);
done:
	eunion_sidecar_close_fd(&node, 0);
	{
		int close_result = eunion_sidecar_view_close(view);
		if (result >= 0)
			result = close_result;
	}
	return result;
}
#endif

static int eunion_sidecar_publish_created_record(
	eunion_sidecar_view view, const char* guest_path,
	const struct eunion_sidecar_identity* upper,
	const struct eunion_sidecar_identity* lower, int directory)
{
	int node = -1;
	struct eunion_sidecar_node_disk record;
	int result = eunion_sidecar_open_record_path(
		view, guest_path, &node, &record);
	if (result == -LINUX_ENOENT)
		result = eunion_sidecar_walk(view, guest_path, 1,
			EUNION_SIDECAR_RECORD_INDEX, &node, &record);
	if (result < 0)
		return result;
	record.kind = directory && lower->present &&
		(lower->mode & LINUX_S_IFMT) == LINUX_S_IFDIR
			? EUNION_SIDECAR_RECORD_OPAQUE
			: EUNION_SIDECAR_RECORD_INDEX;
	record.generation++;
	record.upper = *upper;
	record.lower = *lower;
	result = eunion_sidecar_write_node_file(node, &record, 1);
	return eunion_sidecar_close_fd(&node, result);
}

static int eunion_sidecar_restore_journal_record(
	eunion_sidecar_view view,
	const struct eunion_sidecar_journal_disk* journal, int forward)
{
	const struct eunion_sidecar_node_disk* wanted =
		forward ? &journal->new_record : &journal->old_record;
	int wanted_valid =
		forward ? journal->new_record_valid : journal->old_record_valid;
	if (forward && !wanted_valid)
		return 0;
	int node = -1;
	struct eunion_sidecar_node_disk current;
	int result = eunion_sidecar_open_record_path(
		view, journal->path, &node, &current);
	if (!wanted_valid) {
		if (result == -LINUX_ENOENT)
			return 0;
		if (result < 0)
			return result;
		current.kind = EUNION_SIDECAR_RECORD_INDEX;
		current.generation++;
		current.upper = journal->upper;
		current.lower = journal->lower;
		result = eunion_sidecar_write_node_file(node, &current, 1);
		return eunion_sidecar_close_fd(&node, result);
	}
	if (result < 0)
		return result == -LINUX_ENOENT ? -LINUX_EIO : result;
	struct eunion_sidecar_node_disk restored = *wanted;
	/*
	 * A PREPARED crash may have left a newly allocated INDEX node. Keep its
	 * structural generation/parent binding while restoring the typed payload.
	 */
	if (!forward && !journal->old_record_valid) {
		restored.generation = current.generation + 1;
		restored.parent_generation = current.parent_generation;
	}
	result = eunion_sidecar_write_node_file(node, &restored, 1);
	return eunion_sidecar_close_fd(&node, result);
}

static int eunion_sidecar_dispose_private_backing(
	int parent, const char* name)
{
	sidecar_stat_t status;
	int result = SIDECAR_SYSCALL(__NR_newfstatat,
		parent, name, &status, LINUX_AT_SYMLINK_NOFOLLOW);
	if (result == -LINUX_ENOENT)
		return 0;
	if (result < 0)
		return result;
	if (((unsigned int)status.st_mode & LINUX_S_IFMT) != LINUX_S_IFDIR) {
		result = SIDECAR_SYSCALL(__NR_unlinkat, parent, name, 0);
		if (result >= 0)
			result = SIDECAR_SYSCALL(__NR_fsync, parent);
		return result;
	}

	/*
	 * This inode is private transaction state, never guest-addressable.
	 * Temporarily making it owner-readable is therefore safe and lets cleanup
	 * reap a staged mode-000 lower subtree without touching a live guest inode.
	 */
	result = SIDECAR_SYSCALL(__NR_fchmodat2,
		parent, name, 0700, LINUX_AT_SYMLINK_NOFOLLOW);
	if (result < 0)
		return result;
	int directory = SIDECAR_SYSCALL(__NR_openat, parent, name,
		LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
			LINUX_O_CLOEXEC, 0);
	if (directory < 0)
		return directory;
	char buffer[8192];
	for (;;) {
		int length = SIDECAR_SYSCALL(__NR_getdents64,
			directory, buffer, sizeof(buffer));
		if (length < 0) {
			result = length;
			break;
		}
		if (length == 0)
			break;
		int offset = 0;
		while (offset < length) {
			struct eunion_sidecar_dirent64* entry =
				(struct eunion_sidecar_dirent64*)(buffer + offset);
			size_t fixed = offsetof(
				struct eunion_sidecar_dirent64, name);
			if (entry->record_length < fixed + 2 ||
				offset + entry->record_length > length) {
				result = -LINUX_EIO;
				break;
			}
			size_t capacity = entry->record_length - fixed;
			size_t name_length = strnlen(entry->name, capacity);
			if (name_length == 0 || name_length == capacity ||
				name_length > EUNION_SIDECAR_NAME_MAX) {
				result = -LINUX_EIO;
				break;
			}
			offset += entry->record_length;
			if ((name_length == 1 && entry->name[0] == '.') ||
				(name_length == 2 && entry->name[0] == '.' &&
				 entry->name[1] == '.'))
				continue;
			result = eunion_sidecar_dispose_private_backing(
				directory, entry->name);
			if (result < 0)
				break;
		}
		if (result < 0)
			break;
	}
	eunion_sidecar_close_fd(&directory, 0);
	if (result >= 0)
		result = SIDECAR_SYSCALL(
			__NR_unlinkat, parent, name, 0x200);
	if (result >= 0)
		result = SIDECAR_SYSCALL(__NR_fsync, parent);
	return result;
}

static int eunion_sidecar_cleanup_copyup_stage(eunion_sidecar_view view)
{
	int staging = SIDECAR_SYSCALL(__NR_openat,
		view->sidecar_descriptor, "staging-v1",
		LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
		LINUX_O_CLOEXEC, 0);
	if (staging < 0)
		return staging;
	int result = eunion_sidecar_dispose_private_backing(
		staging, "copyup-v1");
	return eunion_sidecar_close_fd(&staging, result);
}

static int eunion_sidecar_open_tree_parent(
	eunion_sidecar_view view, const char* guest_path, int* children_result,
	uint64_t* parent_generation_result, char hash_result[17])
{
	struct eunion_sidecar_path path;
	int result = eunion_sidecar_parse_path(guest_path, &path);
	if (result < 0)
		return result;
	int parent = view->root_descriptor;
	int own_parent = 0;
	uint64_t parent_generation = view->root_generation;
	for (int index = 0; index < path.count - 1; ++index) {
		int child = -1;
		struct eunion_sidecar_node_disk record;
		result = eunion_sidecar_open_child(view, parent,
			parent_generation, path.component[index].name,
			path.component[index].length,
			&child, &record);
		if (result < 0)
			break;
		if (own_parent)
			eunion_sidecar_close_fd(&parent, 0);
		parent = child;
		own_parent = 1;
		parent_generation = record.generation;
	}
	if (result >= 0) {
		*children_result = eunion_sidecar_open_children(parent);
		if (*children_result < 0)
			result = *children_result;
	}
	if (result >= 0) {
		*parent_generation_result = parent_generation;
		eunion_sidecar_hash_name(eunion_sidecar_component_hash(
			view->key, path.component[path.count - 1].name,
			path.component[path.count - 1].length), hash_result);
	}
	if (own_parent)
		eunion_sidecar_close_fd(&parent, 0);
	eunion_sidecar_path_release(&path);
	return result;
}

static int eunion_sidecar_update_renamed_node(
	int node, const char* new_guest_path, uint64_t parent_generation,
	const struct eunion_sidecar_identity* upper,
	const struct eunion_sidecar_identity* lower)
{
	const char* leaf = strrchr(new_guest_path, '/');
	if (!leaf || !leaf[1])
		return -LINUX_EINVAL;
	++leaf;
	size_t length = strlen(leaf);
	if (length > EUNION_SIDECAR_NAME_MAX)
		return -LINUX_EINVAL;
	struct eunion_sidecar_node_disk record;
	int result = eunion_sidecar_read_node(node, &record);
	if (result < 0)
		return result;
	record.kind = (upper->mode & LINUX_S_IFMT) == LINUX_S_IFDIR &&
		lower->present &&
		(lower->mode & LINUX_S_IFMT) == LINUX_S_IFDIR
			? EUNION_SIDECAR_RECORD_OPAQUE
			: EUNION_SIDECAR_RECORD_INDEX;
	record.name_length = (uint32_t)length;
	/*
	 * Preserve this node's generation when moving the subtree: every direct
	 * child is bound to it. The destination parent/name binding changes, but
	 * the node and its descendants remain the same logical subtree.
	 */
	record.parent_generation = parent_generation;
	record.upper = *upper;
	record.lower = *lower;
	memset(record.name, 0, sizeof(record.name));
	memcpy(record.name, leaf, length);
	return eunion_sidecar_write_node_file(node, &record, 1);
}

static int eunion_sidecar_apply_rename_records(
	eunion_sidecar_view view,
	const struct eunion_sidecar_journal_disk* journal,
	const struct eunion_sidecar_identity* destination)
{
	int source_children = -1;
	int destination_children = -1;
	uint64_t source_parent_generation = 0;
	uint64_t destination_parent_generation = 0;
	char source_hash[17];
	char destination_hash[17];
	int result = eunion_sidecar_open_tree_parent(view, journal->path,
		&source_children, &source_parent_generation, source_hash);
	if (result >= 0)
		result = eunion_sidecar_open_tree_parent(
			view, journal->secondary_path,
			&destination_children, &destination_parent_generation,
			destination_hash);
	if (result < 0)
		goto rename_records_done;
	int destination_node = SIDECAR_SYSCALL(__NR_openat,
		destination_children, destination_hash,
		LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
		LINUX_O_CLOEXEC, 0);
	int destination_is_new = 0;
	int destination_is_moved_source = 0;
	if (destination_node >= 0) {
		struct eunion_sidecar_node_disk record;
		if (eunion_sidecar_read_node(destination_node, &record) == 0) {
			const char* destination_leaf = strrchr(
				journal->secondary_path, '/');
			if (destination_leaf && destination_leaf[1] &&
				record.name_length == strlen(destination_leaf + 1) &&
				eunion_sidecar_bytes_equal(
					record.name, destination_leaf + 1,
					record.name_length) &&
				eunion_sidecar_same_object(
					&record.upper, destination))
				destination_is_new = 1;
			const char* source_leaf = strrchr(journal->path, '/');
			if (!destination_is_new && source_leaf && source_leaf[1] &&
				record.name_length == strlen(source_leaf + 1) &&
				eunion_sidecar_bytes_equal(
					record.name, source_leaf + 1,
					record.name_length) &&
				eunion_sidecar_same_object(
					&record.upper, &journal->upper) &&
				eunion_sidecar_same_object(
					&journal->upper, destination))
				destination_is_moved_source = 1;
		}
		if (!destination_is_moved_source)
			eunion_sidecar_close_fd(&destination_node, 0);
	}
	if (!destination_is_new) {
		if (!destination_is_moved_source) {
			int source_node = SIDECAR_SYSCALL(__NR_openat,
				source_children, source_hash,
				LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
				LINUX_O_CLOEXEC, 0);
			if (source_node < 0) {
				result = -LINUX_EIO;
				goto rename_records_done;
			}
			eunion_sidecar_close_fd(&source_node, 0);
			sidecar_stat_t existing;
			int destination_exists = SIDECAR_SYSCALL(__NR_newfstatat,
				destination_children, destination_hash, &existing,
				LINUX_AT_SYMLINK_NOFOLLOW) == 0;
			result = SIDECAR_SYSCALL(__NR_renameat2,
				source_children, source_hash,
				destination_children, destination_hash,
				destination_exists
					? LINUX_RENAME_EXCHANGE
					: LINUX_RENAME_NOREPLACE);
			if (result < 0)
				goto rename_records_done;
			result = SIDECAR_SYSCALL(__NR_fsync, destination_children);
			if (result >= 0)
				result = SIDECAR_SYSCALL(__NR_fsync, source_children);
			if (result < 0)
				goto rename_records_done;
			destination_node = SIDECAR_SYSCALL(__NR_openat,
				destination_children, destination_hash,
				LINUX_O_RDONLY | LINUX_O_DIRECTORY |
				LINUX_O_NOFOLLOW | LINUX_O_CLOEXEC, 0);
			if (destination_node < 0) {
				result = destination_node;
				goto rename_records_done;
			}
		}
		/*
		 * rename callers deep-copy the complete visible source subtree.
		 * At the destination it is therefore self-contained (and the root
		 * becomes OPAQUE when a destination lower directory exists).
		 * Descendant records still bind the old lower path, so retire them
		 * rather than accepting stale identities after the move.
		 */
		result = eunion_sidecar_dispose_children(destination_node);
		if (result < 0) {
			eunion_sidecar_close_fd(&destination_node, 0);
			goto rename_records_done;
		}
		result = eunion_sidecar_update_renamed_node(
			destination_node, journal->secondary_path,
			destination_parent_generation, destination,
			&journal->secondary_lower);
		eunion_sidecar_close_fd(&destination_node, 0);
		if (result < 0)
			goto rename_records_done;
	}
	sidecar_stat_t stale;
	if (SIDECAR_SYSCALL(__NR_newfstatat,
			source_children, source_hash, &stale,
			LINUX_AT_SYMLINK_NOFOLLOW) == 0) {
		result = eunion_sidecar_dispose_node(
			source_children, source_hash);
		if (result < 0)
			goto rename_records_done;
	}
	if (journal->lower.present) {
		int node = -1;
		struct eunion_sidecar_node_disk record;
		result = eunion_sidecar_walk(view, journal->path, 1,
			EUNION_SIDECAR_RECORD_WHITEOUT, &node, &record);
		eunion_sidecar_close_fd(&node, 0);
	}

rename_records_done:
	eunion_sidecar_close_fd(&destination_children, 0);
	eunion_sidecar_close_fd(&source_children, 0);
	return result;
}

static int eunion_sidecar_recover_locked(eunion_sidecar_view view)
{
	struct eunion_sidecar_journal_disk journal;
	int result = eunion_sidecar_read_journal(
		view->sidecar_descriptor, &journal);
	if (result < 0)
		return result;
	EUNION_SIDECAR_AUTO_PATH(path);
	result = eunion_sidecar_parse_path(journal.path, &path);
	if (result < 0)
		return result;
	int upper_parent = eunion_sidecar_open_parent(
		view->upper_descriptor, &path, 0);
	if (upper_parent < 0)
		return upper_parent;
	struct eunion_sidecar_identity current;
	result = eunion_sidecar_fstatat_identity_or_absent(
		upper_parent, path.component[path.count - 1].name, &current);
	eunion_sidecar_close_fd(&upper_parent, 0);
	if (result < 0 || current.present == 2)
		return result < 0 ? result : -LINUX_EIO;
	if (journal.operation == EUNION_SIDECAR_OPERATION_RENAME) {
		EUNION_SIDECAR_AUTO_PATH(secondary);
		result = eunion_sidecar_parse_path(
			journal.secondary_path, &secondary);
		if (result < 0)
			return result;
		int destination_parent = eunion_sidecar_open_parent(
			view->upper_descriptor, &secondary, 0);
		if (destination_parent < 0)
			return destination_parent;
		struct eunion_sidecar_identity destination;
		result = eunion_sidecar_fstatat_identity_or_absent(
			destination_parent,
			secondary.component[secondary.count - 1].name,
			&destination);
		eunion_sidecar_close_fd(&destination_parent, 0);
		if (result < 0 || current.present == 2 ||
			destination.present == 2)
			return result < 0 ? result : -LINUX_EIO;
		int old_backing = current.present &&
			eunion_sidecar_same_object(&journal.upper, &current) &&
			((!journal.secondary_upper.present &&
			  !destination.present) ||
			 (journal.secondary_upper.present &&
			  destination.present &&
			  eunion_sidecar_same_object(
				&journal.secondary_upper, &destination)));
		int new_backing = !current.present && destination.present &&
			eunion_sidecar_same_object(&journal.upper, &destination);
		if (journal.phase == EUNION_SIDECAR_JOURNAL_PREPARED &&
			old_backing) {
			result = eunion_sidecar_remove_journal(view);
			return result;
		}
		if (!new_backing ||
			(journal.phase != EUNION_SIDECAR_JOURNAL_PREPARED &&
			 journal.phase !=
				EUNION_SIDECAR_JOURNAL_BACKING_COMMITTED &&
			 journal.phase != EUNION_SIDECAR_JOURNAL_DURABLE))
			return -LINUX_EIO;
		result = eunion_sidecar_apply_rename_records(
			view, &journal, &destination);
		if (result >= 0)
			result = SIDECAR_SYSCALL(
				__NR_syncfs, view->upper_descriptor);
		if (result >= 0)
			result = eunion_sidecar_remove_journal(view);
		return result;
	}
	if (journal.operation == EUNION_SIDECAR_OPERATION_COPY_UP &&
		journal.recursive_tree) {
		if (!current.present ||
			!eunion_sidecar_same_object(&journal.upper, &current) ||
			(current.mode & LINUX_S_IFMT) != LINUX_S_IFDIR ||
			!journal.lower.present ||
			(journal.lower.mode & LINUX_S_IFMT) != LINUX_S_IFDIR)
			return -LINUX_EIO;
		int current_upper_parent = eunion_sidecar_open_parent(
			view->upper_descriptor, &path, 0);
		int current_lower_parent = eunion_sidecar_open_parent(
			view->lower_descriptor, &path, 0);
		if (current_upper_parent < 0 || current_lower_parent < 0) {
			result = current_upper_parent < 0
				? current_upper_parent : current_lower_parent;
			eunion_sidecar_close_fd(&current_lower_parent, 0);
			eunion_sidecar_close_fd(&current_upper_parent, 0);
			return result;
		}
		struct eunion_sidecar_identity current_lower;
		result = eunion_sidecar_fstatat_identity_or_absent(
			current_lower_parent,
			path.component[path.count - 1].name,
			&current_lower);
		if (result >= 0 &&
			!eunion_sidecar_same_object(
				&journal.lower, &current_lower))
			result = -LINUX_EIO;
		int upper_directory = -1;
		int lower_directory = -1;
		if (result >= 0) {
			upper_directory = SIDECAR_SYSCALL(__NR_openat,
				current_upper_parent,
				path.component[path.count - 1].name,
				LINUX_O_RDONLY | LINUX_O_DIRECTORY |
					LINUX_O_NOFOLLOW | LINUX_O_CLOEXEC,
				0);
			if (upper_directory < 0)
				result = upper_directory;
		}
		if (result >= 0) {
			lower_directory = SIDECAR_SYSCALL(__NR_openat,
				current_lower_parent,
				path.component[path.count - 1].name,
				LINUX_O_RDONLY | LINUX_O_DIRECTORY |
					LINUX_O_NOFOLLOW | LINUX_O_CLOEXEC,
				0);
			if (lower_directory < 0)
				result = lower_directory;
		}
		if (result >= 0)
			result = eunion_sidecar_cleanup_copyup_stage(view);
		if (result >= 0)
			result = eunion_sidecar_materialize_merged_tree(
				view, upper_directory, lower_directory,
				journal.path);
		eunion_sidecar_close_fd(&lower_directory, 0);
		eunion_sidecar_close_fd(&upper_directory, 0);
		eunion_sidecar_close_fd(&current_lower_parent, 0);
		eunion_sidecar_close_fd(&current_upper_parent, 0);
		if (result >= 0)
			result = SIDECAR_SYSCALL(
				__NR_syncfs, view->upper_descriptor);
		if (result >= 0)
			result = eunion_sidecar_remove_journal(view);
		return result;
	}
	int backing_old = journal.upper.present &&
		current.present &&
		eunion_sidecar_same_object(&journal.upper, &current);
	int backing_new = !current.present;
	if (!journal.upper.present)
		backing_old = !current.present;
	if (journal.operation == EUNION_SIDECAR_OPERATION_CREATE ||
		journal.operation == EUNION_SIDECAR_OPERATION_COPY_UP) {
		int forward = 0;
		switch ((enum eunion_sidecar_journal_phase)journal.phase) {
			case EUNION_SIDECAR_JOURNAL_PREPARED:
				forward = current.present == 1;
				break;
			case EUNION_SIDECAR_JOURNAL_BACKING_COMMITTED:
			case EUNION_SIDECAR_JOURNAL_DURABLE:
				if (!current.present ||
					(journal.backing_new.present &&
					 !eunion_sidecar_same_object(
						&journal.backing_new, &current)))
					return -LINUX_EIO;
				forward = 1;
				break;
			case EUNION_SIDECAR_JOURNAL_LOGICALLY_PUBLISHED:
			case EUNION_SIDECAR_JOURNAL_ABSENT:
			case EUNION_SIDECAR_JOURNAL_INVALID:
			default:
				return -LINUX_EIO;
		}
		if (forward) {
			if (journal.operation == EUNION_SIDECAR_OPERATION_COPY_UP &&
				journal.backing_new.present &&
				!eunion_sidecar_same_object(
					&journal.backing_new, &current))
				return -LINUX_EIO;
			result = eunion_sidecar_publish_created_record(
				view, journal.path, &current, &journal.lower,
				journal.remove_directory != 0);
			if (result >= 0)
				result = SIDECAR_SYSCALL(
					__NR_syncfs, view->upper_descriptor);
		} else {
			result = eunion_sidecar_restore_journal_record(
				view, &journal, 0);
		}
		if (result >= 0 &&
			journal.operation == EUNION_SIDECAR_OPERATION_COPY_UP)
			result = eunion_sidecar_cleanup_copyup_stage(view);
		if (result >= 0)
			result = eunion_sidecar_remove_journal(view);
		return result;
	}
	if (!backing_old && !backing_new)
		return -LINUX_EIO;

	int forward;
	switch ((enum eunion_sidecar_journal_phase)journal.phase) {
		case EUNION_SIDECAR_JOURNAL_PREPARED:
			forward = 0;
			break;
		case EUNION_SIDECAR_JOURNAL_LOGICALLY_PUBLISHED:
			forward = backing_new;
			break;
		case EUNION_SIDECAR_JOURNAL_BACKING_COMMITTED:
		case EUNION_SIDECAR_JOURNAL_DURABLE:
			if (!backing_new)
				return -LINUX_EIO;
			forward = 1;
			break;
		case EUNION_SIDECAR_JOURNAL_ABSENT:
		case EUNION_SIDECAR_JOURNAL_INVALID:
		default:
			return -LINUX_EIO;
	}
	result = eunion_sidecar_restore_journal_record(view, &journal, forward);
	if (result >= 0 && forward)
		result = SIDECAR_SYSCALL(__NR_syncfs, view->upper_descriptor);
	if (result >= 0)
		result = eunion_sidecar_remove_journal(view);
	return result;
}

int eunion_sidecar_remove_path(const struct eunion_sidecar_runtime* runtime,
	const char* guest_path, int remove_directory)
{
	eunion_sidecar_transaction transaction = {{0}};
	union eunion_sidecar_transaction_intent intent = {
		.remove = {
			.remove_directory = (uint32_t)(remove_directory != 0),
		},
	};
	int result = eunion_sidecar_transaction_begin(transaction, runtime,
		EUNION_SIDECAR_OPERATION_REMOVE, intent);
	if (result < 0)
		return result;
	struct eunion_sidecar_view_storage* view = &transaction->view;
	EUNION_SIDECAR_AUTO_PATH(path);
	int upper_parent = -1;
	int lower_parent = -1;
	int sidecar_node = -1;
	struct eunion_sidecar_node_disk old_record;
	struct eunion_sidecar_node_disk new_record;
	int record_published = 0;
	int old_record_valid = 0;
	int journal_active = 0;
	struct eunion_sidecar_journal_disk journal;
	memset(&journal, 0, sizeof(journal));
	result = eunion_sidecar_parse_path(guest_path, &path);
	if (result < 0)
		return eunion_sidecar_transaction_release(transaction, result);

	upper_parent = eunion_sidecar_open_parent(
		view->upper_descriptor, &path, 0);
	lower_parent = eunion_sidecar_open_parent(
		view->lower_descriptor, &path, 0);
	if (upper_parent < 0) {
		result = upper_parent;
		goto done;
	}
	if (lower_parent < 0 && lower_parent != -LINUX_ENOENT) {
		result = lower_parent;
		goto done;
	}
	struct eunion_sidecar_identity upper;
	struct eunion_sidecar_identity lower;
	result = eunion_sidecar_fstatat_identity_or_absent(
		upper_parent, path.component[path.count - 1].name, &upper);
	if (result < 0 || upper.present == 2)
		goto done;
	if (lower_parent >= 0)
		result = eunion_sidecar_fstatat_identity_or_absent(
			lower_parent, path.component[path.count - 1].name, &lower);
	else {
		memset(&lower, 0, sizeof(lower));
		result = 0;
	}
	if (result < 0 || lower.present == 2)
		goto done;

	struct eunion_sidecar_lookup lookup;
	int lower_hidden = 0;
	char ancestor[EUNION_SIDECAR_PATH_MAX] = "/";
	size_t ancestor_length = 1;
	for (int index = 0; index < path.count - 1; ++index) {
		size_t needed = ancestor_length +
			(ancestor_length > 1 ? 1 : 0) +
			path.component[index].length + 1;
		if (needed > sizeof(ancestor)) {
			result = -LINUX_EINVAL;
			goto done;
		}
		if (ancestor_length > 1)
			ancestor[ancestor_length++] = '/';
		memcpy(ancestor + ancestor_length,
			path.component[index].name,
			path.component[index].length);
		ancestor_length += path.component[index].length;
		ancestor[ancestor_length] = '\0';
		result = eunion_sidecar_lookup_path(view, ancestor, &lookup);
		if (result < 0)
			goto done;
		if (lookup.kind == EUNION_SIDECAR_RECORD_WHITEOUT) {
			result = -LINUX_ENOENT;
			goto done;
		}
		if (lookup.kind == EUNION_SIDECAR_RECORD_OPAQUE)
			lower_hidden = 1;
	}
	result = eunion_sidecar_lookup_path(view, guest_path, &lookup);
	if (result < 0)
		goto done;
	if (lookup.kind == EUNION_SIDECAR_RECORD_WHITEOUT) {
		result = -LINUX_ENOENT;
		goto done;
	}
	int visible_upper = upper.present == 1;
	int visible_lower = !lower_hidden && lower.present == 1 &&
		lookup.kind != EUNION_SIDECAR_RECORD_OPAQUE;
	const struct eunion_sidecar_identity* visible =
		visible_upper ? &upper : visible_lower ? &lower : NULL;
	if (!visible) {
		result = -LINUX_ENOENT;
		goto done;
	}
	int is_directory =
		(visible->mode & LINUX_S_IFMT) == LINUX_S_IFDIR;
	if (remove_directory && !is_directory) {
		result = -LINUX_ENOTDIR;
		goto done;
	}
	if (!remove_directory && is_directory) {
		result = -LINUX_EISDIR;
		goto done;
	}

	if (remove_directory) {
		int nonempty = 0;
		if (visible_upper) {
			int directory = SIDECAR_SYSCALL(__NR_openat, upper_parent,
			path.component[path.count - 1].name,
				LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
				LINUX_O_CLOEXEC, 0);
			if (directory >= 0) {
				result = eunion_sidecar_directory_has_entry(
					directory, &nonempty);
				eunion_sidecar_close_fd(&directory, 0);
				if (result < 0)
					goto done;
				if (nonempty) {
					result = -LINUX_ENOTEMPTY;
					goto done;
				}
			}
			else if (directory != -LINUX_EACCES) {
				result = directory;
				goto done;
			}
		}
		if (visible_lower &&
			(lower.mode & LINUX_S_IFMT) == LINUX_S_IFDIR) {
			int directory = SIDECAR_SYSCALL(__NR_openat, lower_parent,
			path.component[path.count - 1].name,
				LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
				LINUX_O_CLOEXEC, 0);
			if (directory < 0) {
				result = directory;
				goto done;
			}
			result = eunion_sidecar_lower_directory_nonempty(
				view, directory, guest_path, &nonempty);
			eunion_sidecar_close_fd(&directory, 0);
			if (result < 0)
				goto done;
			if (nonempty) {
				result = -LINUX_ENOTEMPTY;
				goto done;
			}
		}
	}
#ifdef TEST
	if (eunion_test_sidecar_checkpoint_hook)
		eunion_test_sidecar_checkpoint_hook(
			EUNION_SIDECAR_TEST_RESOLVED, guest_path);
#endif

	int existing_node = -1;
	struct eunion_sidecar_node_disk existing_record;
	int existing_result = eunion_sidecar_walk(view, guest_path, 0,
		EUNION_SIDECAR_RECORD_NONE, &existing_node, &existing_record);
	if (existing_result == 0) {
		old_record = existing_record;
		old_record_valid = 1;
		eunion_sidecar_close_fd(&existing_node, 0);
	}
	else if (existing_result != -LINUX_ENOENT) {
		result = existing_result;
		goto done;
	}
	size_t path_length = strlen(guest_path);
	if (path_length >= sizeof(journal.path)) {
		result = -LINUX_EINVAL;
		goto done;
	}
	journal.phase = EUNION_SIDECAR_JOURNAL_PREPARED;
	journal.operation = EUNION_SIDECAR_OPERATION_REMOVE;
	journal.remove_directory = (uint32_t)(remove_directory != 0);
	journal.path_length = (uint32_t)path_length;
	journal.old_record_valid = (uint32_t)old_record_valid;
	journal.upper = upper;
	journal.lower = lower;
	if (old_record_valid)
		journal.old_record = old_record;
	memcpy(journal.path, guest_path, path_length + 1);
	result = eunion_sidecar_write_journal(view, &journal);
	if (result < 0)
		goto done;
	result = eunion_sidecar_transaction_transition(
		transaction, EUNION_SIDECAR_PHASE_PREPARED);
	if (result < 0)
		goto done;
	journal_active = 1;
#ifdef TEST
	if (eunion_test_sidecar_checkpoint_hook)
		eunion_test_sidecar_checkpoint_hook(
			EUNION_SIDECAR_TEST_JOURNAL_PREPARED, guest_path);
#endif

	if (visible_lower) {
		result = eunion_sidecar_walk(view, guest_path, 1,
			EUNION_SIDECAR_RECORD_INDEX, &sidecar_node, &old_record);
		if (result < 0)
			goto rollback;
		if (!old_record_valid)
			journal.old_record_valid = 0;
		new_record = old_record;
		new_record.kind = EUNION_SIDECAR_RECORD_WHITEOUT;
		new_record.generation++;
		memset(&new_record.upper, 0, sizeof(new_record.upper));
		new_record.lower = lower;
		result = eunion_sidecar_write_node_file(
			sidecar_node, &new_record, 1);
		if (result < 0)
			goto rollback;
		record_published = 1;
		journal.new_record_valid = 1;
		journal.new_record = new_record;
	}
	journal.phase = EUNION_SIDECAR_JOURNAL_LOGICALLY_PUBLISHED;
	result = eunion_sidecar_write_journal(view, &journal);
	if (result < 0)
		goto rollback;
	result = eunion_sidecar_transaction_transition(
		transaction, EUNION_SIDECAR_PHASE_LOGICALLY_PUBLISHED);
	if (result < 0)
		goto rollback;
#ifdef TEST
	if (eunion_test_sidecar_checkpoint_hook)
		eunion_test_sidecar_checkpoint_hook(
			EUNION_SIDECAR_TEST_LOGICALLY_PUBLISHED, guest_path);
#endif

#ifdef TEST
	if (eunion_test_sidecar_checkpoint_hook)
		eunion_test_sidecar_checkpoint_hook(
			EUNION_SIDECAR_TEST_PRE_BACKING, guest_path);
#endif
	struct eunion_sidecar_identity current_upper;
	struct eunion_sidecar_identity current_lower;
	result = eunion_sidecar_fstatat_identity_or_absent(
		upper_parent, path.component[path.count - 1].name,
		&current_upper);
	if (result >= 0 && lower_parent >= 0)
		result = eunion_sidecar_fstatat_identity_or_absent(
			lower_parent, path.component[path.count - 1].name,
			&current_lower);
	else if (result >= 0)
		memset(&current_lower, 0, sizeof(current_lower));
	if (result < 0 ||
		!eunion_sidecar_same_object(&upper, &current_upper) ||
		!eunion_sidecar_same_object(&lower, &current_lower)) {
		if (result >= 0)
			result = -LINUX_EAGAIN;
		goto rollback;
	}
	if (visible_upper) {
		result = SIDECAR_SYSCALL(__NR_unlinkat, upper_parent,
			path.component[path.count - 1].name,
			remove_directory ? 0x200 : 0);
		if (result < 0)
			goto rollback;
	}
	journal.phase = EUNION_SIDECAR_JOURNAL_BACKING_COMMITTED;
	result = eunion_sidecar_write_journal(view, &journal);
	if (result < 0)
		goto done;
	result = eunion_sidecar_transaction_transition(
		transaction, EUNION_SIDECAR_PHASE_BACKING_COMMITTED);
	if (result < 0)
		goto done;
	result = SIDECAR_SYSCALL(__NR_syncfs, view->upper_descriptor);
	if (result < 0)
		goto done;
#ifdef TEST
	if (eunion_test_sidecar_checkpoint_hook)
		eunion_test_sidecar_checkpoint_hook(
			EUNION_SIDECAR_TEST_BACKING_COMMITTED, guest_path);
#endif
	if (record_published)
		result = SIDECAR_SYSCALL(__NR_fsync, sidecar_node);
	if (result < 0)
		goto done;
	journal.phase = EUNION_SIDECAR_JOURNAL_DURABLE;
	result = eunion_sidecar_write_journal(view, &journal);
	if (result < 0)
		goto done;
	result = eunion_sidecar_transaction_transition(
		transaction, EUNION_SIDECAR_PHASE_DURABLE);
	if (result < 0)
		goto done;
#ifdef TEST
	if (eunion_test_sidecar_checkpoint_hook)
		eunion_test_sidecar_checkpoint_hook(
			EUNION_SIDECAR_TEST_DURABLE, guest_path);
#endif
	result = eunion_sidecar_remove_journal(view);
	if (result >= 0)
		journal_active = 0;
	goto done;

rollback:
	{
		int original_result = result;
		int rollback_result = eunion_sidecar_restore_journal_record(
			view, &journal, 0);
		if (rollback_result >= 0)
			rollback_result = eunion_sidecar_remove_journal(view);
		if (rollback_result >= 0)
			journal_active = 0;
		if (rollback_result >= 0 &&
			transaction->phase ==
				EUNION_SIDECAR_PHASE_LOGICALLY_PUBLISHED) {
			rollback_result = eunion_sidecar_transaction_transition(
				transaction, EUNION_SIDECAR_PHASE_ROLLED_BACK);
			if (rollback_result >= 0)
				rollback_result =
					eunion_sidecar_transaction_transition(
						transaction,
						EUNION_SIDECAR_PHASE_DURABLE);
		}
		result = rollback_result < 0 ? rollback_result : original_result;
	}

done:
	eunion_sidecar_close_fd(&sidecar_node, 0);
	eunion_sidecar_close_fd(&lower_parent, 0);
	eunion_sidecar_close_fd(&upper_parent, 0);
	(void)journal_active;
	return eunion_sidecar_transaction_release(transaction, result);
}

enum eunion_sidecar_create_kind {
	EUNION_SIDECAR_CREATE_OPEN = 1,
	EUNION_SIDECAR_CREATE_DIRECTORY = 2,
	EUNION_SIDECAR_CREATE_SYMLINK = 3,
	EUNION_SIDECAR_CREATE_MKNOD = 4,
	EUNION_SIDECAR_CREATE_HARDLINK = 5,
	EUNION_SIDECAR_CREATE_SOCKET = 6,
};

struct eunion_sidecar_sockaddr_un {
	unsigned short family;
	char path[108];
};

static int eunion_sidecar_append_decimal(
	char* output, size_t capacity, size_t* length, unsigned int value)
{
	char reverse[16];
	size_t digits = 0;
	do {
		reverse[digits++] = (char)('0' + value % 10);
		value /= 10;
	} while (value != 0 && digits < sizeof(reverse));
	if (*length + digits >= capacity)
		return -LINUX_ENAMETOOLONG;
	while (digits > 0)
		output[(*length)++] = reverse[--digits];
	output[*length] = '\0';
	return 0;
}

static int eunion_sidecar_bind_at(
	int socket_descriptor, int parent, const char* leaf)
{
	static const char prefix[] = "/proc/self/fd/";
	struct eunion_sidecar_sockaddr_un address;
	memset(&address, 0, sizeof(address));
	address.family = LINUX_AF_UNIX;
	size_t length = sizeof(prefix) - 1;
	memcpy(address.path, prefix, length);
	int result = eunion_sidecar_append_decimal(
		address.path, sizeof(address.path), &length,
		(unsigned int)parent);
	size_t leaf_length = leaf ? strlen(leaf) : 0;
	if (result < 0 || leaf_length == 0 ||
		length + 1 + leaf_length + 1 > sizeof(address.path))
		return result < 0 ? result : -LINUX_ENAMETOOLONG;
	address.path[length++] = '/';
	memcpy(address.path + length, leaf, leaf_length + 1);
	length += leaf_length;
	return SIDECAR_SYSCALL(__NR_bind, socket_descriptor, &address,
		offsetof(struct eunion_sidecar_sockaddr_un, path) + length + 1);
}

static int eunion_sidecar_create_common(
	const struct eunion_sidecar_runtime* runtime, const char* guest_path,
	enum eunion_sidecar_create_kind kind, int flags, unsigned int mode,
	unsigned int device, const char* auxiliary)
{
	eunion_sidecar_transaction transaction = {{0}};
	union eunion_sidecar_transaction_intent intent = {
		.create = {
			.kind = (uint32_t)kind,
		},
	};
	int result = eunion_sidecar_transaction_begin(transaction, runtime,
		EUNION_SIDECAR_OPERATION_CREATE, intent);
	if (result < 0)
		return result;
	struct eunion_sidecar_view_storage* view = &transaction->view;
	EUNION_SIDECAR_AUTO_PATH(path);
	int upper_parent = -1;
	int lower_parent = -1;
	int source_parent = -1;
	int created_descriptor = -1;
	int directory = kind == EUNION_SIDECAR_CREATE_DIRECTORY;
	struct eunion_sidecar_journal_disk journal;
	memset(&journal, 0, sizeof(journal));
	result = eunion_sidecar_parse_path(guest_path, &path);
	if (result < 0)
		goto done_create;
	upper_parent = eunion_sidecar_open_parent(
		view->upper_descriptor, &path, 0);
	if (upper_parent < 0) {
		result = upper_parent;
		goto done_create;
	}
	lower_parent = eunion_sidecar_open_parent(
		view->lower_descriptor, &path, 0);
	if (lower_parent < 0 && lower_parent != -LINUX_ENOENT) {
		result = lower_parent;
		goto done_create;
	}
	struct eunion_sidecar_identity upper;
	struct eunion_sidecar_identity lower;
	result = eunion_sidecar_fstatat_identity_or_absent(
		upper_parent, path.component[path.count - 1].name, &upper);
	if (result < 0 || upper.present == 2)
		goto done_create;
	if (lower_parent >= 0)
		result = eunion_sidecar_fstatat_identity_or_absent(
			lower_parent, path.component[path.count - 1].name, &lower);
	else {
		memset(&lower, 0, sizeof(lower));
		result = 0;
	}
	if (result < 0 || lower.present == 2)
		goto done_create;
	struct eunion_sidecar_lookup lookup;
	result = eunion_sidecar_lookup_path(view, guest_path, &lookup);
	if (result < 0)
		goto done_create;
	if (upper.present) {
		if (kind != EUNION_SIDECAR_CREATE_OPEN) {
			result = -LINUX_EEXIST;
			goto done_create;
		}
		created_descriptor = SIDECAR_SYSCALL(__NR_openat,
			upper_parent, path.component[path.count - 1].name,
			flags, mode);
		result = created_descriptor;
		goto done_create;
	}
	if (lower.present &&
		lookup.kind != EUNION_SIDECAR_RECORD_WHITEOUT) {
		result = kind != EUNION_SIDECAR_CREATE_OPEN ||
				(flags & LINUX_O_EXCL)
			? -LINUX_EEXIST : -LINUX_EIO;
		goto done_create;
	}
#ifdef TEST
	if (eunion_test_sidecar_checkpoint_hook)
		eunion_test_sidecar_checkpoint_hook(
			EUNION_SIDECAR_TEST_RESOLVED, guest_path);
#endif
	int old_node = -1;
	struct eunion_sidecar_node_disk old_record;
	int old_result = eunion_sidecar_walk(view, guest_path, 0,
		EUNION_SIDECAR_RECORD_NONE, &old_node, &old_record);
	if (old_result == 0) {
		journal.old_record_valid = 1;
		journal.old_record = old_record;
		eunion_sidecar_close_fd(&old_node, 0);
	} else if (old_result != -LINUX_ENOENT) {
		result = old_result;
		goto done_create;
	}
	size_t path_length = strlen(guest_path);
	if (path_length >= sizeof(journal.path)) {
		result = -LINUX_EINVAL;
		goto done_create;
	}
	journal.phase = EUNION_SIDECAR_JOURNAL_PREPARED;
	journal.operation = EUNION_SIDECAR_OPERATION_CREATE;
	journal.remove_directory = (uint32_t)(directory != 0);
	journal.path_length = (uint32_t)path_length;
	journal.upper = upper;
	journal.lower = lower;
	memcpy(journal.path, guest_path, path_length + 1);
	result = eunion_sidecar_write_journal(view, &journal);
	if (result < 0)
		goto done_create;
	result = eunion_sidecar_transaction_transition(
		transaction, EUNION_SIDECAR_PHASE_PREPARED);
	if (result < 0)
		goto done_create;
#ifdef TEST
	if (eunion_test_sidecar_checkpoint_hook)
		eunion_test_sidecar_checkpoint_hook(
			EUNION_SIDECAR_TEST_JOURNAL_PREPARED, guest_path);
	if (eunion_test_sidecar_checkpoint_hook)
		eunion_test_sidecar_checkpoint_hook(
			EUNION_SIDECAR_TEST_PRE_BACKING, guest_path);
#endif
	struct eunion_sidecar_identity current_upper;
	struct eunion_sidecar_identity current_lower;
	result = eunion_sidecar_fstatat_identity_or_absent(
		upper_parent, path.component[path.count - 1].name,
		&current_upper);
	if (result >= 0 && lower_parent >= 0)
		result = eunion_sidecar_fstatat_identity_or_absent(
			lower_parent, path.component[path.count - 1].name,
			&current_lower);
	else if (result >= 0)
		memset(&current_lower, 0, sizeof(current_lower));
	if (result < 0 ||
		!eunion_sidecar_same_object(&upper, &current_upper) ||
		!eunion_sidecar_same_object(&lower, &current_lower)) {
		int original = result < 0 ? result : -LINUX_EAGAIN;
		(void)eunion_sidecar_remove_journal(view);
		result = original;
		goto done_create;
	}
	switch (kind) {
		case EUNION_SIDECAR_CREATE_DIRECTORY:
			result = SIDECAR_SYSCALL(__NR_mkdirat,
				upper_parent, path.component[path.count - 1].name,
				mode);
			break;
		case EUNION_SIDECAR_CREATE_OPEN:
			created_descriptor = SIDECAR_SYSCALL(__NR_openat,
				upper_parent, path.component[path.count - 1].name,
				flags | LINUX_O_CREAT | LINUX_O_EXCL |
					LINUX_O_NOFOLLOW,
				mode);
			result = created_descriptor < 0 ? created_descriptor : 0;
			break;
		case EUNION_SIDECAR_CREATE_SYMLINK:
			if (!auxiliary) {
				result = -LINUX_EINVAL;
				break;
			}
			result = SIDECAR_SYSCALL(__NR_symlinkat, auxiliary,
				upper_parent, path.component[path.count - 1].name);
			break;
		case EUNION_SIDECAR_CREATE_MKNOD:
			result = SIDECAR_SYSCALL(__NR_mknodat, upper_parent,
				path.component[path.count - 1].name, mode, device);
			break;
		case EUNION_SIDECAR_CREATE_HARDLINK:
		{
			EUNION_SIDECAR_AUTO_PATH(source_path);
			result = auxiliary
				? eunion_sidecar_parse_path(auxiliary,
					&source_path)
				: -LINUX_EINVAL;
			if (result < 0)
				break;
			source_parent = eunion_sidecar_open_parent(
				view->upper_descriptor, &source_path, 0);
			if (source_parent < 0) {
				result = source_parent;
				break;
			}
			result = SIDECAR_SYSCALL(__NR_linkat,
				source_parent,
				source_path.component[source_path.count - 1].name,
				upper_parent, path.component[path.count - 1].name,
				flags);
			break;
		}
		case EUNION_SIDECAR_CREATE_SOCKET:
			result = eunion_sidecar_bind_at(
				(int)device, upper_parent,
				path.component[path.count - 1].name);
			break;
		default:
			result = -LINUX_EINVAL;
			break;
	}
	if (result < 0) {
		int original = result;
		(void)eunion_sidecar_remove_journal(view);
		result = original;
		goto done_create;
	}
#ifdef TEST
	if (eunion_test_sidecar_checkpoint_hook)
		eunion_test_sidecar_checkpoint_hook(
			EUNION_SIDECAR_TEST_POST_BACKING_PRE_JOURNAL, guest_path);
#endif
	result = eunion_sidecar_fstatat_identity_or_absent(
		upper_parent, path.component[path.count - 1].name,
		&journal.backing_new);
	if (result < 0 || journal.backing_new.present != 1) {
		if (result >= 0)
			result = -LINUX_EIO;
		goto irreversible_create_failure;
	}
	journal.phase = EUNION_SIDECAR_JOURNAL_BACKING_COMMITTED;
	result = eunion_sidecar_write_journal(view, &journal);
	if (result < 0)
		goto irreversible_create_failure;
	result = eunion_sidecar_transaction_transition(
		transaction, EUNION_SIDECAR_PHASE_BACKING_COMMITTED);
	if (result < 0)
		goto irreversible_create_failure;
#ifdef TEST
	if (eunion_test_sidecar_checkpoint_hook)
		eunion_test_sidecar_checkpoint_hook(
			EUNION_SIDECAR_TEST_BACKING_COMMITTED, guest_path);
#endif
	result = eunion_sidecar_publish_created_record(
		view, guest_path, &journal.backing_new, &lower, directory);
	if (result < 0)
		goto irreversible_create_failure;
	/*
	 * The parent capability is intentionally O_PATH so write+execute-only
	 * directories remain mutable without acquiring read permission. fsync(2)
	 * rejects O_PATH; syncfs on the already anchored upper root provides the
	 * required durability without reopening or chmod'ing the live directory.
	 */
	result = SIDECAR_SYSCALL(__NR_syncfs, view->upper_descriptor);
	if (result < 0)
		goto irreversible_create_failure;
	result = eunion_sidecar_transaction_transition(
		transaction, EUNION_SIDECAR_PHASE_LOGICALLY_PUBLISHED);
	if (result < 0)
		goto irreversible_create_failure;
	journal.phase = EUNION_SIDECAR_JOURNAL_DURABLE;
	result = eunion_sidecar_write_journal(view, &journal);
	if (result < 0)
		goto irreversible_create_failure;
	result = eunion_sidecar_transaction_transition(
		transaction, EUNION_SIDECAR_PHASE_DURABLE);
	if (result < 0)
		goto irreversible_create_failure;
#ifdef TEST
	if (eunion_test_sidecar_checkpoint_hook)
		eunion_test_sidecar_checkpoint_hook(
			EUNION_SIDECAR_TEST_DURABLE, guest_path);
#endif
	result = eunion_sidecar_remove_journal(view);
	if (result < 0)
		goto irreversible_create_failure;
	result = kind == EUNION_SIDECAR_CREATE_OPEN
		? created_descriptor : 0;
	if (kind == EUNION_SIDECAR_CREATE_OPEN)
		created_descriptor = -1;
	goto done_create;

irreversible_create_failure:
	eunion_sidecar_close_fd(&created_descriptor, 0);

done_create:
	eunion_sidecar_close_fd(&created_descriptor, 0);
	eunion_sidecar_close_fd(&source_parent, 0);
	eunion_sidecar_close_fd(&lower_parent, 0);
	eunion_sidecar_close_fd(&upper_parent, 0);
	return eunion_sidecar_transaction_release(transaction, result);
}

int eunion_sidecar_open_create(const struct eunion_sidecar_runtime* runtime,
	const char* guest_path, int flags, unsigned int mode)
{
	if (!(flags & LINUX_O_CREAT))
		return -LINUX_EINVAL;
	return eunion_sidecar_create_common(
		runtime, guest_path, EUNION_SIDECAR_CREATE_OPEN,
		flags, mode, 0, NULL);
}

int eunion_sidecar_mkdir_create(const struct eunion_sidecar_runtime* runtime,
	const char* guest_path, unsigned int mode)
{
	return eunion_sidecar_create_common(
		runtime, guest_path, EUNION_SIDECAR_CREATE_DIRECTORY,
		0, mode, 0, NULL);
}

int eunion_sidecar_symlink_create(
	const struct eunion_sidecar_runtime* runtime, const char* target,
	const char* guest_path)
{
	if (!target)
		return -LINUX_EINVAL;
	return eunion_sidecar_create_common(
		runtime, guest_path, EUNION_SIDECAR_CREATE_SYMLINK,
		0, 0, 0, target);
}

int eunion_sidecar_mknod_create(
	const struct eunion_sidecar_runtime* runtime, const char* guest_path,
	unsigned int mode, unsigned int device)
{
	return eunion_sidecar_create_common(
		runtime, guest_path, EUNION_SIDECAR_CREATE_MKNOD,
		0, mode, device, NULL);
}

int eunion_sidecar_link_create(
	const struct eunion_sidecar_runtime* runtime,
	const char* source_guest_path, const char* destination_guest_path,
	int flags)
{
	if (!source_guest_path)
		return -LINUX_EINVAL;
	return eunion_sidecar_create_common(
		runtime, destination_guest_path, EUNION_SIDECAR_CREATE_HARDLINK,
		flags, 0, 0, source_guest_path);
}

int eunion_sidecar_socket_bind_create(
	const struct eunion_sidecar_runtime* runtime,
	const char* guest_path, int socket_descriptor)
{
	if (socket_descriptor < 0)
		return -LINUX_EINVAL;
	return eunion_sidecar_create_common(
		runtime, guest_path, EUNION_SIDECAR_CREATE_SOCKET,
		0, 0, (unsigned int)socket_descriptor, NULL);
}

static int eunion_sidecar_copy_bytes(int source, int destination)
{
	char buffer[65536];
	for (;;) {
		int count = SIDECAR_SYSCALL(__NR_read,
			source, buffer, sizeof(buffer));
		if (count < 0)
			return count;
		if (count == 0)
			return 0;
		int offset = 0;
		while (offset < count) {
			int written = SIDECAR_SYSCALL(__NR_write,
				destination, buffer + offset, count - offset);
			if (written < 0)
				return written;
			if (written == 0)
				return -LINUX_EIO;
			offset += written;
		}
	}
}

static int eunion_sidecar_copy_xattrs(int source, int destination)
{
#if defined(__NR_flistxattr) && defined(__NR_fgetxattr) && \
	defined(__NR_fsetxattr)
	char names[8192];
	int length = SIDECAR_SYSCALL(__NR_flistxattr,
		source, names, sizeof(names));
	if (length < 0)
		return length;
	int offset = 0;
	while (offset < length) {
		const char* name = names + offset;
		size_t name_length = strlen(name);
		if (name_length == 0 || offset + (int)name_length >= length)
			return -LINUX_EIO;
		offset += (int)name_length + 1;
		if (strcmp(name, "security.capability") == 0)
			continue;
		if (strncmp(name, "user.union.",
				sizeof("user.union.") - 1) == 0)
			return -LINUX_EIO;
		char value[8192];
		int value_length = SIDECAR_SYSCALL(__NR_fgetxattr,
			source, name, value, sizeof(value));
		if (value_length < 0)
			return value_length;
		int result = SIDECAR_SYSCALL(__NR_fsetxattr,
			destination, name, value, value_length, 0);
		if (result < 0)
			return result;
	}
#else
	(void)source;
	(void)destination;
#endif
	return 0;
}

static int eunion_sidecar_copy_metadata(
	int source, int destination, unsigned int mode,
	const sidecar_stat_t* status)
{
	int result = SIDECAR_SYSCALL(
		__NR_fchown, destination, status->st_uid, status->st_gid);
	if (result < 0)
		return result;
	result = eunion_sidecar_copy_xattrs(source, destination);
	if (result < 0)
		return result;
	result = SIDECAR_SYSCALL(__NR_fchmod, destination, mode & 07777);
	if (result < 0)
		return result;
	struct {
		long tv_sec;
		long tv_nsec;
	} times[2];
#ifdef TEST
	times[0].tv_sec = status->st_atim.tv_sec;
	times[0].tv_nsec = status->st_atim.tv_nsec;
	times[1].tv_sec = status->st_mtim.tv_sec;
	times[1].tv_nsec = status->st_mtim.tv_nsec;
#else
	times[0].tv_sec = status->st_atime;
	times[0].tv_nsec = status->st_atime_nsec;
	times[1].tv_sec = status->st_mtime;
	times[1].tv_nsec = status->st_mtime_nsec;
#endif
	result = SIDECAR_SYSCALL(
		__NR_utimensat, destination, "", times, 0x1000);
	return result;
}

static int eunion_sidecar_copy_tree_contents(
	int source_directory, int destination_directory)
{
	char buffer[8192];
	for (;;) {
		int length = SIDECAR_SYSCALL(__NR_getdents64,
			source_directory, buffer, sizeof(buffer));
		if (length < 0)
			return length;
		if (length == 0)
			return SIDECAR_SYSCALL(
				__NR_fsync, destination_directory);
		int offset = 0;
		while (offset < length) {
			struct eunion_sidecar_dirent64* entry =
				(struct eunion_sidecar_dirent64*)(buffer + offset);
			size_t fixed = offsetof(
				struct eunion_sidecar_dirent64, name);
			if (entry->record_length < fixed + 2 ||
				offset + entry->record_length > length)
				return -LINUX_EIO;
			size_t capacity = entry->record_length - fixed;
			size_t name_length = strnlen(entry->name, capacity);
			if (name_length == 0 || name_length == capacity ||
				name_length > EUNION_SIDECAR_NAME_MAX)
				return -LINUX_EIO;
			offset += entry->record_length;
			if ((name_length == 1 && entry->name[0] == '.') ||
				(name_length == 2 && entry->name[0] == '.' &&
				 entry->name[1] == '.'))
				continue;

			sidecar_stat_t status;
			int result = SIDECAR_SYSCALL(__NR_newfstatat,
				source_directory, entry->name, &status,
				LINUX_AT_SYMLINK_NOFOLLOW);
			if (result < 0)
				return result;
			unsigned int type =
				(unsigned int)status.st_mode & LINUX_S_IFMT;
			if (type == LINUX_S_IFREG) {
				int source = SIDECAR_SYSCALL(__NR_openat,
					source_directory, entry->name,
					LINUX_O_RDONLY | LINUX_O_NOFOLLOW |
						LINUX_O_CLOEXEC,
					0);
				if (source < 0)
					return source;
				int destination = SIDECAR_SYSCALL(__NR_openat,
					destination_directory, entry->name,
					LINUX_O_WRONLY | LINUX_O_CREAT |
						LINUX_O_EXCL | LINUX_O_NOFOLLOW |
						LINUX_O_CLOEXEC,
					0600);
				if (destination < 0) {
					eunion_sidecar_close_fd(&source, 0);
					return destination;
				}
				result = SIDECAR_SYSCALL(
					__NR_fchmod, destination, 0600);
				if (result >= 0)
					result = eunion_sidecar_copy_bytes(
						source, destination);
				if (result >= 0)
					result = eunion_sidecar_copy_metadata(
						source, destination,
						(unsigned int)status.st_mode &
							07777,
						&status);
				if (result >= 0)
					result = SIDECAR_SYSCALL(
						__NR_fsync, destination);
				eunion_sidecar_close_fd(&destination, 0);
				eunion_sidecar_close_fd(&source, 0);
				if (result < 0)
					return result;
			} else if (type == LINUX_S_IFDIR) {
				int source = SIDECAR_SYSCALL(__NR_openat,
					source_directory, entry->name,
					LINUX_O_RDONLY | LINUX_O_DIRECTORY |
						LINUX_O_NOFOLLOW | LINUX_O_CLOEXEC,
					0);
				if (source < 0)
					return source;
				result = eunion_sidecar_mkdir_private(
					destination_directory, entry->name);
				if (result < 0) {
					eunion_sidecar_close_fd(&source, 0);
					return result;
				}
				int destination = SIDECAR_SYSCALL(__NR_openat,
					destination_directory, entry->name,
					LINUX_O_RDONLY | LINUX_O_DIRECTORY |
						LINUX_O_NOFOLLOW | LINUX_O_CLOEXEC,
					0);
				if (destination < 0) {
					eunion_sidecar_close_fd(&source, 0);
					return destination;
				}
				result = eunion_sidecar_copy_tree_contents(
					source, destination);
				if (result >= 0)
					result = eunion_sidecar_copy_metadata(
						source, destination,
						(unsigned int)status.st_mode &
							07777,
						&status);
				if (result >= 0)
					result = SIDECAR_SYSCALL(
						__NR_fsync, destination);
				eunion_sidecar_close_fd(&destination, 0);
				eunion_sidecar_close_fd(&source, 0);
				if (result < 0)
					return result;
			} else if (type == LINUX_S_IFLNK) {
				char target[EUNION_SIDECAR_PATH_MAX];
				int target_length = SIDECAR_SYSCALL(
					__NR_readlinkat, source_directory,
					entry->name, target,
					sizeof(target) - 1);
				if (target_length < 0)
					return target_length;
				target[target_length] = '\0';
				result = SIDECAR_SYSCALL(__NR_symlinkat,
					target, destination_directory,
					entry->name);
				if (result < 0)
					return result;
			} else {
				return -LINUX_EPERM;
			}
		}
	}
}

static int eunion_sidecar_stage_copyup(
	eunion_sidecar_view view, int lower_parent, const char* leaf,
	const struct eunion_sidecar_identity* lower, int recursive,
	int* staging_result)
{
	*staging_result = -1;
	int staging = SIDECAR_SYSCALL(__NR_openat,
		view->sidecar_descriptor, "staging-v1",
		LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
		LINUX_O_CLOEXEC, 0);
	if (staging < 0)
		return staging;
	int result = eunion_sidecar_cleanup_copyup_stage(view);
	if (result < 0) {
		eunion_sidecar_close_fd(&staging, 0);
		return result;
	}
	unsigned int type = lower->mode & LINUX_S_IFMT;
	int source = -1;
	int staged = -1;
	sidecar_stat_t source_status;
	if (type == LINUX_S_IFREG) {
		source = SIDECAR_SYSCALL(__NR_openat, lower_parent, leaf,
			LINUX_O_RDONLY | LINUX_O_NOFOLLOW | LINUX_O_CLOEXEC, 0);
		if (source < 0)
			result = source;
		if (result >= 0)
			result = SIDECAR_SYSCALL(
				__NR_fstat, source, &source_status);
		if (result >= 0) {
			staged = SIDECAR_SYSCALL(__NR_openat, staging, "copyup-v1",
				LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_EXCL |
				LINUX_O_NOFOLLOW | LINUX_O_CLOEXEC,
				lower->mode & 0777);
			if (staged < 0)
				result = staged;
		}
		if (result >= 0)
			result = SIDECAR_SYSCALL(__NR_fchmod, staged, 0600);
		if (result >= 0)
			result = eunion_sidecar_copy_bytes(source, staged);
		if (result >= 0)
			result = eunion_sidecar_copy_metadata(
				source, staged, lower->mode & 0777,
				&source_status);
		if (result >= 0)
			result = SIDECAR_SYSCALL(__NR_fsync, staged);
	} else if (type == LINUX_S_IFDIR) {
		source = SIDECAR_SYSCALL(__NR_openat, lower_parent, leaf,
			LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
			LINUX_O_CLOEXEC, 0);
		if (source < 0)
			result = source;
		if (result >= 0)
			result = SIDECAR_SYSCALL(
				__NR_fstat, source, &source_status);
		if (result >= 0)
			result = eunion_sidecar_mkdir_private(
				staging, "copyup-v1");
		if (result >= 0) {
			staged = SIDECAR_SYSCALL(__NR_openat,
				staging, "copyup-v1",
				LINUX_O_RDONLY | LINUX_O_DIRECTORY |
				LINUX_O_NOFOLLOW | LINUX_O_CLOEXEC, 0);
			if (staged < 0)
				result = staged;
		}
		if (result >= 0 && recursive)
			result = eunion_sidecar_copy_tree_contents(source, staged);
		if (result >= 0)
			result = eunion_sidecar_copy_metadata(
				source, staged, lower->mode & 07777,
				&source_status);
		if (result >= 0)
			result = SIDECAR_SYSCALL(__NR_fsync, staged);
	} else if (type == LINUX_S_IFLNK) {
		char target[EUNION_SIDECAR_PATH_MAX];
		int target_length = SIDECAR_SYSCALL(__NR_readlinkat,
			lower_parent, leaf, target, sizeof(target) - 1);
		if (target_length < 0)
			result = target_length;
		else {
			target[target_length] = '\0';
			result = SIDECAR_SYSCALL(__NR_symlinkat,
				target, staging, "copyup-v1");
		}
	} else {
		result = -LINUX_EPERM;
	}
	eunion_sidecar_close_fd(&source, 0);
	eunion_sidecar_close_fd(&staged, 0);
	if (result >= 0)
		result = SIDECAR_SYSCALL(__NR_fsync, staging);
	if (result >= 0)
		*staging_result = staging;
	else {
		eunion_sidecar_close_fd(&staging, 0);
		(void)eunion_sidecar_cleanup_copyup_stage(view);
	}
	return result;
}

/*
 * Materialize every lower-only descendant of an already-present upper
 * directory while the caller owns the sidecar's exclusive lifecycle lock.
 *
 * This is a sequence of idempotent, atomic child publications: each complete
 * lower subtree is first built under private staging, fsynced, then renamed
 * into the upper directory with RENAME_NOREPLACE.  A crash can therefore leave
 * only a semantically equivalent prefix of materialized children; retrying the
 * walk completes it.  No guest lookup can observe the walk because all
 * sidecar-aware resolver paths take the shared sidecar lock.
 */
static int eunion_sidecar_materialize_merged_tree(
	eunion_sidecar_view view, int upper_directory, int lower_directory,
	const char* guest_path)
{
	char buffer[8192];
	for (;;) {
		int length = SIDECAR_SYSCALL(__NR_getdents64,
			lower_directory, buffer, sizeof(buffer));
		if (length < 0)
			return length;
		if (length == 0)
			return SIDECAR_SYSCALL(__NR_fsync, upper_directory);
		int offset = 0;
		while (offset < length) {
			struct eunion_sidecar_dirent64* entry =
				(struct eunion_sidecar_dirent64*)(buffer + offset);
			size_t fixed = offsetof(
				struct eunion_sidecar_dirent64, name);
			if (entry->record_length < fixed + 2 ||
				offset + entry->record_length > length)
				return -LINUX_EIO;
			size_t capacity = entry->record_length - fixed;
			size_t name_length = strnlen(entry->name, capacity);
			if (name_length == 0 || name_length == capacity ||
				name_length > EUNION_SIDECAR_NAME_MAX)
				return -LINUX_EIO;
			offset += entry->record_length;
			if ((name_length == 1 && entry->name[0] == '.') ||
				(name_length == 2 && entry->name[0] == '.' &&
				 entry->name[1] == '.'))
				continue;

			char child_path[EUNION_SIDECAR_PATH_MAX];
			size_t parent_length = strlen(guest_path);
			size_t needed = parent_length +
				(parent_length > 1 ? 1 : 0) + name_length + 1;
			if (needed > sizeof(child_path))
				return -LINUX_ENAMETOOLONG;
			memcpy(child_path, guest_path, parent_length);
			size_t cursor = parent_length;
			if (cursor > 1)
				child_path[cursor++] = '/';
			memcpy(child_path + cursor, entry->name, name_length);
			child_path[cursor + name_length] = '\0';

			struct eunion_sidecar_lookup lookup;
			int result = eunion_sidecar_lookup_path(
				view, child_path, &lookup);
			if (result < 0)
				return result;
			if (lookup.kind == EUNION_SIDECAR_RECORD_WHITEOUT)
				continue;

			struct eunion_sidecar_identity lower;
			struct eunion_sidecar_identity upper;
			result = eunion_sidecar_fstatat_identity_or_absent(
				lower_directory, entry->name, &lower);
			if (result >= 0)
				result = eunion_sidecar_fstatat_identity_or_absent(
					upper_directory, entry->name, &upper);
			if (result < 0 || lower.present != 1 ||
				upper.present == 2)
				return result < 0 ? result : -LINUX_EIO;

			if (!upper.present) {
				int staging = -1;
				result = eunion_sidecar_stage_copyup(
					view, lower_directory, entry->name,
					&lower, 1, &staging);
				if (result < 0)
					return result;
				struct eunion_sidecar_identity staged;
				result = eunion_sidecar_fstatat_identity_or_absent(
					staging, "copyup-v1", &staged);
				if (result >= 0 && staged.present != 1)
					result = -LINUX_EIO;
				if (result >= 0)
					result = SIDECAR_SYSCALL(__NR_renameat2,
						staging, "copyup-v1",
						upper_directory, entry->name,
						LINUX_RENAME_NOREPLACE);
				eunion_sidecar_close_fd(&staging, 0);
				if (result >= 0)
					result = SIDECAR_SYSCALL(
						__NR_fsync, upper_directory);
				if (result >= 0)
					result =
						eunion_sidecar_fstatat_identity_or_absent(
							upper_directory, entry->name,
							&upper);
				if (result >= 0 &&
					(upper.present != 1 ||
					 !eunion_sidecar_same_object(
						&staged, &upper)))
					result = -LINUX_EIO;
				if (result >= 0)
					result = eunion_sidecar_publish_created_record(
						view, child_path, &upper, &lower, 0);
				if (result >= 0)
					result =
						eunion_sidecar_cleanup_copyup_stage(view);
				if (result < 0)
					return result;
				continue;
			}

			if ((upper.mode & LINUX_S_IFMT) == LINUX_S_IFDIR &&
				(lower.mode & LINUX_S_IFMT) == LINUX_S_IFDIR &&
				lookup.kind != EUNION_SIDECAR_RECORD_OPAQUE) {
				int upper_child = SIDECAR_SYSCALL(__NR_openat,
					upper_directory, entry->name,
					LINUX_O_RDONLY | LINUX_O_DIRECTORY |
						LINUX_O_NOFOLLOW | LINUX_O_CLOEXEC,
					0);
				if (upper_child < 0)
					return upper_child;
				int lower_child = SIDECAR_SYSCALL(__NR_openat,
					lower_directory, entry->name,
					LINUX_O_RDONLY | LINUX_O_DIRECTORY |
						LINUX_O_NOFOLLOW | LINUX_O_CLOEXEC,
					0);
				if (lower_child < 0) {
					eunion_sidecar_close_fd(&upper_child, 0);
					return lower_child;
				}
				result = eunion_sidecar_materialize_merged_tree(
					view, upper_child, lower_child, child_path);
				eunion_sidecar_close_fd(&lower_child, 0);
				eunion_sidecar_close_fd(&upper_child, 0);
				if (result < 0)
					return result;
			}
		}
	}
}

static int eunion_sidecar_copy_up_common(
	const struct eunion_sidecar_runtime* runtime,
	const char* guest_path, int recursive)
{
	eunion_sidecar_transaction transaction = {{0}};
	union eunion_sidecar_transaction_intent intent = {
		.copy_up = {
			.directory = 0,
		},
	};
	int result = eunion_sidecar_transaction_begin(transaction, runtime,
		EUNION_SIDECAR_OPERATION_COPY_UP, intent);
	if (result < 0)
		return result;
	struct eunion_sidecar_view_storage* view = &transaction->view;
	EUNION_SIDECAR_AUTO_PATH(path);
	int upper_parent = -1;
	int lower_parent = -1;
	int staging = -1;
	struct eunion_sidecar_journal_disk journal;
	memset(&journal, 0, sizeof(journal));
	result = eunion_sidecar_parse_path(guest_path, &path);
	if (result < 0)
		goto copyup_done;
	upper_parent = eunion_sidecar_open_parent(
		view->upper_descriptor, &path, 0);
	lower_parent = eunion_sidecar_open_parent(
		view->lower_descriptor, &path, 0);
	if (upper_parent < 0 || lower_parent < 0) {
		result = upper_parent < 0 ? upper_parent : lower_parent;
		goto copyup_done;
	}
	struct eunion_sidecar_identity upper;
	struct eunion_sidecar_identity lower;
	result = eunion_sidecar_fstatat_identity_or_absent(
		upper_parent, path.component[path.count - 1].name, &upper);
	if (result >= 0)
		result = eunion_sidecar_fstatat_identity_or_absent(
			lower_parent, path.component[path.count - 1].name, &lower);
	if (result < 0 || upper.present == 2 || lower.present == 2)
		goto copyup_done;
	struct eunion_sidecar_lookup lookup;
	result = eunion_sidecar_lookup_path(view, guest_path, &lookup);
	if (result < 0)
		goto copyup_done;
	if (lookup.kind == EUNION_SIDECAR_RECORD_WHITEOUT) {
		result = -LINUX_ENOENT;
		goto copyup_done;
	}
	if (upper.present) {
		if (recursive &&
			(upper.mode & LINUX_S_IFMT) == LINUX_S_IFDIR &&
			lower.present &&
			(lower.mode & LINUX_S_IFMT) == LINUX_S_IFDIR &&
			lookup.kind != EUNION_SIDECAR_RECORD_OPAQUE) {
			size_t path_length = strlen(guest_path);
			if (path_length >= sizeof(journal.path)) {
				result = -LINUX_ENAMETOOLONG;
				goto copyup_done;
			}
			journal.phase = EUNION_SIDECAR_JOURNAL_PREPARED;
			journal.operation = EUNION_SIDECAR_OPERATION_COPY_UP;
			journal.remove_directory = 1;
			journal.recursive_tree = 1;
			journal.path_length = (uint32_t)path_length;
			journal.upper = upper;
			journal.lower = lower;
			journal.backing_new = upper;
			memcpy(journal.path, guest_path, path_length + 1);
			int root_node = -1;
			struct eunion_sidecar_node_disk root_record;
			result = eunion_sidecar_walk(view, guest_path, 1,
				EUNION_SIDECAR_RECORD_INDEX,
				&root_node, &root_record);
			eunion_sidecar_close_fd(&root_node, 0);
			if (result < 0)
				goto copyup_done;
			result = eunion_sidecar_write_journal(view, &journal);
			if (result < 0)
				goto copyup_done;
			result = eunion_sidecar_transaction_transition(
				transaction, EUNION_SIDECAR_PHASE_PREPARED);
			if (result < 0)
				goto copyup_done;
#ifdef TEST
			if (eunion_test_sidecar_checkpoint_hook)
				eunion_test_sidecar_checkpoint_hook(
					EUNION_SIDECAR_TEST_JOURNAL_PREPARED,
					guest_path);
			if (eunion_test_sidecar_checkpoint_hook)
				eunion_test_sidecar_checkpoint_hook(
					EUNION_SIDECAR_TEST_PRE_BACKING,
					guest_path);
#endif
			int upper_directory = SIDECAR_SYSCALL(__NR_openat,
				upper_parent, path.component[path.count - 1].name,
				LINUX_O_RDONLY | LINUX_O_DIRECTORY |
					LINUX_O_NOFOLLOW | LINUX_O_CLOEXEC,
				0);
			if (upper_directory < 0) {
				result = upper_directory;
				goto copyup_done;
			}
			int lower_directory = SIDECAR_SYSCALL(__NR_openat,
				lower_parent, path.component[path.count - 1].name,
				LINUX_O_RDONLY | LINUX_O_DIRECTORY |
					LINUX_O_NOFOLLOW | LINUX_O_CLOEXEC,
				0);
			if (lower_directory < 0)
				result = lower_directory;
			else
				result = eunion_sidecar_materialize_merged_tree(
					view, upper_directory, lower_directory,
					guest_path);
			eunion_sidecar_close_fd(&lower_directory, 0);
			eunion_sidecar_close_fd(&upper_directory, 0);
			if (result < 0) {
				(void)eunion_sidecar_transaction_transition(
					transaction,
					EUNION_SIDECAR_PHASE_RECOVERY_DELEGATED);
				goto copyup_done;
			}
#ifdef TEST
			if (eunion_test_sidecar_checkpoint_hook)
				eunion_test_sidecar_checkpoint_hook(
					EUNION_SIDECAR_TEST_POST_BACKING_PRE_JOURNAL,
					guest_path);
#endif
			journal.phase =
				EUNION_SIDECAR_JOURNAL_BACKING_COMMITTED;
			result = eunion_sidecar_write_journal(view, &journal);
			if (result < 0) {
				(void)eunion_sidecar_transaction_transition(
					transaction,
					EUNION_SIDECAR_PHASE_RECOVERY_DELEGATED);
				goto copyup_done;
			}
			result = eunion_sidecar_transaction_transition(
				transaction,
				EUNION_SIDECAR_PHASE_BACKING_COMMITTED);
			if (result < 0)
				goto copyup_done;
#ifdef TEST
			if (eunion_test_sidecar_checkpoint_hook)
				eunion_test_sidecar_checkpoint_hook(
					EUNION_SIDECAR_TEST_BACKING_COMMITTED,
					guest_path);
#endif
			result = SIDECAR_SYSCALL(
				__NR_syncfs, view->upper_descriptor);
			if (result < 0) {
				(void)eunion_sidecar_transaction_transition(
					transaction,
					EUNION_SIDECAR_PHASE_RECOVERY_DELEGATED);
				goto copyup_done;
			}
			result = eunion_sidecar_transaction_transition(
				transaction,
				EUNION_SIDECAR_PHASE_LOGICALLY_PUBLISHED);
			if (result < 0)
				goto copyup_done;
			journal.phase = EUNION_SIDECAR_JOURNAL_DURABLE;
			result = eunion_sidecar_write_journal(view, &journal);
			if (result < 0) {
				(void)eunion_sidecar_transaction_transition(
					transaction,
					EUNION_SIDECAR_PHASE_RECOVERY_DELEGATED);
				goto copyup_done;
			}
			result = eunion_sidecar_transaction_transition(
				transaction, EUNION_SIDECAR_PHASE_DURABLE);
			if (result < 0)
				goto copyup_done;
#ifdef TEST
			if (eunion_test_sidecar_checkpoint_hook)
				eunion_test_sidecar_checkpoint_hook(
					EUNION_SIDECAR_TEST_DURABLE,
					guest_path);
#endif
			result = eunion_sidecar_remove_journal(view);
		} else {
			result = 0;
		}
		goto copyup_done;
	}
	if (!lower.present) {
		result = -LINUX_ENOENT;
		goto copyup_done;
	}
#ifdef TEST
	if (eunion_test_sidecar_checkpoint_hook)
		eunion_test_sidecar_checkpoint_hook(
			EUNION_SIDECAR_TEST_RESOLVED, guest_path);
#endif
	int old_node = -1;
	struct eunion_sidecar_node_disk old_record;
	int old_result = eunion_sidecar_walk(view, guest_path, 0,
		EUNION_SIDECAR_RECORD_NONE, &old_node, &old_record);
	if (old_result == 0) {
		journal.old_record_valid = 1;
		journal.old_record = old_record;
		eunion_sidecar_close_fd(&old_node, 0);
	} else if (old_result != -LINUX_ENOENT) {
		result = old_result;
		goto copyup_done;
	}
	size_t path_length = strlen(guest_path);
	if (path_length >= sizeof(journal.path)) {
		result = -LINUX_EINVAL;
		goto copyup_done;
	}
	result = eunion_sidecar_stage_copyup(view, lower_parent,
		path.component[path.count - 1].name,
		&lower, recursive, &staging);
	if (result < 0)
		goto copyup_done;
	result = eunion_sidecar_fstatat_identity_or_absent(
		staging, "copyup-v1", &journal.backing_new);
	if (result < 0 || journal.backing_new.present != 1) {
		if (result >= 0)
			result = -LINUX_EIO;
		goto copyup_done;
	}
	journal.phase = EUNION_SIDECAR_JOURNAL_PREPARED;
	journal.operation = EUNION_SIDECAR_OPERATION_COPY_UP;
	journal.remove_directory =
		(uint32_t)((lower.mode & LINUX_S_IFMT) == LINUX_S_IFDIR);
	transaction->intent.copy_up.directory = journal.remove_directory;
	journal.path_length = (uint32_t)path_length;
	journal.upper = upper;
	journal.lower = lower;
	memcpy(journal.path, guest_path, path_length + 1);
	result = eunion_sidecar_write_journal(view, &journal);
	if (result < 0)
		goto copyup_done;
	result = eunion_sidecar_transaction_transition(
		transaction, EUNION_SIDECAR_PHASE_PREPARED);
	if (result < 0)
		goto copyup_done;
#ifdef TEST
	if (eunion_test_sidecar_checkpoint_hook)
		eunion_test_sidecar_checkpoint_hook(
			EUNION_SIDECAR_TEST_JOURNAL_PREPARED, guest_path);
	if (eunion_test_sidecar_checkpoint_hook)
		eunion_test_sidecar_checkpoint_hook(
			EUNION_SIDECAR_TEST_PRE_BACKING, guest_path);
#endif
	struct eunion_sidecar_identity current_upper;
	struct eunion_sidecar_identity current_lower;
	result = eunion_sidecar_fstatat_identity_or_absent(
		upper_parent, path.component[path.count - 1].name,
		&current_upper);
	if (result >= 0)
		result = eunion_sidecar_fstatat_identity_or_absent(
			lower_parent, path.component[path.count - 1].name,
			&current_lower);
	if (result < 0 ||
		!eunion_sidecar_same_object(&upper, &current_upper) ||
		!eunion_sidecar_same_object(&lower, &current_lower)) {
		if (result >= 0)
			result = -LINUX_EAGAIN;
		goto copyup_precommit_failure;
	}
	result = SIDECAR_SYSCALL(__NR_renameat2, staging, "copyup-v1",
		upper_parent, path.component[path.count - 1].name,
		LINUX_RENAME_NOREPLACE);
	if (result < 0)
		goto copyup_precommit_failure;
#ifdef TEST
	if (eunion_test_sidecar_checkpoint_hook)
		eunion_test_sidecar_checkpoint_hook(
			EUNION_SIDECAR_TEST_POST_BACKING_PRE_JOURNAL, guest_path);
#endif
	journal.phase = EUNION_SIDECAR_JOURNAL_BACKING_COMMITTED;
	result = eunion_sidecar_write_journal(view, &journal);
	if (result < 0)
		goto copyup_irreversible_failure;
	result = eunion_sidecar_transaction_transition(
		transaction, EUNION_SIDECAR_PHASE_BACKING_COMMITTED);
	if (result < 0)
		goto copyup_irreversible_failure;
#ifdef TEST
	if (eunion_test_sidecar_checkpoint_hook)
		eunion_test_sidecar_checkpoint_hook(
			EUNION_SIDECAR_TEST_BACKING_COMMITTED, guest_path);
#endif
	result = eunion_sidecar_publish_created_record(view, guest_path,
		&journal.backing_new, &lower, 0);
	if (result >= 0)
		result = SIDECAR_SYSCALL(__NR_syncfs, view->upper_descriptor);
	if (result < 0)
		goto copyup_irreversible_failure;
	result = eunion_sidecar_transaction_transition(
		transaction, EUNION_SIDECAR_PHASE_LOGICALLY_PUBLISHED);
	if (result < 0)
		goto copyup_irreversible_failure;
	journal.phase = EUNION_SIDECAR_JOURNAL_DURABLE;
	result = eunion_sidecar_write_journal(view, &journal);
	if (result < 0)
		goto copyup_irreversible_failure;
	result = eunion_sidecar_transaction_transition(
		transaction, EUNION_SIDECAR_PHASE_DURABLE);
	if (result < 0)
		goto copyup_irreversible_failure;
#ifdef TEST
	if (eunion_test_sidecar_checkpoint_hook)
		eunion_test_sidecar_checkpoint_hook(
			EUNION_SIDECAR_TEST_DURABLE, guest_path);
#endif
	result = eunion_sidecar_remove_journal(view);
	if (result >= 0)
		result = eunion_sidecar_cleanup_copyup_stage(view);
	goto copyup_done;

copyup_precommit_failure:
	{
		int original = result;
		(void)eunion_sidecar_cleanup_copyup_stage(view);
		(void)eunion_sidecar_remove_journal(view);
		result = original;
	}
	goto copyup_done;

copyup_irreversible_failure:
	/* The durable journal owns forward recovery after the backing rename. */

copyup_done:
	eunion_sidecar_close_fd(&staging, 0);
	eunion_sidecar_close_fd(&lower_parent, 0);
	eunion_sidecar_close_fd(&upper_parent, 0);
	return eunion_sidecar_transaction_release(transaction, result);
}

int eunion_sidecar_copy_up(const struct eunion_sidecar_runtime* runtime,
	const char* guest_path)
{
	return eunion_sidecar_copy_up_common(runtime, guest_path, 0);
}

int eunion_sidecar_copy_up_tree(const struct eunion_sidecar_runtime* runtime,
	const char* guest_path)
{
	return eunion_sidecar_copy_up_common(runtime, guest_path, 1);
}

int eunion_sidecar_rename_path(const struct eunion_sidecar_runtime* runtime,
	const char* old_guest_path, const char* new_guest_path)
{
	if (!old_guest_path || !new_guest_path)
		return -LINUX_EINVAL;
	if (strcmp(old_guest_path, new_guest_path) == 0)
		return 0;
	eunion_sidecar_transaction transaction = {{0}};
	union eunion_sidecar_transaction_intent intent = {
		.rename = {
			.two_path = 1,
		},
	};
	int result = eunion_sidecar_transaction_begin(transaction, runtime,
		EUNION_SIDECAR_OPERATION_RENAME, intent);
	if (result < 0)
		return result;
	struct eunion_sidecar_view_storage* view = &transaction->view;
	EUNION_SIDECAR_AUTO_PATH(old_path);
	EUNION_SIDECAR_AUTO_PATH(new_path);
	int old_parent = -1;
	int new_parent = -1;
	struct eunion_sidecar_journal_disk journal;
	memset(&journal, 0, sizeof(journal));
	result = eunion_sidecar_parse_path(
		old_guest_path, &old_path);
	if (result >= 0)
		result = eunion_sidecar_parse_path(
			new_guest_path, &new_path);
	if (result < 0)
		goto rename_done;
	old_parent = eunion_sidecar_open_parent(
		view->upper_descriptor, &old_path, 0);
	new_parent = eunion_sidecar_open_parent(
		view->upper_descriptor, &new_path, 0);
	if (old_parent < 0 || new_parent < 0) {
		result = old_parent < 0 ? old_parent : new_parent;
		goto rename_done;
	}
	result = eunion_sidecar_fstatat_identity_or_absent(
		old_parent, old_path.component[old_path.count - 1].name,
		&journal.upper);
	if (result >= 0)
		result = eunion_sidecar_fstatat_identity_or_absent(
			new_parent, new_path.component[new_path.count - 1].name,
			&journal.secondary_upper);
	if (result < 0 || journal.upper.present != 1 ||
		journal.secondary_upper.present == 2) {
		if (result >= 0)
			result = journal.upper.present ? -LINUX_EIO : -LINUX_ENOENT;
		goto rename_done;
	}
	int old_lower_parent = eunion_sidecar_open_parent(
		view->lower_descriptor, &old_path, 0);
	int new_lower_parent = eunion_sidecar_open_parent(
		view->lower_descriptor, &new_path, 0);
	if (old_lower_parent >= 0)
		result = eunion_sidecar_fstatat_identity_or_absent(
			old_lower_parent,
			old_path.component[old_path.count - 1].name,
			&journal.lower);
	else if (old_lower_parent == -LINUX_ENOENT)
		memset(&journal.lower, 0, sizeof(journal.lower));
	else
		result = old_lower_parent;
	if (result >= 0 && new_lower_parent >= 0)
		result = eunion_sidecar_fstatat_identity_or_absent(
			new_lower_parent,
			new_path.component[new_path.count - 1].name,
			&journal.secondary_lower);
	else if (result >= 0 && new_lower_parent == -LINUX_ENOENT)
		memset(&journal.secondary_lower, 0,
			sizeof(journal.secondary_lower));
	else if (result >= 0)
		result = new_lower_parent;
	eunion_sidecar_close_fd(&new_lower_parent, 0);
	eunion_sidecar_close_fd(&old_lower_parent, 0);
	if (result < 0 || journal.lower.present == 2 ||
		journal.secondary_lower.present == 2)
		goto rename_done;
	struct eunion_sidecar_lookup old_lookup;
	struct eunion_sidecar_lookup new_lookup;
	result = eunion_sidecar_lookup_path(
		view, old_guest_path, &old_lookup);
	if (result >= 0)
		result = eunion_sidecar_lookup_path(
			view, new_guest_path, &new_lookup);
	if (result < 0 ||
		old_lookup.kind == EUNION_SIDECAR_RECORD_WHITEOUT)
		goto rename_done;
#ifdef TEST
	if (eunion_test_sidecar_checkpoint_hook)
		eunion_test_sidecar_checkpoint_hook(
			EUNION_SIDECAR_TEST_RESOLVED, old_guest_path);
#endif
	int node = -1;
	struct eunion_sidecar_node_disk record;
	int record_result = eunion_sidecar_open_record_path(
		view, old_guest_path, &node, &record);
	if (record_result < 0) {
		result = record_result;
		goto rename_done;
	}
	journal.old_record_valid = 1;
	journal.old_record = record;
	eunion_sidecar_close_fd(&node, 0);
	record_result = eunion_sidecar_open_record_path(
		view, new_guest_path, &node, &record);
	if (record_result == 0) {
		journal.secondary_old_record_valid = 1;
		journal.secondary_old_record = record;
		eunion_sidecar_close_fd(&node, 0);
	} else if (record_result != -LINUX_ENOENT) {
		result = record_result;
		goto rename_done;
	}
	size_t old_path_length = strlen(old_guest_path);
	size_t new_path_length = strlen(new_guest_path);
	if (old_path_length >= sizeof(journal.path) ||
		new_path_length >= sizeof(journal.secondary_path)) {
		result = -LINUX_EINVAL;
		goto rename_done;
	}
	journal.phase = EUNION_SIDECAR_JOURNAL_PREPARED;
	journal.operation = EUNION_SIDECAR_OPERATION_RENAME;
	journal.path_length = (uint32_t)old_path_length;
	journal.secondary_path_length = (uint32_t)new_path_length;
	memcpy(journal.path, old_guest_path, old_path_length + 1);
	memcpy(journal.secondary_path,
		new_guest_path, new_path_length + 1);
	result = eunion_sidecar_write_journal(view, &journal);
	if (result < 0)
		goto rename_done;
	result = eunion_sidecar_transaction_transition(
		transaction, EUNION_SIDECAR_PHASE_PREPARED);
	if (result < 0)
		goto rename_done;
#ifdef TEST
	if (eunion_test_sidecar_checkpoint_hook)
		eunion_test_sidecar_checkpoint_hook(
			EUNION_SIDECAR_TEST_JOURNAL_PREPARED, old_guest_path);
	if (eunion_test_sidecar_checkpoint_hook)
		eunion_test_sidecar_checkpoint_hook(
			EUNION_SIDECAR_TEST_PRE_BACKING, old_guest_path);
#endif
	struct eunion_sidecar_identity current_source;
	struct eunion_sidecar_identity current_destination;
	result = eunion_sidecar_fstatat_identity_or_absent(
		old_parent, old_path.component[old_path.count - 1].name,
		&current_source);
	if (result >= 0)
		result = eunion_sidecar_fstatat_identity_or_absent(
			new_parent, new_path.component[new_path.count - 1].name,
			&current_destination);
	if (result < 0 ||
		!eunion_sidecar_same_object(
			&journal.upper, &current_source) ||
		!eunion_sidecar_same_object(
			&journal.secondary_upper, &current_destination)) {
		int original = result < 0 ? result : -LINUX_EAGAIN;
		(void)eunion_sidecar_remove_journal(view);
		result = original;
		goto rename_done;
	}
	result = SIDECAR_SYSCALL(__NR_renameat,
		old_parent, old_path.component[old_path.count - 1].name,
		new_parent, new_path.component[new_path.count - 1].name);
	if (result < 0) {
		int original = result;
		(void)eunion_sidecar_remove_journal(view);
		result = original;
		goto rename_done;
	}
#ifdef TEST
	if (eunion_test_sidecar_checkpoint_hook)
		eunion_test_sidecar_checkpoint_hook(
			EUNION_SIDECAR_TEST_POST_BACKING_PRE_JOURNAL,
			old_guest_path);
#endif
	result = eunion_sidecar_fstatat_identity_or_absent(
		new_parent, new_path.component[new_path.count - 1].name,
		&journal.backing_new);
	if (result < 0 || !journal.backing_new.present ||
		!eunion_sidecar_same_object(
			&journal.upper, &journal.backing_new)) {
		if (result >= 0)
			result = -LINUX_EIO;
		goto rename_irreversible;
	}
	journal.phase = EUNION_SIDECAR_JOURNAL_BACKING_COMMITTED;
	result = eunion_sidecar_write_journal(view, &journal);
	if (result < 0)
		goto rename_irreversible;
	result = eunion_sidecar_transaction_transition(
		transaction, EUNION_SIDECAR_PHASE_BACKING_COMMITTED);
	if (result < 0)
		goto rename_irreversible;
#ifdef TEST
	if (eunion_test_sidecar_checkpoint_hook)
		eunion_test_sidecar_checkpoint_hook(
			EUNION_SIDECAR_TEST_BACKING_COMMITTED, old_guest_path);
#endif
	result = eunion_sidecar_apply_rename_records(
		view, &journal, &journal.backing_new);
	if (result >= 0)
		result = SIDECAR_SYSCALL(__NR_syncfs, view->upper_descriptor);
	if (result < 0)
		goto rename_irreversible;
	result = eunion_sidecar_transaction_transition(
		transaction, EUNION_SIDECAR_PHASE_LOGICALLY_PUBLISHED);
	if (result < 0)
		goto rename_irreversible;
	journal.phase = EUNION_SIDECAR_JOURNAL_DURABLE;
	result = eunion_sidecar_write_journal(view, &journal);
	if (result < 0)
		goto rename_irreversible;
	result = eunion_sidecar_transaction_transition(
		transaction, EUNION_SIDECAR_PHASE_DURABLE);
	if (result < 0)
		goto rename_irreversible;
#ifdef TEST
	if (eunion_test_sidecar_checkpoint_hook)
		eunion_test_sidecar_checkpoint_hook(
			EUNION_SIDECAR_TEST_DURABLE, old_guest_path);
#endif
	result = eunion_sidecar_remove_journal(view);
	goto rename_done;

rename_irreversible:
	/* A retained durable journal owns forward recovery. */

rename_done:
	eunion_sidecar_close_fd(&new_parent, 0);
	eunion_sidecar_close_fd(&old_parent, 0);
	return eunion_sidecar_transaction_release(transaction, result);
}

int eunion_sidecar_transition_allowed(enum eunion_sidecar_phase from,
	enum eunion_sidecar_phase to)
{
	switch (from)
	{
		case EUNION_SIDECAR_PHASE_EMPTY:
			return to == EUNION_SIDECAR_PHASE_RESOLVED ? 0 : -EINVAL;
		case EUNION_SIDECAR_PHASE_RESOLVED:
			return to == EUNION_SIDECAR_PHASE_LOCKED ||
				to == EUNION_SIDECAR_PHASE_RELEASED ? 0 : -EINVAL;
		case EUNION_SIDECAR_PHASE_LOCKED:
			return to == EUNION_SIDECAR_PHASE_PREPARED ||
				to == EUNION_SIDECAR_PHASE_RELEASED ? 0 : -EINVAL;
		case EUNION_SIDECAR_PHASE_PREPARED:
			return to == EUNION_SIDECAR_PHASE_LOGICALLY_PUBLISHED ||
				to == EUNION_SIDECAR_PHASE_RELEASED ? 0 : -EINVAL;
		case EUNION_SIDECAR_PHASE_LOGICALLY_PUBLISHED:
			return to == EUNION_SIDECAR_PHASE_BACKING_COMMITTED ||
				to == EUNION_SIDECAR_PHASE_ROLLED_BACK ||
				to == EUNION_SIDECAR_PHASE_RECOVERY_DELEGATED
					? 0 : -EINVAL;
		case EUNION_SIDECAR_PHASE_BACKING_COMMITTED:
			return to == EUNION_SIDECAR_PHASE_DURABLE ||
				to == EUNION_SIDECAR_PHASE_FORWARD_RECOVERY ||
				to == EUNION_SIDECAR_PHASE_RECOVERY_DELEGATED
					? 0 : -EINVAL;
		case EUNION_SIDECAR_PHASE_ROLLED_BACK:
		case EUNION_SIDECAR_PHASE_FORWARD_RECOVERY:
			return to == EUNION_SIDECAR_PHASE_DURABLE ? 0 : -EINVAL;
		case EUNION_SIDECAR_PHASE_RECOVERY_DELEGATED:
			return to == EUNION_SIDECAR_PHASE_RELEASED ? 0 : -EINVAL;
		case EUNION_SIDECAR_PHASE_DURABLE:
			return to == EUNION_SIDECAR_PHASE_RELEASED ? 0 : -EINVAL;
		case EUNION_SIDECAR_PHASE_RELEASED:
		case EUNION_SIDECAR_PHASE_INVALID:
		default:
			return -EINVAL;
	}
}

int eunion_sidecar_operation_transition_allowed(
	enum eunion_sidecar_operation operation,
	enum eunion_sidecar_phase from, enum eunion_sidecar_phase to)
{
	if (operation < EUNION_SIDECAR_OPERATION_REMOVE ||
		operation >= EUNION_SIDECAR_OPERATION_INVALID)
		return -EINVAL;
	int backing_first =
		operation == EUNION_SIDECAR_OPERATION_CREATE ||
		operation == EUNION_SIDECAR_OPERATION_COPY_UP ||
		operation == EUNION_SIDECAR_OPERATION_RENAME ||
		operation == EUNION_SIDECAR_OPERATION_PREFIX_RECREATE;
	if (!backing_first)
		return eunion_sidecar_transition_allowed(from, to);
	switch (from) {
		case EUNION_SIDECAR_PHASE_PREPARED:
			return to == EUNION_SIDECAR_PHASE_BACKING_COMMITTED ||
				to == EUNION_SIDECAR_PHASE_RECOVERY_DELEGATED ||
				to == EUNION_SIDECAR_PHASE_RELEASED ? 0 : -EINVAL;
		case EUNION_SIDECAR_PHASE_BACKING_COMMITTED:
			return to == EUNION_SIDECAR_PHASE_LOGICALLY_PUBLISHED ||
				to == EUNION_SIDECAR_PHASE_FORWARD_RECOVERY ||
				to == EUNION_SIDECAR_PHASE_RECOVERY_DELEGATED
					? 0 : -EINVAL;
		case EUNION_SIDECAR_PHASE_LOGICALLY_PUBLISHED:
			return to == EUNION_SIDECAR_PHASE_DURABLE ||
				to == EUNION_SIDECAR_PHASE_FORWARD_RECOVERY ||
				to == EUNION_SIDECAR_PHASE_RECOVERY_DELEGATED
					? 0 : -EINVAL;
		default:
			return eunion_sidecar_transition_allowed(from, to);
	}
}

enum eunion_sidecar_recovery_action eunion_sidecar_plan_operation_recovery(
	enum eunion_sidecar_operation operation,
	enum eunion_sidecar_journal_phase journal,
	enum eunion_sidecar_stable_state stable,
	enum eunion_sidecar_backing_state backing)
{
	if (operation < EUNION_SIDECAR_OPERATION_REMOVE ||
		operation >= EUNION_SIDECAR_OPERATION_INVALID ||
		journal < EUNION_SIDECAR_JOURNAL_ABSENT ||
		journal >= EUNION_SIDECAR_JOURNAL_INVALID ||
		stable < EUNION_SIDECAR_STABLE_OLD ||
		stable >= EUNION_SIDECAR_STABLE_INVALID ||
		backing < EUNION_SIDECAR_BACKING_OLD ||
		backing >= EUNION_SIDECAR_BACKING_INVALID)
		return EUNION_SIDECAR_RECOVERY_INVALID;

	if (stable == EUNION_SIDECAR_STABLE_MIXED ||
		stable == EUNION_SIDECAR_STABLE_CORRUPT ||
		backing == EUNION_SIDECAR_BACKING_REPLACEMENT ||
		backing == EUNION_SIDECAR_BACKING_CORRUPT)
		return EUNION_SIDECAR_RECOVERY_CORRUPTION;

	int backing_first =
		operation == EUNION_SIDECAR_OPERATION_CREATE ||
		operation == EUNION_SIDECAR_OPERATION_COPY_UP ||
		operation == EUNION_SIDECAR_OPERATION_RENAME ||
		operation == EUNION_SIDECAR_OPERATION_PREFIX_RECREATE;

	switch (journal)
	{
		case EUNION_SIDECAR_JOURNAL_ABSENT:
			if ((stable == EUNION_SIDECAR_STABLE_OLD &&
				 backing == EUNION_SIDECAR_BACKING_OLD) ||
				(stable == EUNION_SIDECAR_STABLE_NEW &&
				 backing == EUNION_SIDECAR_BACKING_NEW))
				return EUNION_SIDECAR_RECOVERY_QUIESCENT;
			return EUNION_SIDECAR_RECOVERY_CORRUPTION;

		case EUNION_SIDECAR_JOURNAL_PREPARED:
			if (stable == EUNION_SIDECAR_STABLE_OLD &&
				backing == EUNION_SIDECAR_BACKING_OLD)
				return EUNION_SIDECAR_RECOVERY_DISCARD_PREPARED;
			if (stable == EUNION_SIDECAR_STABLE_NEW &&
				backing == EUNION_SIDECAR_BACKING_OLD)
				return backing_first
					? EUNION_SIDECAR_RECOVERY_CORRUPTION
					: EUNION_SIDECAR_RECOVERY_ROLL_BACK;
			if (stable == EUNION_SIDECAR_STABLE_NEW &&
				backing == EUNION_SIDECAR_BACKING_NEW)
				return EUNION_SIDECAR_RECOVERY_FORWARD;
			if (stable == EUNION_SIDECAR_STABLE_OLD &&
				backing == EUNION_SIDECAR_BACKING_NEW)
				return EUNION_SIDECAR_RECOVERY_REPUBLISH_FORWARD;
			return EUNION_SIDECAR_RECOVERY_CORRUPTION;

		case EUNION_SIDECAR_JOURNAL_LOGICALLY_PUBLISHED:
			if (backing_first)
				return EUNION_SIDECAR_RECOVERY_CORRUPTION;
			if (stable == EUNION_SIDECAR_STABLE_NEW &&
				backing == EUNION_SIDECAR_BACKING_OLD)
				return EUNION_SIDECAR_RECOVERY_ROLL_BACK;
			if (stable == EUNION_SIDECAR_STABLE_NEW &&
				backing == EUNION_SIDECAR_BACKING_NEW)
				return EUNION_SIDECAR_RECOVERY_FORWARD;
			if (stable == EUNION_SIDECAR_STABLE_OLD &&
				backing == EUNION_SIDECAR_BACKING_OLD)
				return EUNION_SIDECAR_RECOVERY_DISCARD_PREPARED;
			if (stable == EUNION_SIDECAR_STABLE_OLD &&
				backing == EUNION_SIDECAR_BACKING_NEW)
				return EUNION_SIDECAR_RECOVERY_REPUBLISH_FORWARD;
			return EUNION_SIDECAR_RECOVERY_CORRUPTION;

		case EUNION_SIDECAR_JOURNAL_BACKING_COMMITTED:
		case EUNION_SIDECAR_JOURNAL_DURABLE:
			if (backing != EUNION_SIDECAR_BACKING_NEW)
				return EUNION_SIDECAR_RECOVERY_CORRUPTION;
			return stable == EUNION_SIDECAR_STABLE_NEW
				? EUNION_SIDECAR_RECOVERY_FORWARD
				: EUNION_SIDECAR_RECOVERY_REPUBLISH_FORWARD;

		case EUNION_SIDECAR_JOURNAL_INVALID:
		default:
			return EUNION_SIDECAR_RECOVERY_INVALID;
	}
}

enum eunion_sidecar_recovery_action eunion_sidecar_plan_recovery(
	enum eunion_sidecar_journal_phase journal,
	enum eunion_sidecar_stable_state stable,
	enum eunion_sidecar_backing_state backing)
{
	return eunion_sidecar_plan_operation_recovery(
		EUNION_SIDECAR_OPERATION_REMOVE, journal, stable, backing);
}
