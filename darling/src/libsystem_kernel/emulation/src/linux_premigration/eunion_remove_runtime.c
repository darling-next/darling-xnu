#ifdef TEST
#	define _GNU_SOURCE
#endif

#include <linux_premigration/eunion_remove_runtime.h>

#ifdef TEST
#	include <errno.h>
#	include <dirent.h>
#	include <fcntl.h>
#	include <stdint.h>
#	include <string.h>
#	include <sys/file.h>
#	include <sys/stat.h>
#	include <sys/syscall.h>
#	include <sys/types.h>
#	include <sys/xattr.h>
#	include <unistd.h>
#	define LINUX_SYSCALL(...) eunion_test_syscall_result(syscall(__VA_ARGS__))
#	define linux_dirent64 dirent
typedef struct stat stat_t;
#else
#	include <stdbool.h>
#	include <stddef.h>
#	include <string.h>
#	include <darling/emulation/common/base.h>
#	include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#	include <darling/emulation/conversion/duct_errno.h>
#	include <darling/emulation/conversion/dirent/getdirentries.h>
#	include <darling/emulation/conversion/stat/common.h>
typedef struct linux_stat stat_t;
#endif

#ifndef LINUX_AT_FDCWD
#define LINUX_AT_FDCWD -100
#endif
#ifndef LINUX_AT_REMOVEDIR
#define LINUX_AT_REMOVEDIR 0x200
#endif
#ifndef LINUX_AT_SYMLINK_NOFOLLOW
#define LINUX_AT_SYMLINK_NOFOLLOW 0x100
#endif
#ifndef LINUX_AT_EMPTY_PATH
#define LINUX_AT_EMPTY_PATH 0x1000
#endif
#ifndef LINUX_O_RDONLY
#define LINUX_O_RDONLY 0
#endif
#ifndef LINUX_O_WRONLY
#define LINUX_O_WRONLY 01
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
#ifndef LINUX_RENAME_NOREPLACE
#define LINUX_RENAME_NOREPLACE 1
#endif
#ifndef LINUX_RENAME_EXCHANGE
#define LINUX_RENAME_EXCHANGE 2
#endif
#ifndef LINUX_LOCK_EX
#define LINUX_LOCK_EX 2
#endif
#ifndef LINUX_LOCK_UN
#define LINUX_LOCK_UN 8
#endif
#ifndef LINUX_EAGAIN
#define LINUX_EAGAIN 11
#endif
#ifndef LINUX_EBUSY
#define LINUX_EBUSY 16
#endif
#ifndef LINUX_EEXIST
#define LINUX_EEXIST 17
#endif
#ifndef LINUX_ENOENT
#define LINUX_ENOENT 2
#endif
#ifndef LINUX_EINTR
#define LINUX_EINTR 4
#endif
#ifndef LINUX_EIO
#define LINUX_EIO 5
#endif
#ifndef LINUX_EBADF
#define LINUX_EBADF 9
#endif
#ifndef LINUX_EACCES
#define LINUX_EACCES 13
#endif
#ifndef LINUX_ENOTDIR
#define LINUX_ENOTDIR 20
#endif
#ifndef LINUX_ENOTEMPTY
#define LINUX_ENOTEMPTY 39
#endif
#ifndef LINUX_EISDIR
#define LINUX_EISDIR 21
#endif
#ifndef LINUX_EINVAL
#define LINUX_EINVAL 22
#endif
#ifndef LINUX_ENAMETOOLONG
#define LINUX_ENAMETOOLONG 36
#endif
#ifndef LINUX_ELOOP
#define LINUX_ELOOP 40
#endif
#ifndef LINUX_ENODATA
#define LINUX_ENODATA 61
#endif
#ifndef LINUX_S_IFMT
#define LINUX_S_IFMT 00170000
#endif
#ifndef LINUX_S_IFDIR
#define LINUX_S_IFDIR 0040000
#endif
#ifndef LINUX_S_IFREG
#define LINUX_S_IFREG 0100000
#endif
#ifndef LINUX_S_IFLNK
#define LINUX_S_IFLNK 0120000
#endif
#ifndef __NR_fchmodat2
#define __NR_fchmodat2 452
#endif

#define EUNION_REMOVE_PATH_MAX 4096
#define EUNION_REMOVE_NAME_MAX 255
#define EUNION_REMOVE_COMPONENT_MAX 64

enum eunion_remove_phase {
	EUNION_REMOVE_PHASE_EMPTY = 0,
	EUNION_REMOVE_PHASE_RESOLVED,
	EUNION_REMOVE_PHASE_REVALIDATED,
	EUNION_REMOVE_PHASE_PREPARED,
	EUNION_REMOVE_PHASE_APPLIED,
	EUNION_REMOVE_PHASE_COMMITTED,
	EUNION_REMOVE_PHASE_RELEASED,
};

enum eunion_identity_tag {
	EUNION_IDENTITY_ABSENT = 0,
	EUNION_IDENTITY_PRESENT,
	EUNION_IDENTITY_WHITEOUT,
	EUNION_IDENTITY_OPAQUE,
	EUNION_IDENTITY_INVALID,
};

struct eunion_inode_identity {
	enum eunion_identity_tag tag;
	unsigned long long device;
	unsigned long long inode;
	unsigned int mode;
};

struct eunion_directory_chain {
	int count;
	int descriptor[EUNION_REMOVE_COMPONENT_MAX + 1];
	char name[EUNION_REMOVE_COMPONENT_MAX][EUNION_REMOVE_NAME_MAX + 1];
	struct eunion_inode_identity identity[EUNION_REMOVE_COMPONENT_MAX + 1];
};

struct eunion_readable_directory {
	int descriptor;
	int pinned_descriptor;
	unsigned int original_mode;
	int permission_lifted;
};

struct eunion_remove_capability_storage {
	enum eunion_remove_phase phase;
	const struct eunion_remove_runtime* runtime;
	enum eunion_operation_intent intent;
	struct eunion_resolved_remove_state resolved;
	struct eunion_remove_plan plan;
	struct eunion_directory_chain upper;
	struct eunion_directory_chain lower;
	int parent_component_count;
	int upper_parent_complete;
	int lower_parent_complete;
	int lower_hidden_by_opaque_ancestor;
	int upper_ancestor_opacity_unknown;
	unsigned char created_upper_parent[EUNION_REMOVE_COMPONENT_MAX];
	struct eunion_inode_identity upper_leaf;
	struct eunion_inode_identity lower_leaf;
	struct eunion_inode_identity staged_whiteout;
	char guest_path[EUNION_REMOVE_PATH_MAX];
	char parent_path[EUNION_REMOVE_PATH_MAX];
	char leaf[EUNION_REMOVE_NAME_MAX + 1];
	char stage_name[EUNION_REMOVE_NAME_MAX + 1];
	char tomb_name[EUNION_REMOVE_NAME_MAX + 1];
	int work_descriptor;
	int tomb_descriptor;
	int tomb_contains_originals;
	int lock_held;
	int applied_kind;
};

// Arrays cannot be directly assigned or initialized from one another in C.
// This representation is assignment-resistant; runtime phase checks remain the
// authoritative ownership/typestate enforcement.
typedef struct eunion_remove_capability_storage eunion_remove_capability[1];

static unsigned long eunion_remove_sequence;

#ifdef TEST
static int eunion_test_syscall_result(long result)
{
	return result == -1 ? -errno : (int)result;
}
#endif

#ifdef TEST
int eunion_test_remove_fail_checkpoint;
int eunion_test_remove_interrupt_checkpoint;
int eunion_test_remove_fail_fsync_ordinal;
int eunion_test_remove_fsync_count;
int eunion_test_remove_fail_tomb_move_ordinal;
int eunion_test_remove_tomb_move_count;
void (*eunion_test_remove_checkpoint_hook)(
	enum eunion_remove_test_checkpoint checkpoint,
	const char* guest_path
);
#endif

static int eunion_fsync(int descriptor)
{
#ifdef TEST
	++eunion_test_remove_fsync_count;
	if (eunion_test_remove_fail_fsync_ordinal ==
		eunion_test_remove_fsync_count)
		return -LINUX_EIO;
#endif
	return LINUX_SYSCALL(__NR_fsync, descriptor);
}

static int eunion_fsync_directory(eunion_remove_capability capability,
	int descriptor)
{
	int result = eunion_fsync(descriptor);
#if defined(__NR_syncfs)
	if (result == -LINUX_EBADF &&
		descriptor != capability->upper.descriptor[0])
		result = LINUX_SYSCALL(__NR_syncfs,
			capability->upper.descriptor[0]);
#endif
	return result;
}

static struct eunion_inode_identity eunion_absent_identity(void)
{
	return (struct eunion_inode_identity) {
		.tag = EUNION_IDENTITY_ABSENT,
	};
}

static int eunion_identity_equal(const struct eunion_inode_identity* left,
	const struct eunion_inode_identity* right)
{
	return left->tag == right->tag &&
		left->device == right->device &&
		left->inode == right->inode &&
		left->mode == right->mode;
}

static int eunion_same_object(const struct eunion_inode_identity* left,
	const struct eunion_inode_identity* right)
{
	return left->tag != EUNION_IDENTITY_ABSENT &&
		right->tag != EUNION_IDENTITY_ABSENT &&
		left->device == right->device &&
		left->inode == right->inode &&
		left->mode == right->mode;
}

static enum eunion_node_kind eunion_node_kind(unsigned int mode)
{
	switch (mode & LINUX_S_IFMT)
	{
		case LINUX_S_IFREG:
			return EUNION_NODE_REGULAR;
		case LINUX_S_IFDIR:
			return EUNION_NODE_DIRECTORY;
		case LINUX_S_IFLNK:
			return EUNION_NODE_SYMLINK;
		default:
			return EUNION_NODE_OTHER;
	}
}

static int eunion_fstat_identity(int descriptor,
	struct eunion_inode_identity* identity)
{
	stat_t status;
	int result = LINUX_SYSCALL(__NR_fstat, descriptor, &status);
	if (result < 0)
		return result;
	*identity = (struct eunion_inode_identity) {
		.tag = EUNION_IDENTITY_PRESENT,
		.device = (unsigned long long)status.st_dev,
		.inode = (unsigned long long)status.st_ino,
		.mode = (unsigned int)status.st_mode,
	};
	return 0;
}

static int eunion_fstatat_identity(int parent, const char* name,
	struct eunion_inode_identity* identity)
{
	stat_t status;
	int result;
#if defined(__NR_newfstatat)
	result = LINUX_SYSCALL(__NR_newfstatat, parent, name, &status,
		LINUX_AT_SYMLINK_NOFOLLOW);
#else
	result = LINUX_SYSCALL(__NR_fstatat64, parent, name, &status,
		LINUX_AT_SYMLINK_NOFOLLOW);
#endif
	if (result == -LINUX_ENOENT)
	{
		*identity = eunion_absent_identity();
		return 0;
	}
	if (result < 0)
		return result;
	*identity = (struct eunion_inode_identity) {
		.tag = EUNION_IDENTITY_PRESENT,
		.device = (unsigned long long)status.st_dev,
		.inode = (unsigned long long)status.st_ino,
		.mode = (unsigned int)status.st_mode,
	};
	return 0;
}

static int eunion_marker_descriptor(int descriptor, const char* marker)
{
	char value[2];
	int result = LINUX_SYSCALL(__NR_fgetxattr, descriptor, marker,
		value, sizeof(value));
	if (result == -LINUX_ENODATA)
		result = 0;
	else if (result >= 0)
		result = result > 0 && value[0] == 'y';
	return result;
}

static void eunion_readable_directory_init(
	struct eunion_readable_directory* directory)
{
	directory->descriptor = -1;
	directory->pinned_descriptor = -1;
	directory->original_mode = 0;
	directory->permission_lifted = 0;
}

static int eunion_close_readable_directory(
	struct eunion_readable_directory* directory);

static int eunion_open_directory_readable_at(int parent, const char* name,
	const struct eunion_inode_identity* expected,
	unsigned int required_permissions,
	struct eunion_readable_directory* directory)
{
	eunion_readable_directory_init(directory);
	int descriptor = LINUX_SYSCALL(__NR_openat, parent, name,
		LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
		LINUX_O_CLOEXEC, 0);
	if (descriptor == -LINUX_EACCES && required_permissions != 0)
	{
		int lifted = 0;
		int pinned = LINUX_SYSCALL(__NR_openat, parent, name,
			LINUX_O_PATH | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
			LINUX_O_CLOEXEC, 0);
		if (pinned < 0)
			return pinned;
		struct eunion_inode_identity pinned_identity =
			eunion_absent_identity();
		int result = eunion_fstat_identity(pinned, &pinned_identity);
		if (result >= 0 && expected &&
			!eunion_same_object(&pinned_identity, expected))
			result = -LINUX_EAGAIN;
		if (result >= 0)
		{
			unsigned int relaxed_mode =
				(pinned_identity.mode & 07777) | required_permissions;
			if ((pinned_identity.mode & required_permissions) ==
				required_permissions)
				result = -LINUX_EACCES;
			else
				result = LINUX_SYSCALL(__NR_fchmodat2, pinned, "",
					relaxed_mode, LINUX_AT_EMPTY_PATH);
			if (result >= 0)
				lifted = 1;
		}
		if (result >= 0)
		{
			descriptor = LINUX_SYSCALL(__NR_openat, pinned, ".",
				LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_CLOEXEC, 0);
			result = descriptor;
		}
		if (result < 0)
		{
			if (descriptor >= 0)
				LINUX_SYSCALL(__NR_close, descriptor);
			if (lifted)
				LINUX_SYSCALL(__NR_fchmodat2, pinned, "",
					pinned_identity.mode & 07777, LINUX_AT_EMPTY_PATH);
			LINUX_SYSCALL(__NR_close, pinned);
			return result;
		}
		directory->pinned_descriptor = pinned;
		directory->original_mode = pinned_identity.mode;
		directory->permission_lifted = lifted;
	}
	if (descriptor < 0)
		return descriptor;
	if (expected)
	{
		struct eunion_inode_identity observed;
		int result = eunion_fstat_identity(descriptor, &observed);
		if (result >= 0 && directory->permission_lifted)
			observed.mode = (observed.mode & ~07777U) |
				(directory->original_mode & 07777);
		if (result >= 0 && !eunion_same_object(&observed, expected))
			result = -LINUX_EAGAIN;
		if (result < 0)
		{
			if (directory->descriptor < 0)
				directory->descriptor = descriptor;
			eunion_close_readable_directory(directory);
			return result;
		}
	}
	directory->descriptor = descriptor;
	return 0;
}

static int eunion_close_readable_directory(
	struct eunion_readable_directory* directory)
{
	int result = 0;
	if (directory->permission_lifted)
	{
		result = LINUX_SYSCALL(__NR_fchmodat2,
			directory->pinned_descriptor, "",
			directory->original_mode & 07777, LINUX_AT_EMPTY_PATH);
		directory->permission_lifted = 0;
	}
	if (directory->descriptor >= 0)
	{
		int close_result =
			LINUX_SYSCALL(__NR_close, directory->descriptor);
		if (result >= 0 && close_result < 0)
			result = close_result;
		directory->descriptor = -1;
	}
	if (directory->pinned_descriptor >= 0)
	{
		int close_result =
			LINUX_SYSCALL(__NR_close, directory->pinned_descriptor);
		if (result >= 0 && close_result < 0)
			result = close_result;
		directory->pinned_descriptor = -1;
	}
	return result;
}

static int eunion_marker_at(int parent, const char* name,
	const char* marker, const struct eunion_inode_identity* identity)
{
	int descriptor = LINUX_SYSCALL(__NR_openat, parent, name,
		LINUX_O_RDONLY | LINUX_O_NOFOLLOW | LINUX_O_CLOEXEC, 0);
	struct eunion_readable_directory directory;
	eunion_readable_directory_init(&directory);
	if (descriptor == -LINUX_EACCES && identity &&
		eunion_node_kind(identity->mode) == EUNION_NODE_DIRECTORY)
	{
		int result = eunion_open_directory_readable_at(parent, name,
			identity, 0500, &directory);
		if (result < 0)
			return result;
		descriptor = directory.descriptor;
	}
	if (descriptor == -LINUX_ELOOP)
		return 0;
	// Marker files created by this implementation are regular mode 0600
	// objects. A noncanonical unreadable regular file is still a guest object:
	// unlink permission is governed by its parent, not by read permission on
	// the leaf. Canonical-looking unreadable markers remain fail-closed.
	if (descriptor == -LINUX_EACCES && identity &&
		eunion_node_kind(identity->mode) == EUNION_NODE_REGULAR &&
		(identity->mode & 0777) != 0600)
		return 0;
	if (descriptor < 0)
		return descriptor;
	int result = eunion_marker_descriptor(descriptor, marker);
	int close_result;
	if (directory.descriptor >= 0)
		close_result = eunion_close_readable_directory(&directory);
	else
		close_result = LINUX_SYSCALL(__NR_close, descriptor);
	if (result >= 0 && close_result < 0)
		return close_result;
	return result;
}

static void eunion_close_chain(struct eunion_directory_chain* chain)
{
	for (int index = chain->count - 1; index >= 0; --index)
	{
		if (chain->descriptor[index] >= 0)
			LINUX_SYSCALL(__NR_close, chain->descriptor[index]);
		chain->descriptor[index] = -1;
	}
	chain->count = 0;
}

static int eunion_open_absolute_root(const char* path)
{
	char component[EUNION_REMOVE_NAME_MAX + 1];
	const char* cursor;
	int current;

	if (!path || path[0] != '/')
		return -LINUX_EINVAL;
	current = LINUX_SYSCALL(__NR_openat, LINUX_AT_FDCWD, "/",
		LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
		LINUX_O_CLOEXEC, 0);
	if (current < 0)
		return current;
	cursor = path;
	while (*cursor == '/')
		++cursor;
	while (*cursor)
	{
		int length = 0;
		while (cursor[length] && cursor[length] != '/')
			++length;
		if (length <= 0 || length > EUNION_REMOVE_NAME_MAX ||
			(length == 1 && cursor[0] == '.') ||
			(length == 2 && cursor[0] == '.' && cursor[1] == '.'))
		{
			LINUX_SYSCALL(__NR_close, current);
			return length > EUNION_REMOVE_NAME_MAX
				? -LINUX_ENAMETOOLONG : -LINUX_EINVAL;
		}
		memcpy(component, cursor, (size_t)length);
		component[length] = '\0';
		int next = LINUX_SYSCALL(__NR_openat, current, component,
			LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
			LINUX_O_CLOEXEC, 0);
		if (next < 0)
		{
			LINUX_SYSCALL(__NR_close, current);
			return next;
		}
		LINUX_SYSCALL(__NR_close, current);
		current = next;
		cursor += length;
		while (*cursor == '/')
			++cursor;
	}
	return current;
}

static int eunion_revalidate_absolute_root(const char* path,
	const struct eunion_inode_identity* expected)
{
	int descriptor = eunion_open_absolute_root(path);
	if (descriptor < 0)
		return descriptor;
	struct eunion_inode_identity observed;
	int result = eunion_fstat_identity(descriptor, &observed);
	int close_result = LINUX_SYSCALL(__NR_close, descriptor);
	if (result >= 0 && !eunion_identity_equal(&observed, expected))
		result = -LINUX_EAGAIN;
	if (result >= 0 && close_result < 0)
		result = close_result;
	return result;
}

static int eunion_split_guest(eunion_remove_capability capability,
	const char* guest)
{
	int length;
	int leaf_start;

	if (!guest || guest[0] != '/')
		return -LINUX_EINVAL;
	length = (int)strlen(guest);
	if (length <= 1 || length >= EUNION_REMOVE_PATH_MAX)
		return length <= 1 ? -LINUX_EBUSY : -LINUX_ENAMETOOLONG;
	while (length > 1 && guest[length - 1] == '/')
		--length;
	leaf_start = length - 1;
	while (leaf_start > 0 && guest[leaf_start - 1] != '/')
		--leaf_start;
	int leaf_length = length - leaf_start;
	if (leaf_length <= 0 || leaf_length > EUNION_REMOVE_NAME_MAX)
		return -LINUX_ENAMETOOLONG;
	if ((leaf_length == 1 && guest[leaf_start] == '.') ||
		(leaf_length == 2 && guest[leaf_start] == '.' &&
			guest[leaf_start + 1] == '.'))
		return -LINUX_EINVAL;

	memcpy(capability->guest_path, guest, (size_t)length);
	capability->guest_path[length] = '\0';
	memcpy(capability->leaf, guest + leaf_start, (size_t)leaf_length);
	capability->leaf[leaf_length] = '\0';
	if (leaf_start <= 1)
	{
		capability->parent_path[0] = '/';
		capability->parent_path[1] = '\0';
	}
	else
	{
		memcpy(capability->parent_path, guest, (size_t)(leaf_start - 1));
		capability->parent_path[leaf_start - 1] = '\0';
	}
	const char* cursor = capability->parent_path;
	while (*cursor == '/')
		++cursor;
	while (*cursor)
	{
		++capability->parent_component_count;
		while (*cursor && *cursor != '/')
			++cursor;
		while (*cursor == '/')
			++cursor;
	}
	if (capability->parent_component_count > EUNION_REMOVE_COMPONENT_MAX)
		return -LINUX_ENAMETOOLONG;
	return 0;
}

static int eunion_chain_start(struct eunion_directory_chain* chain,
	const char* root)
{
	int descriptor = eunion_open_absolute_root(root);
	if (descriptor < 0)
		return descriptor;
	chain->count = 1;
	chain->descriptor[0] = descriptor;
	return eunion_fstat_identity(descriptor, &chain->identity[0]);
}

static int eunion_chain_append(struct eunion_directory_chain* chain,
	const char* component)
{
	int current;
	int next;

	if (chain->count <= 0 || chain->count > EUNION_REMOVE_COMPONENT_MAX)
		return -LINUX_ENAMETOOLONG;
	current = chain->descriptor[chain->count - 1];
	next = LINUX_SYSCALL(__NR_openat, current, component,
		LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
		LINUX_O_CLOEXEC, 0);
	if (next == -LINUX_EACCES)
		next = LINUX_SYSCALL(__NR_openat, current, component,
			LINUX_O_PATH | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
			LINUX_O_CLOEXEC, 0);
	if (next < 0)
		return next;
	strcpy(chain->name[chain->count - 1], component);
	chain->descriptor[chain->count] = next;
	int result = eunion_fstat_identity(next, &chain->identity[chain->count]);
	if (result < 0)
	{
		LINUX_SYSCALL(__NR_close, next);
		chain->descriptor[chain->count] = -1;
		return result;
	}
	++chain->count;
	return 0;
}

static int eunion_open_parent_chains(eunion_remove_capability capability,
	int create_upper)
{
	char component[EUNION_REMOVE_NAME_MAX + 1];
	const char* cursor = capability->parent_path;
	int upper_available = capability->upper.count > 0;
	int lower_available = capability->lower.count > 0;

	while (*cursor == '/')
		++cursor;
	while (*cursor)
	{
		int length = 0;
		while (cursor[length] && cursor[length] != '/')
			++length;
		if (length <= 0 || length > EUNION_REMOVE_NAME_MAX ||
			(length == 1 && cursor[0] == '.') ||
			(length == 2 && cursor[0] == '.' && cursor[1] == '.'))
			return length > EUNION_REMOVE_NAME_MAX
				? -LINUX_ENAMETOOLONG : -LINUX_EINVAL;
		memcpy(component, cursor, (size_t)length);
		component[length] = '\0';

		if (lower_available)
		{
			int result = eunion_chain_append(&capability->lower, component);
			if (result == -LINUX_ENOENT)
				lower_available = 0;
			else if (result < 0)
				return result;
		}
		if (upper_available)
		{
			int result = eunion_chain_append(&capability->upper, component);
			if (result == -LINUX_ENOENT && create_upper)
			{
				if (!lower_available)
					return -LINUX_ENOENT;
				struct eunion_inode_identity* lower =
					&capability->lower.identity[capability->lower.count - 1];
				if (eunion_node_kind(lower->mode) != EUNION_NODE_DIRECTORY)
					return -LINUX_ENOTDIR;
				int upper_parent =
					capability->upper.descriptor[capability->upper.count - 1];
				result = LINUX_SYSCALL(__NR_mkdirat, upper_parent,
					component, lower->mode & 07777);
				if (result < 0 && result != -LINUX_EEXIST)
					return result;
				if (result == 0)
				{
					result = LINUX_SYSCALL(__NR_fchmodat, upper_parent,
						component, lower->mode & 0777);
					if (result < 0)
						return result;
				}
				if (eunion_fsync_directory(capability, upper_parent) < 0)
					return -LINUX_EIO;
				result = eunion_chain_append(&capability->upper, component);
			}
			if (result == -LINUX_ENOENT)
				upper_available = 0;
			else if (result < 0)
				return result;
			else if (lower_available)
			{
				int opaque = eunion_marker_descriptor(
					capability->upper.descriptor[
						capability->upper.count - 1],
					"user.union.opaque");
				if (opaque == -LINUX_EBADF)
				{
					// O_PATH is intentionally used when the guest grants
					// search but not read permission. Do not mutate a retained
					// ancestor merely to inspect its xattrs. The leaf resolver
					// may proceed only when lower visibility cannot affect the
					// selected remove action.
					capability->upper_ancestor_opacity_unknown = 1;
					opaque = 0;
				}
				if (opaque < 0)
					return opaque;
				if (opaque)
				{
					lower_available = 0;
					capability->lower_hidden_by_opaque_ancestor = 1;
				}
			}
		}
		cursor += length;
		while (*cursor == '/')
			++cursor;
	}
	capability->upper_parent_complete =
		capability->upper.count == capability->parent_component_count + 1;
	capability->lower_parent_complete =
		!capability->lower_hidden_by_opaque_ancestor &&
		capability->lower.count == capability->parent_component_count + 1;
	return 0;
}

static int eunion_copy_parent_xattrs(int lower, int upper)
{
#if defined(__NR_flistxattr) && defined(__NR_fgetxattr) && \
	defined(__NR_fsetxattr)
	char names[4096];
	char value[4096];
	int length = LINUX_SYSCALL(__NR_flistxattr, lower, names,
		sizeof(names));
	if (length < 0)
		return length;
	int offset = 0;
	while (offset < length)
	{
		const char* name = names + offset;
		int name_length = (int)strlen(name);
		if (name_length <= 0 || offset + name_length >= length)
			return -LINUX_EIO;
		offset += name_length + 1;
		// Directory materialization follows the existing copy-up security
		// contract: metadata is preserved, but privilege-bearing capabilities
		// and private union markers are never imported from the lower layer.
		if (strcmp(name, "security.capability") == 0 ||
			strncmp(name, "user.union.", 11) == 0)
			continue;
		int value_length = LINUX_SYSCALL(__NR_fgetxattr, lower, name,
			value, sizeof(value));
		if (value_length < 0)
			return value_length;
		int result = LINUX_SYSCALL(__NR_fsetxattr, upper, name, value,
			value_length, 0);
		if (result < 0)
			return result;
	}
#else
	(void)lower;
	(void)upper;
#endif
	return 0;
}

static int eunion_copy_parent_metadata(int lower, int upper)
{
	stat_t lower_status;
	stat_t upper_status;
	int result = LINUX_SYSCALL(__NR_fstat, lower, &lower_status);
	if (result < 0)
		return result;
	result = LINUX_SYSCALL(__NR_fstat, upper, &upper_status);
	if (result < 0)
		return result;
#if defined(__NR_fchown)
	if ((unsigned int)upper_status.st_uid !=
			(unsigned int)lower_status.st_uid ||
		(unsigned int)upper_status.st_gid !=
			(unsigned int)lower_status.st_gid)
	{
		result = LINUX_SYSCALL(__NR_fchown, upper,
			(unsigned int)lower_status.st_uid,
			(unsigned int)lower_status.st_gid);
		if (result < 0)
			return result;
	}
#endif
	// Match the established copy-up security contract: preserve ordinary
	// permission bits exactly and never manufacture setid authority.
	result = LINUX_SYSCALL(__NR_fchmod, upper,
		(unsigned int)lower_status.st_mode & 0777);
	if (result < 0)
		return result;
	result = eunion_copy_parent_xattrs(lower, upper);
	if (result < 0)
		return result;
	return eunion_fsync(upper);
}

static int eunion_materialize_upper_parent_chain(
	eunion_remove_capability capability)
{
	if (!capability->lower_parent_complete)
		return -LINUX_ENOENT;
	eunion_close_chain(&capability->upper);
	int result = eunion_chain_start(&capability->upper,
		capability->runtime->upper_root);
	if (result < 0)
		return result;
	for (int index = 0; index < capability->parent_component_count; ++index)
	{
		const char* component = capability->lower.name[index];
		const struct eunion_inode_identity* lower =
			&capability->lower.identity[index + 1];
		if (eunion_node_kind(lower->mode) != EUNION_NODE_DIRECTORY)
			return -LINUX_ENOTDIR;
		result = eunion_chain_append(&capability->upper, component);
		if (result == -LINUX_ENOENT)
		{
			int upper_parent =
				capability->upper.descriptor[capability->upper.count - 1];
			result = LINUX_SYSCALL(__NR_mkdirat, upper_parent, component,
				lower->mode & 07777);
			int created = result == 0;
			if (result < 0 && result != -LINUX_EEXIST)
				return result;
			if (created)
			{
				result = LINUX_SYSCALL(__NR_fchmodat, upper_parent,
					component, lower->mode & 0777);
				if (result < 0)
					return result;
			}
			if (created)
			{
				capability->created_upper_parent[index] = 1;
				strcpy(capability->upper.name[index], component);
			}
			result = eunion_chain_append(&capability->upper, component);
			if (result < 0)
				return result;
			if (created)
			{
				result = eunion_copy_parent_metadata(
					capability->lower.descriptor[index + 1],
					capability->upper.descriptor[index + 1]);
				if (result < 0)
					return result;
				result = eunion_fstat_identity(
					capability->upper.descriptor[index + 1],
					&capability->upper.identity[index + 1]);
				if (result < 0)
					return result;
			}
			result = eunion_fsync_directory(capability, upper_parent);
		}
		if (result < 0)
			return result;
	}
	capability->upper_parent_complete = 1;
	return 0;
}

static int eunion_revalidate_chain(const struct eunion_directory_chain* chain)
{
	for (int index = 0; index < chain->count; ++index)
	{
		struct eunion_inode_identity descriptor_identity;
		int result = eunion_fstat_identity(chain->descriptor[index],
			&descriptor_identity);
		if (result < 0)
			return result;
		if (!eunion_identity_equal(&descriptor_identity, &chain->identity[index]))
			return -LINUX_EAGAIN;
		if (index > 0)
		{
			struct eunion_inode_identity named_identity;
			result = eunion_fstatat_identity(chain->descriptor[index - 1],
				chain->name[index - 1], &named_identity);
			if (result < 0)
				return result;
			if (!eunion_identity_equal(&named_identity, &chain->identity[index]))
				return -LINUX_EAGAIN;
			if (eunion_node_kind(named_identity.mode) != EUNION_NODE_DIRECTORY)
				return -LINUX_ENOTDIR;
		}
	}
	return 0;
}

static int eunion_read_leaf(int parent, const char* leaf,
	const char* whiteout_marker, int allow_unreadable_directory,
	struct eunion_inode_identity* identity)
{
	int result;
	int whiteout;
	int opaque;

	if (parent < 0)
	{
		*identity = eunion_absent_identity();
		return 0;
	}
	result = eunion_fstatat_identity(parent, leaf, identity);
	if (result < 0 || identity->tag == EUNION_IDENTITY_ABSENT)
		return result;
	enum eunion_node_kind kind = eunion_node_kind(identity->mode);
	if (kind != EUNION_NODE_REGULAR && kind != EUNION_NODE_DIRECTORY)
		return 0;
	whiteout = eunion_marker_at(parent, leaf, whiteout_marker, identity);
	if (whiteout == -LINUX_EACCES && allow_unreadable_directory &&
		kind == EUNION_NODE_DIRECTORY)
		whiteout = 0;
	if (whiteout < 0)
		return whiteout;
	opaque = eunion_marker_at(parent, leaf, "user.union.opaque", identity);
	if (opaque == -LINUX_EACCES && allow_unreadable_directory &&
		kind == EUNION_NODE_DIRECTORY)
		opaque = 0;
	if (opaque < 0)
		return opaque;
	if (whiteout && opaque)
		identity->tag = EUNION_IDENTITY_INVALID;
	else if (whiteout)
		identity->tag = (eunion_node_kind(identity->mode) == EUNION_NODE_REGULAR)
			? EUNION_IDENTITY_WHITEOUT : EUNION_IDENTITY_INVALID;
	else if (opaque)
		identity->tag = (eunion_node_kind(identity->mode) == EUNION_NODE_DIRECTORY)
			? EUNION_IDENTITY_OPAQUE : EUNION_IDENTITY_INVALID;
	return 0;
}

static int eunion_open_leaf_directory(int parent, const char* leaf,
	const struct eunion_inode_identity* identity,
	unsigned int required_permissions,
	struct eunion_readable_directory* directory)
{
	if (parent < 0)
		return -LINUX_ENOENT;
	return eunion_open_directory_readable_at(parent, leaf, identity,
		required_permissions, directory);
}

static int eunion_next_directory_entry(int descriptor, char* buffer,
	int capacity, int* length, int* offset, const char** name)
{
	for (;;)
	{
		if (*offset >= *length)
		{
			*length = LINUX_SYSCALL(__NR_getdents64, descriptor, buffer,
				capacity);
			*offset = 0;
			if (*length <= 0)
				return *length;
		}
		struct linux_dirent64* entry =
			(struct linux_dirent64*)(buffer + *offset);
		if (entry->d_reclen == 0 ||
			*offset + entry->d_reclen > *length)
			return -LINUX_EIO;
		*offset += entry->d_reclen;
		if (entry->d_name[0] == '.' &&
			(entry->d_name[1] == '\0' ||
			 (entry->d_name[1] == '.' && entry->d_name[2] == '\0')))
			continue;
		*name = entry->d_name;
		return 1;
	}
}

static int eunion_upper_directory_nonempty(int upper,
	const char* whiteout_marker, int* nonempty)
{
	char buffer[4096];
	int length = 0;
	int offset = 0;
	const char* name;
	int result;
	while ((result = eunion_next_directory_entry(upper, buffer,
		sizeof(buffer), &length, &offset, &name)) > 0)
	{
		struct eunion_inode_identity identity;
		result = eunion_fstatat_identity(upper, name, &identity);
		if (result < 0)
			return result;
		int whiteout = eunion_marker_at(upper, name, whiteout_marker,
			&identity);
		if (whiteout < 0)
			return whiteout;
		if (!whiteout)
		{
			*nonempty = 1;
			return 0;
		}
	}
	return result;
}

static int eunion_lower_directory_nonempty(int lower, int upper,
	const char* whiteout_marker, int* nonempty)
{
	char buffer[4096];
	int length = 0;
	int offset = 0;
	const char* name;
	int result;
	while ((result = eunion_next_directory_entry(lower, buffer,
		sizeof(buffer), &length, &offset, &name)) > 0)
	{
		if (upper >= 0)
		{
			struct eunion_inode_identity upper_identity;
			result = eunion_fstatat_identity(upper, name, &upper_identity);
			if (result < 0)
				return result;
			if (upper_identity.tag != EUNION_IDENTITY_ABSENT)
			{
				int whiteout = eunion_marker_at(upper, name,
					whiteout_marker, &upper_identity);
				if (whiteout < 0)
					return whiteout;
				if (whiteout)
					continue;
			}
		}
		*nonempty = 1;
		return 0;
	}
	return result;
}

static int eunion_resolve_directory_view(eunion_remove_capability capability)
{
	if (capability->resolved.visible_kind != EUNION_NODE_DIRECTORY)
	{
		capability->resolved.directory_view =
			EUNION_DIRECTORY_NOT_APPLICABLE;
		return 0;
	}
	int upper_parent = capability->upper_parent_complete
		? capability->upper.descriptor[capability->upper.count - 1] : -1;
	int lower_parent = capability->lower_parent_complete
		? capability->lower.descriptor[capability->lower.count - 1] : -1;
	struct eunion_readable_directory upper;
	struct eunion_readable_directory lower;
	eunion_readable_directory_init(&upper);
	eunion_readable_directory_init(&lower);
	int result = 0;
	int nonempty = 0;

	if ((capability->upper_leaf.tag == EUNION_IDENTITY_PRESENT ||
		 capability->upper_leaf.tag == EUNION_IDENTITY_OPAQUE) &&
		eunion_node_kind(capability->upper_leaf.mode) == EUNION_NODE_DIRECTORY)
	{
		result = eunion_open_leaf_directory(upper_parent, capability->leaf,
			&capability->upper_leaf, 0500, &upper);
		if (result < 0)
			return result;
		else
		{
		result = eunion_upper_directory_nonempty(upper.descriptor,
			capability->runtime->whiteout_marker, &nonempty);
		if (result < 0 || nonempty)
			goto done;
		}
	}
	if (capability->upper_leaf.tag != EUNION_IDENTITY_OPAQUE &&
		capability->lower_leaf.tag == EUNION_IDENTITY_PRESENT &&
		eunion_node_kind(capability->lower_leaf.mode) == EUNION_NODE_DIRECTORY)
	{
		result = eunion_open_leaf_directory(lower_parent, capability->leaf,
			&capability->lower_leaf, 0, &lower);
		if (result < 0)
		{
			goto done;
		}
		result = eunion_lower_directory_nonempty(lower.descriptor,
			upper.descriptor,
			capability->runtime->whiteout_marker, &nonempty);
	}
done:
	if (lower.descriptor >= 0)
	{
		int close_result = eunion_close_readable_directory(&lower);
		if (result >= 0 && close_result < 0)
			result = close_result;
	}
	if (upper.descriptor >= 0)
	{
		int close_result = eunion_close_readable_directory(&upper);
		if (result >= 0 && close_result < 0)
			result = close_result;
	}
	if (result < 0)
		return result;
	capability->resolved.directory_view = nonempty
		? EUNION_DIRECTORY_NONEMPTY : EUNION_DIRECTORY_EMPTY;
	return 0;
}

static int eunion_resolve_capability(eunion_remove_capability capability)
{
	int upper_parent = capability->upper_parent_complete
		? capability->upper.descriptor[capability->upper.count - 1] : -1;
	int lower_parent = capability->lower_parent_complete
		? capability->lower.descriptor[capability->lower.count - 1] : -1;
	int result = eunion_read_leaf(lower_parent, capability->leaf,
		capability->runtime->whiteout_marker, 0,
		&capability->lower_leaf);
	if (result < 0)
		return result;
	result = eunion_read_leaf(upper_parent, capability->leaf,
		capability->runtime->whiteout_marker,
		capability->lower_leaf.tag == EUNION_IDENTITY_ABSENT,
		&capability->upper_leaf);
	if (result < 0)
		return result;
	if (capability->upper_ancestor_opacity_unknown &&
		capability->lower_leaf.tag == EUNION_IDENTITY_PRESENT &&
		(capability->upper_leaf.tag == EUNION_IDENTITY_PRESENT ||
		 capability->upper_leaf.tag == EUNION_IDENTITY_ABSENT))
		return -LINUX_EACCES;

	if (capability->upper_leaf.tag == EUNION_IDENTITY_INVALID ||
		capability->lower_leaf.tag == EUNION_IDENTITY_INVALID ||
		capability->lower_leaf.tag == EUNION_IDENTITY_WHITEOUT ||
		capability->lower_leaf.tag == EUNION_IDENTITY_OPAQUE)
	{
		capability->resolved = (struct eunion_resolved_remove_state) {
			.presence = EUNION_PRESENCE_INVALID,
			.visible_kind = EUNION_NODE_NONE,
		};
	}
	else if (capability->upper_leaf.tag == EUNION_IDENTITY_WHITEOUT)
	{
		capability->resolved = (struct eunion_resolved_remove_state) {
			.presence = EUNION_PRESENCE_WHITEOUTED,
			.visible_kind = EUNION_NODE_NONE,
		};
	}
	else if (capability->upper_leaf.tag == EUNION_IDENTITY_OPAQUE)
	{
		capability->resolved = (struct eunion_resolved_remove_state) {
			.presence = EUNION_PRESENCE_OPAQUE_DIRECTORY,
			.visible_kind = EUNION_NODE_DIRECTORY,
		};
	}
	else if (capability->upper_leaf.tag == EUNION_IDENTITY_PRESENT &&
		capability->lower_leaf.tag == EUNION_IDENTITY_PRESENT)
	{
		capability->resolved = (struct eunion_resolved_remove_state) {
			.presence = EUNION_PRESENCE_MERGED,
			.visible_kind = eunion_node_kind(capability->upper_leaf.mode),
		};
	}
	else if (capability->upper_leaf.tag == EUNION_IDENTITY_PRESENT)
	{
		capability->resolved = (struct eunion_resolved_remove_state) {
			.presence = EUNION_PRESENCE_UPPER_ONLY,
			.visible_kind = eunion_node_kind(capability->upper_leaf.mode),
		};
	}
	else if (capability->lower_leaf.tag == EUNION_IDENTITY_PRESENT)
	{
		capability->resolved = (struct eunion_resolved_remove_state) {
			.presence = EUNION_PRESENCE_LOWER_ONLY,
			.visible_kind = eunion_node_kind(capability->lower_leaf.mode),
		};
	}
	else
	{
		capability->resolved = (struct eunion_resolved_remove_state) {
			.presence = EUNION_PRESENCE_ABSENT,
			.visible_kind = EUNION_NODE_NONE,
		};
	}
	capability->resolved.ancestor_visibility =
		capability->lower_hidden_by_opaque_ancestor
			? EUNION_ANCESTOR_OPAQUE : EUNION_ANCESTORS_VISIBLE;
	result = eunion_resolve_directory_view(capability);
	if (result < 0)
		return result;
	capability->plan = eunion_plan_remove((struct eunion_remove_request) {
		.intent = capability->intent,
		.state = capability->resolved,
	});
	return capability->plan.error;
}

static int eunion_open_work_directory(eunion_remove_capability capability)
{
	int root = capability->upper.descriptor[0];
	int descriptor = LINUX_SYSCALL(__NR_openat, root, ".union-work",
		LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
		LINUX_O_CLOEXEC, 0);
	if (descriptor < 0)
		return descriptor;
	capability->work_descriptor = descriptor;
	return 0;
}

static int eunion_checkpoint(eunion_remove_capability capability,
	enum eunion_remove_test_checkpoint checkpoint)
{
#ifdef TEST
	if (eunion_test_remove_checkpoint_hook)
		eunion_test_remove_checkpoint_hook(checkpoint, capability->guest_path);
	if (eunion_test_remove_fail_checkpoint == (int)checkpoint)
		return -LINUX_EIO;
	if (eunion_test_remove_interrupt_checkpoint == (int)checkpoint)
		return -LINUX_EINTR;
#else
	(void)capability;
	(void)checkpoint;
#endif
	return 0;
}

static int eunion_anchor(eunion_remove_capability capability,
	const struct eunion_remove_runtime* runtime, const char* guest_path,
	enum eunion_operation_intent intent)
{
	if (capability->phase != EUNION_REMOVE_PHASE_EMPTY)
		return -LINUX_EBUSY;
	memset(capability, 0, sizeof(*capability));
	capability->work_descriptor = -1;
	capability->tomb_descriptor = -1;
	capability->runtime = runtime;
	capability->intent = intent;
	for (int index = 0; index <= EUNION_REMOVE_COMPONENT_MAX; ++index)
	{
		capability->upper.descriptor[index] = -1;
		capability->lower.descriptor[index] = -1;
	}
	int result = eunion_split_guest(capability, guest_path);
	if (result < 0)
		return result;
	result = eunion_chain_start(&capability->upper, runtime->upper_root);
	if (result < 0)
		return result;
	result = eunion_chain_start(&capability->lower, runtime->lower_root);
	if (result < 0)
		return result;
	result = eunion_open_parent_chains(capability, 0);
	if (result < 0)
		return result;
	result = eunion_resolve_capability(capability);
	if (result < 0)
		return result;
	capability->phase = EUNION_REMOVE_PHASE_RESOLVED;
	return 0;
}

static int eunion_revalidate(eunion_remove_capability capability)
{
	struct eunion_inode_identity old_upper = capability->upper_leaf;
	struct eunion_inode_identity old_lower = capability->lower_leaf;
	struct eunion_resolved_remove_state old_state = capability->resolved;
	struct eunion_remove_plan old_plan = capability->plan;
	int result;

	if (capability->phase != EUNION_REMOVE_PHASE_RESOLVED &&
		capability->phase != EUNION_REMOVE_PHASE_REVALIDATED)
		return -LINUX_EIO;
	if (!capability->lock_held)
	{
		result = LINUX_SYSCALL(__NR_flock, capability->upper.descriptor[0],
			LINUX_LOCK_EX);
		if (result < 0)
			return result;
		capability->lock_held = 1;
	}
	result = eunion_revalidate_chain(&capability->upper);
	if (result < 0)
		return result;
	result = eunion_revalidate_chain(&capability->lower);
	if (result < 0)
		return result;
	result = eunion_revalidate_absolute_root(capability->runtime->upper_root,
		&capability->upper.identity[0]);
	if (result < 0)
		return result;
	result = eunion_revalidate_absolute_root(capability->runtime->lower_root,
		&capability->lower.identity[0]);
	if (result < 0)
		return result;

	if (!capability->upper_parent_complete &&
		(old_plan.action == EUNION_REMOVE_PUBLISH_WHITEOUT ||
		 old_plan.action == EUNION_REMOVE_UPPER_AND_PUBLISH_WHITEOUT ||
		 old_plan.action == EUNION_REMOVE_OPAQUE_DIRECTORY))
	{
		result = eunion_materialize_upper_parent_chain(capability);
		if (result < 0)
			return result;
	}
	result = eunion_resolve_capability(capability);
	if (result < 0)
		return result;
	if (!eunion_identity_equal(&old_upper, &capability->upper_leaf) ||
		!eunion_identity_equal(&old_lower, &capability->lower_leaf) ||
		old_state.presence != capability->resolved.presence ||
		old_state.visible_kind != capability->resolved.visible_kind ||
		old_state.ancestor_visibility !=
			capability->resolved.ancestor_visibility ||
		old_state.directory_view != capability->resolved.directory_view ||
		old_plan.action != capability->plan.action ||
		old_plan.error != capability->plan.error)
		return -LINUX_EAGAIN;
	capability->phase = EUNION_REMOVE_PHASE_REVALIDATED;
	return 0;
}

static int eunion_prepare(eunion_remove_capability capability)
{
	if (capability->phase != EUNION_REMOVE_PHASE_REVALIDATED)
		return -LINUX_EIO;
	int result = eunion_open_work_directory(capability);
	if (result < 0)
		return result;
	int tid = (int)LINUX_SYSCALL(__NR_gettid);
	unsigned long sequence = eunion_remove_sequence++;
	char tid_digits[32];
	char sequence_digits[32];
	unsigned int tid_value = tid < 0 ? (unsigned int)(-tid) : (unsigned int)tid;
	int tid_length = 0;
	int sequence_length = 0;
	do {
		tid_digits[tid_length++] = (char)('0' + tid_value % 10);
		tid_value /= 10;
	} while (tid_value != 0 && tid_length < (int)sizeof(tid_digits));
	do {
		sequence_digits[sequence_length++] = (char)('0' + sequence % 10);
		sequence /= 10;
	} while (sequence != 0 && sequence_length < (int)sizeof(sequence_digits));
	const char prefix[] = "remove.";
	int length = (int)sizeof(prefix) - 1 + tid_length + 1 + sequence_length;
	if (length >= (int)sizeof(capability->stage_name))
		return -LINUX_ENAMETOOLONG;
	int offset = 0;
	memcpy(capability->stage_name + offset, prefix, sizeof(prefix) - 1);
	offset += (int)sizeof(prefix) - 1;
	if (tid < 0)
		capability->stage_name[offset++] = '-';
	for (int index = tid_length - 1; index >= 0; --index)
		capability->stage_name[offset++] = tid_digits[index];
	capability->stage_name[offset++] = '.';
	for (int index = sequence_length - 1; index >= 0; --index)
		capability->stage_name[offset++] = sequence_digits[index];
	capability->stage_name[offset] = '\0';

	if (capability->plan.action == EUNION_REMOVE_PUBLISH_WHITEOUT ||
		capability->plan.action == EUNION_REMOVE_UPPER_AND_PUBLISH_WHITEOUT ||
		(capability->plan.action == EUNION_REMOVE_OPAQUE_DIRECTORY &&
		 capability->lower_leaf.tag == EUNION_IDENTITY_PRESENT))
	{
		int descriptor = LINUX_SYSCALL(__NR_openat,
			capability->work_descriptor, capability->stage_name,
			LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_EXCL |
			LINUX_O_CLOEXEC, 0600);
		if (descriptor < 0)
			return descriptor;
		result = LINUX_SYSCALL(__NR_fchmod, descriptor, 0600);
		if (result >= 0)
			result = LINUX_SYSCALL(__NR_fsetxattr, descriptor,
			capability->runtime->whiteout_marker, "y", 1, 0);
		if (result >= 0)
			result = eunion_fsync(descriptor);
		int close_result = LINUX_SYSCALL(__NR_close, descriptor);
		if (result >= 0 && close_result < 0)
			result = close_result;
		if (result < 0)
		{
			LINUX_SYSCALL(__NR_unlinkat, capability->work_descriptor,
				capability->stage_name, 0);
			return result;
		}
		result = eunion_fsync(capability->work_descriptor);
		if (result < 0)
			return result;
		result = eunion_fstatat_identity(capability->work_descriptor,
			capability->stage_name, &capability->staged_whiteout);
		if (result < 0)
			return result;
	}
	capability->phase = EUNION_REMOVE_PHASE_PREPARED;
	return 0;
}

static int eunion_validate_applied_publication(
	eunion_remove_capability capability)
{
	int upper_parent =
		capability->upper.descriptor[capability->upper.count - 1];
	struct eunion_inode_identity named;
	struct eunion_inode_identity staged;
	int result = eunion_revalidate_chain(&capability->upper);
	if (result < 0)
		return result;
	result = eunion_revalidate_chain(&capability->lower);
	if (result < 0)
		return result;
	result = eunion_revalidate_absolute_root(capability->runtime->upper_root,
		&capability->upper.identity[0]);
	if (result < 0)
		return result;
	result = eunion_revalidate_absolute_root(capability->runtime->lower_root,
		&capability->lower.identity[0]);
	if (result < 0)
		return result;
	result = eunion_fstatat_identity(upper_parent, capability->leaf, &named);
	if (result < 0)
		return result;
	result = eunion_fstatat_identity(capability->work_descriptor,
		capability->stage_name, &staged);
	if (result < 0)
		return result;

	switch (capability->plan.action)
	{
		case EUNION_REMOVE_PUBLISH_WHITEOUT:
			if (!eunion_same_object(&named,
				&capability->staged_whiteout) ||
				staged.tag != EUNION_IDENTITY_ABSENT)
				return -LINUX_EAGAIN;
			break;
		case EUNION_REMOVE_UPPER:
			if (named.tag != EUNION_IDENTITY_ABSENT ||
				!eunion_same_object(&staged, &capability->upper_leaf))
				return -LINUX_EAGAIN;
			break;
		case EUNION_REMOVE_UPPER_AND_PUBLISH_WHITEOUT:
			if (!eunion_same_object(&named,
					&capability->staged_whiteout) ||
				!eunion_same_object(&staged, &capability->upper_leaf))
				return -LINUX_EAGAIN;
			break;
		case EUNION_REMOVE_OPAQUE_DIRECTORY:
			if (capability->lower_leaf.tag == EUNION_IDENTITY_PRESENT)
			{
				if (!eunion_same_object(&named,
						&capability->staged_whiteout) ||
					!eunion_same_object(&staged,
						&capability->upper_leaf))
					return -LINUX_EAGAIN;
			}
			else if (named.tag != EUNION_IDENTITY_ABSENT ||
				!eunion_same_object(&staged, &capability->upper_leaf))
				return -LINUX_EAGAIN;
			break;
		case EUNION_REMOVE_REJECT:
		default:
			return -LINUX_EIO;
	}
	return 0;
}

static int eunion_apply_namespace(eunion_remove_capability capability,
	int upper_parent)
{
	int result;
	switch (capability->plan.action)
	{
		case EUNION_REMOVE_PUBLISH_WHITEOUT:
			result = LINUX_SYSCALL(__NR_renameat2,
				capability->work_descriptor, capability->stage_name,
				upper_parent, capability->leaf, LINUX_RENAME_NOREPLACE);
			break;
		case EUNION_REMOVE_UPPER:
			result = LINUX_SYSCALL(__NR_renameat2,
				upper_parent, capability->leaf,
				capability->work_descriptor, capability->stage_name,
				LINUX_RENAME_NOREPLACE);
			break;
		case EUNION_REMOVE_UPPER_AND_PUBLISH_WHITEOUT:
			result = LINUX_SYSCALL(__NR_renameat2,
				capability->work_descriptor, capability->stage_name,
				upper_parent, capability->leaf, LINUX_RENAME_EXCHANGE);
			break;
		case EUNION_REMOVE_OPAQUE_DIRECTORY:
			if (capability->lower_leaf.tag == EUNION_IDENTITY_PRESENT)
				result = LINUX_SYSCALL(__NR_renameat2,
					capability->work_descriptor, capability->stage_name,
					upper_parent, capability->leaf,
					LINUX_RENAME_EXCHANGE);
			else
				result = LINUX_SYSCALL(__NR_renameat2,
					upper_parent, capability->leaf,
					capability->work_descriptor, capability->stage_name,
					LINUX_RENAME_NOREPLACE);
			break;
		case EUNION_REMOVE_REJECT:
		default:
			return -LINUX_EIO;
	}
	return result;
}

static int eunion_apply(eunion_remove_capability capability)
{
	if (capability->phase != EUNION_REMOVE_PHASE_PREPARED)
		return -LINUX_EIO;
	int upper_parent =
		capability->upper.descriptor[capability->upper.count - 1];
	int directory_descriptor = -1;
	int relaxed_mode = 0;
	int result;
	capability->applied_kind = capability->resolved.visible_kind;

	if (capability->applied_kind == EUNION_NODE_DIRECTORY &&
		capability->plan.action != EUNION_REMOVE_PUBLISH_WHITEOUT)
	{
		directory_descriptor = LINUX_SYSCALL(__NR_openat, upper_parent,
			capability->leaf,
			LINUX_O_PATH | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
			LINUX_O_CLOEXEC, 0);
		if (directory_descriptor < 0)
			return directory_descriptor;
		struct eunion_inode_identity identity;
		result = eunion_fstat_identity(directory_descriptor, &identity);
		if (result < 0 ||
			!eunion_same_object(&identity, &capability->upper_leaf))
		{
			LINUX_SYSCALL(__NR_close, directory_descriptor);
			return result < 0 ? result : -LINUX_EAGAIN;
		}
	}

	result = eunion_apply_namespace(capability, upper_parent);
	if (result == -LINUX_EACCES && directory_descriptor >= 0)
	{
		result = LINUX_SYSCALL(__NR_fchmodat2, directory_descriptor, "",
			(capability->upper_leaf.mode & 07777) | 0300,
			LINUX_AT_EMPTY_PATH);
		if (result >= 0)
		{
			relaxed_mode = 1;
			result = eunion_apply_namespace(capability, upper_parent);
		}
	}
	if (result >= 0)
		capability->phase = EUNION_REMOVE_PHASE_APPLIED;
	if (relaxed_mode)
	{
		int restore_result = LINUX_SYSCALL(__NR_fchmodat2,
			directory_descriptor, "",
			capability->upper_leaf.mode & 07777, LINUX_AT_EMPTY_PATH);
		if (result >= 0 && restore_result < 0)
			result = restore_result;
	}
	if (directory_descriptor >= 0)
	{
		int close_result =
			LINUX_SYSCALL(__NR_close, directory_descriptor);
		if (result >= 0 && close_result < 0)
			result = close_result;
	}
	if (result < 0)
		return result;
	result = eunion_validate_applied_publication(capability);
	if (result < 0)
		return result;
	return eunion_fsync_directory(capability, upper_parent);
}

static int eunion_first_directory_entry(int descriptor,
	char name[EUNION_REMOVE_NAME_MAX + 1])
{
	char buffer[4096];
	int length = 0;
	int offset = 0;
	const char* observed;
	int result = LINUX_SYSCALL(__NR_lseek, descriptor, 0, 0);
	if (result < 0)
		return result;
	result = eunion_next_directory_entry(descriptor, buffer,
		sizeof(buffer), &length, &offset, &observed);
	if (result <= 0)
		return result;
	int name_length = (int)strlen(observed);
	if (name_length <= 0 || name_length > EUNION_REMOVE_NAME_MAX)
		return -LINUX_EIO;
	memcpy(name, observed, (size_t)name_length + 1);
	return 1;
}

static int eunion_open_tomb_directory(eunion_remove_capability capability)
{
	const char suffix[] = ".tombs";
	int stage_length = (int)strlen(capability->stage_name);
	if (stage_length <= 0 ||
		stage_length + (int)sizeof(suffix) >
			(int)sizeof(capability->tomb_name))
		return -LINUX_ENAMETOOLONG;
	memcpy(capability->tomb_name, capability->stage_name,
		(size_t)stage_length);
	memcpy(capability->tomb_name + stage_length, suffix, sizeof(suffix));
	int result = LINUX_SYSCALL(__NR_mkdirat, capability->work_descriptor,
		capability->tomb_name, 0700);
	if (result < 0)
		return result;
	result = LINUX_SYSCALL(__NR_fchmodat, capability->work_descriptor,
		capability->tomb_name, 0700);
	if (result < 0)
		return result;
	capability->tomb_descriptor = LINUX_SYSCALL(__NR_openat,
		capability->work_descriptor, capability->tomb_name,
		LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
		LINUX_O_CLOEXEC, 0);
	if (capability->tomb_descriptor < 0)
		return capability->tomb_descriptor;
	result = eunion_fsync(capability->tomb_descriptor);
	if (result < 0)
		return result;
	return eunion_fsync(capability->work_descriptor);
}

static int eunion_move_internal_whiteouts(
	eunion_remove_capability capability, int source)
{
	char name[EUNION_REMOVE_NAME_MAX + 1];
	for (;;)
	{
		int result = eunion_first_directory_entry(source, name);
		if (result <= 0)
			return result;
		struct eunion_inode_identity identity;
		result = eunion_fstatat_identity(source, name, &identity);
		if (result < 0)
			return result;
		int whiteout = eunion_marker_at(source, name,
			capability->runtime->whiteout_marker, &identity);
		if (whiteout < 0)
			return whiteout;
		int opaque = eunion_marker_at(source, name, "user.union.opaque",
			&identity);
		if (opaque < 0)
			return opaque;
		if (!whiteout || opaque ||
			eunion_node_kind(identity.mode) != EUNION_NODE_REGULAR)
			return -LINUX_ENOTEMPTY;
#ifdef TEST
		++eunion_test_remove_tomb_move_count;
		if (eunion_test_remove_fail_tomb_move_ordinal ==
			eunion_test_remove_tomb_move_count)
			return -LINUX_EIO;
#endif
		result = LINUX_SYSCALL(__NR_renameat2, source, name,
			capability->tomb_descriptor, name, LINUX_RENAME_NOREPLACE);
		if (result < 0)
			return result;
		capability->tomb_contains_originals = 1;
	}
}

static int eunion_restore_internal_whiteouts(
	eunion_remove_capability capability, int destination)
{
	char name[EUNION_REMOVE_NAME_MAX + 1];
	for (;;)
	{
		int result = eunion_first_directory_entry(
			capability->tomb_descriptor, name);
		if (result < 0)
			return result;
		if (result == 0)
		{
			capability->tomb_contains_originals = 0;
			result = eunion_fsync(destination);
			if (result < 0)
				return result;
			return eunion_fsync(capability->tomb_descriptor);
		}
		result = LINUX_SYSCALL(__NR_renameat2,
			capability->tomb_descriptor, name, destination, name,
			LINUX_RENAME_NOREPLACE);
		if (result < 0)
			return result;
	}
}

static int eunion_purge_internal_whiteouts(
	eunion_remove_capability capability)
{
	char name[EUNION_REMOVE_NAME_MAX + 1];
	for (;;)
	{
		int result = eunion_first_directory_entry(
			capability->tomb_descriptor, name);
		if (result < 0)
			return result;
		if (result == 0)
		{
			capability->tomb_contains_originals = 0;
			return eunion_fsync(capability->tomb_descriptor);
		}
		result = LINUX_SYSCALL(__NR_unlinkat,
			capability->tomb_descriptor, name, 0);
		if (result < 0)
			return result;
	}
}

static int eunion_remove_tomb_directory(
	eunion_remove_capability capability)
{
	int result = 0;
	if (capability->tomb_descriptor >= 0)
	{
		result = LINUX_SYSCALL(__NR_close, capability->tomb_descriptor);
		capability->tomb_descriptor = -1;
	}
	if (result >= 0 && capability->tomb_name[0] != '\0')
	{
		result = LINUX_SYSCALL(__NR_unlinkat, capability->work_descriptor,
			capability->tomb_name, LINUX_AT_REMOVEDIR);
		if (result == -LINUX_ENOENT)
			result = 0;
	}
	if (result >= 0)
	{
		capability->tomb_name[0] = '\0';
		result = eunion_fsync(capability->work_descriptor);
	}
	return result;
}

static int eunion_dispose_staged_directory(
	eunion_remove_capability capability)
{
	int result = LINUX_SYSCALL(__NR_unlinkat, capability->work_descriptor,
		capability->stage_name, LINUX_AT_REMOVEDIR);
	if (result == 0)
	{
		capability->phase = EUNION_REMOVE_PHASE_COMMITTED;
		return 0;
	}
	if (result != -LINUX_ENOTEMPTY)
		return result;
	struct eunion_readable_directory source;
	result = eunion_open_directory_readable_at(
		capability->work_descriptor, capability->stage_name,
		&capability->upper_leaf, 0700, &source);
	if (result < 0)
		return result;
	result = eunion_open_tomb_directory(capability);
	if (result >= 0)
		result = eunion_move_internal_whiteouts(capability,
			source.descriptor);
	if (result >= 0)
	{
		result = eunion_fsync(source.descriptor);
		if (result >= 0)
			result = eunion_fsync(capability->tomb_descriptor);
	}
	if (result >= 0)
		result = LINUX_SYSCALL(__NR_unlinkat, capability->work_descriptor,
			capability->stage_name, LINUX_AT_REMOVEDIR);
	if (result >= 0)
		capability->phase = EUNION_REMOVE_PHASE_COMMITTED;
	if (result < 0 && capability->tomb_contains_originals)
	{
		int restore_result =
			eunion_restore_internal_whiteouts(capability,
				source.descriptor);
		if (restore_result < 0)
			result = restore_result;
	}
	int close_result = eunion_close_readable_directory(&source);
	if (result >= 0 && close_result < 0)
		result = close_result;
	if (result < 0)
	{
		int tomb_result = eunion_remove_tomb_directory(capability);
		if (tomb_result < 0)
			return tomb_result;
		return result;
	}

	// The old upper directory inode is gone. The published namespace is now
	// irreversible; quarantined internal whiteouts are transaction garbage,
	// not state that rollback may resurrect.
	result = eunion_purge_internal_whiteouts(capability);
	if (result >= 0)
		result = eunion_remove_tomb_directory(capability);
	return result;
}

static int eunion_remove_staged_original(eunion_remove_capability capability)
{
	if (capability->plan.action == EUNION_REMOVE_PUBLISH_WHITEOUT)
	{
		capability->phase = EUNION_REMOVE_PHASE_COMMITTED;
		return 0;
	}
	int flags = capability->applied_kind == EUNION_NODE_DIRECTORY
		? LINUX_AT_REMOVEDIR : 0;
	if (flags == LINUX_AT_REMOVEDIR)
		return eunion_dispose_staged_directory(capability);
	int result = LINUX_SYSCALL(__NR_unlinkat, capability->work_descriptor,
		capability->stage_name, 0);
	if (result >= 0)
		capability->phase = EUNION_REMOVE_PHASE_COMMITTED;
	return result;
}

static int eunion_rollback_namespace(eunion_remove_capability capability,
	int upper_parent)
{
	int result = 0;
	switch (capability->plan.action)
	{
		case EUNION_REMOVE_PUBLISH_WHITEOUT:
			result = LINUX_SYSCALL(__NR_renameat2, upper_parent,
				capability->leaf, capability->work_descriptor,
				capability->stage_name, LINUX_RENAME_NOREPLACE);
			break;
		case EUNION_REMOVE_UPPER:
			result = LINUX_SYSCALL(__NR_renameat2,
				capability->work_descriptor, capability->stage_name,
				upper_parent, capability->leaf, LINUX_RENAME_NOREPLACE);
			break;
		case EUNION_REMOVE_UPPER_AND_PUBLISH_WHITEOUT:
			result = LINUX_SYSCALL(__NR_renameat2,
				capability->work_descriptor, capability->stage_name,
				upper_parent, capability->leaf, LINUX_RENAME_EXCHANGE);
			break;
		case EUNION_REMOVE_OPAQUE_DIRECTORY:
			if (capability->lower_leaf.tag == EUNION_IDENTITY_PRESENT)
				result = LINUX_SYSCALL(__NR_renameat2,
					capability->work_descriptor, capability->stage_name,
					upper_parent, capability->leaf,
					LINUX_RENAME_EXCHANGE);
			else
				result = LINUX_SYSCALL(__NR_renameat2,
					capability->work_descriptor, capability->stage_name,
					upper_parent, capability->leaf,
					LINUX_RENAME_NOREPLACE);
			break;
		case EUNION_REMOVE_REJECT:
		default:
			result = -LINUX_EIO;
			break;
	}
	return result;
}

static int eunion_rollback_applied(eunion_remove_capability capability)
{
	int upper_parent =
		capability->upper.descriptor[capability->upper.count - 1];
	int directory_descriptor = -1;
	int relaxed_mode = 0;
	int result = eunion_rollback_namespace(capability, upper_parent);
	if (result == -LINUX_EACCES &&
		capability->applied_kind == EUNION_NODE_DIRECTORY &&
		capability->plan.action != EUNION_REMOVE_PUBLISH_WHITEOUT)
	{
		directory_descriptor = LINUX_SYSCALL(__NR_openat,
			capability->work_descriptor, capability->stage_name,
			LINUX_O_PATH | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW |
			LINUX_O_CLOEXEC, 0);
		if (directory_descriptor >= 0)
		{
			struct eunion_inode_identity identity;
			result = eunion_fstat_identity(directory_descriptor, &identity);
			if (result >= 0 &&
				eunion_same_object(&identity, &capability->upper_leaf))
			{
				result = LINUX_SYSCALL(__NR_fchmodat2,
					directory_descriptor, "",
					(capability->upper_leaf.mode & 07777) | 0300,
					LINUX_AT_EMPTY_PATH);
				if (result >= 0)
				{
					relaxed_mode = 1;
					result = eunion_rollback_namespace(capability,
						upper_parent);
				}
			}
			else if (result >= 0)
				result = -LINUX_EAGAIN;
		}
		else
			result = directory_descriptor;
	}
	if (relaxed_mode)
	{
		int restore_result = LINUX_SYSCALL(__NR_fchmodat2,
			directory_descriptor, "",
			capability->upper_leaf.mode & 07777, LINUX_AT_EMPTY_PATH);
		if (result >= 0 && restore_result < 0)
			result = restore_result;
	}
	if (directory_descriptor >= 0)
	{
		int close_result =
			LINUX_SYSCALL(__NR_close, directory_descriptor);
		if (result >= 0 && close_result < 0)
			result = close_result;
	}
	if (result >= 0)
	{
		eunion_fsync_directory(capability, upper_parent);
		eunion_fsync(capability->work_descriptor);
	}
	return result;
}

static int eunion_cleanup(eunion_remove_capability capability,
	int operation_error)
{
	int cleanup_error = 0;
	if (capability->phase == EUNION_REMOVE_PHASE_COMMITTED &&
		capability->tomb_descriptor >= 0 &&
		capability->tomb_contains_originals)
	{
		int result = eunion_purge_internal_whiteouts(capability);
		if (result < 0)
			cleanup_error = result;
	}
	if (capability->tomb_descriptor >= 0 &&
		!capability->tomb_contains_originals)
	{
		int result = eunion_remove_tomb_directory(capability);
		if (result < 0 && cleanup_error == 0)
			cleanup_error = result;
	}
	if (capability->phase == EUNION_REMOVE_PHASE_APPLIED &&
		operation_error < 0)
	{
		int result = eunion_rollback_applied(capability);
		if (result < 0)
			cleanup_error = result;
	}
	if (capability->work_descriptor >= 0 &&
		capability->stage_name[0] != '\0')
	{
		struct eunion_inode_identity staged;
		int result = eunion_fstatat_identity(capability->work_descriptor,
			capability->stage_name, &staged);
		int flags = staged.tag != EUNION_IDENTITY_ABSENT &&
			eunion_node_kind(staged.mode) == EUNION_NODE_DIRECTORY
				? LINUX_AT_REMOVEDIR : 0;
		if (result >= 0 && staged.tag != EUNION_IDENTITY_ABSENT)
			result = LINUX_SYSCALL(__NR_unlinkat,
				capability->work_descriptor, capability->stage_name,
				flags);
		if (result < 0 && result != -LINUX_ENOENT && cleanup_error == 0)
			cleanup_error = result;
		eunion_fsync(capability->work_descriptor);
	}
	if (operation_error < 0 &&
		capability->phase != EUNION_REMOVE_PHASE_COMMITTED)
	{
		for (int index = capability->parent_component_count - 1;
			index >= 0; --index)
		{
			if (!capability->created_upper_parent[index])
				continue;
			int parent = capability->upper.descriptor[index];
			int result = LINUX_SYSCALL(__NR_unlinkat, parent,
				capability->upper.name[index], LINUX_AT_REMOVEDIR);
			if (result < 0 && result != -LINUX_ENOENT &&
				cleanup_error == 0)
				cleanup_error = result;
			if (result >= 0)
				eunion_fsync_directory(capability, parent);
		}
	}
	if (capability->lock_held)
	{
		int result = LINUX_SYSCALL(__NR_flock,
			capability->upper.descriptor[0], LINUX_LOCK_UN);
		if (result < 0 && cleanup_error == 0)
			cleanup_error = result;
		capability->lock_held = 0;
	}
	if (capability->work_descriptor >= 0)
	{
		int result = LINUX_SYSCALL(__NR_close, capability->work_descriptor);
		if (result < 0 && cleanup_error == 0)
			cleanup_error = result;
		capability->work_descriptor = -1;
	}
	eunion_close_chain(&capability->lower);
	eunion_close_chain(&capability->upper);
	capability->phase = EUNION_REMOVE_PHASE_RELEASED;
	return operation_error < 0 ? operation_error : cleanup_error;
}

int eunion_remove_path(const struct eunion_remove_runtime* runtime,
	const char* guest_path, enum eunion_operation_intent intent)
{
	eunion_remove_capability capability = {{0}};
	int result;

	if (!runtime || !runtime->upper_root || !runtime->lower_root ||
		!runtime->whiteout_marker)
		return -LINUX_EINVAL;
#ifdef TEST
	eunion_test_remove_fsync_count = 0;
	eunion_test_remove_tomb_move_count = 0;
#endif
	result = eunion_anchor(capability, runtime, guest_path, intent);
	if (result < 0)
		return eunion_cleanup(capability, result);
	result = eunion_revalidate(capability);
	if (result < 0)
		return eunion_cleanup(capability, result);
	result = eunion_checkpoint(capability, EUNION_REMOVE_TEST_REVALIDATED);
	if (result < 0)
		return eunion_cleanup(capability, result);
	// A test hook or concurrent namespace operation may have substituted any
	// retained component. Revalidate the fd chain and leaf again immediately
	// before the first mutation.
	result = eunion_revalidate(capability);
	if (result < 0)
		return eunion_cleanup(capability, result);
	result = eunion_prepare(capability);
	if (result < 0)
		return eunion_cleanup(capability, result);
	result = eunion_checkpoint(capability, EUNION_REMOVE_TEST_PREPARED);
	if (result < 0)
		return eunion_cleanup(capability, result);
	result = eunion_apply(capability);
	if (result < 0)
		return eunion_cleanup(capability, result);
	result = eunion_checkpoint(capability, EUNION_REMOVE_TEST_APPLIED);
	if (result < 0)
		return eunion_cleanup(capability, result);
	result = eunion_checkpoint(capability, EUNION_REMOVE_TEST_PRE_COMMIT);
	if (result < 0)
		return eunion_cleanup(capability, result);
	result = eunion_remove_staged_original(capability);
	if (result < 0)
		return eunion_cleanup(capability, result);
	if (capability->phase != EUNION_REMOVE_PHASE_COMMITTED)
		return eunion_cleanup(capability, -LINUX_EIO);
	if (eunion_fsync(capability->work_descriptor) < 0)
		return eunion_cleanup(capability, -LINUX_EIO);
	return eunion_cleanup(capability, 0);
}

#ifdef TEST
int eunion_test_remove_capability_reopen(
	const struct eunion_remove_runtime* runtime, const char* guest_path,
	enum eunion_operation_intent intent)
{
	eunion_remove_capability capability = {{0}};
	int result = eunion_anchor(capability, runtime, guest_path, intent);
	if (result < 0)
		return result;
	result = eunion_cleanup(capability, 0);
	if (result < 0)
		return result;
	return eunion_anchor(capability, runtime, guest_path, intent);
}
#endif
