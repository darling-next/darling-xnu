#define _GNU_SOURCE
#define TEST 1
#define EUNION 1

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#define LINUX_AT_FDCWD AT_FDCWD
#define LINUX_EEXIST EEXIST
#define LINUX_EINVAL EINVAL
#define LINUX_EIO EIO
#define LINUX_EMFILE EMFILE
#define LINUX_ENOTDIR ENOTDIR
#define LINUX_EPERM EPERM

#define main embedded_vchroot_main
#include "../src/linux_premigration/vchroot_userspace.c"
#undef main

static void require(int condition, const char* message)
{
	if (condition)
		return;
	fprintf(stderr, "eunion_lower_readdir_test: %s (errno=%d)\n",
		message, errno);
	exit(1);
}

static void join(char* output, size_t capacity,
	const char* root, const char* suffix)
{
	int length = snprintf(output, capacity, "%s%s", root, suffix);
	require(length > 0 && (size_t)length < capacity, "join path");
}

static void make_file(const char* path)
{
	int descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	require(descriptor >= 0 && close(descriptor) == 0, "create fixture file");
}

static int page_has_name(const char* page, int length, const char* name)
{
	for (int offset = 0; offset < length;) {
		const struct linux_dirent64* entry =
			(const struct linux_dirent64*)(page + offset);
		require(entry->d_reclen > 0 && offset + entry->d_reclen <= length,
			"valid dirent record");
		if (strcmp(entry->d_name, name) == 0)
			return 1;
		offset += entry->d_reclen;
	}
	return 0;
}

static int resolve_guest(const char* guest, char* host, size_t capacity)
{
	struct vchroot_expand_args args;
	memset(&args, 0, sizeof(args));
	require(strlen(guest) + 1 <= sizeof(args.path), "guest path fits resolver");
	strcpy(args.path, guest);
	args.flags = VCHROOT_FOLLOW;
	args.dfd = LINUX_AT_FDCWD;
	int result = vchroot_expand(&args);
	if (result == 0) {
		require(strlen(args.path) + 1 <= capacity, "resolved path fits output");
		strcpy(host, args.path);
	}
	return result;
}

int main(void)
{
	char root[] = "/tmp/eunion-lower-readdir.XXXXXX";
	require(mkdtemp(root) != NULL, "create fixture root");
	char upper[512], lower[512], upper_dir[512], lower_dir[512];
	join(upper, sizeof(upper), root, "/writable-upper-long");
	join(lower, sizeof(lower), root, "/lo");
	join(upper_dir, sizeof(upper_dir), upper, "/merged");
	join(lower_dir, sizeof(lower_dir), lower, "/merged");
	require(mkdir(upper, 0700) == 0 && mkdir(lower, 0700) == 0 &&
		mkdir(upper_dir, 0700) == 0 && mkdir(lower_dir, 0700) == 0,
		"create upper and lower directories");

	char lower_only[512], shadow_lower[512], shadow_upper[512], hidden_lower[512],
		hidden_upper[512];
	join(lower_only, sizeof(lower_only), lower_dir, "/lower-only");
	join(shadow_lower, sizeof(shadow_lower), lower_dir, "/shadow");
	join(shadow_upper, sizeof(shadow_upper), upper_dir, "/shadow");
	join(hidden_lower, sizeof(hidden_lower), lower_dir, "/hidden");
	join(hidden_upper, sizeof(hidden_upper), upper_dir, "/hidden");
	make_file(lower_only);
	make_file(shadow_lower);
	make_file(shadow_upper);
	make_file(hidden_lower);
	make_file(hidden_upper);
	require(setxattr(hidden_upper, "user.union.whiteout", "y", 1, 0) == 0,
		"mark whiteout");

	memcpy(prefix_path, upper, strlen(upper) + 1);
	prefix_path_len = (int)strlen(prefix_path);
	set_libexec_path(lower);
	require(prefix_path_len != libexec_path_len,
		"fixture uses unequal upper/lower root lengths");

	/* A lower relative symlink must be rebased using the logical guest parent,
	 * not byte offsets from whichever host layer supplied the link. */
	char upper_private[512], upper_private_tmp[512], lower_private[512],
		lower_tmp_link[512], lower_nested[512], lower_nested_link[512],
		lower_absolute_link[512], lower_target[512], lower_target_link[512],
		lower_hidden[512], upper_hidden[512], lower_hidden_link[512];
	join(upper_private, sizeof(upper_private), upper, "/private");
	join(upper_private_tmp, sizeof(upper_private_tmp), upper, "/private/tmp");
	join(lower_private, sizeof(lower_private), lower, "/private");
	join(lower_tmp_link, sizeof(lower_tmp_link), lower, "/tmp");
	join(lower_nested, sizeof(lower_nested), lower, "/nested");
	join(lower_nested_link, sizeof(lower_nested_link), lower, "/nested/to-tmp");
	join(lower_absolute_link, sizeof(lower_absolute_link), lower, "/absolute-tmp");
	join(lower_target, sizeof(lower_target), lower, "/private/lower-target");
	join(lower_target_link, sizeof(lower_target_link), lower, "/lower-target-link");
	join(lower_hidden, sizeof(lower_hidden), lower, "/private/hidden-target");
	join(upper_hidden, sizeof(upper_hidden), upper, "/private/hidden-target");
	join(lower_hidden_link, sizeof(lower_hidden_link), lower, "/hidden-target-link");
	require(mkdir(upper_private, 0755) == 0 &&
		mkdir(upper_private_tmp, 01777) == 0 &&
		mkdir(lower_private, 0755) == 0 &&
		mkdir(lower_nested, 0755) == 0 &&
		mkdir(lower_target, 0700) == 0,
		"create symlink layer fixtures");
	require(chmod(upper_private_tmp, 01777) == 0,
		"set exact upper tmp mode independent of umask");
	make_file(lower_hidden);
	make_file(upper_hidden);
	require(setxattr(upper_hidden, "user.union.whiteout", "y", 1, 0) == 0,
		"mark symlink target whiteout");
	require(symlink("private/tmp", lower_tmp_link) == 0 &&
		symlink("../tmp", lower_nested_link) == 0 &&
		symlink("/private/tmp", lower_absolute_link) == 0 &&
		symlink("private/lower-target", lower_target_link) == 0 &&
		symlink("private/hidden-target", lower_hidden_link) == 0,
		"create relative and absolute symlinks");

	char resolved[512];
	struct stat expected, observed;
	require(stat(upper_private_tmp, &expected) == 0, "stat expected upper tmp");
	int tmp_status = resolve_guest("/tmp", resolved, sizeof(resolved));
	int tmp_stat_status = tmp_status == 0 ? stat(resolved, &observed) : -1;
	require(tmp_status == 0 && tmp_stat_status == 0 && observed.st_dev == expected.st_dev &&
		observed.st_ino == expected.st_ino && (observed.st_mode & 07777) == 01777,
		"lower relative /tmp symlink resolves to exact upper inode");
	require(resolve_guest("/nested/to-tmp", resolved, sizeof(resolved)) == 0 &&
		stat(resolved, &observed) == 0 && observed.st_ino == expected.st_ino,
		"nested relative symlink resolves across layers");
	require(resolve_guest("/absolute-tmp", resolved, sizeof(resolved)) == 0 &&
		stat(resolved, &observed) == 0 && observed.st_ino == expected.st_ino,
		"absolute symlink resolves to upper target");
	require(stat(lower_target, &expected) == 0 &&
		resolve_guest("/lower-target-link", resolved, sizeof(resolved)) == 0 &&
		stat(resolved, &observed) == 0 && observed.st_dev == expected.st_dev &&
		observed.st_ino == expected.st_ino,
		"relative symlink resolves to lower target");
	require(resolve_guest("/hidden-target-link", resolved, sizeof(resolved)) ==
		-LINUX_ENOENT, "whiteout suppresses symlink target");

	/* When the upper directory itself is absent, vchroot resolves opendir(3)
	 * directly to the lower directory.  The per-fd merge path must still expose
	 * that lower stream instead of manufacturing EOF. */
	char direct_lower[512], direct_name[512];
	join(direct_lower, sizeof(direct_lower), lower, "/direct-lower");
	join(direct_name, sizeof(direct_name), direct_lower, "/lower-direct-entry");
	require(mkdir(direct_lower, 0700) == 0, "create direct lower directory");
	make_file(direct_name);
	int direct_descriptor = open(direct_lower,
		O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	require(direct_descriptor >= 0, "open lower directory directly");
	char direct_page[512];
	int direct_length = vchroot_getdents_merge(
		direct_descriptor, direct_page, sizeof(direct_page));
	require(direct_length > 0 &&
		page_has_name(direct_page, direct_length, "lower-direct-entry"),
		"direct lower descriptor exposes populated lower directory");
	vchroot_dir_closed(direct_descriptor);
	require(close(direct_descriptor) == 0, "close direct lower directory");

	int descriptor = open(upper_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	require(descriptor >= 0, "open empty-upper merged directory");
	char page[512];
	require(vchroot_getdents_merge(descriptor, page, 8) == -EINVAL,
		"undersized page is not reported as EOF");
	int length = vchroot_getdents_merge(descriptor, page, sizeof(page));
	require(length > 0, "merged page is not false EOF");
	require(page_has_name(page, length, "lower-only"), "lower-only name visible");
	require(page_has_name(page, length, "shadow"), "upper shadow visible once");
	require(!page_has_name(page, length, "hidden"), "whiteout suppresses lower name");

	require(vchroot_dir_seek(descriptor, 0) == 0, "rewind merged cursor");
	length = vchroot_getdents_merge(descriptor, page, sizeof(page));
	require(length > 0 && page_has_name(page, length, "lower-only"),
		"rewind replays lower listing");
	int recycled_descriptor = descriptor;
	require(close(descriptor) == 0, "close first directory");

	char second_upper[512], second_lower[512], second_name[512];
	join(second_upper, sizeof(second_upper), upper, "/second");
	join(second_lower, sizeof(second_lower), lower, "/second");
	join(second_name, sizeof(second_name), second_lower, "/fresh-after-reuse");
	require(mkdir(second_upper, 0700) == 0 && mkdir(second_lower, 0700) == 0,
		"create reuse directories");
	make_file(second_name);
	descriptor = open(second_upper, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	require(descriptor >= 0, "open reused directory descriptor");
	require(descriptor == recycled_descriptor,
		"fixture reuses the numeric directory descriptor");
	length = vchroot_getdents_merge(descriptor, page, sizeof(page));
	require(length > 0 && page_has_name(page, length, "fresh-after-reuse"),
		"descriptor reuse has fresh merge state");
	vchroot_dir_closed(descriptor);
	close(descriptor);

	char command[640];
	require(snprintf(command, sizeof(command), "rm -rf -- '%s'", root) > 0,
		"construct cleanup command");
	require(system(command) == 0, "remove fixture root");
	puts("EUNION_LOWER_READDIR_OK");
	return 0;
}
