#define _GNU_SOURCE

#include <linux_premigration/eunion_sidecar.h>
#include "eunion_sidecar_test_support.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

static int checks;

static void require(int condition, const char* message)
{
	++checks;
	if (!condition) {
		fprintf(stderr, "eunion_sidecar_storage_test: %s (errno=%d)\n",
			message, errno);
		exit(1);
	}
}

static void join_path(char* output, size_t capacity, const char* root,
	const char* suffix)
{
	int length = snprintf(output, capacity, "%s%s", root, suffix);
	require(length > 0 && (size_t)length < capacity, "path overflow");
}

static void remove_tree(const char* root)
{
	char command[640];
	int length = snprintf(command, sizeof(command), "rm -rf -- '%s'", root);
	require(length > 0 && (size_t)length < sizeof(command),
		"cleanup command size");
	require(system(command) == 0, "cleanup");
}

static void require_upper_only_remove(
	const struct eunion_sidecar_runtime* runtime,
	const char* guest_path, const char* upper_path, int directory)
{
	require(eunion_sidecar_remove_path(runtime, guest_path, directory) == 0,
		"remove upper-only object");
	struct stat status;
	require(lstat(upper_path, &status) == -1 && errno == ENOENT,
		"upper-only backing object is absent");
	require(eunion_sidecar_test_record_present(runtime, guest_path) == 0,
		"upper-only removal publishes record ABSENT");
	eunion_sidecar_view reader = {{0}};
	require(eunion_sidecar_view_open(reader, runtime,
		EUNION_SIDECAR_ACCESS_SHARED) == 0,
		"open upper-only removal reader");
	struct eunion_sidecar_lookup lookup;
	require(eunion_sidecar_lookup_path(reader, guest_path, &lookup) == 0 &&
		lookup.kind == EUNION_SIDECAR_RECORD_NONE,
		"upper-only removal remains guest-visible absent");
	require(eunion_sidecar_view_close(reader) == 0,
		"close upper-only removal reader");
	require(eunion_sidecar_remove_path(
		runtime, guest_path, directory) == -ENOENT,
		"repeat upper-only removal is idempotently absent");
	require(eunion_sidecar_test_record_present(runtime, guest_path) == 0,
		"repeat upper-only removal does not recreate a record");
}

int main(void)
{
	char root[] = "/tmp/eunion-sidecar-storage.XXXXXX";
	require(mkdtemp(root) != NULL, "mkdtemp");
	char upper[512];
	char lower[512];
	char sidecar[512];
	char link[512];
	char intermediate_link[512];
	char intermediate_sidecar[512];
	char lock[512];
	char format[512];
	char lower_deleted[512];
	char upper_deleted[512];
	char upper_opaque[512];
	char lower_opaque[512];
	char upper_recreated[512];
	char lower_recreated[512];
	char lower_recreated_child[512];
	char lower_tree[512];
	char lower_tree_child[512];
	char upper_tree[512];
	char upper_tree_child[512];
	char upper_moved[512];
	char upper_moved_child[512];
	char lower_merged_tree[512];
	char lower_merged_child[512];
	char upper_merged_tree[512];
	char upper_merged_child[512];
	char upper_merged_lower_child[512];
	char upper_merged_moved[512];
	char upper_merged_moved_upper_child[512];
	char upper_merged_moved_lower_child[512];
	char upper_created[512];
	char upper_link[512];
	char upper_hardlink[512];
	char upper_fifo[512];
	char upper_socket[512];
	char upper_empty_directory[512];
	char lower_locked_tree[512];
	char lower_locked_child[512];
	char upper_locked_tree[512];
	join_path(upper, sizeof(upper), root, "/upper");
	join_path(lower, sizeof(lower), root, "/lower");
	join_path(sidecar, sizeof(sidecar), root, "/sidecar");
	join_path(link, sizeof(link), root, "/sidecar-link");
	join_path(intermediate_link, sizeof(intermediate_link),
		root, "/intermediate-link");
	join_path(intermediate_sidecar, sizeof(intermediate_sidecar),
		intermediate_link, "/sidecar");
	join_path(lock, sizeof(lock), sidecar, "/lock-v1");
	join_path(format, sizeof(format), sidecar, "/format-v1");
	join_path(lower_deleted, sizeof(lower_deleted), lower, "/deleted");
	join_path(upper_deleted, sizeof(upper_deleted), upper, "/deleted");
	join_path(upper_opaque, sizeof(upper_opaque), upper, "/opaque");
	join_path(lower_opaque, sizeof(lower_opaque), lower, "/opaque");
	join_path(upper_recreated, sizeof(upper_recreated),
		upper, "/recreated");
	join_path(lower_recreated, sizeof(lower_recreated),
		lower, "/recreated");
	join_path(lower_recreated_child, sizeof(lower_recreated_child),
		lower, "/recreated/child");
	join_path(lower_tree, sizeof(lower_tree), lower, "/tree");
	join_path(lower_tree_child, sizeof(lower_tree_child),
		lower, "/tree/child");
	join_path(upper_tree, sizeof(upper_tree), upper, "/tree");
	join_path(upper_tree_child, sizeof(upper_tree_child),
		upper, "/tree/child");
	join_path(upper_moved, sizeof(upper_moved), upper, "/moved");
	join_path(upper_moved_child, sizeof(upper_moved_child),
		upper, "/moved/child");
	join_path(lower_merged_tree, sizeof(lower_merged_tree),
		lower, "/merged-tree");
	join_path(lower_merged_child, sizeof(lower_merged_child),
		lower, "/merged-tree/lower-child");
	join_path(upper_merged_tree, sizeof(upper_merged_tree),
		upper, "/merged-tree");
	join_path(upper_merged_child, sizeof(upper_merged_child),
		upper, "/merged-tree/upper-child");
	join_path(upper_merged_lower_child, sizeof(upper_merged_lower_child),
		upper, "/merged-tree/lower-child");
	join_path(upper_merged_moved, sizeof(upper_merged_moved),
		upper, "/merged-moved");
	join_path(upper_merged_moved_upper_child,
		sizeof(upper_merged_moved_upper_child),
		upper, "/merged-moved/upper-child");
	join_path(upper_merged_moved_lower_child,
		sizeof(upper_merged_moved_lower_child),
		upper, "/merged-moved/lower-child");
	join_path(upper_created, sizeof(upper_created), upper, "/created");
	join_path(upper_link, sizeof(upper_link), upper, "/link");
	join_path(upper_hardlink, sizeof(upper_hardlink),
		upper, "/hardlink");
	join_path(upper_fifo, sizeof(upper_fifo), upper, "/fifo");
	join_path(upper_socket, sizeof(upper_socket), upper, "/socket");
	join_path(upper_empty_directory, sizeof(upper_empty_directory),
		upper, "/empty-directory");
	join_path(lower_locked_tree, sizeof(lower_locked_tree),
		lower, "/locked-tree");
	join_path(lower_locked_child, sizeof(lower_locked_child),
		lower, "/locked-tree/child");
	join_path(upper_locked_tree, sizeof(upper_locked_tree),
		upper, "/locked-tree");
	require(mkdir(upper, 0700) == 0, "mkdir upper");
	require(mkdir(lower, 0700) == 0, "mkdir lower");
	require(mkdir(sidecar, 0700) == 0, "mkdir sidecar");
	require(mkdir(lower_tree, 0700) == 0, "mkdir lower rename tree");
	struct timespec tree_times[2] = {
		{ .tv_sec = 1700000000, .tv_nsec = 123456789 },
		{ .tv_sec = 1700000001, .tv_nsec = 987654321 },
	};
	require(chmod(lower_tree, 0777) == 0 &&
		setxattr(lower_tree, "user.review", "preserved", 9, 0) == 0 &&
		utimensat(AT_FDCWD, lower_tree, tree_times, 0) == 0,
		"set lower directory metadata");
	int tree_child = open(lower_tree_child,
		O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	require(tree_child >= 0 &&
		write(tree_child, "tree", 4) == 4 &&
		fsync(tree_child) == 0 && close(tree_child) == 0,
		"create lower rename child");
	require(mkdir(lower_merged_tree, 0700) == 0 &&
		mkdir(upper_merged_tree, 0700) == 0,
		"create merged rename tree");
	int merged_lower_child = open(lower_merged_child,
		O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	int merged_upper_child = open(upper_merged_child,
		O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	require(merged_lower_child >= 0 && merged_upper_child >= 0 &&
		write(merged_lower_child, "lower", 5) == 5 &&
		write(merged_upper_child, "upper", 5) == 5 &&
		fsync(merged_lower_child) == 0 &&
		fsync(merged_upper_child) == 0 &&
		close(merged_lower_child) == 0 &&
		close(merged_upper_child) == 0,
		"create disjoint merged rename children");

	struct eunion_sidecar_runtime runtime = {
		.upper_root = upper,
		.lower_root = lower,
		.sidecar_root = sidecar,
	};
	require(eunion_sidecar_test_write_prefix_state(&runtime) == 0,
		"write sidecar-v1 prefix state");
	require(eunion_sidecar_initialize(&runtime) == 0,
		"initialize sidecar");
	require(eunion_sidecar_test_transaction_guards(&runtime) == 0,
		"transaction capability rejects direct copy and reopen");

	struct stat status;
	require(lstat(lock, &status) == 0 && S_ISREG(status.st_mode) &&
		!S_ISLNK(status.st_mode) && (status.st_mode & 0777) == 0600,
		"persistent lock is exact regular mode 0600");
	require(lstat(format, &status) == 0 && S_ISREG(status.st_mode) &&
		!S_ISLNK(status.st_mode) && (status.st_mode & 0777) == 0600,
		"format is exact regular mode 0600");

	eunion_sidecar_view view = {{0}};
	require(eunion_sidecar_view_open(view, &runtime,
		EUNION_SIDECAR_ACCESS_SHARED) == 0, "open shared view");
	struct eunion_sidecar_lookup lookup;
	require(eunion_sidecar_lookup_path(view, "/", &lookup) == 0 &&
		lookup.kind == EUNION_SIDECAR_RECORD_INDEX &&
		lookup.generation == 1, "root index is identity-bound");
	require(eunion_sidecar_lookup_path(view, "/missing", &lookup) == 0 &&
		lookup.kind == EUNION_SIDECAR_RECORD_NONE,
		"missing component has no record");

	eunion_sidecar_view copied;
	memcpy(copied, view, sizeof(copied));
	require(eunion_sidecar_lookup_path(copied, "/missing", &lookup) == -EINVAL,
		"copied view fails owner-address validation");
	require(eunion_sidecar_view_close(view) == 0, "close shared view");
	require(eunion_sidecar_view_open(view, &runtime,
		EUNION_SIDECAR_ACCESS_SHARED) == -EINVAL,
		"released view cannot be reopened");

	int lower_file = open(lower_deleted,
		O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	require(lower_file >= 0 && write(lower_file, "lower", 5) == 5 &&
		fsync(lower_file) == 0 && close(lower_file) == 0,
		"create lower whiteout target");
	eunion_sidecar_view writer = {{0}};
	require(eunion_sidecar_view_open(writer, &runtime,
		EUNION_SIDECAR_ACCESS_EXCLUSIVE) == 0,
		"open exclusive mutation view");
	require(eunion_sidecar_publish_whiteout(writer, "/deleted") == 0,
		"publish typed whiteout");
	require(eunion_sidecar_view_close(writer) == 0,
		"close whiteout writer");
	require(lstat(upper_deleted, &status) == -1 && errno == ENOENT,
		"whiteout publishes no upper placeholder");
	eunion_sidecar_view whiteout_reader = {{0}};
	require(eunion_sidecar_view_open(whiteout_reader, &runtime,
		EUNION_SIDECAR_ACCESS_SHARED) == 0,
		"open whiteout reader");
	require(eunion_sidecar_lookup_path(whiteout_reader,
		"/deleted", &lookup) == 0 &&
		lookup.kind == EUNION_SIDECAR_RECORD_WHITEOUT,
		"lookup observes exact whiteout record");
	require(eunion_sidecar_publish_whiteout(whiteout_reader,
		"/deleted") == -EBUSY,
		"shared view cannot mutate records");
	require(eunion_sidecar_view_close(whiteout_reader) == 0,
		"close whiteout reader");

	eunion_sidecar_view clearer = {{0}};
	require(eunion_sidecar_view_open(clearer, &runtime,
		EUNION_SIDECAR_ACCESS_EXCLUSIVE) == 0,
		"open clear writer");
	require(eunion_sidecar_clear_whiteout(clearer, "/deleted") == 0,
		"clear exact whiteout record");
	require(eunion_sidecar_view_close(clearer) == 0,
		"close clear writer");
	eunion_sidecar_view cleared_reader = {{0}};
	require(eunion_sidecar_view_open(cleared_reader, &runtime,
		EUNION_SIDECAR_ACCESS_SHARED) == 0,
		"open cleared reader");
	require(eunion_sidecar_lookup_path(cleared_reader,
		"/deleted", &lookup) == 0 &&
		lookup.kind == EUNION_SIDECAR_RECORD_NONE,
		"cleared record exposes no semantic sidecar state");
	require(eunion_sidecar_view_close(cleared_reader) == 0,
		"close cleared reader");

	require(mkdir(upper_recreated, 0700) == 0 &&
		mkdir(lower_recreated, 0700) == 0,
		"create recreated directory pair");
	int recreated_child = open(lower_recreated_child,
		O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	require(recreated_child >= 0 &&
		write(recreated_child, "lower", 5) == 5 &&
		fsync(recreated_child) == 0 && close(recreated_child) == 0,
		"create recreated lower child");
	eunion_sidecar_view subtree_writer = {{0}};
	require(eunion_sidecar_view_open(subtree_writer, &runtime,
		EUNION_SIDECAR_ACCESS_EXCLUSIVE) == 0,
		"open subtree writer");
	require(eunion_sidecar_publish_whiteout(
		subtree_writer, "/recreated/child") == 0,
		"publish nested whiteout");
	require(eunion_sidecar_publish_whiteout(
		subtree_writer, "/recreated") == 0,
		"publish parent whiteout");
	require(eunion_sidecar_clear_whiteout(
		subtree_writer, "/recreated") == 0,
		"recreate parent record");
	require(eunion_sidecar_view_close(subtree_writer) == 0,
		"close subtree writer");
	eunion_sidecar_view subtree_reader = {{0}};
	require(eunion_sidecar_view_open(subtree_reader, &runtime,
		EUNION_SIDECAR_ACCESS_SHARED) == 0,
		"open subtree reader");
	require(eunion_sidecar_lookup_path(
		subtree_reader, "/recreated/child", &lookup) == 0 &&
		lookup.kind == EUNION_SIDECAR_RECORD_NONE,
		"recreate cannot inherit stale descendant whiteouts");
	require(eunion_sidecar_view_close(subtree_reader) == 0,
		"close subtree reader");

	require(mkdir(upper_opaque, 0700) == 0 &&
		mkdir(lower_opaque, 0700) == 0,
		"create opaque directory pair");
	eunion_sidecar_view opaque_writer = {{0}};
	require(eunion_sidecar_view_open(opaque_writer, &runtime,
		EUNION_SIDECAR_ACCESS_EXCLUSIVE) == 0,
		"open opaque writer");
	require(eunion_sidecar_publish_opaque(opaque_writer, "/opaque") == 0,
		"publish typed opaque record");
	require(eunion_sidecar_view_close(opaque_writer) == 0,
		"close opaque writer");
	eunion_sidecar_view opaque_reader = {{0}};
	require(eunion_sidecar_view_open(opaque_reader, &runtime,
		EUNION_SIDECAR_ACCESS_SHARED) == 0,
		"open opaque reader");
	require(eunion_sidecar_lookup_path(opaque_reader,
		"/opaque", &lookup) == 0 &&
		lookup.kind == EUNION_SIDECAR_RECORD_OPAQUE,
		"lookup observes identity-bound opaque record");
	require(eunion_sidecar_view_close(opaque_reader) == 0,
		"close opaque reader");

	mode_t old_umask = umask(0777);
	int created = eunion_sidecar_open_create(&runtime, "/created",
		O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	require(created >= 0 && write(created, "create", 6) == 6 &&
		fsync(created) == 0 && close(created) == 0,
		"hostile umask cannot break transactional create");
	require(umask(old_umask) == 0777, "restore umask");
	int symlink_create_result = eunion_sidecar_symlink_create(
		&runtime, "created", "/link");
	if (symlink_create_result < 0)
		fprintf(stderr, "symlink create result=%d\n",
			symlink_create_result);
	require(symlink_create_result == 0,
		"transactional symlink create");
	char target[64];
	ssize_t target_length = readlink(
		upper_link, target, sizeof(target) - 1);
	require(target_length == 7, "read created symlink");
	target[target_length] = '\0';
	require(strcmp(target, "created") == 0,
		"symlink target preserved");
	require(eunion_sidecar_link_create(
		&runtime, "/created", "/hardlink", 0) == 0,
		"transactional hardlink create");
	struct stat created_status;
	struct stat hardlink_status;
	require(lstat(upper_created, &created_status) == 0 &&
		lstat(upper_hardlink, &hardlink_status) == 0 &&
		created_status.st_dev == hardlink_status.st_dev &&
		created_status.st_ino == hardlink_status.st_ino,
		"hardlink identity preserved");
	require(eunion_sidecar_mknod_create(
		&runtime, "/fifo", S_IFIFO | 0600, 0) == 0 &&
		lstat(upper_fifo, &status) == 0 && S_ISFIFO(status.st_mode),
		"transactional fifo create");
	int socket_descriptor = socket(AF_UNIX,
		SOCK_STREAM | SOCK_CLOEXEC, 0);
	require(socket_descriptor >= 0,
		"create transactional unix socket");
	require(eunion_sidecar_socket_bind_create(
		&runtime, "/socket", socket_descriptor) == 0 &&
		lstat(upper_socket, &status) == 0 && S_ISSOCK(status.st_mode),
		"transactional unix socket bind");
	require(close(socket_descriptor) == 0,
		"close transactional unix socket");
	require(eunion_sidecar_mkdir_create(
		&runtime, "/empty-directory", 0700) == 0,
		"create transactional empty directory");
	require_upper_only_remove(
		&runtime, "/socket", upper_socket, 0);
	require_upper_only_remove(
		&runtime, "/created", upper_created, 0);
	require_upper_only_remove(
		&runtime, "/link", upper_link, 0);
	require_upper_only_remove(
		&runtime, "/empty-directory", upper_empty_directory, 1);

	mode_t tree_umask = umask(0777);
	require(eunion_sidecar_copy_up_tree(&runtime, "/tree") == 0,
		"copy up complete rename tree");
	require(umask(tree_umask) == 0777,
		"restore hostile tree-copy umask");
	require(lstat(upper_tree, &status) == 0 && S_ISDIR(status.st_mode),
		"rename tree exists in upper");
	char metadata_value[16] = {0};
	struct stat lower_tree_status;
	require(lstat(lower_tree, &lower_tree_status) == 0 &&
		(status.st_mode & 07777) == 0777 &&
		status.st_uid == lower_tree_status.st_uid &&
		status.st_gid == lower_tree_status.st_gid &&
		status.st_mtim.tv_sec == lower_tree_status.st_mtim.tv_sec &&
		status.st_mtim.tv_nsec == lower_tree_status.st_mtim.tv_nsec &&
		getxattr(upper_tree, "user.review", metadata_value,
			sizeof(metadata_value)) == 9 &&
		memcmp(metadata_value, "preserved", 9) == 0,
		"copy-up preserves directory mode, ownership, timestamps and xattrs");
	require(lstat(upper_tree, &status) == 0 &&
			lstat(upper_tree_child, &status) == 0 &&
			S_ISREG(status.st_mode),
		"tree copy-up materializes descendants at the source");
	require(eunion_sidecar_rename_path(
		&runtime, "/tree", "/moved") == 0,
		"transactional subtree rename");
	require(lstat(upper_tree, &status) == -1 && errno == ENOENT,
		"rename removes old upper name");
	require(lstat(upper_moved, &status) == 0 && S_ISDIR(status.st_mode) &&
		lstat(upper_moved_child, &status) == 0 &&
		S_ISREG(status.st_mode),
		"rename moves full backing subtree");
	eunion_sidecar_view rename_reader = {{0}};
	require(eunion_sidecar_view_open(rename_reader, &runtime,
		EUNION_SIDECAR_ACCESS_SHARED) == 0,
		"open rename result reader");
	require(eunion_sidecar_lookup_path(rename_reader,
		"/tree", &lookup) == 0 &&
		lookup.kind == EUNION_SIDECAR_RECORD_WHITEOUT,
		"rename masks lower source");
	require(eunion_sidecar_lookup_path(rename_reader,
		"/moved", &lookup) == 0 &&
		lookup.kind == EUNION_SIDECAR_RECORD_NONE,
		"renamed destination is visible index");
	int moved_child_lookup = eunion_sidecar_lookup_path(rename_reader,
		"/moved/child", &lookup);
	if (moved_child_lookup < 0 ||
		lookup.kind != EUNION_SIDECAR_RECORD_NONE)
		fprintf(stderr, "moved child lookup=%d kind=%d\n",
			moved_child_lookup, (int)lookup.kind);
	require(moved_child_lookup == 0 &&
		lookup.kind == EUNION_SIDECAR_RECORD_NONE,
		"renamed sidecar subtree follows destination");
	require(eunion_sidecar_view_close(rename_reader) == 0,
		"close rename result reader");

	require(eunion_sidecar_copy_up_tree(
		&runtime, "/merged-tree") == 0,
		"materialize complete pre-existing merged tree");
	require(lstat(upper_merged_child, &status) == 0 &&
		lstat(upper_merged_lower_child, &status) == 0,
		"merged tree materialization preserves upper and lower children");
	require(eunion_sidecar_rename_path(
		&runtime, "/merged-tree", "/merged-moved") == 0,
		"rename pre-existing merged tree");
	require(lstat(upper_merged_tree, &status) == -1 && errno == ENOENT &&
		lstat(upper_merged_moved, &status) == 0 &&
		lstat(upper_merged_moved_upper_child, &status) == 0 &&
		lstat(upper_merged_moved_lower_child, &status) == 0,
		"renamed merged tree retains every visible child");

	require(mkdir(lower_locked_tree, 0700) == 0,
		"create locked lower tree");
	int locked_child = open(lower_locked_child,
		O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	require(locked_child >= 0 &&
		write(locked_child, "locked", 6) == 6 &&
		fsync(locked_child) == 0 && close(locked_child) == 0,
		"create locked lower child");
	require(chmod(lower_locked_tree, 0000) == 0,
		"protect lower tree without live permission lift");
	struct stat locked_before;
	struct stat locked_after;
	require(lstat(lower_locked_tree, &locked_before) == 0,
		"snapshot locked lower tree");
	require(eunion_sidecar_copy_up_tree(
		&runtime, "/locked-tree") == -EACCES,
		"unreadable lower tree did not fail closed");
	require(lstat(lower_locked_tree, &locked_after) == 0 &&
			(locked_after.st_mode & 07777) == 0000 &&
			locked_before.st_ctim.tv_sec ==
				locked_after.st_ctim.tv_sec &&
			locked_before.st_ctim.tv_nsec ==
				locked_after.st_ctim.tv_nsec,
		"failed tree copy-up changed lower permissions or ctime");
	require(lstat(upper_locked_tree, &status) == -1 && errno == ENOENT,
		"failed tree copy-up published a partial upper tree");
	require(chmod(lower_locked_tree, 0700) == 0,
		"restore locked lower fixture for cleanup");

	require(symlink(sidecar, link) == 0, "create sidecar symlink");
	struct eunion_sidecar_runtime symlink_runtime = runtime;
	symlink_runtime.sidecar_root = link;
	eunion_sidecar_view symlink_view = {{0}};
	int symlink_result = eunion_sidecar_view_open(symlink_view,
		&symlink_runtime, EUNION_SIDECAR_ACCESS_SHARED);
	require(symlink_result == -ELOOP || symlink_result == -ENOTDIR,
		"sidecar leaf symlink rejected");
	require(symlink(root, intermediate_link) == 0,
		"create intermediate sidecar symlink");
	struct eunion_sidecar_runtime intermediate_runtime = runtime;
	intermediate_runtime.sidecar_root = intermediate_sidecar;
	eunion_sidecar_view intermediate_view = {{0}};
	int intermediate_result = eunion_sidecar_view_open(
		intermediate_view, &intermediate_runtime,
		EUNION_SIDECAR_ACCESS_SHARED);
	require(intermediate_result == -ELOOP ||
			intermediate_result == -ENOTDIR,
		"sidecar intermediate symlink rejected");

	int descriptor = open(format, O_RDWR | O_CLOEXEC);
	require(descriptor >= 0, "open format for corruption fixture");
	unsigned char byte;
	require(pread(descriptor, &byte, 1, 8) == 1,
		"read format version byte");
	byte ^= 0x80;
	require(pwrite(descriptor, &byte, 1, 8) == 1 && fsync(descriptor) == 0,
		"corrupt format durably");
	require(close(descriptor) == 0, "close corrupt format");
	eunion_sidecar_view corrupt = {{0}};
	require(eunion_sidecar_view_open(corrupt, &runtime,
		EUNION_SIDECAR_ACCESS_SHARED) == -EIO,
		"corrupt format fails closed");

	printf("EUNION_SIDECAR_STORAGE_OK checks=%d\n", checks);
	remove_tree(root);
	return 0;
}
