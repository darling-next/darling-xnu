#define _GNU_SOURCE

#include <linux_premigration/eunion_remove_runtime.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <sys/un.h>
#include <unistd.h>

#define WHITEOUT "user.union.whiteout"
#define OPAQUE "user.union.opaque"

struct fixture {
	char root[256];
	char upper[320];
	char lower[320];
	struct eunion_remove_runtime runtime;
};

static int checks;
static int hook_role;
static int hook_ready_fd = -1;
static int hook_release_fd = -1;
static struct fixture* swap_fixture;
static enum eunion_remove_test_checkpoint swap_checkpoint;

static void require(int condition, const char* message)
{
	++checks;
	if (!condition) {
		fprintf(stderr, "eunion_remove_runtime_test: %s (errno=%d)\n",
			message, errno);
		exit(1);
	}
}

static void join_path(char* out, size_t capacity, const char* root,
	const char* suffix)
{
	int length = snprintf(out, capacity, "%s%s", root, suffix);
	require(length > 0 && (size_t)length < capacity, "path overflow");
}

static void make_directory(const char* path)
{
	require(mkdir(path, 0700) == 0, "mkdir");
}

static void make_file(const char* root, const char* suffix, const char* text)
{
	char path[512];
	join_path(path, sizeof(path), root, suffix);
	int descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	require(descriptor >= 0, "open fixture file");
	size_t length = strlen(text);
	require(write(descriptor, text, length) == (ssize_t)length,
		"write fixture file");
	require(fsync(descriptor) == 0, "fsync fixture file");
	require(close(descriptor) == 0, "close fixture file");
}

static int exists(const char* root, const char* suffix)
{
	char path[512];
	struct stat status;
	join_path(path, sizeof(path), root, suffix);
	return lstat(path, &status) == 0;
}

static int file_equals(const char* root, const char* suffix,
	const char* expected)
{
	char path[512];
	char value[64] = {0};
	join_path(path, sizeof(path), root, suffix);
	int descriptor = open(path, O_RDONLY);
	if (descriptor < 0)
		return 0;
	ssize_t length = read(descriptor, value, sizeof(value));
	int close_result = close(descriptor);
	return close_result == 0 && length == (ssize_t)strlen(expected) &&
		memcmp(value, expected, (size_t)length) == 0;
}

static int marker(const char* root, const char* suffix, const char* name)
{
	char path[512];
	char value[2] = {0};
	join_path(path, sizeof(path), root, suffix);
	ssize_t length = lgetxattr(path, name, value, sizeof(value));
	return length == 1 && value[0] == 'y';
}

static void set_marker(const char* root, const char* suffix, const char* name)
{
	char path[512];
	join_path(path, sizeof(path), root, suffix);
	require(lsetxattr(path, name, "y", 1, 0) == 0, "set fixture marker");
}

static void remove_tree(const char* root)
{
	char command[512];
	int length = snprintf(command, sizeof(command), "rm -rf -- '%s'", root);
	require(length > 0 && (size_t)length < sizeof(command),
		"cleanup command overflow");
	require(system(command) == 0, "cleanup fixture");
}

static void fixture_init(struct fixture* fixture)
{
	char template_path[] = "/tmp/eunion-remove-runtime.XXXXXX";
	char* root = mkdtemp(template_path);
	require(root != NULL, "mkdtemp");
	require(strlen(root) < sizeof(fixture->root), "fixture root size");
	strcpy(fixture->root, root);
	join_path(fixture->upper, sizeof(fixture->upper), root, "/upper");
	join_path(fixture->lower, sizeof(fixture->lower), root, "/lower");
	make_directory(fixture->upper);
	make_directory(fixture->lower);
	char work[512];
	join_path(work, sizeof(work), fixture->upper, "/.union-work");
	make_directory(work);
	fixture->runtime = (struct eunion_remove_runtime) {
		.upper_root = fixture->upper,
		.lower_root = fixture->lower,
		.whiteout_marker = WHITEOUT,
	};
}

static void fixture_destroy(struct fixture* fixture)
{
	remove_tree(fixture->root);
}

static void require_work_empty(const struct fixture* fixture)
{
	char path[512];
	join_path(path, sizeof(path), fixture->upper, "/.union-work");
	DIR* directory = opendir(path);
	require(directory != NULL, "open work directory");
	int entries = 0;
	struct dirent* entry;
	while ((entry = readdir(directory)) != NULL) {
		if (strcmp(entry->d_name, ".") != 0 &&
			strcmp(entry->d_name, "..") != 0)
			++entries;
	}
	require(closedir(directory) == 0, "close work directory");
	require(entries == 0, "no staged remove artifact");
}

static void test_basic_actions(void)
{
	struct fixture fixture;
	fixture_init(&fixture);

	make_file(fixture.lower, "/lower-file", "lower");
	require(eunion_remove_path(&fixture.runtime, "/lower-file",
		EUNION_INTENT_REMOVE_FILE) == 0, "remove lower-only file");
	require(exists(fixture.lower, "/lower-file"), "lower file preserved");
	require(marker(fixture.upper, "/lower-file", WHITEOUT),
		"lower file hidden by whiteout");

	make_file(fixture.upper, "/upper-file", "upper");
	require(eunion_remove_path(&fixture.runtime, "/upper-file",
		EUNION_INTENT_REMOVE_FILE) == 0, "remove upper-only file");
	require(!exists(fixture.upper, "/upper-file"), "upper-only file removed");

	make_file(fixture.lower, "/merged-file", "lower");
	make_file(fixture.upper, "/merged-file", "upper");
	require(eunion_remove_path(&fixture.runtime, "/merged-file",
		EUNION_INTENT_REMOVE_FILE) == 0, "remove merged file");
	require(exists(fixture.lower, "/merged-file"), "merged lower preserved");
	require(marker(fixture.upper, "/merged-file", WHITEOUT),
		"merged file replaced by whiteout");

	char lower_directory[512];
	join_path(lower_directory, sizeof(lower_directory), fixture.lower,
		"/lower-directory");
	make_directory(lower_directory);
	require(eunion_remove_path(&fixture.runtime, "/lower-directory",
		EUNION_INTENT_REMOVE_DIRECTORY) == 0,
		"remove lower-only directory");
	require(exists(fixture.lower, "/lower-directory"),
		"lower directory preserved");
	require(marker(fixture.upper, "/lower-directory", WHITEOUT),
		"lower directory hidden by whiteout");

	char upper_directory[512];
	join_path(upper_directory, sizeof(upper_directory), fixture.upper,
		"/opaque-directory");
	make_directory(upper_directory);
	set_marker(fixture.upper, "/opaque-directory", OPAQUE);
	require(eunion_remove_path(&fixture.runtime, "/opaque-directory",
		EUNION_INTENT_REMOVE_DIRECTORY) == 0,
		"remove upper-only opaque directory");
	require(!exists(fixture.upper, "/opaque-directory"),
		"upper-only opaque directory removed");

	make_file(fixture.lower, "/wrong-kind", "file");
	require(eunion_remove_path(&fixture.runtime, "/wrong-kind",
		EUNION_INTENT_REMOVE_DIRECTORY) == -ENOTDIR,
		"rmdir rejects visible file");
	require(eunion_remove_path(&fixture.runtime, "/missing",
		EUNION_INTENT_REMOVE_FILE) == -ENOENT,
		"missing path remains missing");
	require_work_empty(&fixture);
	fixture_destroy(&fixture);
}

static void test_af_unix_removal(void)
{
	struct fixture fixture;
	fixture_init(&fixture);
	char path[512];
	join_path(path, sizeof(path), fixture.upper, "/socket");
	int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
	require(descriptor >= 0, "create AF_UNIX socket");
	struct sockaddr_un address;
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	require(strlen(path) < sizeof(address.sun_path), "socket path capacity");
	strcpy(address.sun_path, path);
	require(bind(descriptor, (struct sockaddr*)&address, sizeof(address)) == 0,
		"bind AF_UNIX fixture");
	require(eunion_remove_path(&fixture.runtime, "/socket",
		EUNION_INTENT_REMOVE_FILE) == 0, "remove AF_UNIX upper node");
	require(!exists(fixture.upper, "/socket"), "AF_UNIX node removed");
	require(close(descriptor) == 0, "close AF_UNIX fixture");
	require_work_empty(&fixture);
	fixture_destroy(&fixture);
}

static void test_nested_and_symlink_rejection(void)
{
	struct fixture fixture;
	fixture_init(&fixture);
	char lower_a[512];
	char lower_b[512];
	join_path(lower_a, sizeof(lower_a), fixture.lower, "/a");
	join_path(lower_b, sizeof(lower_b), fixture.lower, "/a/b");
	make_directory(lower_a);
	make_directory(lower_b);
	make_file(fixture.lower, "/a/b/nested", "nested");
	require(eunion_remove_path(&fixture.runtime, "/a/b/nested",
		EUNION_INTENT_REMOVE_FILE) == 0, "nested lower removal");
	require(exists(fixture.lower, "/a/b/nested"), "nested lower preserved");
	require(marker(fixture.upper, "/a/b/nested", WHITEOUT),
		"nested whiteout published");

	char target[512];
	char link[512];
	join_path(target, sizeof(target), fixture.lower, "/target");
	join_path(link, sizeof(link), fixture.lower, "/link");
	make_directory(target);
	require(symlink("target", link) == 0, "create intermediate symlink");
	make_file(fixture.lower, "/target/victim", "victim");
	int symlink_result = eunion_remove_path(&fixture.runtime, "/link/victim",
		EUNION_INTENT_REMOVE_FILE);
	require(symlink_result == -ELOOP || symlink_result == -ENOTDIR,
		"intermediate symlink fails closed");
	require(exists(fixture.lower, "/target/victim"),
		"intermediate symlink target untouched");

	require_work_empty(&fixture);
	fixture_destroy(&fixture);
}

static void swap_hook(enum eunion_remove_test_checkpoint checkpoint,
	const char* guest_path)
{
	if (checkpoint != swap_checkpoint ||
		!swap_fixture || strcmp(guest_path, "/swap") != 0)
		return;
	char old_path[512];
	char new_path[512];
	join_path(old_path, sizeof(old_path), swap_fixture->upper, "/swap");
	join_path(new_path, sizeof(new_path), swap_fixture->upper, "/swap.new");
	if (rename(old_path, new_path) != 0)
		_exit(90);
	int descriptor = open(old_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (descriptor < 0)
		_exit(91);
	if (write(descriptor, "replacement", 11) != 11 ||
		close(descriptor) != 0)
		_exit(92);
}

static void test_leaf_swap_revalidation(void)
{
	struct fixture fixture;
	fixture_init(&fixture);
	make_file(fixture.upper, "/swap", "original");
	swap_fixture = &fixture;
	swap_checkpoint = EUNION_REMOVE_TEST_REVALIDATED;
	eunion_test_remove_checkpoint_hook = swap_hook;
	require(eunion_remove_path(&fixture.runtime, "/swap",
		EUNION_INTENT_REMOVE_FILE) == -EAGAIN,
		"leaf replacement detected before mutation");
	eunion_test_remove_checkpoint_hook = NULL;
	swap_fixture = NULL;
	require(exists(fixture.upper, "/swap"), "replacement remains");
	require(exists(fixture.upper, "/swap.new"), "original remains");
	require_work_empty(&fixture);
	fixture_destroy(&fixture);
}

static void test_leaf_swap_at_publication_boundary(void)
{
	struct fixture fixture;
	fixture_init(&fixture);
	make_file(fixture.upper, "/swap", "original");
	swap_fixture = &fixture;
	swap_checkpoint = EUNION_REMOVE_TEST_PREPARED;
	eunion_test_remove_checkpoint_hook = swap_hook;
	require(eunion_remove_path(&fixture.runtime, "/swap",
		EUNION_INTENT_REMOVE_FILE) == -EAGAIN,
		"leaf replacement detected at publication boundary");
	eunion_test_remove_checkpoint_hook = NULL;
	swap_fixture = NULL;
	require(exists(fixture.upper, "/swap"),
		"publication-boundary replacement remains");
	require(exists(fixture.upper, "/swap.new"),
		"publication-boundary original remains");
	require(file_equals(fixture.upper, "/swap", "replacement"),
		"publication-boundary replacement content preserved");
	require(file_equals(fixture.upper, "/swap.new", "original"),
		"publication-boundary original content preserved");
	require_work_empty(&fixture);
	fixture_destroy(&fixture);
}

static void parent_swap_prepared_hook(
	enum eunion_remove_test_checkpoint checkpoint, const char* guest_path)
{
	if (checkpoint != EUNION_REMOVE_TEST_PREPARED || !swap_fixture ||
		strcmp(guest_path, "/parent/victim") != 0)
		return;
	char parent[512];
	char old_parent[512];
	join_path(parent, sizeof(parent), swap_fixture->upper, "/parent");
	join_path(old_parent, sizeof(old_parent), swap_fixture->upper,
		"/parent.old");
	if (rename(parent, old_parent) != 0 || mkdir(parent, 0700) != 0)
		_exit(96);
}

static void test_parent_swap_at_publication_boundary(void)
{
	struct fixture fixture;
	fixture_init(&fixture);
	char parent[512];
	join_path(parent, sizeof(parent), fixture.upper, "/parent");
	make_directory(parent);
	make_file(fixture.upper, "/parent/victim", "original");
	swap_fixture = &fixture;
	eunion_test_remove_checkpoint_hook = parent_swap_prepared_hook;
	require(eunion_remove_path(&fixture.runtime, "/parent/victim",
		EUNION_INTENT_REMOVE_FILE) == -EAGAIN,
		"parent replacement detected at publication boundary");
	eunion_test_remove_checkpoint_hook = NULL;
	swap_fixture = NULL;
	require(!exists(fixture.upper, "/parent/victim"),
		"replacement parent remains untouched");
	require(file_equals(fixture.upper, "/parent.old/victim", "original"),
		"old parent retains original after rollback");
	require_work_empty(&fixture);
	fixture_destroy(&fixture);
}

static void unreadable_directory_swap_hook(
	enum eunion_remove_test_checkpoint checkpoint, const char* guest_path)
{
	if (checkpoint != EUNION_REMOVE_TEST_PREPARED || !swap_fixture ||
		strcmp(guest_path, "/swap-dir") != 0)
		return;
	char current[512];
	char original[512];
	join_path(current, sizeof(current), swap_fixture->upper, "/swap-dir");
	join_path(original, sizeof(original), swap_fixture->upper,
		"/swap-dir.old");
	if (rename(current, original) != 0 || mkdir(current, 0000) != 0)
		_exit(97);
}

static void test_unreadable_directory_swap_at_publication_boundary(void)
{
	struct fixture fixture;
	fixture_init(&fixture);
	char current[512];
	char original[512];
	join_path(current, sizeof(current), fixture.upper, "/swap-dir");
	join_path(original, sizeof(original), fixture.upper, "/swap-dir.old");
	make_directory(current);
	require(chmod(current, 0000) == 0, "chmod original swap directory");
	swap_fixture = &fixture;
	eunion_test_remove_checkpoint_hook = unreadable_directory_swap_hook;
	require(eunion_remove_path(&fixture.runtime, "/swap-dir",
		EUNION_INTENT_REMOVE_DIRECTORY) == -EAGAIN,
		"unreadable directory replacement detected before mutation");
	eunion_test_remove_checkpoint_hook = NULL;
	swap_fixture = NULL;
	require(exists(fixture.upper, "/swap-dir"),
		"unreadable replacement directory remains");
	require(exists(fixture.upper, "/swap-dir.old"),
		"unreadable original directory remains");
	require(chmod(current, 0700) == 0 &&
		chmod(original, 0700) == 0,
		"restore swapped directory modes");
	require_work_empty(&fixture);
	fixture_destroy(&fixture);
}

static void test_union_directory_emptiness(void)
{
	struct fixture fixture;
	fixture_init(&fixture);
	char lower_only[512];
	char merged_lower[512];
	char merged_upper[512];
	join_path(lower_only, sizeof(lower_only), fixture.lower, "/lower-nonempty");
	join_path(merged_lower, sizeof(merged_lower), fixture.lower,
		"/merged-nonempty");
	join_path(merged_upper, sizeof(merged_upper), fixture.upper,
		"/merged-nonempty");
	make_directory(lower_only);
	make_directory(merged_lower);
	make_directory(merged_upper);
	make_file(fixture.lower, "/lower-nonempty/child", "lower");
	make_file(fixture.lower, "/merged-nonempty/lower-child", "lower");

	require(eunion_remove_path(&fixture.runtime, "/lower-nonempty",
		EUNION_INTENT_REMOVE_DIRECTORY) == -ENOTEMPTY,
		"rmdir rejects lower-only non-empty union directory");
	require(!exists(fixture.upper, "/lower-nonempty"),
		"rejected lower-only rmdir publishes no whiteout");
	require(eunion_remove_path(&fixture.runtime, "/merged-nonempty",
		EUNION_INTENT_REMOVE_DIRECTORY) == -ENOTEMPTY,
		"rmdir rejects merged directory with visible lower child");
	require(exists(fixture.upper, "/merged-nonempty"),
		"rejected merged rmdir preserves upper directory");
	require(!marker(fixture.upper, "/merged-nonempty", WHITEOUT),
		"rejected merged rmdir publishes no whiteout");
	require_work_empty(&fixture);
	fixture_destroy(&fixture);
}

static void test_opaque_ancestor_hides_lower_target(void)
{
	struct fixture fixture;
	fixture_init(&fixture);
	char lower_parent[512];
	char upper_parent[512];
	join_path(lower_parent, sizeof(lower_parent), fixture.lower,
		"/opaque-parent");
	join_path(upper_parent, sizeof(upper_parent), fixture.upper,
		"/opaque-parent");
	make_directory(lower_parent);
	make_directory(upper_parent);
	make_file(fixture.lower, "/opaque-parent/hidden", "lower");
	set_marker(fixture.upper, "/opaque-parent", OPAQUE);

	require(eunion_remove_path(&fixture.runtime, "/opaque-parent/hidden",
		EUNION_INTENT_REMOVE_FILE) == -ENOENT,
		"opaque ancestor makes hidden lower target absent");
	require(!exists(fixture.upper, "/opaque-parent/hidden"),
		"opaque ancestor rejection publishes no whiteout");
	require(exists(fixture.lower, "/opaque-parent/hidden"),
		"opaque ancestor rejection preserves hidden lower target");
	require_work_empty(&fixture);
	fixture_destroy(&fixture);
}

static void test_unreadable_upper_file_can_be_unlinked(void)
{
	struct fixture fixture;
	fixture_init(&fixture);
	char path[512];
	make_file(fixture.upper, "/unreadable", "upper");
	join_path(path, sizeof(path), fixture.upper, "/unreadable");
	require(chmod(path, 0000) == 0, "chmod unreadable upper file");
	require(eunion_remove_path(&fixture.runtime, "/unreadable",
		EUNION_INTENT_REMOVE_FILE) == 0,
		"unlink does not require target read permission");
	require(!exists(fixture.upper, "/unreadable"),
		"unreadable upper file removed");
	require_work_empty(&fixture);
	fixture_destroy(&fixture);
}

static void test_materialized_parent_metadata(void)
{
	struct fixture fixture;
	fixture_init(&fixture);
	char lower_parent[512];
	char upper_parent[512];
	struct stat lower_status;
	struct stat upper_status;
	char value[32] = {0};
	mode_t old_umask;
	join_path(lower_parent, sizeof(lower_parent), fixture.lower, "/metadata");
	join_path(upper_parent, sizeof(upper_parent), fixture.upper, "/metadata");
	make_directory(lower_parent);
	require(chmod(lower_parent, 0777) == 0, "set lower parent mode");
	require(lsetxattr(lower_parent, "user.review", "preserved", 9, 0) == 0,
		"set lower parent xattr");
	make_file(fixture.lower, "/metadata/victim", "lower");

	old_umask = umask(0077);
	int remove_result = eunion_remove_path(&fixture.runtime,
		"/metadata/victim", EUNION_INTENT_REMOVE_FILE);
	require(remove_result == 0,
		"nested lower removal materializes metadata parent");
	umask(old_umask);

	require(lstat(lower_parent, &lower_status) == 0, "stat lower parent");
	require(lstat(upper_parent, &upper_status) == 0, "stat upper parent");
	require((upper_status.st_mode & 07777) ==
		(lower_status.st_mode & 07777),
		"materialized parent mode ignores caller umask");
	require(upper_status.st_uid == lower_status.st_uid &&
		upper_status.st_gid == lower_status.st_gid,
		"materialized parent ownership preserved");
	require(lgetxattr(upper_parent, "user.review", value,
		sizeof(value)) == 9 && memcmp(value, "preserved", 9) == 0,
		"materialized parent xattr preserved");
	require(marker(fixture.upper, "/metadata/victim", WHITEOUT),
		"nested whiteout published after metadata copy");
	require_work_empty(&fixture);
	fixture_destroy(&fixture);
}

static int recursive_whiteout_directory_case(void)
{
	struct fixture fixture;
	fixture_init(&fixture);
	char lower_parent[512];
	join_path(lower_parent, sizeof(lower_parent), fixture.lower, "/recursive");
	make_directory(lower_parent);
	make_file(fixture.lower, "/recursive/child", "lower");

	int child_result = eunion_remove_path(&fixture.runtime,
		"/recursive/child", EUNION_INTENT_REMOVE_FILE);
	int parent_result = eunion_remove_path(&fixture.runtime, "/recursive",
		EUNION_INTENT_REMOVE_DIRECTORY);
	int parent_whiteout = marker(fixture.upper, "/recursive", WHITEOUT);
	int lower_preserved = exists(fixture.lower, "/recursive");
	printf("EUNION_REMOVE_FOLLOWUP recursive child=%d parent=%d "
		"whiteout=%d lower=%d\n", child_result, parent_result,
		parent_whiteout, lower_preserved);
	int passed = child_result == 0 && parent_result == 0 &&
		parent_whiteout && lower_preserved;
	fixture_destroy(&fixture);
	return passed;
}

static int hostile_umask_whiteout_case(void)
{
	struct fixture fixture;
	fixture_init(&fixture);
	make_file(fixture.lower, "/umask-victim", "lower");
	mode_t old_umask = umask(0777);
	int result = eunion_remove_path(&fixture.runtime, "/umask-victim",
		EUNION_INTENT_REMOVE_FILE);
	umask(old_umask);
	int whiteout = marker(fixture.upper, "/umask-victim", WHITEOUT);
	char path[512];
	struct stat status;
	join_path(path, sizeof(path), fixture.upper, "/umask-victim");
	int stat_result = lstat(path, &status);
	unsigned int mode = stat_result == 0
		? (unsigned int)status.st_mode & 0777 : 0;
	printf("EUNION_REMOVE_FOLLOWUP umask result=%d whiteout=%d mode=%04o\n",
		result, whiteout, mode);
	int passed = result == 0 && whiteout &&
		stat_result == 0 && mode == 0600;
	fixture_destroy(&fixture);
	return passed;
}

static int write_execute_parent_unlink_case(void)
{
	struct fixture fixture;
	fixture_init(&fixture);
	char parent[512];
	join_path(parent, sizeof(parent), fixture.upper, "/write-execute");
	make_directory(parent);
	make_file(fixture.upper, "/write-execute/victim", "upper");
	require(chmod(parent, 0300) == 0, "chmod write-execute parent");
	int result = eunion_remove_path(&fixture.runtime,
		"/write-execute/victim", EUNION_INTENT_REMOVE_FILE);
	int target_exists = exists(fixture.upper, "/write-execute/victim");
	require(chmod(parent, 0700) == 0, "restore write-execute parent mode");
	printf("EUNION_REMOVE_FOLLOWUP parent0300 result=%d target=%d\n",
		result, target_exists);
	int passed = result == 0 && !target_exists;
	fixture_destroy(&fixture);
	return passed;
}

static int unreadable_empty_directory_case(void)
{
	struct fixture fixture;
	fixture_init(&fixture);
	char directory[512];
	join_path(directory, sizeof(directory), fixture.upper, "/unreadable-dir");
	make_directory(directory);
	require(chmod(directory, 0000) == 0, "chmod unreadable directory");
	int result = eunion_remove_path(&fixture.runtime, "/unreadable-dir",
		EUNION_INTENT_REMOVE_DIRECTORY);
	int target_exists = exists(fixture.upper, "/unreadable-dir");
	if (target_exists)
		require(chmod(directory, 0700) == 0,
			"restore unreadable directory mode");
	printf("EUNION_REMOVE_FOLLOWUP dir000 result=%d target=%d\n",
		result, target_exists);
	int passed = result == 0 && !target_exists;

	char nonempty[512];
	join_path(nonempty, sizeof(nonempty), fixture.upper,
		"/unreadable-nonempty");
	make_directory(nonempty);
	make_file(fixture.upper, "/unreadable-nonempty/child", "upper");
	require(chmod(nonempty, 0000) == 0,
		"chmod unreadable nonempty directory");
	result = eunion_remove_path(&fixture.runtime, "/unreadable-nonempty",
		EUNION_INTENT_REMOVE_DIRECTORY);
	target_exists = exists(fixture.upper, "/unreadable-nonempty");
	require(chmod(nonempty, 0700) == 0,
		"restore unreadable nonempty directory mode");
	printf("EUNION_REMOVE_FOLLOWUP dir000-nonempty result=%d target=%d\n",
		result, target_exists);
	passed = passed && result == -ENOTEMPTY && target_exists;
	fixture_destroy(&fixture);
	return passed;
}

static void test_followup_adversarial_remove_cases(void)
{
	int recursive = recursive_whiteout_directory_case();
	int hostile_umask = hostile_umask_whiteout_case();
	int parent_permissions = write_execute_parent_unlink_case();
	int directory_permissions = unreadable_empty_directory_case();
	require(recursive, "recursive whiteout-only directory removal");
	require(hostile_umask, "whiteout creation ignores guest umask");
	require(parent_permissions,
		"unlink requires no parent read permission");
	require(directory_permissions,
		"rmdir requires no target directory read permission");
}

static void test_recursive_whiteout_disposal_rollback(void)
{
	struct fixture fixture;
	fixture_init(&fixture);
	char lower_parent[512];
	join_path(lower_parent, sizeof(lower_parent), fixture.lower,
		"/recursive-rollback");
	make_directory(lower_parent);
	make_file(fixture.lower, "/recursive-rollback/one", "lower");
	make_file(fixture.lower, "/recursive-rollback/two", "lower");
	require(eunion_remove_path(&fixture.runtime,
		"/recursive-rollback/one", EUNION_INTENT_REMOVE_FILE) == 0,
		"publish first recursive whiteout");
	require(eunion_remove_path(&fixture.runtime,
		"/recursive-rollback/two", EUNION_INTENT_REMOVE_FILE) == 0,
		"publish second recursive whiteout");

	eunion_test_remove_fail_tomb_move_ordinal = 2;
	require(eunion_remove_path(&fixture.runtime, "/recursive-rollback",
		EUNION_INTENT_REMOVE_DIRECTORY) == -EIO,
		"whiteout quarantine failure is reported");
	eunion_test_remove_fail_tomb_move_ordinal = 0;
	require(exists(fixture.upper, "/recursive-rollback"),
		"failed quarantine restores upper directory");
	require(marker(fixture.upper, "/recursive-rollback/one", WHITEOUT) &&
		marker(fixture.upper, "/recursive-rollback/two", WHITEOUT),
		"failed quarantine restores every internal whiteout");
	require(!marker(fixture.upper, "/recursive-rollback", WHITEOUT),
		"failed quarantine does not publish parent whiteout");
	require_work_empty(&fixture);

	require(eunion_remove_path(&fixture.runtime, "/recursive-rollback",
		EUNION_INTENT_REMOVE_DIRECTORY) == 0,
		"recursive directory removal succeeds after rollback");
	require(marker(fixture.upper, "/recursive-rollback", WHITEOUT),
		"recursive retry publishes parent whiteout");
	require_work_empty(&fixture);
	fixture_destroy(&fixture);
}

static void root_swap_hook(enum eunion_remove_test_checkpoint checkpoint,
	const char* guest_path)
{
	if (checkpoint != EUNION_REMOVE_TEST_REVALIDATED ||
		!swap_fixture || strcmp(guest_path, "/root-swap") != 0)
		return;
	char old_root[512];
	join_path(old_root, sizeof(old_root), swap_fixture->root, "/upper.old");
	if (rename(swap_fixture->upper, old_root) != 0 ||
		mkdir(swap_fixture->upper, 0700) != 0)
		_exit(95);
}

static void test_root_swap_revalidation(void)
{
	struct fixture fixture;
	fixture_init(&fixture);
	make_file(fixture.upper, "/root-swap", "original");
	swap_fixture = &fixture;
	eunion_test_remove_checkpoint_hook = root_swap_hook;
	require(eunion_remove_path(&fixture.runtime, "/root-swap",
		EUNION_INTENT_REMOVE_FILE) == -EAGAIN,
		"upper root replacement detected before mutation");
	eunion_test_remove_checkpoint_hook = NULL;
	swap_fixture = NULL;
	char new_root[512];
	char old_root[512];
	join_path(new_root, sizeof(new_root), fixture.root, "/upper");
	join_path(old_root, sizeof(old_root), fixture.root, "/upper.old");
	require(rmdir(new_root) == 0, "remove replacement upper root");
	require(rename(old_root, new_root) == 0, "restore original upper root");
	require(exists(fixture.upper, "/root-swap"),
		"root swap original remains");
	require_work_empty(&fixture);
	fixture_destroy(&fixture);
}

static void seed_interruption_fixture(struct fixture* fixture, int action)
{
	fixture_init(fixture);
	make_file(fixture->lower, "/victim", "lower");
	if (action != 0)
		make_file(fixture->upper, "/victim", "upper");
	if (action == 1) {
		char lower[512];
		join_path(lower, sizeof(lower), fixture->lower, "/victim");
		require(unlink(lower) == 0, "make upper-only fixture");
	}
}

static void require_interruption_restored(const struct fixture* fixture,
	int action)
{
	require(exists(fixture->lower, "/victim") == (action != 1),
		"lower state restored");
	require(exists(fixture->upper, "/victim") == (action != 0),
		"upper state restored");
	require(!marker(fixture->upper, "/victim", WHITEOUT),
		"no partial whiteout");
	require_work_empty(fixture);
}

static void test_all_interruption_cases(void)
{
	for (int action = 0; action < 3; ++action) {
		for (int checkpoint = EUNION_REMOVE_TEST_REVALIDATED;
			checkpoint <= EUNION_REMOVE_TEST_PRE_COMMIT; ++checkpoint) {
			for (int interrupted = 0; interrupted < 2; ++interrupted) {
				struct fixture fixture;
				seed_interruption_fixture(&fixture, action);
				eunion_test_remove_fail_checkpoint =
					interrupted ? 0 : checkpoint;
				eunion_test_remove_interrupt_checkpoint =
					interrupted ? checkpoint : 0;
				int result = eunion_remove_path(&fixture.runtime, "/victim",
					EUNION_INTENT_REMOVE_FILE);
				require(result == (interrupted ? -EINTR : -EIO),
					"injected error preserved");
				eunion_test_remove_fail_checkpoint = 0;
				eunion_test_remove_interrupt_checkpoint = 0;
				require_interruption_restored(&fixture, action);
				fixture_destroy(&fixture);
			}
		}
	}
}

static void test_staged_durability_failures(void)
{
	for (int ordinal = 1; ordinal <= 2; ++ordinal) {
		struct fixture fixture;
		seed_interruption_fixture(&fixture, 2);
		eunion_test_remove_fail_fsync_ordinal = ordinal;
		require(eunion_remove_path(&fixture.runtime, "/victim",
			EUNION_INTENT_REMOVE_FILE) == -EIO,
			"staged fsync failure is reported");
		eunion_test_remove_fail_fsync_ordinal = 0;
		require_interruption_restored(&fixture, 2);
		fixture_destroy(&fixture);
	}
}

static void test_nested_parent_rollback(void)
{
	struct fixture fixture;
	fixture_init(&fixture);
	char lower_a[512];
	char lower_b[512];
	join_path(lower_a, sizeof(lower_a), fixture.lower, "/a");
	join_path(lower_b, sizeof(lower_b), fixture.lower, "/a/b");
	make_directory(lower_a);
	make_directory(lower_b);
	make_file(fixture.lower, "/a/b/victim", "lower");
	eunion_test_remove_fail_checkpoint = EUNION_REMOVE_TEST_PREPARED;
	require(eunion_remove_path(&fixture.runtime, "/a/b/victim",
		EUNION_INTENT_REMOVE_FILE) == -EIO,
		"nested prepared failure is reported");
	eunion_test_remove_fail_checkpoint = 0;
	require(exists(fixture.lower, "/a/b/victim"),
		"nested lower remains after failure");
	require(!exists(fixture.upper, "/a"),
		"transaction-created parent chain is rolled back");
	require_work_empty(&fixture);
	fixture_destroy(&fixture);
}

static void test_capability_reopen_rejected(void)
{
	struct fixture fixture;
	fixture_init(&fixture);
	make_file(fixture.lower, "/reopen", "lower");
	require(eunion_test_remove_capability_reopen(&fixture.runtime, "/reopen",
		EUNION_INTENT_REMOVE_FILE) == -EBUSY,
		"released owning capability cannot be reopened");
	require(exists(fixture.lower, "/reopen"),
		"reopen probe does not mutate lower state");
	require(!exists(fixture.upper, "/reopen"),
		"reopen probe does not publish upper state");
	require_work_empty(&fixture);
	fixture_destroy(&fixture);
}

static void blocking_hook(enum eunion_remove_test_checkpoint checkpoint,
	const char* guest_path)
{
	(void)guest_path;
	if (hook_role != 1 || checkpoint != EUNION_REMOVE_TEST_REVALIDATED)
		return;
	char byte = 'R';
	if (write(hook_ready_fd, &byte, 1) != 1)
		_exit(93);
	if (read(hook_release_fd, &byte, 1) != 1)
		_exit(94);
}

static pid_t start_remove_child(struct fixture* fixture, int role,
	int ready_fd, int release_fd)
{
	pid_t child = fork();
	require(child >= 0, "fork remove child");
	if (child == 0) {
		hook_role = role;
		hook_ready_fd = ready_fd;
		hook_release_fd = release_fd;
		eunion_test_remove_checkpoint_hook = blocking_hook;
		int result = eunion_remove_path(&fixture->runtime, "/race",
			EUNION_INTENT_REMOVE_FILE);
		_exit(result == 0 ? 0 : result == -EAGAIN || result == -ENOENT ? 2 : 3);
	}
	return child;
}

static void test_three_process_lock_race(void)
{
	struct fixture fixture;
	fixture_init(&fixture);
	make_file(fixture.lower, "/race", "lower");
	int ready[2];
	int release[2];
	require(pipe(ready) == 0 && pipe(release) == 0, "race pipes");
	pid_t first = start_remove_child(&fixture, 1, ready[1], release[0]);
	char byte;
	require(read(ready[0], &byte, 1) == 1, "first process owns lock");
	pid_t second = start_remove_child(&fixture, 2, -1, -1);
	pid_t third = start_remove_child(&fixture, 3, -1, -1);
	struct pollfd waiters[] = {
		{.fd = ready[0], .events = POLLIN},
	};
	require(poll(waiters, 1, 100) == 0,
		"waiters do not pass persistent root lock");
	require(write(release[1], "G", 1) == 1, "release first process");
	int statuses[3];
	require(waitpid(first, &statuses[0], 0) == first, "wait first child");
	require(waitpid(second, &statuses[1], 0) == second, "wait second child");
	require(waitpid(third, &statuses[2], 0) == third, "wait third child");
	int success = 0;
	int stale = 0;
	for (int index = 0; index < 3; ++index) {
		require(WIFEXITED(statuses[index]), "race child exited");
		if (WEXITSTATUS(statuses[index]) == 0)
			++success;
		else if (WEXITSTATUS(statuses[index]) == 2)
			++stale;
	}
	require(success == 1 && stale == 2,
		"one remove commits and two stale capabilities fail closed");
	require(exists(fixture.lower, "/race"), "race lower remains");
	require(marker(fixture.upper, "/race", WHITEOUT),
		"race publishes exactly one whiteout");
	require_work_empty(&fixture);
	close(ready[0]);
	close(ready[1]);
	close(release[0]);
	close(release[1]);
	fixture_destroy(&fixture);
}

static void test_remove_create_remove_linearization(void)
{
	struct fixture fixture;
	fixture_init(&fixture);
	make_file(fixture.lower, "/linear", "lower");
	make_file(fixture.upper, "/linear", "old-upper");
	int ready[2];
	int release[2];
	require(pipe(ready) == 0 && pipe(release) == 0,
		"linearization pipes");

	// The first remover owns the persistent upper-root lock and has retained
	// the original leaf identity.
	pid_t first = fork();
	require(first >= 0, "fork first linear remover");
	if (first == 0) {
		hook_role = 1;
		hook_ready_fd = ready[1];
		hook_release_fd = release[0];
		eunion_test_remove_checkpoint_hook = blocking_hook;
		int result = eunion_remove_path(&fixture.runtime, "/linear",
			EUNION_INTENT_REMOVE_FILE);
		_exit(result == -EAGAIN ? 0 : 4);
	}
	char byte;
	require(read(ready[0], &byte, 1) == 1,
		"first linear remover reached revalidated state");

	// Publish a create-like replacement while the first capability is live.
	// The retained dev/inode identity must make that remover fail closed.
	char replacement[512];
	char target[512];
	join_path(replacement, sizeof(replacement), fixture.upper, "/linear.new");
	join_path(target, sizeof(target), fixture.upper, "/linear");
	int descriptor = open(replacement, O_WRONLY | O_CREAT | O_EXCL, 0600);
	require(descriptor >= 0, "create replacement");
	require(write(descriptor, "new-upper", 9) == 9, "write replacement");
	require(fsync(descriptor) == 0 && close(descriptor) == 0,
		"durable replacement");
	require(rename(replacement, target) == 0, "publish replacement");

	// Once the first rejects its stale capability, a second remove must operate
	// on the replacement rather than on the superseded inode.
	require(write(release[1], "G", 1) == 1, "release first linear remover");
	int first_status;
	require(waitpid(first, &first_status, 0) == first,
		"wait first linear remover");
	require(WIFEXITED(first_status) && WEXITSTATUS(first_status) == 0,
		"stale remover rejects replacement");
	eunion_test_remove_checkpoint_hook = NULL;
	require(eunion_remove_path(&fixture.runtime, "/linear",
		EUNION_INTENT_REMOVE_FILE) == 0,
		"new remover commits replacement removal");
	require(exists(fixture.lower, "/linear"), "linear lower remains");
	require(marker(fixture.upper, "/linear", WHITEOUT),
		"linear final state is a whiteout");
	require_work_empty(&fixture);
	close(ready[0]);
	close(ready[1]);
	close(release[0]);
	close(release[1]);
	fixture_destroy(&fixture);
}

int main(void)
{
	test_basic_actions();
	test_af_unix_removal();
	test_nested_and_symlink_rejection();
	test_leaf_swap_revalidation();
	test_leaf_swap_at_publication_boundary();
	test_parent_swap_at_publication_boundary();
	test_unreadable_directory_swap_at_publication_boundary();
	test_root_swap_revalidation();
	test_union_directory_emptiness();
	test_opaque_ancestor_hides_lower_target();
	test_unreadable_upper_file_can_be_unlinked();
	test_materialized_parent_metadata();
	test_followup_adversarial_remove_cases();
	test_recursive_whiteout_disposal_rollback();
	test_all_interruption_cases();
	test_staged_durability_failures();
	test_nested_parent_rollback();
	test_capability_reopen_rejected();
	test_three_process_lock_race();
	test_remove_create_remove_linearization();
	printf("EUNION_REMOVE_RUNTIME_OK checks=%d interruption_cases=24\n", checks);
	return 0;
}
