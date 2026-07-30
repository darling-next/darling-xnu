#define _GNU_SOURCE

#include <linux_premigration/eunion_sidecar.h>
#include "eunion_sidecar_test_support.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int failures;
static char protected_payload[512];
static int protected_payload_read;
static int concurrent_directory = -1;
static int concurrent_chmod_count;

static void check(int condition, const char* message)
{
	if (condition)
		return;
	++failures;
	fprintf(stderr, "EUNION_SIDECAR_RED %s\n", message);
}

static void join_path(char* output, size_t capacity, const char* root,
	const char* suffix)
{
	int length = snprintf(output, capacity, "%s%s", root, suffix);
	if (length <= 0 || (size_t)length >= capacity) {
		perror("path overflow");
		exit(2);
	}
}

static void make_file(const char* path, const char* contents)
{
	int descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (descriptor < 0 ||
		write(descriptor, contents, strlen(contents)) !=
			(ssize_t)strlen(contents) ||
		fsync(descriptor) != 0 || close(descriptor) != 0) {
		perror("make file");
		exit(2);
	}
}

static void cleanup(const char* root, const char* secret)
{
	chmod(secret, 0700);
	char command[640];
	int length = snprintf(command, sizeof(command), "rm -rf -- '%s'", root);
	if (length <= 0 || (size_t)length >= sizeof(command) ||
		system(command) != 0) {
		perror("cleanup");
		exit(2);
	}
}

static void sidecar_checkpoint_hook(
	enum eunion_sidecar_test_checkpoint checkpoint,
	const char* guest_path)
{
	if (checkpoint != EUNION_SIDECAR_TEST_PRE_BACKING ||
		strcmp(guest_path, "/chmod-race") != 0)
		return;
	if (fchmod(concurrent_directory, 0711) != 0) {
		perror("concurrent chmod");
		exit(2);
	}
	++concurrent_chmod_count;
}

static enum eunion_sidecar_record_kind sidecar_kind(
	const struct eunion_sidecar_runtime* runtime, const char* guest_path)
{
	eunion_sidecar_view view = {{0}};
	check(eunion_sidecar_view_open(view, runtime,
		EUNION_SIDECAR_ACCESS_SHARED) == 0,
		"open sidecar evidence view");
	struct eunion_sidecar_lookup lookup;
	check(eunion_sidecar_lookup_path(view, guest_path, &lookup) == 0,
		"read sidecar evidence");
	check(eunion_sidecar_view_close(view) == 0,
		"close sidecar evidence view");
	return lookup.kind;
}

int main(void)
{
	char root[] = "/tmp/eunion-sidecar-contract.XXXXXX";
	if (!mkdtemp(root)) {
		perror("mkdtemp");
		return 2;
	}
	char upper[512];
	char lower[512];
	char sidecar[512];
	char lower_file[512];
	char upper_file[512];
	char secret[512];
	char chmod_race[512];
	char chmod_payload[512];
	char merged_upper[512];
	char merged_lower[512];
	char recursive_upper[512];
	char recursive_lower[512];
	char recursive_lower_child[512];
	char parent0300_upper[512];
	char parent0300_lower[512];
	char parent0300_upper_child[512];
	char parent0300_lower_child[512];
	char hostile_lower[512];
	char hostile_upper[512];
	char opaque_upper[512];
	char opaque_lower[512];
	char opaque_hidden[512];
	join_path(upper, sizeof(upper), root, "/upper");
	join_path(lower, sizeof(lower), root, "/lower");
	join_path(sidecar, sizeof(sidecar), root, "/sidecar");
	join_path(lower_file, sizeof(lower_file), lower, "/deleted");
	join_path(upper_file, sizeof(upper_file), upper, "/deleted");
	join_path(secret, sizeof(secret), upper, "/secret");
	join_path(protected_payload, sizeof(protected_payload), secret, "/payload");
	join_path(chmod_race, sizeof(chmod_race), upper, "/chmod-race");
	join_path(chmod_payload, sizeof(chmod_payload),
		chmod_race, "/payload");
	join_path(merged_upper, sizeof(merged_upper), upper, "/merged-empty");
	join_path(merged_lower, sizeof(merged_lower), lower, "/merged-empty");
	join_path(recursive_upper, sizeof(recursive_upper),
		upper, "/recursive");
	join_path(recursive_lower, sizeof(recursive_lower),
		lower, "/recursive");
	join_path(recursive_lower_child, sizeof(recursive_lower_child),
		lower, "/recursive/child");
	join_path(parent0300_upper, sizeof(parent0300_upper),
		upper, "/parent0300");
	join_path(parent0300_lower, sizeof(parent0300_lower),
		lower, "/parent0300");
	join_path(parent0300_upper_child, sizeof(parent0300_upper_child),
		upper, "/parent0300/child");
	join_path(parent0300_lower_child, sizeof(parent0300_lower_child),
		lower, "/parent0300/child");
	join_path(hostile_lower, sizeof(hostile_lower),
		lower, "/hostile-umask");
	join_path(hostile_upper, sizeof(hostile_upper),
		upper, "/hostile-umask");
	join_path(opaque_upper, sizeof(opaque_upper),
		upper, "/opaque-parent");
	join_path(opaque_lower, sizeof(opaque_lower),
		lower, "/opaque-parent");
	join_path(opaque_hidden, sizeof(opaque_hidden),
		lower, "/opaque-parent/hidden");
	if (mkdir(upper, 0700) || mkdir(lower, 0700) || mkdir(sidecar, 0700)) {
		perror("mkdir");
		return 2;
	}

	struct eunion_sidecar_runtime runtime = {
		.upper_root = upper,
		.lower_root = lower,
		.sidecar_root = sidecar,
	};
	check(eunion_sidecar_test_write_prefix_state(&runtime) == 0,
		"write sidecar-v1 prefix state");
	check(eunion_sidecar_initialize(&runtime) == 0,
		"initialize external sidecar");
	check(mkdir(secret, 0700) == 0,
		"create protected directory after format activation");

	make_file(lower_file, "lower");
	int result = eunion_sidecar_remove_path(&runtime, "/deleted", 0);
	struct stat status;
	int physical_whiteout = lstat(upper_file, &status) == 0;
	check(result == 0, "lower-only unlink must succeed");
	check(!physical_whiteout,
		"new unlink must not publish a physical whiteout object");

	make_file(protected_payload, "secret");
	if (chmod(secret, 0000) != 0 || lstat(secret, &status) != 0) {
		perror("protect secret directory");
		return 2;
	}
	struct timespec before_ctime = status.st_ctim;
	protected_payload_read = 0;
	result = eunion_sidecar_remove_path(&runtime, "/secret", 1);
	if (lstat(secret, &status) != 0) {
		perror("stat protected directory");
		return 2;
	}
	int ctime_preserved =
		before_ctime.tv_sec == status.st_ctim.tv_sec &&
		before_ctime.tv_nsec == status.st_ctim.tv_nsec;
	check(result == -ENOTEMPTY,
		"mode-000 nonempty rmdir must return ENOTEMPTY");
	check(protected_payload_read == 0,
		"concurrent code must not gain read access during failed rmdir");
	check((status.st_mode & 0777) == 0000,
		"failed rmdir must preserve the exact directory mode");
	check(ctime_preserved,
		"failed rmdir must preserve directory ctime");

	check(mkdir(chmod_race, 0700) == 0,
		"create concurrent chmod directory");
	make_file(chmod_payload, "payload");
	concurrent_directory = open(chmod_race,
		O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	check(concurrent_directory >= 0,
		"retain directory capability before chmod");
	check(chmod(chmod_race, 0000) == 0,
		"protect concurrent chmod directory");
	concurrent_chmod_count = 0;
	eunion_test_sidecar_checkpoint_hook = sidecar_checkpoint_hook;
	result = eunion_sidecar_remove_path(&runtime, "/chmod-race", 1);
	eunion_test_sidecar_checkpoint_hook = NULL;
	check(lstat(chmod_race, &status) == 0,
		"concurrent chmod directory remains after ENOTEMPTY");
	check(result == -ENOTEMPTY,
		"concurrent chmod rmdir returns ENOTEMPTY");
	check(concurrent_chmod_count == 1,
		"concurrent chmod executes at exact pre-backing boundary");
	check((status.st_mode & 0777) == 0711,
		"successful concurrent chmod remains authoritative");
	int concurrent_chmod_lost = (status.st_mode & 0777) != 0711;
	check(close(concurrent_directory) == 0,
		"close concurrent directory capability");
	concurrent_directory = -1;

	check(mkdir(merged_upper, 0700) == 0 &&
		mkdir(merged_lower, 0700) == 0,
		"create merged empty directory pair");
	check(chmod(merged_upper, 0000) == 0,
		"protect merged empty upper");
	result = eunion_sidecar_remove_path(&runtime, "/merged-empty", 1);
	check(result == 0,
		"merged mode-000 empty rmdir succeeds");
	check(lstat(merged_upper, &status) == -1 && errno == ENOENT,
		"merged upper directory removed");
	check(lstat(merged_lower, &status) == 0 && S_ISDIR(status.st_mode),
		"merged lower directory preserved");
	check(sidecar_kind(&runtime, "/merged-empty") ==
		EUNION_SIDECAR_RECORD_WHITEOUT,
		"merged deletion exists only as sidecar whiteout");

	check(mkdir(recursive_upper, 0700) == 0 &&
		mkdir(recursive_lower, 0700) == 0,
		"create recursive directory pair");
	make_file(recursive_lower_child, "lower");
	result = eunion_sidecar_remove_path(&runtime, "/recursive/child", 0);
	check(result == 0, "lower child unlink succeeds");
	check(lstat(recursive_upper, &status) == 0 &&
		S_ISDIR(status.st_mode),
		"recursive upper parent remains physically empty");
	check(sidecar_kind(&runtime, "/recursive/child") ==
		EUNION_SIDECAR_RECORD_WHITEOUT,
		"child whiteout stored in sidecar");
	check(chmod(recursive_upper, 0000) == 0,
		"protect recursive upper parent");
	result = eunion_sidecar_remove_path(&runtime, "/recursive", 1);
	check(result == 0,
		"mode-000 parent rmdir succeeds after lower child unlink");
	check(sidecar_kind(&runtime, "/recursive") ==
		EUNION_SIDECAR_RECORD_WHITEOUT,
		"parent whiteout replaces sidecar subtree identity");

	check(mkdir(parent0300_upper, 0700) == 0 &&
		mkdir(parent0300_lower, 0700) == 0,
		"create mode-0300 merged parents");
	make_file(parent0300_upper_child, "upper");
	make_file(parent0300_lower_child, "lower");
	check(chmod(parent0300_upper, 0300) == 0 &&
		chmod(parent0300_lower, 0300) == 0,
		"remove read permission from merged parents");
	result = eunion_sidecar_remove_path(&runtime,
		"/parent0300/child", 0);
	check(result == 0, "unlink under mode-0300 merged parent succeeds");
	check(sidecar_kind(&runtime, "/parent0300/child") ==
		EUNION_SIDECAR_RECORD_WHITEOUT,
		"mode-0300 removal publishes typed whiteout");
	check(chmod(parent0300_upper, 0700) == 0 &&
		chmod(parent0300_lower, 0700) == 0,
		"restore mode-0300 fixture for cleanup");

	make_file(hostile_lower, "lower");
	mode_t old_umask = umask(0777);
	result = eunion_sidecar_remove_path(&runtime, "/hostile-umask", 0);
	umask(old_umask);
	check(result == 0, "hostile umask lower unlink succeeds");
	check(lstat(hostile_upper, &status) == -1 && errno == ENOENT,
		"hostile umask creates no physical placeholder");
	check(sidecar_kind(&runtime, "/hostile-umask") ==
		EUNION_SIDECAR_RECORD_WHITEOUT,
		"hostile umask sidecar record is valid");

	check(mkdir(opaque_upper, 0700) == 0 &&
		mkdir(opaque_lower, 0700) == 0,
		"create opaque ancestor pair");
	make_file(opaque_hidden, "lower");
	eunion_sidecar_view opaque_writer = {{0}};
	check(eunion_sidecar_view_open(opaque_writer, &runtime,
		EUNION_SIDECAR_ACCESS_EXCLUSIVE) == 0,
		"open opaque writer");
	check(eunion_sidecar_publish_opaque(
		opaque_writer, "/opaque-parent") == 0,
		"publish typed opaque ancestor");
	check(eunion_sidecar_view_close(opaque_writer) == 0,
		"close opaque writer");
	result = eunion_sidecar_remove_path(&runtime,
		"/opaque-parent/hidden", 0);
	check(result == -ENOENT,
		"opaque ancestor hides lower child from remove");
	check(sidecar_kind(&runtime, "/opaque-parent/hidden") ==
		EUNION_SIDECAR_RECORD_NONE,
		"opaque hidden child creates no sidecar record");

	printf("EUNION_SIDECAR_CONTRACT physical_whiteout=%d "
		"permission_lifts=0 payload_read=%d ctime_preserved=%d "
		"concurrent_chmod_lost=%d failures=%d\n",
		physical_whiteout, protected_payload_read,
		ctime_preserved, concurrent_chmod_lost, failures);
	cleanup(root, secret);
	return failures == 0 ? 0 : 1;
}
