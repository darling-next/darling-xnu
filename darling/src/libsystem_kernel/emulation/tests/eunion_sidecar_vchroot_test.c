#define _GNU_SOURCE
#define TEST 1
#define EUNION 1

#define main eunion_embedded_vchroot_main
#include "../src/linux_premigration/vchroot_userspace.c"
#undef main

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "eunion_sidecar_test_support.h"

static int checks;

static void require(int condition, const char* message)
{
	if (condition) {
		++checks;
		return;
	}
	fprintf(stderr, "eunion_sidecar_vchroot_test: %s (errno=%d)\n",
		message, errno);
	exit(1);
}

static void make_file(const char* path, const char* contents)
{
	int descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	require(descriptor >= 0, "create fixture file");
	require(write(descriptor, contents, strlen(contents)) ==
		(ssize_t)strlen(contents), "write fixture file");
	require(fsync(descriptor) == 0, "fsync fixture file");
	require(close(descriptor) == 0, "close fixture file");
}

static int contains_name(const char* names, int count, const char* wanted)
{
	for (int index = 0; index < count; ++index) {
		if (strcmp(names, wanted) == 0)
			return 1;
		names += strlen(names) + 1;
	}
	return 0;
}

static void require_record_none(
	const struct eunion_sidecar_runtime* runtime,
	const char* path,
	const char* message)
{
	eunion_sidecar_view reader = {{0}};
	require(eunion_sidecar_view_open(reader, runtime,
		EUNION_SIDECAR_ACCESS_SHARED) == 0,
		"open record-retirement reader");
	struct eunion_sidecar_lookup lookup;
	require(eunion_sidecar_lookup_path(reader, path, &lookup) == 0 &&
		lookup.kind == EUNION_SIDECAR_RECORD_NONE, message);
	require(eunion_sidecar_view_close(reader) == 0,
		"close record-retirement reader");
}

int main(void)
{
	require(!eunion_sidecar_path_has_deleted_suffix(NULL, 0),
		"NULL sidecar path is not deleted");
	require(!eunion_sidecar_path_has_deleted_suffix("short", 5),
		"short sidecar path is not deleted");
	require(!eunion_sidecar_path_has_deleted_suffix(
		"/tmp/upper (deleted)/child", 26),
		"intermediate deleted text is not a suffix");
	static const char deleted_path[] = "/tmp/upper (deleted)";
	require(eunion_sidecar_path_has_deleted_suffix(
		deleted_path, (int)sizeof(deleted_path) - 1),
		"exact readlink deleted suffix is rejected");

	char root[] = "/tmp/eunion-sidecar-vchroot.XXXXXX";
	require(mkdtemp(root) != NULL, "create vchroot fixture");
	char upper[512], lower[512], sidecar[512];
	char lower_deleted[512], lower_copy[512], upper_copy[512];
	char upper_opaque[512], lower_opaque[512];
	char upper_visible[512], lower_hidden[512], legacy_work[512];
	char lower_recreate[512], upper_recreate[512];
	require(snprintf(upper, sizeof(upper), "%s/upper", root) > 0,
		"construct upper path");
	require(snprintf(lower, sizeof(lower), "%s/lower", root) > 0,
		"construct lower path");
	require(snprintf(sidecar, sizeof(sidecar),
		"%s/upper.eunion-sidecar-v1", root) > 0,
		"construct external sidecar path");
	require(snprintf(lower_deleted, sizeof(lower_deleted),
		"%s/deleted", lower) > 0, "construct deleted path");
	require(snprintf(lower_copy, sizeof(lower_copy),
		"%s/copied", lower) > 0, "construct lower copy path");
	require(snprintf(upper_copy, sizeof(upper_copy),
		"%s/copied", upper) > 0, "construct upper copy path");
	require(snprintf(upper_opaque, sizeof(upper_opaque),
		"%s/opaque", upper) > 0, "construct upper opaque path");
	require(snprintf(lower_opaque, sizeof(lower_opaque),
		"%s/opaque", lower) > 0, "construct lower opaque path");
	require(snprintf(upper_visible, sizeof(upper_visible),
		"%s/opaque/visible", upper) > 0, "construct upper visible path");
	require(snprintf(lower_hidden, sizeof(lower_hidden),
		"%s/opaque/hidden", lower) > 0, "construct lower hidden path");
	require(snprintf(legacy_work, sizeof(legacy_work),
		"%s/.union-work", upper) > 0, "construct legacy work path");
	require(snprintf(lower_recreate, sizeof(lower_recreate),
		"%s/recreate", lower) > 0, "construct lower recreate path");
	require(snprintf(upper_recreate, sizeof(upper_recreate),
		"%s/recreate", upper) > 0, "construct upper recreate path");
	require(mkdir(upper, 0700) == 0, "create upper root");
	require(mkdir(lower, 0700) == 0, "create lower root");
	require(mkdir(sidecar, 0700) == 0, "create sidecar root");
	make_file(lower_deleted, "lower");
	make_file(lower_copy, "copy");
	require(mkdir(lower_opaque, 0700) == 0, "create lower opaque");
	make_file(lower_hidden, "lower");
	make_file(lower_recreate, "lower");

	struct eunion_sidecar_runtime runtime = {
		.upper_root = upper,
		.lower_root = lower,
		.sidecar_root = sidecar,
	};
	memcpy(prefix_path, upper, strlen(upper) + 1);
	prefix_path_len = (int)strlen(prefix_path);
	set_libexec_path(lower);
	eunion_sidecar_path[0] = '\0';
	eunion_sidecar_path_len = -1;
	int upper_descriptor = open(
		upper, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	require(upper_descriptor >= 0, "open retained upper descriptor");
	require(eunion_init_from_prefix(upper_descriptor) ==
		-EUNION_PREFIX_RECREATE_REQUIRED_ERROR,
		"unversioned prefix fails with typed recreate verdict");
	struct stat status;
	require(lstat(sidecar, &status) == 0 && S_ISDIR(status.st_mode),
		"legacy rejection does not mutate sidecar root");
	require(eunion_sidecar_test_write_prefix_state(&runtime) == 0,
		"write sidecar-v1 prefix state");
	require(eunion_sidecar_initialize(&runtime) == 0,
		"initialize external sidecar");
	require(eunion_init_from_prefix(upper_descriptor) == 0 &&
		eunion_anchored_runtime.anchored,
		"versioned prefix activates exact external sidecar");
	require(mkdir(upper_opaque, 0700) == 0, "create upper opaque");
	make_file(upper_visible, "upper");

	require(eunion_sidecar_remove_path(
		&runtime, "/deleted", 0) == 0,
		"publish lower deletion through canonical remove");
	require(eunion_is_whiteout("/deleted") == 1,
		"vchroot whiteout lookup uses sidecar");
	char names[4096] = {0};
	int count = vchroot_readdir_merge("/", names, sizeof(names));
	require(count >= 0 && !contains_name(names, count, "deleted"),
		"merged readdir suppresses sidecar whiteout");
	struct vchroot_expand_args expanded = {
		.dfd = AT_FDCWD,
		.flags = 0,
	};
	strcpy(expanded.path, "/deleted");
	int expand_result = vchroot_expand(&expanded);
	if (expand_result != -ENOENT)
		fprintf(stderr, "expand_result=%d path=%s\n",
			expand_result, expanded.path);
	require(expand_result == -ENOENT,
		"component resolver suppresses sidecar whiteout");
	struct vchroot_expand_args sidecar_escape = {
		.dfd = AT_FDCWD,
		.flags = 0,
	};
	require(snprintf(sidecar_escape.path,
			sizeof(sidecar_escape.path),
			"/Volumes/SystemRoot%s", sidecar) > 0,
		"construct SystemRoot sidecar escape");
	require(vchroot_expand(&sidecar_escape) == -ENOENT,
		"SystemRoot escape cannot enter external sidecar");

	eunion_sidecar_view opaque = {{0}};
	require(eunion_sidecar_view_open(opaque, &runtime,
		EUNION_SIDECAR_ACCESS_EXCLUSIVE) == 0,
		"open opaque writer");
	require(eunion_sidecar_publish_opaque(opaque, "/opaque") == 0,
		"publish sidecar opacity");
	require(eunion_sidecar_view_close(opaque) == 0,
		"close opaque writer");
	memset(names, 0, sizeof(names));
	count = vchroot_readdir_merge("/opaque", names, sizeof(names));
	require(count == 1 && contains_name(names, count, "visible") &&
		!contains_name(names, count, "hidden"),
		"opaque sidecar record suppresses lower enumeration");

	require(vchroot_copyup("/copied") == 0,
		"copy-up succeeds with external sidecar staging");
	require(lstat(upper_copy, &status) == 0 && S_ISREG(status.st_mode),
		"copy-up publishes upper file");
	require(lstat(legacy_work, &status) == -1 && errno == ENOENT,
		"sidecar copy-up creates no guest-visible work directory");

	/* launchctl empty_dir() changes into the managed parent and calls the libc
	 * remove() path with a relative leaf.  Exercise the exact vchroot boundary
	 * used by unlink/rmdir before the syscall wrapper falls back to host unlink. */
	char relative_parent[512], relative_leaf[512];
	require(snprintf(relative_parent, sizeof(relative_parent),
		"%s/relative-remove", upper) > 0,
		"construct relative remove parent");
	require(snprintf(relative_leaf, sizeof(relative_leaf),
		"%s/leaf", relative_parent) > 0,
		"construct relative remove leaf");
	require(vchroot_mkdir_create("/relative-remove", 0700) == 0,
		"create indexed relative remove parent");
	int relative_fd = vchroot_open_create(
		"/relative-remove/leaf", O_WRONLY | O_CREAT | O_EXCL, 0600);
	require(relative_fd >= 0 && close(relative_fd) == 0,
		"create indexed relative remove leaf");
	int saved_cwd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	require(saved_cwd >= 0, "retain fixture cwd");
	require(chdir(relative_parent) == 0,
		"enter managed parent like launchctl empty_dir");
	int handled = 0;
	require(vchroot_remove_at(AT_FDCWD, "leaf", 0, &handled) == 0 && handled,
		"AT_FDCWD relative remove uses sidecar transaction");
	require(fchdir(saved_cwd) == 0 && close(saved_cwd) == 0,
		"restore fixture cwd");
	require(lstat(relative_leaf, &status) == -1 && errno == ENOENT,
		"relative remove retires backing");
	require_record_none(&runtime, "/relative-remove/leaf",
		"relative remove retires INDEX record");

	/* A real directory descriptor must resolve to the same canonical guest
	 * path and transaction as AT_FDCWD. */
	require(vchroot_mkdir_create("/relative-dirfd", 0700) == 0,
		"create indexed real-dirfd parent");
	int dirfd_leaf = vchroot_open_create(
		"/relative-dirfd/leaf", O_WRONLY | O_CREAT | O_EXCL, 0600);
	require(dirfd_leaf >= 0 && close(dirfd_leaf) == 0,
		"create indexed real-dirfd leaf");
	char real_dirfd_parent[512];
	require(snprintf(real_dirfd_parent, sizeof(real_dirfd_parent),
		"%s/relative-dirfd", upper) > 0,
		"construct real-dirfd parent");
	int real_dirfd = open(real_dirfd_parent,
		O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	require(real_dirfd >= 0, "open real managed dirfd");
	handled = 0;
	require(vchroot_remove_at(real_dirfd, "leaf", 0, &handled) == 0 &&
		handled, "real dirfd relative unlink uses sidecar transaction");
	require(close(real_dirfd) == 0, "close real managed dirfd");
	require_record_none(&runtime, "/relative-dirfd/leaf",
		"real dirfd unlink retires INDEX record");

	/* libc remove(3) chooses rmdir for a directory after launchctl has changed
	 * into its parent.  Exercise that directory arm at the syscall boundary. */
	require(vchroot_mkdir_create("/relative-rmdir", 0700) == 0,
		"create indexed relative-rmdir parent");
	require(vchroot_mkdir_create("/relative-rmdir/empty", 0700) == 0,
		"create indexed relative-rmdir leaf");
	char relative_rmdir_parent[512];
	require(snprintf(relative_rmdir_parent, sizeof(relative_rmdir_parent),
		"%s/relative-rmdir", upper) > 0,
		"construct relative-rmdir parent");
	saved_cwd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	require(saved_cwd >= 0 && chdir(relative_rmdir_parent) == 0,
		"enter relative-rmdir parent");
	handled = 0;
	require(vchroot_remove_at(AT_FDCWD, "empty", 1, &handled) == 0 &&
		handled, "AT_FDCWD relative rmdir uses sidecar transaction");
	require(fchdir(saved_cwd) == 0 && close(saved_cwd) == 0,
		"restore cwd after relative rmdir");
	require_record_none(&runtime, "/relative-rmdir/empty",
		"relative rmdir retires INDEX record");

	/* Exact launchctl boot-cleanup paths: /var/tmp/launchd is removed through
	 * the directory arm, while the two /var/run markers use the file arm. */
	require(vchroot_mkdir_create("/var", 0755) == 0,
		"create indexed var directory");
	require(vchroot_mkdir_create("/var/tmp", 01777) == 0,
		"create indexed var/tmp directory");
	require(vchroot_mkdir_create("/var/run", 0755) == 0,
		"create indexed var/run directory");
	require(vchroot_mkdir_create("/var/tmp/launchd", 0700) == 0,
		"create indexed launchd directory");
	char var_tmp[512];
	require(snprintf(var_tmp, sizeof(var_tmp), "%s/var/tmp", upper) > 0,
		"construct var/tmp backing path");
	saved_cwd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	require(saved_cwd >= 0 && chdir(var_tmp) == 0,
		"enter launchctl var/tmp cwd");
	handled = 0;
	require(vchroot_remove_at(AT_FDCWD, "launchd", 1, &handled) == 0 &&
		handled, "launchctl launchd rmdir uses record-to-ABSENT transaction");
	require(fchdir(saved_cwd) == 0 && close(saved_cwd) == 0,
		"restore cwd after launchd rmdir");
	require_record_none(&runtime, "/var/tmp/launchd",
		"launchd rmdir retires INDEX record");

	int utmpx_fd = vchroot_open_create(
		"/var/run/utmpx", O_WRONLY | O_CREAT | O_EXCL, 0664);
	require(utmpx_fd >= 0 && close(utmpx_fd) == 0,
		"create indexed utmpx marker");
	int starter_fd = vchroot_open_create(
		"/var/run/.systemStarterRunning",
		O_WRONLY | O_CREAT | O_EXCL, 0664);
	require(starter_fd >= 0 && close(starter_fd) == 0,
		"create indexed system-starter marker");
	char var_run[512];
	require(snprintf(var_run, sizeof(var_run), "%s/var/run", upper) > 0,
		"construct var/run backing path");
	saved_cwd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	require(saved_cwd >= 0 && chdir(var_run) == 0,
		"enter launchctl var/run cwd");
	handled = 0;
	require(vchroot_remove_at(AT_FDCWD, "utmpx", 0, &handled) == 0 &&
		handled, "launchctl utmpx unlink uses record-to-ABSENT transaction");
	require(fchdir(saved_cwd) == 0 && close(saved_cwd) == 0,
		"restore cwd after utmpx unlink");
	int var_run_fd = open(var_run,
		O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	require(var_run_fd >= 0, "open real var/run dirfd");
	handled = 0;
	require(vchroot_remove_at(var_run_fd, ".systemStarterRunning", 0,
		&handled) == 0 && handled,
		"real dirfd system-starter unlink uses record-to-ABSENT transaction");
	require(close(var_run_fd) == 0, "close real var/run dirfd");
	require_record_none(&runtime, "/var/run/utmpx",
		"utmpx unlink retires INDEX record");
	require_record_none(&runtime, "/var/run/.systemStarterRunning",
		"system-starter unlink retires INDEX record");

	eunion_sidecar_view recreate_writer = {{0}};
	require(eunion_sidecar_view_open(recreate_writer, &runtime,
		EUNION_SIDECAR_ACCESS_EXCLUSIVE) == 0,
		"open recreate whiteout writer");
	require(eunion_sidecar_publish_whiteout(
		recreate_writer, "/recreate") == 0,
		"publish recreate whiteout");
	require(eunion_sidecar_view_close(recreate_writer) == 0,
		"close recreate whiteout writer");
	int recreate_fd = vchroot_open_create(
		"/recreate", O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (recreate_fd < 0)
		fprintf(stderr, "recreate_fd=%d\n", recreate_fd);
	require(recreate_fd >= 0,
		"managed open-create commits through sidecar journal");
	require(write(recreate_fd, "new", 3) == 3 &&
		fsync(recreate_fd) == 0 && close(recreate_fd) == 0,
		"write recreated upper file");
	require(lstat(upper_recreate, &status) == 0 &&
		S_ISREG(status.st_mode),
		"recreate publishes upper backing");
	eunion_sidecar_view recreate_reader = {{0}};
	require(eunion_sidecar_view_open(recreate_reader, &runtime,
		EUNION_SIDECAR_ACCESS_SHARED) == 0,
		"open recreated reader");
	struct eunion_sidecar_lookup recreated_lookup;
	require(eunion_sidecar_lookup_path(recreate_reader,
		"/recreate", &recreated_lookup) == 0 &&
		recreated_lookup.kind == EUNION_SIDECAR_RECORD_NONE,
		"successful create retires whiteout atomically");
	require(eunion_sidecar_view_close(recreate_reader) == 0,
		"close recreated reader");
	require(eunion_sidecar_runtime_release(
			&eunion_anchored_runtime) == 0,
		"release anchored vchroot runtime");
	require(close(upper_descriptor) == 0,
		"close retained upper descriptor");

	char command[640];
	require(snprintf(command, sizeof(command), "rm -rf -- '%s'", root) > 0,
		"construct cleanup command");
	require(system(command) == 0, "remove vchroot fixture");
	printf("EUNION_SIDECAR_VCHROOT_OK checks=%d\n", checks);
	return 0;
}
