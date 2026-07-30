#define _GNU_SOURCE

#include <linux_premigration/eunion_sidecar.h>
#include "eunion_sidecar_test_support.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static enum eunion_sidecar_test_checkpoint kill_checkpoint;
static const char* kill_path = "/victim";
static int termination_signal = SIGKILL;
static enum eunion_sidecar_test_checkpoint fault_checkpoint;
static long fault_syscall;
static int fault_armed;
static int checks;

static void require(int condition, const char* message)
{
	if (condition) {
		++checks;
		return;
	}
	fprintf(stderr, "eunion_sidecar_recovery_test: %s (errno=%d)\n",
		message, errno);
	exit(1);
}

static void join_path(char* output, size_t capacity,
	const char* root, const char* suffix)
{
	int length = snprintf(output, capacity, "%s%s", root, suffix);
	require(length > 0 && (size_t)length < capacity, "construct path");
}

static void write_file(const char* path)
{
	int descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	require(descriptor >= 0, "create fixture file");
	require(write(descriptor, "x", 1) == 1, "write fixture file");
	require(fsync(descriptor) == 0, "fsync fixture file");
	require(close(descriptor) == 0, "close fixture file");
}

static void kill_at_boundary(
	enum eunion_sidecar_test_checkpoint checkpoint, const char* guest_path)
{
	if (checkpoint == kill_checkpoint && strcmp(guest_path, kill_path) == 0)
		kill(getpid(), termination_signal);
}

static void fail_at_boundary(
	enum eunion_sidecar_test_checkpoint checkpoint, const char* guest_path)
{
	if (checkpoint != fault_checkpoint ||
		strcmp(guest_path, "/victim") != 0 ||
		fault_armed)
		return;
	fault_armed = 1;
	eunion_test_sidecar_fail_syscall = fault_syscall;
	eunion_test_sidecar_fail_after = 1;
	eunion_test_sidecar_fail_errno = EINTR;
}

static void run_remove_fault(
	enum eunion_sidecar_test_checkpoint checkpoint, long syscall_number,
	int expect_committed)
{
	char root[] = "/tmp/eunion-sidecar-fault.XXXXXX";
	require(mkdtemp(root) != NULL, "create fault root");
	char upper[512], lower[512], sidecar[512];
	char upper_file[512], lower_file[512], journal[512];
	join_path(upper, sizeof(upper), root, "/upper");
	join_path(lower, sizeof(lower), root, "/lower");
	join_path(sidecar, sizeof(sidecar), root, "/sidecar");
	join_path(upper_file, sizeof(upper_file), upper, "/victim");
	join_path(lower_file, sizeof(lower_file), lower, "/victim");
	join_path(journal, sizeof(journal), sidecar, "/journal-v1");
	require(mkdir(upper, 0700) == 0, "create fault upper");
	require(mkdir(lower, 0700) == 0, "create fault lower");
	require(mkdir(sidecar, 0700) == 0, "create fault sidecar");
	struct eunion_sidecar_runtime runtime = {
		.upper_root = upper,
		.lower_root = lower,
		.sidecar_root = sidecar,
	};
	require(eunion_sidecar_test_write_prefix_state(&runtime) == 0,
		"write sidecar-v1 prefix state");
	require(eunion_sidecar_initialize(&runtime) == 0,
		"initialize fault sidecar");
	write_file(upper_file);
	write_file(lower_file);
	fault_checkpoint = checkpoint;
	fault_syscall = syscall_number;
	fault_armed = 0;
	eunion_test_sidecar_fail_syscall = -1;
	eunion_test_sidecar_fail_after = 0;
	eunion_test_sidecar_checkpoint_hook = fail_at_boundary;
	int remove_result = eunion_sidecar_remove_path(
		&runtime, "/victim", 0);
	eunion_test_sidecar_checkpoint_hook = NULL;
	eunion_test_sidecar_fail_syscall = -1;
	eunion_test_sidecar_fail_after = 0;
	if (remove_result != -EINTR)
		fprintf(stderr,
			"remove fault checkpoint=%d syscall=%ld result=%d\n",
			checkpoint, syscall_number, remove_result);
	require(remove_result == -EINTR,
		"injected syscall failure is preserved");

	eunion_sidecar_view recovery = {{0}};
	require(eunion_sidecar_view_open(recovery, &runtime,
		EUNION_SIDECAR_ACCESS_EXCLUSIVE) == 0,
		"fault recovery opens");
	require(eunion_sidecar_view_close(recovery) == 0,
		"fault recovery closes");
	struct stat status;
	require(lstat(journal, &status) == -1 && errno == ENOENT,
		"fault recovery consumes journal");
	require((lstat(upper_file, &status) == 0) == !expect_committed,
		"fault recovery backing direction is deterministic");
	eunion_sidecar_view reader = {{0}};
	require(eunion_sidecar_view_open(reader, &runtime,
		EUNION_SIDECAR_ACCESS_SHARED) == 0,
		"fault result reader opens");
	struct eunion_sidecar_lookup lookup;
	require(eunion_sidecar_lookup_path(
		reader, "/victim", &lookup) == 0,
		"fault result lookup");
	require(lookup.kind == (expect_committed
			? EUNION_SIDECAR_RECORD_WHITEOUT
			: EUNION_SIDECAR_RECORD_NONE),
		"fault result record direction is deterministic");
	require(eunion_sidecar_view_close(reader) == 0,
		"fault result reader closes");

	char command[640];
	int length = snprintf(command, sizeof(command), "rm -rf -- '%s'", root);
	require(length > 0 && (size_t)length < sizeof(command),
		"construct fault cleanup command");
	require(system(command) == 0, "remove fault root");
}

static void run_boundary(enum eunion_sidecar_test_checkpoint checkpoint,
	int expect_committed)
{
	char root[] = "/tmp/eunion-sidecar-recovery.XXXXXX";
	require(mkdtemp(root) != NULL, "create recovery root");
	char upper[512], lower[512], sidecar[512];
	char upper_file[512], lower_file[512], journal[512], lock[512];
	join_path(upper, sizeof(upper), root, "/upper");
	join_path(lower, sizeof(lower), root, "/lower");
	join_path(sidecar, sizeof(sidecar), root, "/sidecar");
	join_path(upper_file, sizeof(upper_file), upper, "/victim");
	join_path(lower_file, sizeof(lower_file), lower, "/victim");
	join_path(journal, sizeof(journal), sidecar, "/journal-v1");
	join_path(lock, sizeof(lock), sidecar, "/lock-v1");
	require(mkdir(upper, 0700) == 0, "create upper root");
	require(mkdir(lower, 0700) == 0, "create lower root");
	require(mkdir(sidecar, 0700) == 0, "create sidecar root");
	write_file(lower_file);
	struct eunion_sidecar_runtime runtime = {
		.upper_root = upper,
		.lower_root = lower,
		.sidecar_root = sidecar,
	};
	require(eunion_sidecar_test_write_prefix_state(&runtime) == 0,
		"write sidecar-v1 prefix state");
	require(eunion_sidecar_initialize(&runtime) == 0,
		"initialize recovery sidecar");
	write_file(upper_file);
	struct stat lock_before;
	require(lstat(lock, &lock_before) == 0, "snapshot persistent lock");

	pid_t child = fork();
	require(child >= 0, "fork boundary child");
	if (child == 0) {
		kill_path = "/victim";
		kill_checkpoint = checkpoint;
		eunion_test_sidecar_checkpoint_hook = kill_at_boundary;
		(void)eunion_sidecar_remove_path(&runtime, "/victim", 0);
		_exit(90);
	}
	int status;
	require(waitpid(child, &status, 0) == child, "wait boundary child");
	require(WIFSIGNALED(status) && WTERMSIG(status) == termination_signal,
		"child is killed at durable boundary");
	struct stat file_status;
	require(lstat(journal, &file_status) == 0, "journal survives SIGKILL");

	eunion_sidecar_view recovery = {{0}};
	int recovery_result = eunion_sidecar_view_open(recovery, &runtime,
		EUNION_SIDECAR_ACCESS_EXCLUSIVE);
	if (recovery_result < 0)
		fprintf(stderr, "recovery checkpoint=%d result=%d\n",
			(int)checkpoint, recovery_result);
	require(recovery_result == 0,
		"exclusive open performs recovery");
	require(eunion_sidecar_view_close(recovery) == 0,
		"close recovered view");
	require(lstat(journal, &file_status) == -1 && errno == ENOENT,
		"recovery consumes journal");
	require((lstat(upper_file, &file_status) == 0) == !expect_committed,
		"backing state matches recovery direction");

	eunion_sidecar_view reader = {{0}};
	require(eunion_sidecar_view_open(reader, &runtime,
		EUNION_SIDECAR_ACCESS_SHARED) == 0, "open recovered reader");
	struct eunion_sidecar_lookup lookup;
	require(eunion_sidecar_lookup_path(reader, "/victim", &lookup) == 0,
		"lookup recovered record");
	require(lookup.kind == (expect_committed
			? EUNION_SIDECAR_RECORD_WHITEOUT
			: EUNION_SIDECAR_RECORD_NONE),
		"record state matches recovery direction");
	require(eunion_sidecar_view_close(reader) == 0,
		"close recovered reader");

	eunion_sidecar_view repeated = {{0}};
	require(eunion_sidecar_view_open(repeated, &runtime,
		EUNION_SIDECAR_ACCESS_EXCLUSIVE) == 0,
		"second recovery is idempotent");
	require(eunion_sidecar_view_close(repeated) == 0,
		"close idempotent recovery");
	struct stat lock_after;
	require(lstat(lock, &lock_after) == 0 &&
		lock_before.st_dev == lock_after.st_dev &&
		lock_before.st_ino == lock_after.st_ino,
		"persistent lock inode is never replaced");

	char command[640];
	int length = snprintf(command, sizeof(command), "rm -rf -- '%s'", root);
	require(length > 0 && (size_t)length < sizeof(command),
		"construct cleanup command");
	require(system(command) == 0, "remove recovery root");
}

static void run_create_boundary(
	enum eunion_sidecar_test_checkpoint checkpoint, int expect_committed)
{
	char root[] = "/tmp/eunion-sidecar-create-recovery.XXXXXX";
	require(mkdtemp(root) != NULL, "create create-recovery root");
	char upper[512], lower[512], sidecar[512], created[512], journal[512];
	join_path(upper, sizeof(upper), root, "/upper");
	join_path(lower, sizeof(lower), root, "/lower");
	join_path(sidecar, sizeof(sidecar), root, "/sidecar");
	join_path(created, sizeof(created), upper, "/created");
	join_path(journal, sizeof(journal), sidecar, "/journal-v1");
	require(mkdir(upper, 0700) == 0, "create upper root");
	require(mkdir(lower, 0700) == 0, "create lower root");
	require(mkdir(sidecar, 0700) == 0, "create sidecar root");
	struct eunion_sidecar_runtime runtime = {
		.upper_root = upper,
		.lower_root = lower,
		.sidecar_root = sidecar,
	};
	require(eunion_sidecar_test_write_prefix_state(&runtime) == 0,
		"write sidecar-v1 prefix state");
	require(eunion_sidecar_initialize(&runtime) == 0,
		"initialize create-recovery sidecar");

	pid_t child = fork();
	require(child >= 0, "fork create boundary child");
	if (child == 0) {
		kill_path = "/created";
		kill_checkpoint = checkpoint;
		eunion_test_sidecar_checkpoint_hook = kill_at_boundary;
		(void)eunion_sidecar_mkdir_create(
			&runtime, "/created", 0700);
		_exit(90);
	}
	int status;
	require(waitpid(child, &status, 0) == child,
		"wait create boundary child");
	require(WIFSIGNALED(status) && WTERMSIG(status) == termination_signal,
		"create child is killed at durable boundary");
	struct stat file_status;
	require(lstat(journal, &file_status) == 0,
		"create journal survives SIGKILL");
	eunion_sidecar_view recovery = {{0}};
	require(eunion_sidecar_view_open(recovery, &runtime,
		EUNION_SIDECAR_ACCESS_EXCLUSIVE) == 0,
		"exclusive open recovers interrupted create");
	require(eunion_sidecar_view_close(recovery) == 0,
		"close create recovery");
	require(lstat(journal, &file_status) == -1 && errno == ENOENT,
		"create recovery consumes journal");
	require((lstat(created, &file_status) == 0) == expect_committed,
		"create backing state matches recovery direction");
	eunion_sidecar_view reader = {{0}};
	require(eunion_sidecar_view_open(reader, &runtime,
		EUNION_SIDECAR_ACCESS_SHARED) == 0,
		"open create recovery reader");
	struct eunion_sidecar_lookup lookup;
	require(eunion_sidecar_lookup_path(
		reader, "/created", &lookup) == 0,
		"lookup recovered create");
	require(lookup.kind == EUNION_SIDECAR_RECORD_NONE,
		"created index is not exposed as marker state");
	require(eunion_sidecar_view_close(reader) == 0,
		"close create recovery reader");

	char command[640];
	int length = snprintf(command, sizeof(command), "rm -rf -- '%s'", root);
	require(length > 0 && (size_t)length < sizeof(command),
		"construct create cleanup command");
	require(system(command) == 0, "remove create recovery root");
}

static void run_copyup_boundary(
	enum eunion_sidecar_test_checkpoint checkpoint, int expect_committed)
{
	char root[] = "/tmp/eunion-sidecar-copyup-recovery.XXXXXX";
	require(mkdtemp(root) != NULL, "create copyup-recovery root");
	char upper[512], lower[512], sidecar[512];
	char upper_file[512], lower_file[512], journal[512], staging[512];
	join_path(upper, sizeof(upper), root, "/upper");
	join_path(lower, sizeof(lower), root, "/lower");
	join_path(sidecar, sizeof(sidecar), root, "/sidecar");
	join_path(upper_file, sizeof(upper_file), upper, "/copied");
	join_path(lower_file, sizeof(lower_file), lower, "/copied");
	join_path(journal, sizeof(journal), sidecar, "/journal-v1");
	join_path(staging, sizeof(staging), sidecar,
		"/staging-v1/copyup-v1");
	require(mkdir(upper, 0700) == 0, "create upper root");
	require(mkdir(lower, 0700) == 0, "create lower root");
	require(mkdir(sidecar, 0700) == 0, "create sidecar root");
	write_file(lower_file);
	struct eunion_sidecar_runtime runtime = {
		.upper_root = upper,
		.lower_root = lower,
		.sidecar_root = sidecar,
	};
	require(eunion_sidecar_test_write_prefix_state(&runtime) == 0,
		"write sidecar-v1 prefix state");
	require(eunion_sidecar_initialize(&runtime) == 0,
		"initialize copyup-recovery sidecar");

	pid_t child = fork();
	require(child >= 0, "fork copyup boundary child");
	if (child == 0) {
		kill_path = "/copied";
		kill_checkpoint = checkpoint;
		eunion_test_sidecar_checkpoint_hook = kill_at_boundary;
		(void)eunion_sidecar_copy_up(&runtime, "/copied");
		_exit(90);
	}
	int status;
	require(waitpid(child, &status, 0) == child,
		"wait copyup boundary child");
	require(WIFSIGNALED(status) && WTERMSIG(status) == termination_signal,
		"copyup child is killed at durable boundary");
	struct stat file_status;
	require(lstat(journal, &file_status) == 0,
		"copyup journal survives SIGKILL");
	eunion_sidecar_view recovery = {{0}};
	require(eunion_sidecar_view_open(recovery, &runtime,
		EUNION_SIDECAR_ACCESS_EXCLUSIVE) == 0,
		"exclusive open recovers interrupted copyup");
	require(eunion_sidecar_view_close(recovery) == 0,
		"close copyup recovery");
	require(lstat(journal, &file_status) == -1 && errno == ENOENT,
		"copyup recovery consumes journal");
	require(lstat(staging, &file_status) == -1 && errno == ENOENT,
		"copyup recovery removes private staging");
	require((lstat(upper_file, &file_status) == 0) == expect_committed,
		"copyup backing state matches recovery direction");
	if (expect_committed) {
		char value = '\0';
		int descriptor = open(upper_file, O_RDONLY | O_CLOEXEC);
		require(descriptor >= 0 && read(descriptor, &value, 1) == 1 &&
			value == 'x' && close(descriptor) == 0,
			"recovered copyup preserves content");
	}

	char command[640];
	int length = snprintf(command, sizeof(command), "rm -rf -- '%s'", root);
	require(length > 0 && (size_t)length < sizeof(command),
		"construct copyup cleanup command");
	require(system(command) == 0, "remove copyup recovery root");
}

static void run_rename_boundary(
	enum eunion_sidecar_test_checkpoint checkpoint, int expect_committed)
{
	char root[] = "/tmp/eunion-sidecar-rename-recovery.XXXXXX";
	require(mkdtemp(root) != NULL, "create rename-recovery root");
	char upper[512], lower[512], sidecar[512];
	char old_upper[512], new_upper[512], old_lower[512], journal[512];
	join_path(upper, sizeof(upper), root, "/upper");
	join_path(lower, sizeof(lower), root, "/lower");
	join_path(sidecar, sizeof(sidecar), root, "/sidecar");
	join_path(old_upper, sizeof(old_upper), upper, "/old");
	join_path(new_upper, sizeof(new_upper), upper, "/new");
	join_path(old_lower, sizeof(old_lower), lower, "/old");
	join_path(journal, sizeof(journal), sidecar, "/journal-v1");
	require(mkdir(upper, 0700) == 0, "create upper root");
	require(mkdir(lower, 0700) == 0, "create lower root");
	require(mkdir(sidecar, 0700) == 0, "create sidecar root");
	write_file(old_lower);
	struct eunion_sidecar_runtime runtime = {
		.upper_root = upper,
		.lower_root = lower,
		.sidecar_root = sidecar,
	};
	require(eunion_sidecar_test_write_prefix_state(&runtime) == 0,
		"write sidecar-v1 prefix state");
	require(eunion_sidecar_initialize(&runtime) == 0,
		"initialize rename-recovery sidecar");
	require(eunion_sidecar_copy_up(&runtime, "/old") == 0,
		"copy up rename source");

	pid_t child = fork();
	require(child >= 0, "fork rename boundary child");
	if (child == 0) {
		kill_path = "/old";
		kill_checkpoint = checkpoint;
		eunion_test_sidecar_checkpoint_hook = kill_at_boundary;
		(void)eunion_sidecar_rename_path(&runtime, "/old", "/new");
		_exit(90);
	}
	int status;
	require(waitpid(child, &status, 0) == child,
		"wait rename boundary child");
	require(WIFSIGNALED(status) && WTERMSIG(status) == termination_signal,
		"rename child is killed at durable boundary");
	struct stat file_status;
	require(lstat(journal, &file_status) == 0,
		"rename journal survives SIGKILL");
	eunion_sidecar_view recovery = {{0}};
	require(eunion_sidecar_view_open(recovery, &runtime,
		EUNION_SIDECAR_ACCESS_EXCLUSIVE) == 0,
		"exclusive open recovers interrupted rename");
	require(eunion_sidecar_view_close(recovery) == 0,
		"close rename recovery");
	require(lstat(journal, &file_status) == -1 && errno == ENOENT,
		"rename recovery consumes journal");
	require((lstat(old_upper, &file_status) == 0) == !expect_committed,
		"rename source backing matches recovery direction");
	require((lstat(new_upper, &file_status) == 0) == expect_committed,
		"rename destination backing matches recovery direction");

	eunion_sidecar_view reader = {{0}};
	require(eunion_sidecar_view_open(reader, &runtime,
		EUNION_SIDECAR_ACCESS_SHARED) == 0,
		"open rename recovery reader");
	struct eunion_sidecar_lookup old_lookup;
	struct eunion_sidecar_lookup new_lookup;
	require(eunion_sidecar_lookup_path(
		reader, "/old", &old_lookup) == 0,
		"lookup recovered rename source");
	require(eunion_sidecar_lookup_path(
		reader, "/new", &new_lookup) == 0,
		"lookup recovered rename destination");
	require(old_lookup.kind == (expect_committed
			? EUNION_SIDECAR_RECORD_WHITEOUT
			: EUNION_SIDECAR_RECORD_NONE),
		"rename source record matches recovery direction");
	require(new_lookup.kind == EUNION_SIDECAR_RECORD_NONE,
		"rename destination record matches recovery direction");
	require(eunion_sidecar_view_close(reader) == 0,
		"close rename recovery reader");

	char command[640];
	int length = snprintf(command, sizeof(command), "rm -rf -- '%s'", root);
	require(length > 0 && (size_t)length < sizeof(command),
		"construct rename cleanup command");
	require(system(command) == 0, "remove rename recovery root");
}

static void run_merged_copyup_boundary(
	enum eunion_sidecar_test_checkpoint checkpoint)
{
	char root[] = "/tmp/eunion-sidecar-merged-recovery.XXXXXX";
	require(mkdtemp(root) != NULL, "create merged-recovery root");
	char upper[512], lower[512], sidecar[512], journal[512];
	char upper_tree[512], lower_tree[512];
	char upper_child[512], lower_child[512], copied_child[512];
	join_path(upper, sizeof(upper), root, "/upper");
	join_path(lower, sizeof(lower), root, "/lower");
	join_path(sidecar, sizeof(sidecar), root, "/sidecar");
	join_path(journal, sizeof(journal), sidecar, "/journal-v1");
	join_path(upper_tree, sizeof(upper_tree), upper, "/merged");
	join_path(lower_tree, sizeof(lower_tree), lower, "/merged");
	join_path(upper_child, sizeof(upper_child),
		upper_tree, "/upper-child");
	join_path(lower_child, sizeof(lower_child),
		lower_tree, "/lower-child");
	join_path(copied_child, sizeof(copied_child),
		upper_tree, "/lower-child");
	require(mkdir(upper, 0700) == 0 &&
		mkdir(lower, 0700) == 0 &&
		mkdir(sidecar, 0700) == 0 &&
		mkdir(upper_tree, 0700) == 0 &&
		mkdir(lower_tree, 0700) == 0,
		"create merged recovery directories");
	write_file(upper_child);
	write_file(lower_child);
	struct eunion_sidecar_runtime runtime = {
		.upper_root = upper,
		.lower_root = lower,
		.sidecar_root = sidecar,
	};
	require(eunion_sidecar_test_write_prefix_state(&runtime) == 0,
		"write merged sidecar-v1 prefix state");
	require(eunion_sidecar_initialize(&runtime) == 0,
		"initialize merged recovery sidecar");

	pid_t child = fork();
	require(child >= 0, "fork merged copyup boundary child");
	if (child == 0) {
		kill_path = "/merged";
		kill_checkpoint = checkpoint;
		eunion_test_sidecar_checkpoint_hook = kill_at_boundary;
		(void)eunion_sidecar_copy_up_tree(&runtime, "/merged");
		_exit(90);
	}
	int child_status;
	require(waitpid(child, &child_status, 0) == child,
		"wait merged copyup boundary child");
	require(WIFSIGNALED(child_status) &&
		WTERMSIG(child_status) == termination_signal,
		"merged child is killed at durable boundary");
	struct stat status;
	require(lstat(journal, &status) == 0,
		"merged materialization journal survives interruption");

	eunion_sidecar_view recovery = {{0}};
	int recovery_result = eunion_sidecar_view_open(recovery, &runtime,
		EUNION_SIDECAR_ACCESS_EXCLUSIVE);
	if (recovery_result < 0)
		fprintf(stderr,
			"merged recovery checkpoint=%d result=%d\n",
			(int)checkpoint, recovery_result);
	require(recovery_result == 0,
		"exclusive open recovers merged materialization");
	require(eunion_sidecar_view_close(recovery) == 0,
		"close merged recovery");
	require(lstat(journal, &status) == -1 && errno == ENOENT,
		"merged recovery consumes journal");
	require(lstat(upper_child, &status) == 0 &&
		lstat(copied_child, &status) == 0,
		"merged recovery preserves upper child and materializes lower child");
	eunion_sidecar_view repeated = {{0}};
	require(eunion_sidecar_view_open(repeated, &runtime,
		EUNION_SIDECAR_ACCESS_EXCLUSIVE) == 0 &&
		eunion_sidecar_view_close(repeated) == 0,
		"merged recovery is idempotent");

	char command[640];
	int length = snprintf(command, sizeof(command), "rm -rf -- '%s'", root);
	require(length > 0 && (size_t)length < sizeof(command),
		"construct merged cleanup command");
	require(system(command) == 0, "remove merged recovery root");
}

static void run_all_boundaries(void)
{
	run_boundary(EUNION_SIDECAR_TEST_JOURNAL_PREPARED, 0);
	run_boundary(EUNION_SIDECAR_TEST_LOGICALLY_PUBLISHED, 0);
	run_boundary(EUNION_SIDECAR_TEST_BACKING_COMMITTED, 1);
	run_boundary(EUNION_SIDECAR_TEST_DURABLE, 1);
	run_create_boundary(EUNION_SIDECAR_TEST_JOURNAL_PREPARED, 0);
	run_create_boundary(EUNION_SIDECAR_TEST_PRE_BACKING, 0);
	run_create_boundary(EUNION_SIDECAR_TEST_POST_BACKING_PRE_JOURNAL, 1);
	run_create_boundary(EUNION_SIDECAR_TEST_BACKING_COMMITTED, 1);
	run_create_boundary(EUNION_SIDECAR_TEST_DURABLE, 1);
	run_copyup_boundary(EUNION_SIDECAR_TEST_JOURNAL_PREPARED, 0);
	run_copyup_boundary(EUNION_SIDECAR_TEST_PRE_BACKING, 0);
	run_copyup_boundary(EUNION_SIDECAR_TEST_POST_BACKING_PRE_JOURNAL, 1);
	run_copyup_boundary(EUNION_SIDECAR_TEST_BACKING_COMMITTED, 1);
	run_copyup_boundary(EUNION_SIDECAR_TEST_DURABLE, 1);
	run_rename_boundary(EUNION_SIDECAR_TEST_JOURNAL_PREPARED, 0);
	run_rename_boundary(EUNION_SIDECAR_TEST_PRE_BACKING, 0);
	run_rename_boundary(EUNION_SIDECAR_TEST_POST_BACKING_PRE_JOURNAL, 1);
	run_rename_boundary(EUNION_SIDECAR_TEST_BACKING_COMMITTED, 1);
	run_rename_boundary(EUNION_SIDECAR_TEST_DURABLE, 1);
	run_merged_copyup_boundary(EUNION_SIDECAR_TEST_JOURNAL_PREPARED);
	run_merged_copyup_boundary(EUNION_SIDECAR_TEST_PRE_BACKING);
	run_merged_copyup_boundary(
		EUNION_SIDECAR_TEST_POST_BACKING_PRE_JOURNAL);
	run_merged_copyup_boundary(EUNION_SIDECAR_TEST_BACKING_COMMITTED);
	run_merged_copyup_boundary(EUNION_SIDECAR_TEST_DURABLE);
}

int main(void)
{
	termination_signal = SIGKILL;
	run_all_boundaries();
	termination_signal = SIGINT;
	run_all_boundaries();
	run_remove_fault(EUNION_SIDECAR_TEST_RESOLVED, __NR_openat, 0);
	run_remove_fault(
		EUNION_SIDECAR_TEST_RESOLVED, __NR_renameat, 0);
	run_remove_fault(
		EUNION_SIDECAR_TEST_JOURNAL_PREPARED, __NR_fsync, 0);
	run_remove_fault(
		EUNION_SIDECAR_TEST_PRE_BACKING, __NR_unlinkat, 0);
	run_remove_fault(
		EUNION_SIDECAR_TEST_LOGICALLY_PUBLISHED, __NR_fsync, 1);
	run_remove_fault(
		EUNION_SIDECAR_TEST_PRE_BACKING, __NR_fsync, 1);
	run_remove_fault(
		EUNION_SIDECAR_TEST_BACKING_COMMITTED, __NR_fsync, 1);
	run_remove_fault(
		EUNION_SIDECAR_TEST_DURABLE, __NR_unlinkat, 1);
	printf("EUNION_SIDECAR_RECOVERY_OK checks=%d boundaries=48"
		" sigkill=24 sigint=24 faults=8\n", checks);
	return 0;
}
