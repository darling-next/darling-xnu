#define _GNU_SOURCE

#include <linux_premigration/eunion_sidecar.h>
#include "eunion_sidecar_test_support.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

enum primary_operation {
	PRIMARY_REMOVE = 0,
	PRIMARY_CREATE,
	PRIMARY_COPY_UP,
	PRIMARY_RENAME,
};

enum competing_operation {
	COMPETING_LOOKUP = 0,
	COMPETING_OPEN_CREATE,
	COMPETING_UNLINK,
	COMPETING_RMDIR,
	COMPETING_RENAME,
	COMPETING_COPY_UP,
	COMPETING_COUNT,
};

static enum eunion_sidecar_test_checkpoint pause_checkpoint;
static int checkpoint_ready = -1;
static int checkpoint_release = -1;
static int checks;

static void require(int condition, const char* message)
{
	if (condition) {
		++checks;
		return;
	}
	fprintf(stderr,
		"eunion_sidecar_concurrency_test: %s (errno=%d)\n",
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
	require(write(descriptor, "x", 1) == 1 &&
			fsync(descriptor) == 0 && close(descriptor) == 0,
		"persist fixture file");
}

static void send_byte(int descriptor)
{
	char byte = 'R';
	require(write(descriptor, &byte, 1) == 1,
		"send synchronization byte");
}

static void receive_byte(int descriptor)
{
	char byte;
	require(read(descriptor, &byte, 1) == 1,
		"receive synchronization byte");
}

static void send_result(int descriptor, int result)
{
	require(write(descriptor, &result, sizeof(result)) ==
			(ssize_t)sizeof(result),
		"send operation result");
}

static int receive_result(int descriptor)
{
	int result;
	require(read(descriptor, &result, sizeof(result)) ==
			(ssize_t)sizeof(result),
		"receive operation result");
	return result;
}

static void pause_at_checkpoint(
	enum eunion_sidecar_test_checkpoint checkpoint,
	const char* guest_path)
{
	(void)guest_path;
	if (checkpoint != pause_checkpoint)
		return;
	send_byte(checkpoint_ready);
	receive_byte(checkpoint_release);
}

static void require_blocked(int descriptor)
{
	struct pollfd event = {
		.fd = descriptor,
		.events = POLLIN,
	};
	int result;
	do {
		result = poll(&event, 1, 100);
	} while (result < 0 && errno == EINTR);
	require(result == 0,
		"concurrent operation escaped exclusive transaction lock");
}

static void wait_success(pid_t child, const char* message)
{
	int status;
	require(waitpid(child, &status, 0) == child &&
			WIFEXITED(status) && WEXITSTATUS(status) == 0,
		message);
}

static int run_competing(
	enum competing_operation operation,
	const struct eunion_sidecar_runtime* runtime)
{
	switch (operation) {
		case COMPETING_LOOKUP: {
			eunion_sidecar_view reader = {{0}};
			int result = eunion_sidecar_view_open(reader, runtime,
				EUNION_SIDECAR_ACCESS_SHARED);
			if (result < 0)
				return result;
			struct eunion_sidecar_lookup lookup;
			result = eunion_sidecar_lookup_path(
				reader, "/parallel-copy", &lookup);
			int close_result = eunion_sidecar_view_close(reader);
			return result < 0 ? result : close_result;
		}
		case COMPETING_OPEN_CREATE: {
			int descriptor = eunion_sidecar_open_create(runtime,
				"/parallel-create",
				O_WRONLY | O_CREAT | O_EXCL, 0600);
			if (descriptor < 0)
				return descriptor;
			return close(descriptor) == 0 ? 0 : -errno;
		}
		case COMPETING_UNLINK:
			return eunion_sidecar_remove_path(
				runtime, "/parallel-remove", 0);
		case COMPETING_RMDIR:
			return eunion_sidecar_remove_path(
				runtime, "/parallel-dir", 1);
		case COMPETING_RENAME:
			return eunion_sidecar_rename_path(
				runtime, "/parallel-old", "/parallel-new");
		case COMPETING_COPY_UP:
			return eunion_sidecar_copy_up(
				runtime, "/parallel-copy");
		case COMPETING_COUNT:
		default:
			return -EINVAL;
	}
}

static int run_primary(enum primary_operation operation,
	const struct eunion_sidecar_runtime* runtime)
{
	switch (operation) {
		case PRIMARY_REMOVE:
			return eunion_sidecar_remove_path(runtime, "/victim", 0);
		case PRIMARY_CREATE:
			return eunion_sidecar_mkdir_create(runtime, "/victim", 0700);
		case PRIMARY_COPY_UP:
			return eunion_sidecar_copy_up(runtime, "/victim");
		case PRIMARY_RENAME:
			return eunion_sidecar_rename_path(
				runtime, "/victim", "/renamed");
		default:
			return -EINVAL;
	}
}

static void run_case(enum primary_operation operation,
	enum eunion_sidecar_test_checkpoint checkpoint)
{
	char root[] = "/tmp/eunion-sidecar-concurrency.XXXXXX";
	require(mkdtemp(root) != NULL, "create concurrency fixture");
	char upper[512], lower[512], sidecar[512];
	char upper_victim[512], lower_victim[512];
	char parallel_remove[512], parallel_dir[512];
	char parallel_old[512], parallel_copy[512];
	join_path(upper, sizeof(upper), root, "/upper");
	join_path(lower, sizeof(lower), root, "/lower");
	join_path(sidecar, sizeof(sidecar), root, "/sidecar");
	join_path(upper_victim, sizeof(upper_victim), upper, "/victim");
	join_path(lower_victim, sizeof(lower_victim), lower, "/victim");
	join_path(parallel_remove, sizeof(parallel_remove),
		upper, "/parallel-remove");
	join_path(parallel_dir, sizeof(parallel_dir), upper, "/parallel-dir");
	join_path(parallel_old, sizeof(parallel_old), upper, "/parallel-old");
	join_path(parallel_copy, sizeof(parallel_copy), lower, "/parallel-copy");
	require(mkdir(upper, 0700) == 0 &&
			mkdir(lower, 0700) == 0 &&
			mkdir(sidecar, 0700) == 0,
		"create concurrency roots");
	struct eunion_sidecar_runtime runtime = {
		.upper_root = upper,
		.lower_root = lower,
		.sidecar_root = sidecar,
	};
	require(eunion_sidecar_test_write_prefix_state(&runtime) == 0 &&
			eunion_sidecar_initialize(&runtime) == 0,
		"initialize concurrency sidecar");
	if (operation == PRIMARY_REMOVE) {
		write_file(upper_victim);
		write_file(lower_victim);
	} else if (operation == PRIMARY_COPY_UP) {
		write_file(lower_victim);
	} else if (operation == PRIMARY_RENAME) {
		write_file(lower_victim);
		require(eunion_sidecar_copy_up(&runtime, "/victim") == 0,
			"copy up primary rename source");
	}
	write_file(parallel_remove);
	require(mkdir(parallel_dir, 0700) == 0,
		"create competing empty directory");
	int parallel_old_descriptor = eunion_sidecar_open_create(&runtime,
		"/parallel-old", O_WRONLY | O_CREAT | O_EXCL, 0600);
	require(parallel_old_descriptor >= 0 &&
			close(parallel_old_descriptor) == 0,
		"create competing rename source through sidecar");
	write_file(parallel_copy);

	int ready[2], release[2];
	require(pipe(ready) == 0 && pipe(release) == 0,
		"create primary checkpoint pipes");
	pid_t primary = fork();
	require(primary >= 0, "fork primary transaction");
	if (primary == 0) {
		pause_checkpoint = checkpoint;
		checkpoint_ready = ready[1];
		checkpoint_release = release[0];
		eunion_test_sidecar_checkpoint_hook = pause_at_checkpoint;
		int result = run_primary(operation, &runtime);
		_exit(result == 0 || result >= 0 ? 0 : 20);
	}
	receive_byte(ready[0]);

	pid_t competitors[COMPETING_COUNT];
	int completed[COMPETING_COUNT][2];
	for (int competitor = 0; competitor < COMPETING_COUNT; ++competitor) {
		require(pipe(completed[competitor]) == 0,
			"create competing completion pipe");
		competitors[competitor] = fork();
		require(competitors[competitor] >= 0,
			"fork competing operation");
		if (competitors[competitor] == 0) {
			int result = run_competing(
				(enum competing_operation)competitor, &runtime);
			send_result(completed[competitor][1], result);
			_exit(result >= 0 ? 0 : 30);
		}
		require_blocked(completed[competitor][0]);
	}
	send_byte(release[1]);
	wait_success(primary, "primary transaction failed");
	for (int competitor = 0; competitor < COMPETING_COUNT; ++competitor) {
		int result = receive_result(completed[competitor][0]);
		if (result < 0)
			fprintf(stderr,
				"competing operation=%d result=%d phase=%d primary=%d\n",
				competitor, result, checkpoint, operation);
		require(result >= 0,
			"competing operation failed after serialization");
		wait_success(competitors[competitor],
			"competing operation failed after serialization");
		close(completed[competitor][0]);
		close(completed[competitor][1]);
	}
	close(ready[0]);
	close(ready[1]);
	close(release[0]);
	close(release[1]);

	eunion_sidecar_view quiescent = {{0}};
	require(eunion_sidecar_view_open(quiescent, &runtime,
			EUNION_SIDECAR_ACCESS_EXCLUSIVE) == 0 &&
			eunion_sidecar_view_close(quiescent) == 0,
		"concurrent fixture did not recover to quiescent state");
	char command[640];
	require(snprintf(command, sizeof(command), "rm -rf -- '%s'", root) > 0,
		"construct concurrency cleanup");
	require(system(command) == 0, "remove concurrency fixture");
}

int main(void)
{
	static const enum eunion_sidecar_test_checkpoint remove_phases[] = {
		EUNION_SIDECAR_TEST_RESOLVED,
		EUNION_SIDECAR_TEST_JOURNAL_PREPARED,
		EUNION_SIDECAR_TEST_LOGICALLY_PUBLISHED,
		EUNION_SIDECAR_TEST_PRE_BACKING,
		EUNION_SIDECAR_TEST_BACKING_COMMITTED,
		EUNION_SIDECAR_TEST_DURABLE,
	};
	static const enum eunion_sidecar_test_checkpoint backing_first_phases[] = {
		EUNION_SIDECAR_TEST_RESOLVED,
		EUNION_SIDECAR_TEST_JOURNAL_PREPARED,
		EUNION_SIDECAR_TEST_PRE_BACKING,
		EUNION_SIDECAR_TEST_POST_BACKING_PRE_JOURNAL,
		EUNION_SIDECAR_TEST_BACKING_COMMITTED,
		EUNION_SIDECAR_TEST_DURABLE,
	};
	for (size_t phase = 0;
			phase < sizeof(remove_phases) / sizeof(remove_phases[0]);
			++phase)
		run_case(PRIMARY_REMOVE, remove_phases[phase]);
	for (enum primary_operation operation = PRIMARY_CREATE;
			operation <= PRIMARY_RENAME; ++operation) {
		for (size_t phase = 0;
				phase < sizeof(backing_first_phases) /
					sizeof(backing_first_phases[0]);
				++phase)
			run_case(operation, backing_first_phases[phase]);
	}
	printf("EUNION_SIDECAR_CONCURRENCY_OK checks=%d phases=24"
		" competing_operations=%d\n", checks, COMPETING_COUNT);
	return 0;
}
