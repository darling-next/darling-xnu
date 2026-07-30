#define _GNU_SOURCE

#include <linux_premigration/eunion_sidecar.h>
#include "eunion_sidecar_test_support.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

enum fault_operation {
	FAULT_REMOVE = 0,
	FAULT_CREATE,
	FAULT_COPY_UP,
	FAULT_RENAME,
};

static enum eunion_sidecar_test_checkpoint selected_checkpoint;
static int selected_errno;
static int fault_armed;
static int checks;

static void require(int condition, const char* message)
{
	if (condition) {
		++checks;
		return;
	}
	fprintf(stderr,
		"eunion_sidecar_fault_matrix_test: %s (errno=%d)\n",
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

static void arm_fsync_fault(
	enum eunion_sidecar_test_checkpoint checkpoint,
	const char* guest_path)
{
	if (checkpoint != selected_checkpoint ||
		strcmp(guest_path, "/victim") != 0 || fault_armed)
		return;
	fault_armed = 1;
	eunion_test_sidecar_fail_syscall = __NR_fsync;
	eunion_test_sidecar_fail_after = 1;
	eunion_test_sidecar_fail_errno = selected_errno;
}

static int run_operation(enum fault_operation operation,
	const struct eunion_sidecar_runtime* runtime)
{
	switch (operation) {
		case FAULT_REMOVE:
			return eunion_sidecar_remove_path(runtime, "/victim", 0);
		case FAULT_CREATE: {
			int descriptor = eunion_sidecar_open_create(runtime,
				"/victim", O_WRONLY | O_CREAT | O_EXCL, 0600);
			if (descriptor < 0)
				return descriptor;
			return close(descriptor) == 0 ? 0 : -errno;
		}
		case FAULT_COPY_UP:
			return eunion_sidecar_copy_up(runtime, "/victim");
		case FAULT_RENAME:
			return eunion_sidecar_rename_path(
				runtime, "/victim", "/renamed");
		default:
			return -EINVAL;
	}
}

static void require_quiescent(
	const struct eunion_sidecar_runtime* runtime,
	const char* journal, enum fault_operation operation,
	enum eunion_sidecar_test_checkpoint checkpoint, int failure_errno)
{
	eunion_sidecar_view recovery = {{0}};
	int recovery_result = eunion_sidecar_view_open(recovery, runtime,
		EUNION_SIDECAR_ACCESS_EXCLUSIVE);
	if (recovery_result < 0)
		fprintf(stderr,
			"recovery operation=%d checkpoint=%d injected=%d result=%d\n",
			operation, checkpoint, failure_errno, recovery_result);
	require(recovery_result == 0,
		"exclusive open failed to recover injected fault");
	require(eunion_sidecar_view_close(recovery) == 0,
		"close recovered fault fixture");
	struct stat status;
	require(lstat(journal, &status) == -1 && errno == ENOENT,
		"fault recovery retained transaction journal");
	eunion_sidecar_view repeated = {{0}};
	require(eunion_sidecar_view_open(repeated, runtime,
			EUNION_SIDECAR_ACCESS_EXCLUSIVE) == 0 &&
			eunion_sidecar_view_close(repeated) == 0,
		"fault recovery was not idempotent");
}

static enum eunion_sidecar_record_kind lookup_kind(
	const struct eunion_sidecar_runtime* runtime, const char* path)
{
	eunion_sidecar_view reader = {{0}};
	require(eunion_sidecar_view_open(reader, runtime,
			EUNION_SIDECAR_ACCESS_SHARED) == 0,
		"open fault result reader");
	struct eunion_sidecar_lookup lookup;
	require(eunion_sidecar_lookup_path(reader, path, &lookup) == 0,
		"lookup fault result");
	require(eunion_sidecar_view_close(reader) == 0,
		"close fault result reader");
	return lookup.kind;
}

static void require_coherent_result(
	enum fault_operation operation,
	const struct eunion_sidecar_runtime* runtime,
	const char* upper_victim, const char* upper_renamed)
{
	struct stat victim;
	struct stat renamed;
	int have_victim = lstat(upper_victim, &victim) == 0;
	int have_renamed = lstat(upper_renamed, &renamed) == 0;
	switch (operation) {
		case FAULT_REMOVE:
			require(lookup_kind(runtime, "/victim") ==
					(have_victim ? EUNION_SIDECAR_RECORD_NONE
						: EUNION_SIDECAR_RECORD_WHITEOUT),
				"remove fault left backing/record split");
			break;
		case FAULT_CREATE:
			require(lookup_kind(runtime, "/victim") ==
					(have_victim ? EUNION_SIDECAR_RECORD_NONE
						: EUNION_SIDECAR_RECORD_WHITEOUT),
				"create fault left backing/record split");
			break;
		case FAULT_COPY_UP:
			require(lookup_kind(runtime, "/victim") ==
					EUNION_SIDECAR_RECORD_NONE,
				"copy-up fault exposed internal record state");
			break;
		case FAULT_RENAME:
			require(have_victim != have_renamed,
				"rename fault did not converge to exactly one backing");
			require(lookup_kind(runtime, "/victim") ==
					(have_renamed ? EUNION_SIDECAR_RECORD_WHITEOUT
						: EUNION_SIDECAR_RECORD_NONE),
				"rename fault source record is incoherent");
			require(lookup_kind(runtime, "/renamed") ==
					EUNION_SIDECAR_RECORD_NONE,
				"rename fault destination record is incoherent");
			break;
	}
}

static void run_case(enum fault_operation operation,
	enum eunion_sidecar_test_checkpoint checkpoint, int failure_errno)
{
	char root[] = "/tmp/eunion-sidecar-fault-matrix.XXXXXX";
	require(mkdtemp(root) != NULL, "create fault-matrix fixture");
	char upper[512], lower[512], sidecar[512];
	char upper_victim[512], lower_victim[512], upper_renamed[512];
	char journal[512], staging[512];
	join_path(upper, sizeof(upper), root, "/upper");
	join_path(lower, sizeof(lower), root, "/lower");
	join_path(sidecar, sizeof(sidecar), root, "/sidecar");
	join_path(upper_victim, sizeof(upper_victim), upper, "/victim");
	join_path(lower_victim, sizeof(lower_victim), lower, "/victim");
	join_path(upper_renamed, sizeof(upper_renamed), upper, "/renamed");
	join_path(journal, sizeof(journal), sidecar, "/journal-v1");
	join_path(staging, sizeof(staging), sidecar, "/staging-v1/copyup-v1");
	require(mkdir(upper, 0700) == 0 &&
			mkdir(lower, 0700) == 0 &&
			mkdir(sidecar, 0700) == 0,
		"create fault-matrix roots");
	struct eunion_sidecar_runtime runtime = {
		.upper_root = upper,
		.lower_root = lower,
		.sidecar_root = sidecar,
	};
	require(eunion_sidecar_test_write_prefix_state(&runtime) == 0 &&
			eunion_sidecar_initialize(&runtime) == 0,
		"initialize fault-matrix sidecar");
	if (operation == FAULT_REMOVE) {
		write_file(upper_victim);
		write_file(lower_victim);
	} else if (operation == FAULT_CREATE) {
		write_file(lower_victim);
		eunion_sidecar_view writer = {{0}};
		require(eunion_sidecar_view_open(writer, &runtime,
				EUNION_SIDECAR_ACCESS_EXCLUSIVE) == 0 &&
				eunion_sidecar_publish_whiteout(
					writer, "/victim") == 0 &&
				eunion_sidecar_view_close(writer) == 0,
			"publish create precondition whiteout");
	} else if (operation == FAULT_COPY_UP) {
		write_file(lower_victim);
	} else {
		write_file(lower_victim);
		require(eunion_sidecar_copy_up(&runtime, "/victim") == 0,
			"copy up rename source");
	}

	selected_checkpoint = checkpoint;
	selected_errno = failure_errno;
	fault_armed = 0;
	eunion_test_sidecar_fail_syscall = -1;
	eunion_test_sidecar_fail_after = 0;
	eunion_test_sidecar_fail_errno = failure_errno;
	eunion_test_sidecar_checkpoint_hook = arm_fsync_fault;
	int result = run_operation(operation, &runtime);
	eunion_test_sidecar_checkpoint_hook = NULL;
	eunion_test_sidecar_fail_syscall = -1;
	eunion_test_sidecar_fail_after = 0;
	require(fault_armed,
		"operation did not reach selected transaction phase");
	require(result == -failure_errno,
		"injected operation failure was not propagated exactly");
	require_quiescent(
		&runtime, journal, operation, checkpoint, failure_errno);
	struct stat status;
	require(lstat(staging, &status) == -1 && errno == ENOENT,
		"fault recovery retained private copy-up staging");
	require_coherent_result(
		operation, &runtime, upper_victim, upper_renamed);

	char command[640];
	require(snprintf(command, sizeof(command), "rm -rf -- '%s'", root) > 0,
		"construct fault-matrix cleanup");
	require(system(command) == 0, "remove fault-matrix fixture");
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
	static const int failure_errnos[] = {EINTR, EIO};
	unsigned cases = 0;
	for (size_t failure = 0;
			failure < sizeof(failure_errnos) / sizeof(failure_errnos[0]);
			++failure) {
		for (size_t phase = 0;
				phase < sizeof(remove_phases) / sizeof(remove_phases[0]);
				++phase) {
			run_case(FAULT_REMOVE, remove_phases[phase],
				failure_errnos[failure]);
			++cases;
		}
		for (enum fault_operation operation = FAULT_CREATE;
				operation <= FAULT_RENAME; ++operation) {
			for (size_t phase = 0;
					phase < sizeof(backing_first_phases) /
						sizeof(backing_first_phases[0]);
					++phase) {
				run_case(operation, backing_first_phases[phase],
					failure_errnos[failure]);
				++cases;
			}
		}
	}
	require(cases == 48,
		"failure/EINTR operation-phase matrix was incomplete");
	printf("EUNION_SIDECAR_FAULT_MATRIX_OK checks=%d cases=%u"
		" errnos=EINTR,EIO\n", checks, cases);
	return 0;
}
