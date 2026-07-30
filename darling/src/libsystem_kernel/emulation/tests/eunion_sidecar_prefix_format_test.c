#define _GNU_SOURCE

#include <linux_premigration/eunion_sidecar.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int checks;

static void require(int condition, const char* message)
{
	++checks;
	if (!condition) {
		fprintf(stderr,
			"eunion_sidecar_prefix_format_test: %s (errno=%d)\n",
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

static void write_file(const char* path)
{
	int descriptor = open(path,
		O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	require(descriptor >= 0, "create fixture file");
	require(write(descriptor, "x", 1) == 1, "write fixture file");
	require(fsync(descriptor) == 0, "fsync fixture file");
	require(close(descriptor) == 0, "close fixture file");
}

static void write_prefix_state(
	const char* upper, const char* sidecar)
{
	struct stat upper_status;
	struct stat sidecar_status;
	require(stat(upper, &upper_status) == 0 &&
		stat(sidecar, &sidecar_status) == 0,
		"stat prefix state roots");
	char path[512];
	join_path(path, sizeof(path), upper,
		"/.darling-prefix-state-v3");
	char content[1024];
	int length = snprintf(content, sizeof(content),
		"DARLING_PREFIX_STATE_V3\n"
		"schema_version=3\n"
		"runtime_mode=rootless-eunion\n"
		"generation=1\n"
		"prefix_device=%ju\n"
		"prefix_inode=%ju\n"
		"sidecar_device=%ju\n"
		"sidecar_inode=%ju\n"
		"owner_uid=%ju\n"
		"owner_gid=%ju\n"
		"provenance=darling-runtime-prefix-sidecar-v1\n",
		(uintmax_t)upper_status.st_dev,
		(uintmax_t)upper_status.st_ino,
		(uintmax_t)sidecar_status.st_dev,
		(uintmax_t)sidecar_status.st_ino,
		(uintmax_t)upper_status.st_uid,
		(uintmax_t)upper_status.st_gid);
	require(length > 0 && (size_t)length < sizeof(content),
		"format prefix state");
	int descriptor = open(path,
		O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	require(descriptor >= 0 &&
		write(descriptor, content, (size_t)length) == length &&
		fsync(descriptor) == 0 && close(descriptor) == 0,
		"publish prefix state fixture");
}

static void remove_tree(const char* root)
{
	char command[640];
	int length = snprintf(command, sizeof(command), "rm -rf -- '%s'", root);
	require(length > 0 && (size_t)length < sizeof(command),
		"cleanup command size");
	require(system(command) == 0, "cleanup");
}

int main(void)
{
	char root[] = "/tmp/eunion-sidecar-prefix-format.XXXXXX";
	require(mkdtemp(root) != NULL, "mkdtemp");
	char upper[512];
	char lower[512];
	char sidecar[512];
	char activation[512];
	char legacy_work[512];
	char legacy_payload[512];
	join_path(upper, sizeof(upper), root, "/upper");
	join_path(lower, sizeof(lower), root, "/lower");
	join_path(sidecar, sizeof(sidecar), root, "/sidecar");
	join_path(activation, sizeof(activation), sidecar,
		"/" EUNION_SIDECAR_ACTIVATION_NAME);
	join_path(legacy_work, sizeof(legacy_work), upper, "/.union-work");
	join_path(legacy_payload, sizeof(legacy_payload), upper, "/legacy");
	require(mkdir(upper, 0700) == 0, "mkdir upper");
	require(mkdir(lower, 0700) == 0, "mkdir lower");
	require(mkdir(sidecar, 0700) == 0, "mkdir sidecar");

	struct eunion_sidecar_runtime runtime = {
		.upper_root = upper,
		.lower_root = lower,
		.sidecar_root = sidecar,
	};
	struct eunion_prefix_format_inspection inspection;
	require(eunion_sidecar_inspect_prefix(&runtime, &inspection) == 0 &&
		inspection.verdict == EUNION_PREFIX_FORMAT_UNINITIALIZED,
		"empty sidecar is uninitialized before lifecycle validation");
	require(access(activation, F_OK) == -1 && errno == ENOENT,
		"inspection does not mutate unversioned prefix");

	require(mkdir(legacy_work, 0700) == 0, "mkdir legacy union work");
	write_file(legacy_payload);
	struct stat legacy_before;
	struct stat work_before;
	require(lstat(legacy_payload, &legacy_before) == 0 &&
		lstat(legacy_work, &work_before) == 0,
		"snapshot legacy prefix");
	require(eunion_sidecar_inspect_prefix(&runtime, &inspection) == 0 &&
		inspection.verdict == EUNION_PREFIX_FORMAT_UNINITIALIZED,
		"inspection does not infer format from guest-visible contents");
	struct stat legacy_after;
	struct stat work_after;
	require(lstat(legacy_payload, &legacy_after) == 0 &&
		lstat(legacy_work, &work_after) == 0 &&
		legacy_before.st_dev == legacy_after.st_dev &&
		legacy_before.st_ino == legacy_after.st_ino &&
		legacy_before.st_ctim.tv_sec == legacy_after.st_ctim.tv_sec &&
		legacy_before.st_ctim.tv_nsec == legacy_after.st_ctim.tv_nsec &&
		work_before.st_dev == work_after.st_dev &&
		work_before.st_ino == work_after.st_ino &&
		work_before.st_ctim.tv_sec == work_after.st_ctim.tv_sec &&
		work_before.st_ctim.tv_nsec == work_after.st_ctim.tv_nsec,
		"legacy inspection is byte-and-identity non-mutating");
	require(eunion_sidecar_initialize(&runtime) ==
			-EUNION_PREFIX_RECREATE_REQUIRED_ERROR,
		"unversioned prefix requires explicit lifecycle recreation");
	require(access(activation, F_OK) == -1 && errno == ENOENT,
		"failed initialize never partially activates sidecar");

	require(unlink(legacy_payload) == 0 && rmdir(legacy_work) == 0,
		"clear legacy fixture explicitly");
	write_prefix_state(upper, sidecar);
	require(eunion_sidecar_initialize(&runtime) == 0,
		"fresh prefix initializes directly as sidecar v1");
	require(eunion_sidecar_inspect_prefix(&runtime, &inspection) == 0 &&
		inspection.verdict == EUNION_PREFIX_FORMAT_VALID &&
		inspection.format_version == 1,
		"fresh sidecar prefix validates");
	struct stat status;
	require(lstat(activation, &status) == 0 && S_ISREG(status.st_mode) &&
		!S_ISLNK(status.st_mode) && (status.st_mode & 0777) == 0600,
		"activation is exact regular mode 0600");
	require(eunion_sidecar_initialize(&runtime) == 0,
		"initializer idempotently joins the published sidecar");

	int descriptor = open(activation, O_RDWR | O_CLOEXEC);
	require(descriptor >= 0, "open activation corruption fixture");
	unsigned char byte;
	require(pread(descriptor, &byte, 1, 8) == 1,
		"read activation version byte");
	byte ^= 0x80;
	require(pwrite(descriptor, &byte, 1, 8) == 1 &&
		fsync(descriptor) == 0 && close(descriptor) == 0,
		"durably corrupt activation");
	require(eunion_sidecar_inspect_prefix(&runtime, &inspection) == 0 &&
		inspection.verdict == EUNION_PREFIX_FORMAT_CORRUPT,
		"malformed activation fails closed as corrupt");

	printf("EUNION_SIDECAR_PREFIX_FORMAT_OK checks=%d\n", checks);
	remove_tree(root);
	return 0;
}
