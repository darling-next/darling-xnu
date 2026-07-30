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

static int checks;

static void require(int condition, const char* message)
{
	++checks;
	if (!condition) {
		fprintf(stderr,
			"eunion_sidecar_corruption_test: %s (errno=%d)\n",
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

static void make_file(const char* path)
{
	int descriptor = open(path,
		O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	require(descriptor >= 0 &&
		write(descriptor, "lower", 5) == 5 &&
		fsync(descriptor) == 0 && close(descriptor) == 0,
		"create lower corruption fixture");
}

static void require_lookup_corruption(
	const struct eunion_sidecar_runtime* runtime)
{
	eunion_sidecar_view view = {{0}};
	require(eunion_sidecar_view_open(view, runtime,
		EUNION_SIDECAR_ACCESS_SHARED) == 0,
		"open corruption evidence view");
	struct eunion_sidecar_lookup lookup;
	require(eunion_sidecar_lookup_path(view, "/victim", &lookup) == -EIO,
		"corrupt or stale node did not fail closed");
	require(eunion_sidecar_view_close(view) == 0,
		"close corruption evidence view");
}

static void cleanup(const char* root)
{
	char command[640];
	int length = snprintf(command, sizeof(command), "rm -rf -- '%s'", root);
	require(length > 0 && (size_t)length < sizeof(command) &&
		system(command) == 0, "cleanup corruption fixture");
}

static void run_corruption(enum eunion_sidecar_test_corruption corruption)
{
	char root[] = "/tmp/eunion-sidecar-corruption.XXXXXX";
	require(mkdtemp(root) != NULL, "mkdtemp corruption fixture");
	char upper[512], lower[512], sidecar[512], victim[512];
	join_path(upper, sizeof(upper), root, "/upper");
	join_path(lower, sizeof(lower), root, "/lower");
	join_path(sidecar, sizeof(sidecar), root, "/sidecar");
	join_path(victim, sizeof(victim), lower, "/victim");
	require(mkdir(upper, 0700) == 0 &&
		mkdir(lower, 0700) == 0 &&
		mkdir(sidecar, 0700) == 0,
		"create corruption roots");
	make_file(victim);
	struct eunion_sidecar_runtime runtime = {
		.upper_root = upper,
		.lower_root = lower,
		.sidecar_root = sidecar,
	};
	require(eunion_sidecar_test_write_prefix_state(&runtime) == 0 &&
		eunion_sidecar_initialize(&runtime) == 0 &&
		eunion_sidecar_remove_path(&runtime, "/victim", 0) == 0,
		"publish corruption target");
	require(eunion_sidecar_test_corrupt_record(
		&runtime, "/victim", corruption) == 0,
		"inject bounded record corruption");
	require_lookup_corruption(&runtime);
	cleanup(root);
}

static void run_stale_identity(void)
{
	char root[] = "/tmp/eunion-sidecar-stale.XXXXXX";
	require(mkdtemp(root) != NULL, "mkdtemp stale fixture");
	char upper[512], lower[512], sidecar[512], victim[512], parked[512];
	join_path(upper, sizeof(upper), root, "/upper");
	join_path(lower, sizeof(lower), root, "/lower");
	join_path(sidecar, sizeof(sidecar), root, "/sidecar");
	join_path(victim, sizeof(victim), lower, "/victim");
	join_path(parked, sizeof(parked), lower, "/parked");
	require(mkdir(upper, 0700) == 0 &&
		mkdir(lower, 0700) == 0 &&
		mkdir(sidecar, 0700) == 0,
		"create stale roots");
	make_file(victim);
	struct eunion_sidecar_runtime runtime = {
		.upper_root = upper,
		.lower_root = lower,
		.sidecar_root = sidecar,
	};
	require(eunion_sidecar_test_write_prefix_state(&runtime) == 0 &&
		eunion_sidecar_initialize(&runtime) == 0 &&
		eunion_sidecar_remove_path(&runtime, "/victim", 0) == 0,
		"publish stale identity target");
	require(rename(victim, parked) == 0,
		"park original lower identity");
	make_file(victim);
	require_lookup_corruption(&runtime);
	cleanup(root);
}

int main(void)
{
	run_corruption(EUNION_SIDECAR_TEST_CORRUPT_TRUNCATE);
	run_corruption(EUNION_SIDECAR_TEST_CORRUPT_VERSION);
	run_corruption(EUNION_SIDECAR_TEST_CORRUPT_CHECKSUM);
	run_stale_identity();
	printf("EUNION_SIDECAR_CORRUPTION_OK checks=%d cases=4\n", checks);
	return 0;
}
