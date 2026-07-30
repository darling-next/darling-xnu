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
static char upper_remove[512];
static char remove_parked[512];
static char remove_replacement[512];
static char upper_create[512];
static char upper_copyup[512];
static char upper_rename[512];
static char rename_parked[512];
static char rename_replacement[512];

enum swap_case {
	SWAP_NONE,
	SWAP_REMOVE,
	SWAP_CREATE,
	SWAP_COPYUP,
	SWAP_RENAME,
};

static enum swap_case active_case;

static void require(int condition, const char* message)
{
	++checks;
	if (!condition) {
		fprintf(stderr, "eunion_sidecar_swap_test: %s (errno=%d)\n",
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

static void make_file(const char* path, const char* content)
{
	int descriptor = open(path,
		O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	require(descriptor >= 0, "create swap fixture");
	size_t length = strlen(content);
	require(write(descriptor, content, length) == (ssize_t)length &&
		fsync(descriptor) == 0 && close(descriptor) == 0,
		"persist swap fixture");
}

static void require_file(const char* path, const char* content)
{
	int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	require(descriptor >= 0, "open swap result");
	char observed[64] = {0};
	ssize_t length = read(descriptor, observed, sizeof(observed));
	require(close(descriptor) == 0, "close swap result");
	require(length == (ssize_t)strlen(content) &&
		memcmp(observed, content, (size_t)length) == 0,
		"swap result content mismatch");
}

static void swap_hook(enum eunion_sidecar_test_checkpoint checkpoint,
	const char* guest_path)
{
	if (checkpoint != EUNION_SIDECAR_TEST_PRE_BACKING)
		return;
	switch (active_case) {
	case SWAP_REMOVE:
		require(strcmp(guest_path, "/remove") == 0,
			"remove hook path mismatch");
		require(rename(upper_remove, remove_parked) == 0 &&
			rename(remove_replacement, upper_remove) == 0,
			"replace remove leaf before backing mutation");
		break;
	case SWAP_CREATE:
		require(strcmp(guest_path, "/create") == 0,
			"create hook path mismatch");
		make_file(upper_create, "attacker-create");
		break;
	case SWAP_COPYUP:
		require(strcmp(guest_path, "/copyup") == 0,
			"copy-up hook path mismatch");
		make_file(upper_copyup, "attacker-copyup");
		break;
	case SWAP_RENAME:
		require(strcmp(guest_path, "/rename") == 0,
			"rename hook path mismatch");
		require(rename(upper_rename, rename_parked) == 0 &&
			rename(rename_replacement, upper_rename) == 0,
			"replace rename source before backing mutation");
		break;
	default:
		return;
	}
	active_case = SWAP_NONE;
}

static enum eunion_sidecar_record_kind lookup_kind(
	const struct eunion_sidecar_runtime* runtime, const char* guest_path)
{
	eunion_sidecar_view view = {{0}};
	require(eunion_sidecar_view_open(view, runtime,
		EUNION_SIDECAR_ACCESS_SHARED) == 0,
		"open swap evidence view");
	struct eunion_sidecar_lookup lookup;
	require(eunion_sidecar_lookup_path(view, guest_path, &lookup) == 0,
		"lookup swap evidence");
	require(eunion_sidecar_view_close(view) == 0,
		"close swap evidence view");
	return lookup.kind;
}

int main(void)
{
	char root[] = "/tmp/eunion-sidecar-swap.XXXXXX";
	require(mkdtemp(root) != NULL, "mkdtemp");
	char upper[512], lower[512], sidecar[512], journal[512];
	char lower_copyup[512], upper_rename_destination[512];
	join_path(upper, sizeof(upper), root, "/upper");
	join_path(lower, sizeof(lower), root, "/lower");
	join_path(sidecar, sizeof(sidecar), root, "/sidecar");
	join_path(journal, sizeof(journal), sidecar, "/journal-v1");
	join_path(upper_remove, sizeof(upper_remove), upper, "/remove");
	join_path(remove_parked, sizeof(remove_parked), upper,
		"/remove-parked");
	join_path(remove_replacement, sizeof(remove_replacement), upper,
		"/remove-replacement");
	join_path(upper_create, sizeof(upper_create), upper, "/create");
	join_path(upper_copyup, sizeof(upper_copyup), upper, "/copyup");
	join_path(lower_copyup, sizeof(lower_copyup), lower, "/copyup");
	join_path(upper_rename, sizeof(upper_rename), upper, "/rename");
	join_path(rename_parked, sizeof(rename_parked), upper,
		"/rename-parked");
	join_path(rename_replacement, sizeof(rename_replacement), upper,
		"/rename-replacement");
	join_path(upper_rename_destination,
		sizeof(upper_rename_destination), upper, "/renamed");
	require(mkdir(upper, 0700) == 0 &&
		mkdir(lower, 0700) == 0 &&
		mkdir(sidecar, 0700) == 0,
		"create swap roots");

	struct eunion_sidecar_runtime runtime = {
		.upper_root = upper,
		.lower_root = lower,
		.sidecar_root = sidecar,
	};
	require(eunion_sidecar_test_write_prefix_state(&runtime) == 0 &&
		eunion_sidecar_initialize(&runtime) == 0,
		"initialize swap sidecar");
	eunion_test_sidecar_checkpoint_hook = swap_hook;

	make_file(upper_remove, "original-remove");
	make_file(remove_replacement, "replacement-remove");
	active_case = SWAP_REMOVE;
	require(eunion_sidecar_remove_path(&runtime, "/remove", 0) ==
		-EAGAIN, "remove accepted replaced leaf");
	require_file(upper_remove, "replacement-remove");
	require_file(remove_parked, "original-remove");
	require(access(journal, F_OK) == -1 && errno == ENOENT,
		"remove replacement left a transaction journal");
	require(rename(upper_remove, remove_replacement) == 0 &&
		rename(remove_parked, upper_remove) == 0,
		"restore remove fixture");

	active_case = SWAP_CREATE;
	require(eunion_sidecar_open_create(&runtime, "/create",
		O_WRONLY | O_CREAT | O_CLOEXEC, 0600) == -EAGAIN,
		"create accepted an inserted destination");
	require_file(upper_create, "attacker-create");
	require(lookup_kind(&runtime, "/create") ==
		EUNION_SIDECAR_RECORD_NONE,
		"failed create published sidecar state");

	make_file(lower_copyup, "lower-copyup");
	active_case = SWAP_COPYUP;
	require(eunion_sidecar_copy_up(&runtime, "/copyup") == -EAGAIN,
		"copy-up accepted an inserted destination");
	require_file(upper_copyup, "attacker-copyup");
	require(lookup_kind(&runtime, "/copyup") ==
		EUNION_SIDECAR_RECORD_NONE,
		"failed copy-up published sidecar state");

	int rename_descriptor = eunion_sidecar_open_create(
		&runtime, "/rename",
		O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
	require(rename_descriptor >= 0 &&
		write(rename_descriptor, "original-rename", 15) == 15 &&
		fsync(rename_descriptor) == 0 &&
		close(rename_descriptor) == 0,
		"create transactional rename source");
	make_file(rename_replacement, "replacement-rename");
	active_case = SWAP_RENAME;
	require(eunion_sidecar_rename_path(
		&runtime, "/rename", "/renamed") == -EAGAIN,
		"rename accepted a replaced source");
	require_file(upper_rename, "replacement-rename");
	require_file(rename_parked, "original-rename");
	struct stat status;
	require(lstat(upper_rename_destination, &status) == -1 &&
		errno == ENOENT,
		"failed rename mutated its destination");
	require(access(journal, F_OK) == -1 && errno == ENOENT,
		"rename replacement left a transaction journal");
	require(rename(upper_rename, rename_replacement) == 0 &&
		rename(rename_parked, upper_rename) == 0,
		"restore rename fixture");
	require(lookup_kind(&runtime, "/rename") ==
		EUNION_SIDECAR_RECORD_NONE,
		"failed rename damaged source sidecar state");

	eunion_test_sidecar_checkpoint_hook = NULL;
	char command[640];
	int length = snprintf(command, sizeof(command), "rm -rf -- '%s'", root);
	require(length > 0 && (size_t)length < sizeof(command) &&
		system(command) == 0, "cleanup swap fixture");
	printf("EUNION_SIDECAR_SWAP_OK checks=%d cases=4\n", checks);
	return 0;
}
