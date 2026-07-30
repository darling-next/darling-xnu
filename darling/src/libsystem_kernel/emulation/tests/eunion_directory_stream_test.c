#define _GNU_SOURCE
#define TEST 1
#define EUNION 1

#define main eunion_embedded_vchroot_main
#include "../src/linux_premigration/vchroot_userspace.c"
#undef main

#include "eunion_sidecar_test_support.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

enum {
	LARGE_ENTRY_COUNT = 2600,
	WHITEOUT_COUNT = 96,
};

static int checks;
static int initialize_ready_fd = -1;
static int initialize_release_fd = -1;
static enum eunion_sidecar_test_checkpoint initialize_crash_checkpoint;

static void require(int condition, const char* message)
{
	if (condition) {
		++checks;
		return;
	}
	fprintf(stderr, "eunion_directory_stream_test: %s (errno=%d)\n",
		message, errno);
	exit(1);
}

static void join_path(char* output, size_t capacity,
	const char* root, const char* suffix)
{
	int length = snprintf(output, capacity, "%s%s", root, suffix);
	require(length > 0 && (size_t)length < capacity, "construct path");
}

static void make_empty_file(const char* path)
{
	int descriptor = open(path,
		O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	require(descriptor >= 0 && close(descriptor) == 0,
		"create stream fixture file");
}

static void initialize_checkpoint(
	enum eunion_sidecar_test_checkpoint checkpoint,
	const char* guest_path)
{
	(void)guest_path;
	if (checkpoint != EUNION_SIDECAR_TEST_INITIALIZE_READY)
		return;
	char byte = 'R';
	require(write(initialize_ready_fd, &byte, 1) == 1,
		"signal full first-boot ready");
	require(read(initialize_release_fd, &byte, 1) == 1,
		"release full first-boot initializer");
}

static void initialize_crash(
	enum eunion_sidecar_test_checkpoint checkpoint,
	const char* guest_path)
{
	(void)guest_path;
	if (checkpoint == initialize_crash_checkpoint)
		_exit(90);
}

static void run_first_boot_crash_recovery(void)
{
	static const enum eunion_sidecar_test_checkpoint checkpoints[] = {
		EUNION_SIDECAR_TEST_INITIALIZE_READY,
		EUNION_SIDECAR_TEST_INITIALIZE_LOCKED,
		EUNION_SIDECAR_TEST_INITIALIZE_FORMAT,
		EUNION_SIDECAR_TEST_INITIALIZE_TREE,
		EUNION_SIDECAR_TEST_INITIALIZE_STAGING,
		EUNION_SIDECAR_TEST_INITIALIZE_ACTIVATED,
	};
	for (size_t index = 0;
		index < sizeof(checkpoints) / sizeof(checkpoints[0]); ++index) {
		char root[] = "/tmp/eunion-first-boot-crash.XXXXXX";
		require(mkdtemp(root) != NULL,
			"create first-boot crash fixture");
		char upper[512], lower[512], sidecar[512];
		join_path(upper, sizeof(upper), root, "/upper");
		join_path(lower, sizeof(lower), root, "/lower");
		join_path(sidecar, sizeof(sidecar), root,
			"/upper.eunion-sidecar-v1");
		require(mkdir(upper, 0700) == 0 &&
				mkdir(lower, 0700) == 0 &&
				mkdir(sidecar, 0700) == 0,
			"create first-boot crash roots");
		struct eunion_sidecar_runtime runtime = {
			.upper_root = upper,
			.lower_root = lower,
			.sidecar_root = sidecar,
		};
		require(eunion_sidecar_test_write_prefix_state(&runtime) == 0,
			"publish first-boot crash prefix state");

		pid_t child = fork();
		require(child >= 0, "fork first-boot crash initializer");
		if (child == 0) {
			initialize_crash_checkpoint = checkpoints[index];
			eunion_test_sidecar_checkpoint_hook = initialize_crash;
			int result = eunion_sidecar_initialize(&runtime);
			_exit(result == 0 ? 91 : 92);
		}
		int status;
		require(waitpid(child, &status, 0) == child &&
				WIFEXITED(status) && WEXITSTATUS(status) == 90,
			"initializer stops at requested durable boundary");
		eunion_test_sidecar_checkpoint_hook = NULL;
		require(eunion_sidecar_initialize(&runtime) == 0,
			"next initializer recovers owned partial state");
		struct eunion_prefix_format_inspection inspection;
		require(eunion_sidecar_inspect_prefix(
				&runtime, &inspection) == 0 &&
				inspection.verdict == EUNION_PREFIX_FORMAT_VALID,
			"recovered first boot publishes valid sidecar");
		char command[640];
		require(snprintf(command, sizeof(command),
				"rm -rf -- '%s'", root) > 0,
			"construct first-boot crash cleanup");
		require(system(command) == 0,
			"remove first-boot crash fixture");
	}
}

static void run_full_first_boot_race(void)
{
	char root[] = "/tmp/eunion-full-first-boot.XXXXXX";
	require(mkdtemp(root) != NULL, "create full first-boot fixture");
	char upper[512], lower[512], sidecar[512];
	join_path(upper, sizeof(upper), root, "/upper");
	join_path(lower, sizeof(lower), root, "/lower");
	join_path(sidecar, sizeof(sidecar), root,
		"/upper.eunion-sidecar-v1");
	require(mkdir(upper, 0700) == 0 &&
			mkdir(lower, 0700) == 0 &&
			mkdir(sidecar, 0700) == 0,
		"create full first-boot roots");
	struct eunion_sidecar_runtime runtime = {
		.upper_root = upper,
		.lower_root = lower,
		.sidecar_root = sidecar,
	};
	require(eunion_sidecar_test_write_prefix_state(&runtime) == 0,
		"publish full first-boot prefix state");

	int ready[2], release[2], results[2];
	require(pipe(ready) == 0 && pipe(release) == 0 &&
			pipe(results) == 0, "create full first-boot barriers");
	enum { BOOTERS = 3 };
	pid_t children[BOOTERS];
	for (int index = 0; index < BOOTERS; ++index) {
		children[index] = fork();
		require(children[index] >= 0, "fork full first-boot process");
		if (children[index] == 0) {
			close(ready[0]);
			close(release[1]);
			close(results[0]);
			initialize_ready_fd = ready[1];
			initialize_release_fd = release[0];
			eunion_test_sidecar_checkpoint_hook =
				initialize_checkpoint;
			memcpy(prefix_path, upper, strlen(upper) + 1);
			prefix_path_len = (int)strlen(prefix_path);
			set_libexec_path(lower);
			memset(&eunion_anchored_runtime, 0,
				sizeof(eunion_anchored_runtime));
			int prefix_descriptor = open(upper,
				O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
			int result = prefix_descriptor < 0
				? -errno
				: eunion_init_from_prefix(prefix_descriptor);
			if (result == 0)
				result = eunion_sidecar_runtime_release(
					&eunion_anchored_runtime);
			if (prefix_descriptor >= 0)
				close(prefix_descriptor);
			(void)write(results[1], &result, sizeof(result));
			_exit(result == 0 ? 0 : 1);
		}
	}
	close(ready[1]);
	close(release[0]);
	close(results[1]);
	char byte;
	for (int index = 0; index < BOOTERS; ++index)
		require(read(ready[0], &byte, 1) == 1,
			"receive full first-boot ready");
	for (int index = 0; index < BOOTERS; ++index)
		require(write(release[1], "G", 1) == 1,
			"release full first-boot process");
	for (int index = 0; index < BOOTERS; ++index) {
		int result;
		require(read(results[0], &result, sizeof(result)) ==
				(ssize_t)sizeof(result) && result == 0,
			"full first-boot process converges");
	}
	for (int index = 0; index < BOOTERS; ++index) {
		int status;
		require(waitpid(children[index], &status, 0) ==
				children[index] && WIFEXITED(status) &&
				WEXITSTATUS(status) == 0,
			"full first-boot child exits cleanly");
	}
	struct eunion_prefix_format_inspection inspection;
	require(eunion_sidecar_inspect_prefix(&runtime, &inspection) == 0 &&
			inspection.verdict == EUNION_PREFIX_FORMAT_VALID,
		"full first-boot race leaves one valid sidecar");
	close(ready[0]);
	close(release[1]);
	close(results[0]);
	char command[640];
	require(snprintf(command, sizeof(command), "rm -rf -- '%s'", root) > 0,
		"construct full first-boot cleanup");
	require(system(command) == 0, "remove full first-boot fixture");
}

static int collect_page_names(
	const char* page, int length, unsigned char seen[LARGE_ENTRY_COUNT])
{
	int found = 0;
	for (int offset = 0; offset < length;) {
		const struct linux_dirent64* entry =
			(const struct linux_dirent64*)(page + offset);
		require(entry->d_reclen > 0 &&
				offset + entry->d_reclen <= length,
			"valid merged dirent record");
		int index = -1;
		if (sscanf(entry->d_name,
				"entry-%d-xxxxxxxxxxxxxxxxxxxxxxxx", &index) == 1) {
			require(index >= 0 && index < LARGE_ENTRY_COUNT,
				"merged entry index in range");
			require(!seen[index], "merged entry emitted once");
			seen[index] = 1;
			++found;
		}
		offset += entry->d_reclen;
	}
	return found;
}

struct parallel_reader {
	int descriptor;
	unsigned char* seen;
	pthread_mutex_t* lock;
	int* total;
	int result;
};

static void* drain_merged_directory(void* context)
{
	struct parallel_reader* reader = context;
	reader->result = 0;
	for (;;) {
		char page[1024];
		int length = vchroot_getdents_merge(
			reader->descriptor, page, sizeof(page));
		if (length < 0) {
			reader->result = length;
			return NULL;
		}
		if (length == 0)
			return NULL;
		pthread_mutex_lock(reader->lock);
		*reader->total += collect_page_names(
			page, length, reader->seen);
		pthread_mutex_unlock(reader->lock);
	}
}

static void run_large_listing(
	const char* upper, const char* lower)
{
	char upper_large[512], lower_large[512];
	join_path(upper_large, sizeof(upper_large), upper, "/large");
	join_path(lower_large, sizeof(lower_large), lower, "/large");
	require(mkdir(upper_large, 0700) == 0 &&
			mkdir(lower_large, 0700) == 0,
		"create large merged directory");
	for (int index = 0; index < LARGE_ENTRY_COUNT; ++index) {
		char path[768];
		int length = snprintf(path, sizeof(path),
			"%s/entry-%04d-xxxxxxxxxxxxxxxxxxxxxxxx",
			lower_large, index);
		require(length > 0 && (size_t)length < sizeof(path),
			"construct large entry");
		make_empty_file(path);
	}

	char bounded[65536];
	require(vchroot_readdir_merge(
			"/large", bounded, sizeof(bounded)) == -EOVERFLOW,
		"bounded merged listing fails closed instead of omitting names");

	int descriptor = open(upper_large,
		O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	require(descriptor >= 0, "open merged directory");
	unsigned char seen[LARGE_ENTRY_COUNT] = {0};
	int total = 0;
	for (;;) {
		char page[4096];
		int length = vchroot_getdents_merge(
			descriptor, page, sizeof(page));
		require(length >= 0, "paged merged listing succeeds");
		if (length == 0)
			break;
		total += collect_page_names(page, length, seen);
	}
	require(total == LARGE_ENTRY_COUNT,
		"paged merged listing emits every >64KiB entry");

	vchroot_dir_rewind(descriptor);
	++checks;
	int duplicate = dup(descriptor);
	require(duplicate >= 0 && vchroot_dir_dup(descriptor, duplicate) == 0,
		"duplicate merged directory description");
	char first_page[512], second_page[512];
	int first_length = vchroot_getdents_merge(
		descriptor, first_page, sizeof(first_page));
	int second_length = vchroot_getdents_merge(
		duplicate, second_page, sizeof(second_page));
	require(first_length > 0 && second_length > 0,
		"duplicated descriptors stream pages");
	unsigned char shared_seen[LARGE_ENTRY_COUNT] = {0};
	int shared_total = collect_page_names(
		first_page, first_length, shared_seen);
	shared_total += collect_page_names(
		second_page, second_length, shared_seen);
	require(shared_total > 0,
		"duplicated descriptors share a non-overlapping cursor");

	vchroot_dir_rewind(descriptor);
	int third = dup(descriptor);
	int fourth = dup(descriptor);
	require(third >= 0 && fourth >= 0 &&
			vchroot_dir_dup(descriptor, third) == 0 &&
			vchroot_dir_dup(descriptor, fourth) == 0,
		"bind all parallel descriptor duplicates");
	unsigned char parallel_seen[LARGE_ENTRY_COUNT] = {0};
	pthread_mutex_t parallel_lock = PTHREAD_MUTEX_INITIALIZER;
	int parallel_total = 0;
	struct parallel_reader readers[3] = {
		{descriptor, parallel_seen, &parallel_lock, &parallel_total, 0},
		{third, parallel_seen, &parallel_lock, &parallel_total, 0},
		{fourth, parallel_seen, &parallel_lock, &parallel_total, 0},
	};
	pthread_t threads[3];
	for (int index = 0; index < 3; ++index)
		require(pthread_create(&threads[index], NULL,
				drain_merged_directory, &readers[index]) == 0,
			"start parallel directory reader");
	for (int index = 0; index < 3; ++index)
		require(pthread_join(threads[index], NULL) == 0 &&
				readers[index].result == 0,
			"join parallel directory reader");
	require(parallel_total == LARGE_ENTRY_COUNT,
		"parallel duplicated readers share one complete cursor");
	require(pthread_mutex_destroy(&parallel_lock) == 0,
		"destroy parallel reader lock");
	vchroot_dir_closed(third);
	vchroot_dir_closed(fourth);
	require(close(third) == 0 && close(fourth) == 0,
		"close parallel duplicates");
	vchroot_dir_closed(duplicate);
	require(close(duplicate) == 0, "close duplicate");
	vchroot_dir_closed(descriptor);
	require(close(descriptor) == 0, "close merged directory");
}

static void run_whiteout_pressure(
	const char* upper, const char* lower,
	const struct eunion_sidecar_runtime* runtime)
{
	char upper_hidden[512], lower_hidden[512];
	join_path(upper_hidden, sizeof(upper_hidden), upper, "/hidden");
	join_path(lower_hidden, sizeof(lower_hidden), lower, "/hidden");
	require(mkdir(upper_hidden, 0700) == 0 &&
			mkdir(lower_hidden, 0700) == 0,
		"create whiteout-pressure directory");
	for (int index = 0; index < WHITEOUT_COUNT; ++index) {
		char name[160];
		int name_length = snprintf(name, sizeof(name),
			"hidden-%03d-yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy",
			index);
		require(name_length > 0 &&
				(size_t)name_length < sizeof(name),
			"construct hidden name");
		char host[768], guest[192];
		require(snprintf(host, sizeof(host), "%s/%s",
				lower_hidden, name) > 0,
			"construct hidden host path");
		require(snprintf(guest, sizeof(guest), "/hidden/%s",
				name) > 0, "construct hidden guest path");
		make_empty_file(host);
		require(eunion_sidecar_remove_path(runtime, guest, 0) == 0,
			"publish whiteout-pressure record");
	}
	char names[1024] = {0};
	require(vchroot_readdir_merge(
			"/hidden", names, sizeof(names)) == 0,
		"large whiteout set hides every lower entry");

	char long_name[256];
	memset(long_name, 'n', sizeof(long_name) - 1);
	long_name[sizeof(long_name) - 1] = '\0';
	char host[1024];
	require(snprintf(host, sizeof(host), "%s/%s",
			lower_hidden, long_name) > 0,
		"construct NAME_MAX host path");
	make_empty_file(host);
	char large_names[4096] = {0};
	int count = vchroot_readdir_merge(
		"/hidden", large_names, sizeof(large_names));
	require(count == 1 && strcmp(large_names, long_name) == 0,
		"NAME_MAX entry is emitted without truncation");
	int descriptor = open(upper_hidden,
		O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	require(descriptor >= 0, "open NAME_MAX merged directory");
	char undersized[8];
	require(vchroot_getdents_merge(
			descriptor, undersized, sizeof(undersized)) == -EINVAL,
		"undersized page fails instead of reporting false end-of-stream");
	char full_page[512];
	require(vchroot_getdents_merge(
			descriptor, full_page, sizeof(full_page)) > 0,
		"failed small page does not consume NAME_MAX entry");
	vchroot_dir_closed(descriptor);
	require(close(descriptor) == 0,
		"close NAME_MAX merged directory");
}

static void run_deep_path(
	const char* upper, const char* lower,
	const struct eunion_sidecar_runtime* runtime)
{
	char upper_path[4096], lower_path[4096], guest[4096];
	strcpy(upper_path, upper);
	strcpy(lower_path, lower);
	guest[0] = '\0';
	for (int index = 0; index < 80; ++index) {
		char component[16];
		require(snprintf(component, sizeof(component), "/d%02d", index) > 0,
			"construct deep component");
		require(strlen(upper_path) + strlen(component) + 1 <
				sizeof(upper_path) &&
				strlen(lower_path) + strlen(component) + 1 <
				sizeof(lower_path) &&
				strlen(guest) + strlen(component) + 1 <
				sizeof(guest), "deep path capacity");
		strcat(upper_path, component);
		strcat(lower_path, component);
		strcat(guest, component);
		require(mkdir(upper_path, 0700) == 0 &&
				mkdir(lower_path, 0700) == 0,
			"create deep component");
	}
	strcat(lower_path, "/leaf");
	strcat(guest, "/leaf");
	make_empty_file(lower_path);
	require(eunion_sidecar_remove_path(runtime, guest, 0) == 0,
		"sidecar accepts valid path deeper than 64 components");
	eunion_sidecar_view reader = {{0}};
	struct eunion_sidecar_lookup lookup;
	require(eunion_sidecar_view_open(reader, runtime,
			EUNION_SIDECAR_ACCESS_SHARED) == 0 &&
			eunion_sidecar_lookup_path(reader, guest, &lookup) == 0 &&
			lookup.kind == EUNION_SIDECAR_RECORD_WHITEOUT &&
			eunion_sidecar_view_close(reader) == 0,
		"deep sidecar record remains addressable");
}

int main(void)
{
	run_first_boot_crash_recovery();
	run_full_first_boot_race();

	char root[] = "/tmp/eunion-directory-stream.XXXXXX";
	require(mkdtemp(root) != NULL, "create stream fixture");
	char upper[512], lower[512], sidecar[512];
	join_path(upper, sizeof(upper), root, "/upper");
	join_path(lower, sizeof(lower), root, "/lower");
	join_path(sidecar, sizeof(sidecar), root,
		"/upper.eunion-sidecar-v1");
	require(mkdir(upper, 0700) == 0 &&
			mkdir(lower, 0700) == 0 &&
			mkdir(sidecar, 0700) == 0,
		"create stream roots");
	struct eunion_sidecar_runtime runtime = {
		.upper_root = upper,
		.lower_root = lower,
		.sidecar_root = sidecar,
	};
	require(eunion_sidecar_test_write_prefix_state(&runtime) == 0 &&
			eunion_sidecar_initialize(&runtime) == 0,
		"initialize stream sidecar");
	memcpy(prefix_path, upper, strlen(upper) + 1);
	prefix_path_len = (int)strlen(prefix_path);
	set_libexec_path(lower);
	int upper_descriptor = open(upper,
		O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	require(upper_descriptor >= 0 &&
			eunion_init_from_prefix(upper_descriptor) == 0,
		"anchor stream runtime");

	run_large_listing(upper, lower);
	run_whiteout_pressure(upper, lower, &runtime);
	run_deep_path(upper, lower, &runtime);

	require(eunion_sidecar_runtime_release(
			&eunion_anchored_runtime) == 0,
		"release stream runtime");
	require(close(upper_descriptor) == 0,
		"close stream upper descriptor");
	char command[640];
	require(snprintf(command, sizeof(command), "rm -rf -- '%s'", root) > 0,
		"construct stream cleanup");
	require(system(command) == 0, "remove stream fixture");
	printf("EUNION_DIRECTORY_STREAM_OK checks=%d entries=%d\n",
		checks, LARGE_ENTRY_COUNT);
	return 0;
}
