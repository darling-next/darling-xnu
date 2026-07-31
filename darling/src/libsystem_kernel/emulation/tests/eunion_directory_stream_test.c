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
	DESCRIPTOR_PRESSURE_COUNT = 320,
	PAGE_CAPTURE_CAPACITY = 512,
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

struct page_capture {
	int result;
	int length;
	char page[PAGE_CAPTURE_CAPACITY];
};

static int write_full(int descriptor, const void* data, size_t size)
{
	const unsigned char* cursor = data;
	while (size > 0) {
		ssize_t written = write(descriptor, cursor, size);
		if (written <= 0)
			return -1;
		cursor += written;
		size -= (size_t)written;
	}
	return 0;
}

static int read_full(int descriptor, void* data, size_t size)
{
	unsigned char* cursor = data;
	while (size > 0) {
		ssize_t received = read(descriptor, cursor, size);
		if (received <= 0)
			return -1;
		cursor += received;
		size -= (size_t)received;
	}
	return 0;
}

static struct page_capture capture_page(int descriptor)
{
	struct page_capture capture = {
		.result = 0,
		.length = 0,
	};
	capture.length = vchroot_getdents_merge(
		descriptor, capture.page, sizeof(capture.page));
	if (capture.length < 0)
		capture.result = capture.length;
	return capture;
}

static void collect_two_nonoverlapping_pages(
	const struct page_capture* first,
	const struct page_capture* second,
	const char* message)
{
	require(first->result == 0 && first->length > 0 &&
			second->result == 0 && second->length > 0,
		message);
	unsigned char seen[LARGE_ENTRY_COUNT] = {0};
	int total = collect_page_names(first->page, first->length, seen);
	total += collect_page_names(second->page, second->length, seen);
	require(total > 1, "shared open-file-description cursor advances");
}

static int run_exec_reader(int argc, char** argv)
{
	if (argc != 6)
		return 120;
	int directory_descriptor = atoi(argv[2]);
	int result_descriptor = atoi(argv[3]);
	const char* upper = argv[4];
	const char* lower = argv[5];
	memcpy(prefix_path, upper, strlen(upper) + 1);
	prefix_path_len = (int)strlen(prefix_path);
	set_libexec_path(lower);
	int upper_descriptor = open(upper,
		O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (upper_descriptor < 0)
		return 121;
	int result = eunion_init_from_prefix(upper_descriptor);
	struct page_capture capture = {
		.result = result,
		.length = 0,
	};
	if (result == 0)
		capture = capture_page(directory_descriptor);
	int write_result = write_full(
		result_descriptor, &capture, sizeof(capture));
	int release_result = eunion_sidecar_runtime_release(
		&eunion_anchored_runtime);
	close(upper_descriptor);
	close(result_descriptor);
	return write_result == 0 && release_result == 0 ? 0 : 122;
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

struct concurrent_closer {
	int descriptor;
	int result;
};

static void* close_merged_duplicate(void* context)
{
	struct concurrent_closer* closer = context;
	closer->result = close(closer->descriptor);
	return NULL;
}

static void run_duplication_routes(int directory_descriptor)
{
	require(lseek(directory_descriptor, 0, SEEK_SET) == 0,
		"rewind merged cursor through kernel OFD");
	int duplicate = dup(directory_descriptor);
	require(duplicate >= 0, "dup merged directory descriptor");
	struct page_capture first = capture_page(directory_descriptor);
	struct page_capture second = capture_page(duplicate);
	collect_two_nonoverlapping_pages(
		&first, &second, "dup shares kernel OFD cursor");
	require(close(duplicate) == 0, "close dup descriptor");

	require(lseek(directory_descriptor, 0, SEEK_SET) == 0,
		"rewind before dup2 route");
	int dup2_target = open("/dev/null", O_RDONLY | O_CLOEXEC);
	require(dup2_target >= 0 &&
			dup2(directory_descriptor, dup2_target) == dup2_target,
		"dup2 merged directory descriptor");
	first = capture_page(directory_descriptor);
	second = capture_page(dup2_target);
	collect_two_nonoverlapping_pages(
		&first, &second, "dup2 shares kernel OFD cursor");
	require(close(dup2_target) == 0, "close dup2 descriptor");

	require(lseek(directory_descriptor, 0, SEEK_SET) == 0,
		"rewind before F_DUPFD route");
	int fcntl_duplicate = fcntl(directory_descriptor, F_DUPFD, 0);
	require(fcntl_duplicate >= 0, "F_DUPFD merged directory descriptor");
	first = capture_page(directory_descriptor);
	second = capture_page(fcntl_duplicate);
	collect_two_nonoverlapping_pages(
		&first, &second, "F_DUPFD shares kernel OFD cursor");
	require(close(fcntl_duplicate) == 0, "close F_DUPFD descriptor");

#ifdef F_DUPFD_CLOEXEC
	require(lseek(directory_descriptor, 0, SEEK_SET) == 0,
		"rewind before F_DUPFD_CLOEXEC route");
	int cloexec_duplicate =
		fcntl(directory_descriptor, F_DUPFD_CLOEXEC, 0);
	require(cloexec_duplicate >= 0,
		"F_DUPFD_CLOEXEC merged directory descriptor");
	first = capture_page(directory_descriptor);
	second = capture_page(cloexec_duplicate);
	collect_two_nonoverlapping_pages(
		&first, &second, "F_DUPFD_CLOEXEC shares kernel OFD cursor");
	require(close(cloexec_duplicate) == 0,
		"close F_DUPFD_CLOEXEC descriptor");
#endif
}

static void run_fork_cursor(
	const char* upper_large)
{
	int descriptor = open(upper_large,
		O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	require(descriptor >= 0, "open fork cursor directory");
	int results[2];
	require(pipe(results) == 0, "create fork cursor result pipe");
	pid_t child = fork();
	require(child >= 0, "fork merged cursor reader");
	if (child == 0) {
		close(results[0]);
		struct page_capture capture = capture_page(descriptor);
		int write_result = write_full(
			results[1], &capture, sizeof(capture));
		close(results[1]);
		_exit(write_result == 0 ? 0 : 123);
	}
	close(results[1]);
	struct page_capture child_page;
	require(read_full(results[0], &child_page,
			sizeof(child_page)) == 0,
		"receive fork child page");
	close(results[0]);
	int status;
	require(waitpid(child, &status, 0) == child &&
			WIFEXITED(status) && WEXITSTATUS(status) == 0,
		"fork child exits cleanly");
	struct page_capture parent_page = capture_page(descriptor);
	collect_two_nonoverlapping_pages(
		&child_page, &parent_page,
		"fork shares cursor through kernel OFD");
	require(close(descriptor) == 0, "close fork cursor directory");
}

static void run_exec_cursor(
	const char* upper_large, const char* upper, const char* lower)
{
	int descriptor = open(upper_large, O_RDONLY | O_DIRECTORY);
	require(descriptor >= 0, "open exec cursor directory");
	struct page_capture parent_page = capture_page(descriptor);
	int results[2];
	require(pipe(results) == 0, "create exec cursor result pipe");
	pid_t child = fork();
	require(child >= 0, "fork exec cursor reader");
	if (child == 0) {
		close(results[0]);
		char descriptor_argument[32];
		char result_argument[32];
		require(snprintf(descriptor_argument,
				sizeof(descriptor_argument), "%d", descriptor) > 0,
			"format exec directory descriptor");
		require(snprintf(result_argument,
				sizeof(result_argument), "%d", results[1]) > 0,
			"format exec result descriptor");
		char* arguments[] = {
			"/proc/self/exe",
			"--exec-reader",
			descriptor_argument,
			result_argument,
			(char*)upper,
			(char*)lower,
			NULL,
		};
		execv(arguments[0], arguments);
		_exit(124);
	}
	close(results[1]);
	struct page_capture child_page;
	require(read_full(results[0], &child_page,
			sizeof(child_page)) == 0,
		"receive exec child page");
	close(results[0]);
	int status;
	require(waitpid(child, &status, 0) == child &&
			WIFEXITED(status) && WEXITSTATUS(status) == 0,
		"exec child exits cleanly");
	collect_two_nonoverlapping_pages(
		&parent_page, &child_page,
		"exec preserves cursor through kernel OFD");
	require(close(descriptor) == 0, "close exec cursor directory");
}

static void run_descriptor_pressure(const char* upper_large)
{
	int descriptors[DESCRIPTOR_PRESSURE_COUNT];
	memset(descriptors, -1, sizeof(descriptors));
	for (int index = 0; index < DESCRIPTOR_PRESSURE_COUNT; ++index) {
		descriptors[index] = open(upper_large,
			O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		require(descriptors[index] >= 0,
			"system accepts descriptor pressure fixture");
		struct page_capture page = capture_page(descriptors[index]);
		require(page.result == 0 && page.length > 0,
			"merged cursor has no private descriptor cap");
	}
	for (int index = 0; index < DESCRIPTOR_PRESSURE_COUNT; ++index)
		require(close(descriptors[index]) == 0,
			"close descriptor pressure fixture");
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

	run_duplication_routes(descriptor);
	require(lseek(descriptor, 0, SEEK_SET) == 0,
		"rewind before parallel readers");
	int third = dup(descriptor);
	int fourth = dup(descriptor);
	int concurrently_closed = dup(descriptor);
	require(third >= 0 && fourth >= 0 && concurrently_closed >= 0,
		"duplicate all parallel directory descriptors");
	unsigned char parallel_seen[LARGE_ENTRY_COUNT] = {0};
	pthread_mutex_t parallel_lock = PTHREAD_MUTEX_INITIALIZER;
	int parallel_total = 0;
	struct parallel_reader readers[3] = {
		{descriptor, parallel_seen, &parallel_lock, &parallel_total, 0},
		{third, parallel_seen, &parallel_lock, &parallel_total, 0},
		{fourth, parallel_seen, &parallel_lock, &parallel_total, 0},
	};
	pthread_t threads[3];
	struct concurrent_closer closer = {
		.descriptor = concurrently_closed,
		.result = -1,
	};
	pthread_t close_thread;
	for (int index = 0; index < 3; ++index)
		require(pthread_create(&threads[index], NULL,
				drain_merged_directory, &readers[index]) == 0,
			"start parallel directory reader");
	require(pthread_create(&close_thread, NULL,
			close_merged_duplicate, &closer) == 0,
		"start concurrent sibling close");
	for (int index = 0; index < 3; ++index)
		require(pthread_join(threads[index], NULL) == 0 &&
				readers[index].result == 0,
			"join parallel directory reader");
	require(pthread_join(close_thread, NULL) == 0 &&
			closer.result == 0,
		"concurrent sibling close preserves shared OFD");
	require(parallel_total == LARGE_ENTRY_COUNT,
		"parallel duplicated readers share one complete cursor");
	require(pthread_mutex_destroy(&parallel_lock) == 0,
		"destroy parallel reader lock");
	require(close(third) == 0 && close(fourth) == 0,
		"close parallel duplicates");
	require(close(descriptor) == 0, "close merged directory");

	run_fork_cursor(upper_large);
	run_exec_cursor(upper_large, upper, lower);
	run_descriptor_pressure(upper_large);
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

int main(int argc, char** argv)
{
	if (argc > 1 && strcmp(argv[1], "--exec-reader") == 0)
		return run_exec_reader(argc, argv);

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
	printf(
		"EUNION_DIRECTORY_STREAM_OK checks=%d visible_entries=%d "
		"descriptor_pressure=%d dup2=PASS f_dupfd=PASS "
		"fork=PASS exec=PASS concurrent_close=PASS\n",
		checks, LARGE_ENTRY_COUNT, DESCRIPTOR_PRESSURE_COUNT);
	return 0;
}
