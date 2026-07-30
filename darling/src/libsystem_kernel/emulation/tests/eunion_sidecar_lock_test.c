#define _GNU_SOURCE

#include <linux_premigration/eunion_sidecar.h>
#include "eunion_sidecar_test_support.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int checks;

static void require(int condition, const char* message)
{
	if (condition) {
		++checks;
		return;
	}
	fprintf(stderr, "eunion_sidecar_lock_test: %s (errno=%d)\n",
		message, errno);
	exit(1);
}

static void send_byte(int descriptor, char value)
{
	require(write(descriptor, &value, 1) == 1, "send synchronization byte");
}

static char receive_byte(int descriptor)
{
	char value;
	require(read(descriptor, &value, 1) == 1,
		"receive synchronization byte");
	return value;
}

static void require_blocked(int descriptor, const char* message)
{
	struct pollfd event = {
		.fd = descriptor,
		.events = POLLIN,
	};
	int result = poll(&event, 1, 100);
	require(result == 0, message);
}

static void child_lock(const struct eunion_sidecar_runtime* runtime,
	int started, int acquired, int release)
{
	send_byte(started, 'S');
	eunion_sidecar_view view = {{0}};
	if (eunion_sidecar_view_open(view, runtime,
		EUNION_SIDECAR_ACCESS_EXCLUSIVE) != 0)
		_exit(20);
	send_byte(acquired, 'A');
	(void)receive_byte(release);
	if (eunion_sidecar_view_close(view) != 0)
		_exit(21);
	_exit(0);
}

int main(void)
{
	char root[] = "/tmp/eunion-sidecar-lock.XXXXXX";
	require(mkdtemp(root) != NULL, "create lock fixture");
	char upper[512], lower[512], sidecar[512], lock[512];
	require(snprintf(upper, sizeof(upper), "%s/upper", root) > 0,
		"construct upper path");
	require(snprintf(lower, sizeof(lower), "%s/lower", root) > 0,
		"construct lower path");
	require(snprintf(sidecar, sizeof(sidecar), "%s/sidecar", root) > 0,
		"construct sidecar path");
	require(snprintf(lock, sizeof(lock), "%s/lock-v1", sidecar) > 0,
		"construct lock path");
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
		"initialize lock sidecar");
	struct stat initial;
	require(lstat(lock, &initial) == 0, "snapshot lock inode");

	int a_started[2], a_acquired[2], a_release[2];
	int b_started[2], b_acquired[2], b_release[2];
	int c_started[2], c_acquired[2], c_release[2];
	require(pipe(a_started) == 0 && pipe(a_acquired) == 0 &&
		pipe(a_release) == 0 && pipe(b_started) == 0 &&
		pipe(b_acquired) == 0 && pipe(b_release) == 0 &&
		pipe(c_started) == 0 && pipe(c_acquired) == 0 &&
		pipe(c_release) == 0, "create synchronization pipes");

	pid_t a = fork();
	require(a >= 0, "fork first locker");
	if (a == 0)
		child_lock(&runtime, a_started[1], a_acquired[1], a_release[0]);
	require(receive_byte(a_started[0]) == 'S', "first locker starts");
	require(receive_byte(a_acquired[0]) == 'A', "first locker acquires");

	pid_t b = fork();
	require(b >= 0, "fork second locker");
	if (b == 0)
		child_lock(&runtime, b_started[1], b_acquired[1], b_release[0]);
	require(receive_byte(b_started[0]) == 'S', "second locker starts");
	require_blocked(b_acquired[0],
		"second locker blocks on persistent inode");
	send_byte(a_release[1], 'R');
	require(receive_byte(b_acquired[0]) == 'A',
		"second locker acquires after first releases");

	pid_t c = fork();
	require(c >= 0, "fork third locker");
	if (c == 0)
		child_lock(&runtime, c_started[1], c_acquired[1], c_release[0]);
	require(receive_byte(c_started[0]) == 'S', "third locker starts");
	require_blocked(c_acquired[0],
		"third locker blocks while second owns lock");
	send_byte(b_release[1], 'R');
	require(receive_byte(c_acquired[0]) == 'A',
		"third locker acquires after second releases");
	send_byte(c_release[1], 'R');

	int status;
	require(waitpid(a, &status, 0) == a && WIFEXITED(status) &&
		WEXITSTATUS(status) == 0, "first locker exits cleanly");
	require(waitpid(b, &status, 0) == b && WIFEXITED(status) &&
		WEXITSTATUS(status) == 0, "second locker exits cleanly");
	require(waitpid(c, &status, 0) == c && WIFEXITED(status) &&
		WEXITSTATUS(status) == 0, "third locker exits cleanly");
	struct stat final;
	require(lstat(lock, &final) == 0 &&
		initial.st_dev == final.st_dev && initial.st_ino == final.st_ino,
		"all three processes use one persistent lock inode");

	char command[640];
	require(snprintf(command, sizeof(command), "rm -rf -- '%s'", root) > 0,
		"construct cleanup command");
	require(system(command) == 0, "remove lock fixture");
	printf("EUNION_SIDECAR_LOCK_OK checks=%d processes=3\n", checks);
	return 0;
}
