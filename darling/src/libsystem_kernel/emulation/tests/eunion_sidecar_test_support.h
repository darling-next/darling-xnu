#ifndef EUNION_SIDECAR_TEST_SUPPORT_H
#define EUNION_SIDECAR_TEST_SUPPORT_H

#include <fcntl.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int eunion_sidecar_test_write_prefix_state(
	const struct eunion_sidecar_runtime* runtime)
{
	if (!runtime || !runtime->upper_root || !runtime->sidecar_root)
		return -1;
	struct stat upper;
	struct stat sidecar;
	if (stat(runtime->upper_root, &upper) != 0 ||
		stat(runtime->sidecar_root, &sidecar) != 0)
		return -1;
	char path[EUNION_SIDECAR_PATH_MAX];
	if (snprintf(path, sizeof(path), "%s/.darling-prefix-state-v3",
			runtime->upper_root) >= (int)sizeof(path))
		return -1;
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
		(uintmax_t)upper.st_dev, (uintmax_t)upper.st_ino,
		(uintmax_t)sidecar.st_dev, (uintmax_t)sidecar.st_ino,
		(uintmax_t)upper.st_uid, (uintmax_t)upper.st_gid);
	if (length <= 0 || (size_t)length >= sizeof(content))
		return -1;
	int descriptor = open(path,
		O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (descriptor < 0)
		return -1;
	size_t offset = 0;
	while (offset < (size_t)length) {
		ssize_t written = write(
			descriptor, content + offset, (size_t)length - offset);
		if (written < 0 && errno == EINTR)
			continue;
		if (written <= 0) {
			close(descriptor);
			return -1;
		}
		offset += (size_t)written;
	}
	if (fsync(descriptor) != 0 || close(descriptor) != 0)
		return -1;
	return 0;
}

#endif
