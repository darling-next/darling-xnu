#include <linux_premigration/eunion_resolver.h>

#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

static char fixture_root[] = "/tmp/eunion-resolver.XXXXXX";

static void join(char* out, size_t cap, const char* root, const char* suffix);

static void cleanup_tree(const char* path)
{
	DIR* directory = opendir(path);
	struct dirent* entry;

	if (!directory)
		return;
	while ((entry = readdir(directory)) != NULL)
	{
		char child[EUNION_RESOLVER_PATH_MAX];
		struct stat st;

		if ((entry->d_name[0] == '.' && entry->d_name[1] == '\0') ||
			(entry->d_name[0] == '.' && entry->d_name[1] == '.' && entry->d_name[2] == '\0'))
			continue;
		join(child, sizeof(child), path, "/");
		strncat(child, entry->d_name, sizeof(child) - strlen(child) - 1);
		if (lstat(child, &st) != 0)
			continue;
		if (S_ISDIR(st.st_mode))
			cleanup_tree(child);
		else
			unlink(child);
	}
	closedir(directory);
	rmdir(path);
}

static void cleanup_fixture(void)
{
	cleanup_tree(fixture_root);
}

static void fail(const char* message)
{
	fprintf(stderr, "eunion_resolver_test: %s\n", message);
	exit(1);
}

static int path_status(void* context, const char* path)
{
	struct stat st;
	(void)context;
	return lstat(path, &st) == 0 ? 0 : -errno;
}

static int marker_status(void* context, const char* path, const char* marker)
{
	char value[2];
	ssize_t length;
	(void)context;
	length = lgetxattr(path, marker, value, sizeof(value));
	if (length < 0)
		return errno == ENODATA || errno == ENOENT ? 0 : -errno;
	return length > 0 && value[0] == 'y';
}

static int path_kind(void* context, const char* path)
{
	struct stat st;
	(void)context;
	if (lstat(path, &st) != 0)
		return -errno;
	return S_ISDIR(st.st_mode)
		? EUNION_RESOLVER_DIRECTORY
		: EUNION_RESOLVER_NON_DIRECTORY;
}

static void join(char* out, size_t cap, const char* root, const char* suffix)
{
	if (snprintf(out, cap, "%s%s", root, suffix) >= (int)cap)
		fail("fixture path is too long");
}

static void make_dir(const char* path)
{
	if (mkdir(path, 0700) != 0)
		fail("mkdir failed");
}

static void make_file(const char* path)
{
	int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
	if (fd < 0 || write(fd, "x", 1) != 1 || close(fd) != 0)
		fail("file fixture failed");
}

static void set_marker(const char* path, const char* marker)
{
	if (lsetxattr(path, marker, "y", 1, 0) != 0)
		fail("xattr fixture failed");
}

static void expect(const struct eunion_resolver* resolver, const char* guest,
	enum eunion_resolver_layer layer, const char* expected)
{
	struct eunion_resolver_result result;

	if (eunion_resolve_path(resolver, guest, &result) != 0 || result.layer != layer ||
		strcmp(result.host_path, expected) != 0)
		fail("unexpected resolver result");
}

static void expect_error(const struct eunion_resolver* resolver, const char* guest,
	int error, const char* expected)
{
	struct eunion_resolver_result result;

	if (eunion_resolve_path(resolver, guest, &result) != 0 ||
		result.layer != EUNION_RESOLVER_ERROR || result.error != error ||
		strcmp(result.host_path, expected) != 0)
		fail("unexpected resolver error");
}

int main(void)
{
	char upper[EUNION_RESOLVER_PATH_MAX];
	char lower[EUNION_RESOLVER_PATH_MAX];
	char path[EUNION_RESOLVER_PATH_MAX];
	struct eunion_resolver resolver;

	if (!mkdtemp(fixture_root))
		fail("mkdtemp failed");
	if (atexit(cleanup_fixture) != 0)
		fail("atexit failed");
	join(upper, sizeof(upper), fixture_root, "/upper");
	join(lower, sizeof(lower), fixture_root, "/lower");
	make_dir(upper);
	make_dir(lower);
	join(path, sizeof(path), lower, "/lower-only");
	make_file(path);
	join(path, sizeof(path), lower, "/shared");
	make_file(path);
	join(path, sizeof(path), upper, "/shared");
	make_file(path);
	join(path, sizeof(path), lower, "/masked");
	make_file(path);
	join(path, sizeof(path), upper, "/masked");
	make_file(path);
	set_marker(path, "user.union.whiteout");
	join(path, sizeof(path), lower, "/opaque");
	make_dir(path);
	join(path, sizeof(path), lower, "/opaque/hidden");
	make_file(path);
	join(path, sizeof(path), upper, "/opaque");
	make_dir(path);
	set_marker(path, "user.union.opaque");
	join(path, sizeof(path), upper, "/shadow");
	make_file(path);
	join(path, sizeof(path), lower, "/shadow");
	make_dir(path);
	join(path, sizeof(path), lower, "/shadow/child");
	make_file(path);

	resolver = (struct eunion_resolver){
		.upper_root = upper,
		.lower_root = lower,
		.whiteout_marker = "user.union.whiteout",
		.opaque_marker = "user.union.opaque",
		.missing_status = -ENOENT,
		.not_directory_status = -ENOTDIR,
		.ops = { path_status, marker_status, path_kind },
	};
	join(path, sizeof(path), lower, "/lower-only");
	expect(&resolver, "/lower-only", EUNION_RESOLVER_LOWER, path);
	join(path, sizeof(path), upper, "/shared");
	expect(&resolver, "/shared", EUNION_RESOLVER_UPPER, path);
	join(path, sizeof(path), upper, "/masked");
	expect(&resolver, "/masked", EUNION_RESOLVER_WHITEOUT, path);
	join(path, sizeof(path), upper, "/opaque/hidden");
	expect(&resolver, "/opaque/hidden", EUNION_RESOLVER_MISSING, path);
	join(path, sizeof(path), upper, "/shadow/child");
	expect_error(&resolver, "/shadow/child", -ENOTDIR, path);
	join(path, sizeof(path), upper, "/absent");
	expect(&resolver, "/absent", EUNION_RESOLVER_MISSING, path);
	{
		char nested_lower[EUNION_RESOLVER_PATH_MAX];
		char guest[EUNION_RESOLVER_PATH_MAX];

		join(nested_lower, sizeof(nested_lower), upper, "/libexec");
		make_dir(nested_lower);
		join(nested_lower, sizeof(nested_lower), upper, "/libexec/darling");
		make_dir(nested_lower);
		join(path, sizeof(path), nested_lower, "/usr");
		make_dir(path);
		join(path, sizeof(path), nested_lower, "/usr/lib");
		make_dir(path);
		join(path, sizeof(path), nested_lower, "/usr/lib/libSystem.B.dylib");
		make_file(path);

		resolver.lower_root = nested_lower;
		if (eunion_guest_path_from_host(&resolver, path, guest, sizeof(guest)) != 0 ||
			strcmp(guest, "/usr/lib/libSystem.B.dylib") != 0)
			fail("nested lower root was not converted to its guest path");
	}

	printf("EUNION_RESOLVER_OK\n");
	return 0;
}
