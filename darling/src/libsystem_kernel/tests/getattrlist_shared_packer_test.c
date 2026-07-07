#include <sys/attr.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

struct packed_single {
	uint32_t length;
	attrreference_t name;
	fsobj_type_t objtype;
	char storage[256];
};

struct returned_attrs {
	uint32_t commonattr;
	uint32_t volattr;
	uint32_t dirattr;
	uint32_t fileattr;
	uint32_t forkattr;
};

static int check_single(const char* label, struct packed_single* packed, const char* want_name)
{
	char* name = ((char*)&packed->name) + packed->name.attr_dataoffset;

	if (packed->length < sizeof(*packed) - sizeof(packed->storage)) {
		fprintf(stderr, "%s: short packed length %u\n", label, packed->length);
		return 1;
	}
	if (packed->name.attr_length == 0 || strcmp(name, want_name) != 0) {
		fprintf(stderr, "%s: bad name '%s', want '%s'\n", label, name, want_name);
		return 1;
	}
	if (packed->objtype == 0) {
		fprintf(stderr, "%s: missing object type\n", label);
		return 1;
	}
	return 0;
}

static int check_getattrlist_family(void)
{
	const char* path = "/tmp/dar-getattrlist-packer-file";
	const char* want_name = "dar-getattrlist-packer-file";
	int fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0644);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	struct attrlist attrs = {0};
	attrs.bitmapcount = ATTR_BIT_MAP_COUNT;
	attrs.commonattr = ATTR_CMN_NAME | ATTR_CMN_OBJTYPE;

	struct packed_single packed = {0};
	if (getattrlist(path, &attrs, &packed, sizeof(packed), 0) != 0) {
		fprintf(stderr, "getattrlist: %s\n", strerror(errno));
		return 1;
	}
	if (check_single("getattrlist", &packed, want_name))
		return 1;

	memset(&packed, 0, sizeof(packed));
	if (fgetattrlist(fd, &attrs, &packed, sizeof(packed), 0) != 0) {
		fprintf(stderr, "fgetattrlist: %s\n", strerror(errno));
		return 1;
	}
	if (check_single("fgetattrlist", &packed, want_name))
		return 1;

	memset(&packed, 0, sizeof(packed));
	if (getattrlistat(AT_FDCWD, path, &attrs, &packed, sizeof(packed), 0) != 0) {
		fprintf(stderr, "getattrlistat: %s\n", strerror(errno));
		return 1;
	}
	if (check_single("getattrlistat", &packed, want_name))
		return 1;

	close(fd);
	unlink(path);
	return 0;
}

static int check_bulk_error(void)
{
	const char* dir = "/tmp/dar-getattrlistbulk-packer-dir";
	const char* file = "/tmp/dar-getattrlistbulk-packer-dir/file";
	mkdir(dir, 0755);
	int fd = open(file, O_CREAT | O_TRUNC | O_RDWR, 0644);
	if (fd >= 0)
		close(fd);

	int dfd = open(dir, O_RDONLY | O_DIRECTORY);
	if (dfd < 0) {
		perror("open dir");
		return 1;
	}

	struct attrlist attrs = {0};
	attrs.bitmapcount = ATTR_BIT_MAP_COUNT;
	attrs.commonattr = ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_NAME | ATTR_CMN_OBJTYPE | ATTR_CMN_ERROR;

	char buffer[4096] = {0};
	int count = getattrlistbulk(dfd, &attrs, buffer, sizeof(buffer), 0);
	if (count <= 0) {
		fprintf(stderr, "getattrlistbulk: count=%d errno=%d %s\n", count, errno, strerror(errno));
		return 1;
	}

	uint32_t length = *(uint32_t*)buffer;
	struct returned_attrs* returned = (struct returned_attrs*)(buffer + sizeof(uint32_t));
	if (length <= sizeof(uint32_t) + sizeof(struct returned_attrs)) {
		fprintf(stderr, "getattrlistbulk: short record length %u\n", length);
		return 1;
	}
	if (!(returned->commonattr & ATTR_CMN_ERROR)) {
		fprintf(stderr, "getattrlistbulk: ATTR_CMN_ERROR not returned (common=0x%x)\n", returned->commonattr);
		return 1;
	}

	close(dfd);
	unlink(file);
	rmdir(dir);
	return 0;
}

int main(void)
{
	if (check_getattrlist_family())
		return 1;
	if (check_bulk_error())
		return 1;

	puts("GETATTRLIST_SHARED_PACKER_OK");
	return 0;
}
