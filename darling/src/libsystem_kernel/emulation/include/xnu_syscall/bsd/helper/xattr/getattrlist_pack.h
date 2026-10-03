#ifndef DARLING_XNU_SYSCALL_BSD_HELPER_XATTR_GETATTRLIST_PACK_H
#define DARLING_XNU_SYSCALL_BSD_HELPER_XATTR_GETATTRLIST_PACK_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/errno.h>

#include <darling/emulation/conversion/xattr/getattrlist.h>

#define DARLING_ATTR_BIT_MAP_COUNT 5

#define DARLING_ATTR_CMN_NAME            0x00000001
#define DARLING_ATTR_CMN_OBJTYPE         0x00000008
#define DARLING_ATTR_CMN_OBJTAG          0x00000010
#define DARLING_ATTR_CMN_FNDRINFO        0x00004000
#define DARLING_ATTR_CMN_ERROR           0x20000000
#define DARLING_ATTR_CMN_RETURNED_ATTRS  0x80000000

#define DARLING_ATTR_DIR_ENTRYCOUNT      0x00000002
#define DARLING_ATTR_FILE_RSRCLENGTH     0x00001000

#define DARLING_ATTR_CMN_SUPPORTED \
	(DARLING_ATTR_CMN_RETURNED_ATTRS | DARLING_ATTR_CMN_NAME | DARLING_ATTR_CMN_OBJTYPE | \
	 DARLING_ATTR_CMN_OBJTAG | DARLING_ATTR_CMN_FNDRINFO | DARLING_ATTR_CMN_ERROR)
#define DARLING_ATTR_VOL_SUPPORTED       0
#define DARLING_ATTR_DIR_SUPPORTED       DARLING_ATTR_DIR_ENTRYCOUNT
#define DARLING_ATTR_FILE_SUPPORTED      DARLING_ATTR_FILE_RSRCLENGTH
#define DARLING_ATTR_FORK_SUPPORTED      0

#define DARLING_FSOPT_REPORT_FULLSIZE    4

#define DARLING_VT_UNKNOWN               0

#define DARLING_DTAPE_VNON  0
#define DARLING_DTAPE_VREG  1
#define DARLING_DTAPE_VDIR  2
#define DARLING_DTAPE_VBLK  3
#define DARLING_DTAPE_VCHR  4
#define DARLING_DTAPE_VLNK  5
#define DARLING_DTAPE_VSOCK 6
#define DARLING_DTAPE_VFIFO 7

#define DARLING_LINUX_DT_FIFO    1
#define DARLING_LINUX_DT_CHR     2
#define DARLING_LINUX_DT_DIR     4
#define DARLING_LINUX_DT_BLK     6
#define DARLING_LINUX_DT_REG     8
#define DARLING_LINUX_DT_LNK     10
#define DARLING_LINUX_DT_SOCK    12

#define DARLING_LINUX_S_IFMT   0170000
#define DARLING_LINUX_S_IFSOCK 0140000
#define DARLING_LINUX_S_IFLNK  0120000
#define DARLING_LINUX_S_IFREG  0100000
#define DARLING_LINUX_S_IFBLK  0060000
#define DARLING_LINUX_S_IFDIR  0040000
#define DARLING_LINUX_S_IFCHR  0020000
#define DARLING_LINUX_S_IFIFO  0010000

struct darling_attrreference {
	int attr_dataoffset;
	unsigned int attr_length;
};

struct darling_attribute_set {
	unsigned int commonattr;
	unsigned int volattr;
	unsigned int dirattr;
	unsigned int fileattr;
	unsigned int forkattr;
};

struct darling_attrpack_entry {
	const char* name;
	size_t name_len;
	unsigned int objtype;
	uint32_t objtag;
	const void* finderinfo;
	uint32_t error;
	uint32_t dir_entrycount;
	uint64_t file_rsrclength;
	int has_objtype;
	int has_objtag;
	int has_finderinfo;
	int has_error;
	int has_dir_entrycount;
	int has_file_rsrclength;
};

static inline size_t darling_attr_align4(size_t value)
{
	return (value + 3) & ~(size_t)3;
}

static inline int darling_attrlist_has_unsupported(const struct xnu_attrlist* alist)
{
	return ((alist->commonattr & DARLING_ATTR_CMN_SUPPORTED) != alist->commonattr) ||
		((alist->volattr & DARLING_ATTR_VOL_SUPPORTED) != alist->volattr) ||
		((alist->dirattr & DARLING_ATTR_DIR_SUPPORTED) != alist->dirattr) ||
		((alist->fileattr & DARLING_ATTR_FILE_SUPPORTED) != alist->fileattr) ||
		((alist->forkattr & DARLING_ATTR_FORK_SUPPORTED) != alist->forkattr);
}

static inline int darling_attrlist_validate(const struct xnu_attrlist* alist, int allow_returned_subset)
{
	if (!alist)
		return -EFAULT;
	if (alist->bitmapcount < DARLING_ATTR_BIT_MAP_COUNT)
		return -EINVAL;
	if (!allow_returned_subset || !(alist->commonattr & DARLING_ATTR_CMN_RETURNED_ATTRS)) {
		if (darling_attrlist_has_unsupported(alist))
			return -EINVAL;
	}
	return 0;
}

static inline unsigned int darling_objtype_from_mode(unsigned int mode)
{
	switch (mode & DARLING_LINUX_S_IFMT) {
		case DARLING_LINUX_S_IFREG:  return DARLING_DTAPE_VREG;
		case DARLING_LINUX_S_IFDIR:  return DARLING_DTAPE_VDIR;
		case DARLING_LINUX_S_IFLNK:  return DARLING_DTAPE_VLNK;
		case DARLING_LINUX_S_IFBLK:  return DARLING_DTAPE_VBLK;
		case DARLING_LINUX_S_IFCHR:  return DARLING_DTAPE_VCHR;
		case DARLING_LINUX_S_IFSOCK: return DARLING_DTAPE_VSOCK;
		case DARLING_LINUX_S_IFIFO:  return DARLING_DTAPE_VFIFO;
		default:                     return DARLING_DTAPE_VNON;
	}
}

static inline unsigned int darling_objtype_from_dtype(unsigned char d_type)
{
	switch (d_type) {
		case DARLING_LINUX_DT_REG:  return DARLING_DTAPE_VREG;
		case DARLING_LINUX_DT_DIR:  return DARLING_DTAPE_VDIR;
		case DARLING_LINUX_DT_LNK:  return DARLING_DTAPE_VLNK;
		case DARLING_LINUX_DT_BLK:  return DARLING_DTAPE_VBLK;
		case DARLING_LINUX_DT_CHR:  return DARLING_DTAPE_VCHR;
		case DARLING_LINUX_DT_SOCK: return DARLING_DTAPE_VSOCK;
		case DARLING_LINUX_DT_FIFO: return DARLING_DTAPE_VFIFO;
		default:                    return DARLING_DTAPE_VNON;
	}
}

static inline int darling_attr_wants_objtype(const struct xnu_attrlist* alist)
{
	return (alist->commonattr & DARLING_ATTR_CMN_OBJTYPE) ||
		(alist->dirattr & DARLING_ATTR_DIR_SUPPORTED) ||
		(alist->fileattr & DARLING_ATTR_FILE_SUPPORTED);
}

static inline size_t darling_attrpack_entry_size(const struct xnu_attrlist* alist, const struct darling_attrpack_entry* entry)
{
	size_t size = sizeof(uint32_t);

	if (alist->commonattr & DARLING_ATTR_CMN_RETURNED_ATTRS)
		size += sizeof(struct darling_attribute_set);
	if (alist->commonattr & DARLING_ATTR_CMN_NAME)
		size += sizeof(struct darling_attrreference) + darling_attr_align4(entry->name_len + 1);
	if ((alist->commonattr & DARLING_ATTR_CMN_OBJTYPE) && entry->has_objtype)
		size += sizeof(uint32_t);
	if ((alist->commonattr & DARLING_ATTR_CMN_OBJTAG) && entry->has_objtag)
		size += sizeof(uint32_t);
	if ((alist->commonattr & DARLING_ATTR_CMN_FNDRINFO) && entry->has_finderinfo)
		size += 32;
	if (alist->commonattr & DARLING_ATTR_CMN_ERROR)
		size += sizeof(uint32_t);
	if ((alist->dirattr & DARLING_ATTR_DIR_ENTRYCOUNT) && entry->has_dir_entrycount)
		size += sizeof(uint32_t);
	if ((alist->fileattr & DARLING_ATTR_FILE_RSRCLENGTH) && entry->has_file_rsrclength)
		size += sizeof(uint64_t);

	return size;
}

static inline size_t darling_attrpack_entry(char* out, const struct xnu_attrlist* alist, const struct darling_attrpack_entry* entry)
{
	char* p = out;
	char* len_field = p;
	p += sizeof(uint32_t);

	struct darling_attribute_set* returned = 0;
	if (alist->commonattr & DARLING_ATTR_CMN_RETURNED_ATTRS) {
		returned = (struct darling_attribute_set*)p;
		p += sizeof(struct darling_attribute_set);
	}

	unsigned int r_common = returned ? DARLING_ATTR_CMN_RETURNED_ATTRS : 0;
	unsigned int r_dir = 0;
	unsigned int r_file = 0;

	char* name_ref = 0;
	if (alist->commonattr & DARLING_ATTR_CMN_NAME) {
		name_ref = p;
		p += sizeof(struct darling_attrreference);
		r_common |= DARLING_ATTR_CMN_NAME;
	}
	if ((alist->commonattr & DARLING_ATTR_CMN_OBJTYPE) && entry->has_objtype) {
		*((uint32_t*)p) = entry->objtype;
		p += sizeof(uint32_t);
		r_common |= DARLING_ATTR_CMN_OBJTYPE;
	}
	if ((alist->commonattr & DARLING_ATTR_CMN_OBJTAG) && entry->has_objtag) {
		*((uint32_t*)p) = entry->objtag;
		p += sizeof(uint32_t);
		r_common |= DARLING_ATTR_CMN_OBJTAG;
	}
	if ((alist->commonattr & DARLING_ATTR_CMN_FNDRINFO) && entry->has_finderinfo) {
		memcpy(p, entry->finderinfo, 32);
		p += 32;
		r_common |= DARLING_ATTR_CMN_FNDRINFO;
	}
	if (alist->commonattr & DARLING_ATTR_CMN_ERROR) {
		*((uint32_t*)p) = entry->error;
		p += sizeof(uint32_t);
		r_common |= DARLING_ATTR_CMN_ERROR;
	}
	if ((alist->dirattr & DARLING_ATTR_DIR_ENTRYCOUNT) && entry->has_dir_entrycount) {
		*((uint32_t*)p) = entry->dir_entrycount;
		p += sizeof(uint32_t);
		r_dir |= DARLING_ATTR_DIR_ENTRYCOUNT;
	}
	if ((alist->fileattr & DARLING_ATTR_FILE_RSRCLENGTH) && entry->has_file_rsrclength) {
		*((uint64_t*)p) = entry->file_rsrclength;
		p += sizeof(uint64_t);
		r_file |= DARLING_ATTR_FILE_RSRCLENGTH;
	}
	if (name_ref) {
		struct darling_attrreference* ref = (struct darling_attrreference*)name_ref;
		size_t name_bytes = entry->name_len + 1;
		size_t name_aligned = darling_attr_align4(name_bytes);
		ref->attr_dataoffset = (int)(p - name_ref);
		ref->attr_length = (unsigned int)name_bytes;
		memcpy(p, entry->name, name_bytes);
		if (name_aligned != name_bytes)
			memset(p + name_bytes, 0, name_aligned - name_bytes);
		p += name_aligned;
	}
	if (returned) {
		returned->commonattr = r_common;
		returned->volattr = 0;
		returned->dirattr = r_dir;
		returned->fileattr = r_file;
		returned->forkattr = 0;
	}

	*((uint32_t*)len_field) = (uint32_t)(p - len_field);
	return (size_t)(p - out);
}

#endif
