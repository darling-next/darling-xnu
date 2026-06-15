#ifndef _VCHROOT_EXPAND_H
#define _VCHROOT_EXPAND_H

#define VCHROOT_FOLLOW	1
struct vchroot_expand_args
{
	char path[4096]; // contains evaluated path on return
	unsigned int flags;
	int dfd; // base directory when path is relative
};

struct vchroot_fdpath_args
{
	int fd;
	char* path;
	unsigned int maxlen;
};

struct vchroot_unexpand_args
{
	char path[4096];
};

int vchroot_expand(struct vchroot_expand_args* args);
int vchroot_unexpand(struct vchroot_unexpand_args* args);
int vchroot_fdpath(struct vchroot_fdpath_args* args);

#ifdef EUNION
// E-UNION: writable-upper / read-only-lower union by path translation.
// Copy-up / whiteout / opaque / merged-readdir primitives.
int vchroot_copyup(const char* guest);
int vchroot_whiteout(const char* guest);
int vchroot_unwhiteout(const char* guest);
int vchroot_set_opaque(const char* guest);
int vchroot_readdir_merge(const char* guest, char* out, int cap);
// Thin policy helpers the syscall-emulation sites call (see vchroot_userspace.c):
//   vchroot_prepare_write(guest) BEFORE a write/mutate (expand then hits upper);
//   vchroot_post_unlink(guest)   AFTER a successful unlink/rmdir;
//   vchroot_pre_mkdir(guest)     BEFORE re-creating a possibly-deleted name.
int vchroot_prepare_write(const char* guest);
int vchroot_post_unlink(const char* guest);
int vchroot_pre_mkdir(const char* guest);
#endif // EUNION

#endif // _VCHROOT_EXPAND_H
