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
// Recursive copy-up of a guest subtree (node + ALL descendants). Use for rename
// of a lower-only directory, where the lazy dir-merge no longer applies after
// the host moves the upper dir and whiteouts the source.
int vchroot_copyup_tree(const char* guest);
int vchroot_whiteout(const char* guest);
int vchroot_unwhiteout(const char* guest);
int vchroot_set_opaque(const char* guest);
int vchroot_readdir_merge(const char* guest, char* out, int cap);
// Paged merged getdents for getdirentries (per-fd state); vchroot_dir_closed
// MUST be called from close()/closedir() so the per-fd state is freed.
int vchroot_getdents_merge(int fd, char* out, int cap);
void vchroot_dir_closed(int fd);
// Thin policy helpers the syscall-emulation sites call (see vchroot_userspace.c):
//   vchroot_prepare_write(guest) BEFORE a write/mutate (expand then hits upper);
//   vchroot_post_unlink(guest)   AFTER a successful unlink/rmdir;
//   vchroot_pre_mkdir(guest)     BEFORE re-creating a possibly-deleted name.
int vchroot_prepare_write(const char* guest);
// *at() variant: resolve a dirfd-relative target to a guest-absolute path via
// the dirfd, then prepare_write. For openat/mkdirat/etc. with a relative path.
int vchroot_prepare_write_at(int dfd, const char* rel);
// fd variant for metadata ops (fchmod/futimes/fsetxattr) on a possibly-lower fd:
// recovers the fd's guest path, copies it up, returns the guest path in `out`
// (len > 0) so the caller can re-open the upper copy. 0 = not union-managed.
int vchroot_prepare_write_fd(int fd, char* out, int cap);
// BEFORE unlink/rmdir: decide policy and tell the caller whether to run the host
// delete. The lower template is shared+live (not RO), so a lower-only name must
// be hidden with a whiteout, never deleted on disk.
#define VCHROOT_UNLINK_PROCEED 0  // caller runs the host delete
#define VCHROOT_UNLINK_SKIP    1  // caller must NOT delete (whiteout already set)
int vchroot_prepare_unlink(const char* guest);
// BEFORE a rename destination is committed: copy up the dest's parent dir and
// whiteout a lower-only dest namesake, so the host rename lands in the upper
// layer and never moves into / overwrites the shared template.
int vchroot_prepare_rename_dest(const char* guest);
// BEFORE a create (mkdir/mknod/mkfifo/symlink): copy up the parent dir so the
// new entry lands in the upper layer, and clear any whiteout at the new name.
int vchroot_prepare_create(const char* guest);
int vchroot_post_unlink(const char* guest);
int vchroot_pre_mkdir(const char* guest);
#endif // EUNION

#endif // _VCHROOT_EXPAND_H
