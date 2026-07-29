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
// AFTER a successful mkdir over a name that shadows a LOWER directory: mark the
// new upper dir opaque so the stale lower children are not re-merged (delete-
// recreate of a populated dir must not resurrect its old contents). No-op when
// the name has no lower directory namesake. Call from the mkdir site after the
// host mkdir returns success.
int vchroot_post_mkdir(const char* guest);
// Marker-namespace isolation: 1 if `name` is in the reserved `user.union.*`
// overlay-private namespace. The xattr syscall sites use this to reject guest
// attempts to forge a marker (setxattr/removexattr -> EPERM) and to hide markers
// from the guest (getxattr -> ENOATTR, listxattr -> filtered out).
int vchroot_xattr_is_marker(const char* name);
int vchroot_readdir_merge(const char* guest, char* out, int cap);
// Paged merged getdents for getdirentries (per-fd state); vchroot_dir_closed
// MUST be called from close()/closedir() so the per-fd state is freed.
int vchroot_getdents_merge(int fd, char* out, int cap);
void vchroot_dir_closed(int fd);
void vchroot_dir_rewind(int fd);
int vchroot_dir_dup(int oldfd, int newfd);
// Thin policy helpers the syscall-emulation sites call (see vchroot_userspace.c):
//   vchroot_prepare_write(guest) BEFORE a write/mutate (expand then hits upper);
//   vchroot_post_unlink(guest)   AFTER a successful unlink/rmdir;
//   vchroot_pre_mkdir(guest)     BEFORE re-creating a possibly-deleted name.
int vchroot_prepare_write(const char* guest);
// Convert an absolute or dirfd-relative syscall path into a canonical absolute
// guest path. Returns 0 for a path inside the union, 1 for an unmanaged path,
// or a negative Linux errno. The caller owns `out`.
int vchroot_canonical_guest_path(int dfd, const char* path, char* out, int cap);
// Create-path variant: like vchroot_canonical_guest_path(), but permits a
// missing or whiteouted leaf so create/recreate operations can remove the
// marker and publish the new upper object.
int vchroot_canonical_guest_create_path(int dfd, const char* path, char* out, int cap);
// *at() variant: resolve a dirfd-relative target to a guest-absolute path via
// the dirfd, then prepare_write. For openat/mkdirat/etc. with a relative path.
int vchroot_prepare_write_at(int dfd, const char* rel);
// fd variant for metadata ops (fchmod/futimes/fsetxattr) on a possibly-lower fd:
// recovers the fd's guest path, copies it up, returns the guest path in `out`
// (len > 0) so the caller can re-open the upper copy. 0 = not union-managed.
int vchroot_prepare_write_fd(int fd, char* out, int cap);
// High-level fd-metadata helper: copy up the fd's object if lower-only and return
// a FRESH fd on the upper copy (caller applies the metadata op to it and closes
// it). Returns the ORIGINAL fd unchanged if unmanaged/escape/no-copyup (caller
// keeps using it, does not close it), or a negative errno. Used by fchmod/
// fchmod_extended/futimes/fsetxattr/fremovexattr.
int vchroot_fd_for_meta_write(int fd);
// High-level helper for CONTENT-mutating fd ops (ftruncate): like
// vchroot_fd_for_meta_write but the returned fd is opened O_RDWR (ftruncate needs
// a writable fd; an O_RDONLY fd yields EINVAL). Returns the original fd if
// unmanaged, or a negative errno.
int vchroot_fd_for_content_write(int fd);
// Perform an E-UNION unlink/rmdir through the fd-relative typed remove
// lifecycle. `handled` is set only for a managed union path; unmanaged paths
// retain the ordinary syscall path.
int vchroot_remove_at(int dfd, const char* path, int remove_directory,
	int* handled);
// BEFORE a rename destination is committed: copy up the dest's parent dir and
// whiteout a lower-only dest namesake, so the host rename lands in the upper
// layer and never moves into / overwrites the shared template.
int vchroot_prepare_rename_dest(const char* guest);
// Return the concrete writable host path for a managed guest path. This is used
// after a mutation transaction has prepared an upper destination (for example,
// a rename over a lower-only name that now carries a whiteout). Returns zero for
// a managed path, one for an unmanaged path, or a negative Linux errno.
int vchroot_upper_guest_path(const char* guest, char* out, int cap);
// BEFORE a create (mkdir/mknod/mkfifo/symlink): copy up the parent dir so the
// new entry lands in the upper layer, and clear any whiteout at the new name.
int vchroot_prepare_create(const char* guest);
// Same policy as vchroot_prepare_create(), but also returns the host upper path
// where the create syscall must run. This avoids resolving a lower namesake back
// to the template after the parent has been prepared.
int vchroot_prepare_create_path(const char* guest, char* out, int cap);
int vchroot_post_unlink(const char* guest);
int vchroot_pre_mkdir(const char* guest);
#endif // EUNION

#endif // _VCHROOT_EXPAND_H
