
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#ifdef EUNION
#include <linux_premigration/eunion_resolver.h>
#include <linux_premigration/eunion_sidecar.h>
#endif
#ifdef TEST
#	include <unistd.h>
#	include <sys/stat.h>
#	include <sys/syscall.h>
#	include <stdio.h>
#	include <stdbool.h>
#	include <stdlib.h>
#	include <string.h>
#	include <strings.h>
#	include <errno.h>
#	include <dirent.h>
#	include <fcntl.h>
#	include <stdint.h>

#	define LINUX_SYSCALL(...) ({ int __rv = syscall(__VA_ARGS__); if (__rv == -1) __rv = -errno; __rv; })
#	define LINUX_ENOENT ENOENT
#	define LINUX_EEXIST EEXIST
#	define LINUX_ELOOP ELOOP
#	define LINUX_ENAMETOOLONG ENAMETOOLONG
#	define LINUX_EPERM EPERM
#	define LINUX_EXDEV EXDEV

#	define LINUX_S_IFMT S_IFMT
#	define LINUX_S_IFLNK S_IFLNK

#	define LINUX_AT_FDCWD AT_FDCWD
#	define LINUX_O_RDONLY O_RDONLY

#	define __simple_sprintf sprintf
#	define __simple_snprintf snprintf
#	define __simple_printf(...) fprintf(stderr, __VA_ARGS__)
#	define linux_dirent64 dirent
typedef struct stat stat_t;
#else
#	include <stdbool.h>
#   include <stddef.h>

#	include <darling/emulation/xnu_syscall/bsd/impl/fcntl/open.h>
#	include <darling/emulation/common/base.h>
#	include <darling/emulation/other/mach/lkm.h>
#	include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#	include <darling/emulation/common/simple.h>
#	include <darling/emulation/conversion/dirent/getdirentries.h>
#	include <darling/emulation/conversion/errno.h>
#	include <darling/emulation/conversion/fcntl/open.h>
#	include <darling/emulation/conversion/duct_errno.h>
#	include <darling/emulation/conversion/stat/common.h>
#	include <darling/emulation/xnu_syscall/bsd/impl/dirent/getdirentries.h>
#	include <darling/emulation/conversion/common_at.h>
#	include <string.h>

#include <darlingserver/rpc.h>

typedef struct linux_stat stat_t;

#define LINUX_S_IFMT 00170000
#define LINUX_S_IFLNK 0120000

#define __simple_printf(...)
// #define __simple_printf __simple_kprintf // For bug hunting

#endif

static bool next_component(const char* from, const char** end);

static char prefix_path[4096] = {0}; // MUST NOT end with '/'
static int prefix_path_len = -1;

#ifdef EUNION
// ============================ E-UNION provenance ============================
// The E-UNION code in this file (all #ifdef EUNION blocks: union resolve,
// copy-up, whiteout/opaque, readdir-merge, template protection) is new C written
// for Darling and is covered by this file's existing license. No third-party
// source code is copied or translated in. The union/copy-up/whiteout/merge
// ALGORITHMS are independently reimplemented from concepts in:
//   * gVisor overlay (Apache-2.0) -- https://github.com/google/gvisor
//       pkg/sentry/fsimpl/overlay/{copy_up,directory,overlay}.go. gVisor is Go;
//       this is C over raw Linux syscalls with a different cross-process
//       atomicity model, i.e. an independent reimplementation of the idea, not a
//       derivative of gVisor's code. Cited inline below for auditability.
//   * Linux overlayfs docs (Documentation/filesystems/overlayfs.rst) -- semantics.
// PRoot (GPL-2, https://github.com/proot-me/proot) was reviewed but NO PRoot code
// or design is used here; the path engine is Darling's own vchroot.
// ===========================================================================
//
// E-UNION (dar-test-infra-sp5.8.4.4): shared read-only system template that
// the writable per-prefix layer (prefix_path) is unioned over. When a guest
// path is absent in prefix_path it falls back to libexec_path. Empty/unset
// (len <= 0) disables the union and the resolver behaves exactly as before.
static char libexec_path[4096] = {0}; // MUST NOT end with '/'
static int libexec_path_len = -1;
static char eunion_sidecar_path[4096] = {0};
static int eunion_sidecar_path_len = -1;
static char eunion_sidecar_host_path[4096] = {0};
static int eunion_sidecar_host_path_len = -1;
static struct eunion_sidecar_runtime eunion_anchored_runtime = {0};
#ifndef LINUX_S_IFDIR
#define LINUX_S_IFDIR 0040000
#endif

static void set_libexec_path(const char* p)
{
	if (!p || !*p)
	{
		libexec_path[0] = '\0';
		libexec_path_len = 0;
		return;
	}
	if (p == libexec_path) {
		libexec_path_len = (int)strlen(libexec_path);
		return;
	}
	strcpy(libexec_path, p);
	libexec_path_len = (int)strlen(libexec_path);
}
#define HAVE_LIBEXEC_SETTER 1

// The shared template path baked in at build time (== darlingserver's
// LIBEXEC_PATH). Provided to the emulation build as a compile definition; the
// fallback below keeps the hermetic unit build (which sets the template itself)
// and any build that forgets the define from breaking.
#ifndef EUNION_LIBEXEC_PATH
#define EUNION_LIBEXEC_PATH ""
#endif
#ifndef LINUX_EINVAL
#define LINUX_EINVAL 22
#endif
#ifndef LINUX_EIO
#define LINUX_EIO 5
#endif
#ifndef LINUX_ENOMEM
#define LINUX_ENOMEM 12
#endif
#ifndef LINUX_EOVERFLOW
#define LINUX_EOVERFLOW 75
#endif
#ifndef LINUX_ENOTDIR
#define LINUX_ENOTDIR 20
#endif

extern void* malloc(__SIZE_TYPE__ size);
extern void free(void* pointer);

static int eunion_lstat(const char* host, stat_t* st); // defined below

// A sidecar-v1 prefix is the only supported E-UNION runtime format. The
// external activation record is validated before the union becomes visible.
// Missing activation is a typed legacy verdict: boot must stop and an explicit
// lifecycle-owned recreate must be requested. There is no physical-whiteout
// fallback and inspection never mutates the prefix.
static int eunion_init_from_prefix(int prefix_descriptor)
{
	if (eunion_anchored_runtime.anchored)
		return 0;
	if (prefix_path_len <= 0)
		return -LINUX_EINVAL;

	char sidecar[4096];
	int n = prefix_path_len;
	if (n + (int)sizeof(EUNION_SIDECAR_SUFFIX) > (int)sizeof(sidecar))
		return -LINUX_ENAMETOOLONG;
	memcpy(sidecar, prefix_path, n);
	memcpy(sidecar + n, EUNION_SIDECAR_SUFFIX,
		sizeof(EUNION_SIDECAR_SUFFIX));
	const char* lower = libexec_path_len > 0
		? libexec_path : EUNION_LIBEXEC_PATH;
	if (!lower || !*lower)
		return -LINUX_EIO;
	int result = eunion_sidecar_runtime_anchor(
		&eunion_anchored_runtime, prefix_descriptor, lower, sidecar);
	if (result == -LINUX_ENOENT || result == -LINUX_ENOTDIR) {
		__simple_printf("PREFIX_RECREATE_REQUIRED prefix_format=legacy\n");
		return -EUNION_PREFIX_RECREATE_REQUIRED_ERROR;
	}
	if (result < 0)
		return result;
	struct eunion_prefix_format_inspection inspection;
	result = eunion_sidecar_inspect_prefix(
		&eunion_anchored_runtime, &inspection);
	if (result >= 0 &&
		inspection.verdict != EUNION_PREFIX_FORMAT_VALID &&
		inspection.verdict != EUNION_PREFIX_RECREATE_REQUIRED) {
		result = eunion_sidecar_prefix_state_v3_valid(
			&eunion_anchored_runtime);
		if (result == -EUNION_PREFIX_RECREATE_REQUIRED_ERROR) {
			__simple_printf(
				"PREFIX_RECREATE_REQUIRED prefix_format=legacy\n");
			eunion_sidecar_runtime_release(&eunion_anchored_runtime);
			return result;
		}
		if (result >= 0)
			result = eunion_sidecar_initialize(
				&eunion_anchored_runtime);
		if (result >= 0)
			result = eunion_sidecar_inspect_prefix(
				&eunion_anchored_runtime, &inspection);
	}
	if (result < 0) {
		eunion_sidecar_runtime_release(&eunion_anchored_runtime);
		return result;
	}
	if (inspection.verdict == EUNION_PREFIX_RECREATE_REQUIRED) {
		__simple_printf("PREFIX_RECREATE_REQUIRED prefix_format=legacy\n");
		eunion_sidecar_runtime_release(&eunion_anchored_runtime);
		return -EUNION_PREFIX_RECREATE_REQUIRED_ERROR;
	}
	if (inspection.verdict != EUNION_PREFIX_FORMAT_VALID) {
		eunion_sidecar_runtime_release(&eunion_anchored_runtime);
		return -LINUX_EIO;
	}
	int path_length = __simple_snprintf(eunion_sidecar_path,
		sizeof(eunion_sidecar_path), "/proc/self/fd/%d",
		eunion_anchored_runtime.sidecar_descriptor);
	if (path_length <= 0 ||
		path_length >= (int)sizeof(eunion_sidecar_path)) {
		eunion_sidecar_runtime_release(&eunion_anchored_runtime);
		return -LINUX_ENAMETOOLONG;
	}
	eunion_sidecar_path_len = (int)strlen(eunion_sidecar_path);
	int host_path_length = LINUX_SYSCALL(__NR_readlink,
		eunion_sidecar_path, eunion_sidecar_host_path,
		sizeof(eunion_sidecar_host_path) - 1);
	if (host_path_length <= 0 ||
		host_path_length >= (int)sizeof(eunion_sidecar_host_path) - 1) {
		eunion_sidecar_runtime_release(&eunion_anchored_runtime);
		eunion_sidecar_path_len = -1;
		return host_path_length < 0
			? host_path_length : -LINUX_ENAMETOOLONG;
	}
	eunion_sidecar_host_path[host_path_length] = '\0';
	if (strstr(eunion_sidecar_host_path, " (deleted)") != NULL) {
		eunion_sidecar_runtime_release(&eunion_anchored_runtime);
		eunion_sidecar_path_len = -1;
		eunion_sidecar_host_path_len = -1;
		return -LINUX_EIO;
	}
	eunion_sidecar_host_path_len = host_path_length;
	set_libexec_path(lower);
	return 0;
}

#ifndef TEST
static void eunion_require_anchored_prefix(void)
{
	// E-UNION is anchored only by __darling_vchroot(), which receives the
	// retained prefix directory descriptor. A string-only lazy lookup cannot
	// cross that capability boundary and must fail before any sidecar access.
	__simple_printf(
		"E-UNION prefix capability unavailable; "
		"__darling_vchroot must initialize the prefix\n");
	__simple_abort();
}
#endif

// -------- E-UNION copy-on-write ------------------------------------------
//
// When a guest path that exists only in the read-only lower template is about
// to be mutated (open-for-write, truncate, chmod, rename source, create child,
// ...), it must first be materialized ("copied up") into the writable upper
// layer so the shared template is never modified. Modeled on gVisor overlay
// copy_up.go, with the cross-process safety the gVisor in-process copyMu lacks:
//
//   * recursive parent copy-up first (a lower-only parent dir is recreated up);
//   * copy into UPPER/.union-work/<tid>.<seq> fully (data+mode), then atomic
//     rename() into place -- so a concurrent reader never sees a half file;
//   * winner-takes-all: a rename/EEXIST race just means someone else copied it
//     up first, which is success (idempotent).
//
// This is the shared CoW core that both the pure-union and hardlink layering
// strategies build on (see the bead).

#ifndef LINUX_O_WRONLY
#define LINUX_O_WRONLY 01
#endif
#ifndef LINUX_O_CREAT
#define LINUX_O_CREAT 0100
#endif
#ifndef LINUX_O_EXCL
#define LINUX_O_EXCL 0200
#endif
#ifndef LINUX_EINVAL
#define LINUX_EINVAL 22
#endif
#ifndef LINUX_ENOTDIR
#define LINUX_ENOTDIR 20
#endif
#ifndef LINUX_EIO
#define LINUX_EIO 5
#endif
#ifndef LINUX_EMFILE
#define LINUX_EMFILE 24
#endif
#ifdef TEST
extern int eunion_test_fail_xattr;
#endif
#ifndef LINUX_S_IFDIR
#ifndef LINUX_S_IFDIR
#define LINUX_S_IFDIR 0040000
#endif
#endif
#ifndef LINUX_S_IFREG
#define LINUX_S_IFREG 0100000
#endif

extern int __simple_sprintf(char* str, const char* fmt, ...);

static int eunion_guest_path_safe(const char* guest)
{
	int depth = 0;
	const char* cursor;

	if (!guest || guest[0] != '/')
		return -LINUX_EINVAL;
	for (cursor = guest; *cursor; )
	{
		const char* end;
		int length;
		while (*cursor == '/')
			cursor++;
		if (!*cursor)
			break;
		end = cursor;
		while (*end && *end != '/')
			end++;
		length = (int)(end - cursor);
		if (length == 1 && cursor[0] == '.')
		{
			cursor = end;
			continue;
		}
		if (length == 2 && cursor[0] == '.' && cursor[1] == '.')
		{
			if (depth == 0)
				return -LINUX_EINVAL;
			depth--;
		}
		else
			depth++;
		cursor = end;
	}
	return 0;
}

// Build the host path for `guest` (a guest-absolute path, no symlink follow)
// under `root` (prefix_path or libexec_path). Returns length, or -1 on overflow.
static int eunion_host_path(const char* root, int root_len, const char* guest, char* out, int cap)
{
	int glen = (int)strlen(guest);
	if (eunion_guest_path_safe(guest) < 0)
		return -1;
	if (root_len + glen + 1 > cap)
		return -1;
	memcpy(out, root, root_len);
	memcpy(out + root_len, guest, glen + 1);
	return root_len + glen;
}

static int eunion_lstat(const char* host, stat_t* st)
{
	#if defined(__NR_lstat)
		return LINUX_SYSCALL(__NR_lstat, host, st);
	#elif defined(__NR_newfstatat)
		return LINUX_SYSCALL(__NR_newfstatat, LINUX_AT_FDCWD, host, st, LINUX_AT_SYMLINK_NOFOLLOW);
	#else
		return LINUX_SYSCALL(__NR_fstatat64, LINUX_AT_FDCWD, host, st, LINUX_AT_SYMLINK_NOFOLLOW);
	#endif
}

// Copy up `guest` (a guest-absolute path) from the lower template into the
// upper layer if it lives only in the lower layer. Returns 0 if the object is
// (now) present in the upper layer, a negative Linux errno otherwise.
int vchroot_copyup(const char* guest)
{
	if (libexec_path_len <= 0 || prefix_path_len < 0)
		return -LINUX_ENOENT;
	if (!eunion_anchored_runtime.anchored)
		return -LINUX_EIO;
	return eunion_sidecar_copy_up(&eunion_anchored_runtime, guest);
}

// Recursively copy up a guest subtree into the upper layer (node + ALL
// descendants). Plain vchroot_copyup() is LAZY for directories -- it recreates
// the dir empty and lets the resolver merge contents on demand. That laziness
// is correct for an in-place write, but WRONG for rename(): rename physically
// moves the upper directory and then whiteouts the source name, after which the
// lazy lower-merge no longer applies -- so any descendant left only in the
// template would vanish. rename of a lower-only dir must therefore deep-copy the
// whole subtree first. (gVisor copy_up.go F.3: copy-up src + all descendants
// before the host rename.)
#ifndef LINUX_O_DIRECTORY
#define LINUX_O_DIRECTORY 0200000
#endif
static int eunion_manage(const char* guest); // defined with the write-op helpers

int vchroot_copyup_tree(const char* guest)
{
	if (!eunion_manage(guest))
		return 0;
	if (!eunion_anchored_runtime.anchored)
		return -LINUX_EIO;
	int result = eunion_sidecar_copy_up_tree(
		&eunion_anchored_runtime, guest);
	return result == -LINUX_ENOENT ? 0 : result;
}

// -------- E-UNION sidecar record tags ------------------------------------
//
// Whiteout and opaque state lives only in the anchored sidecar-v1 store.
// These strings are resolver tags and a reserved guest xattr namespace; the
// runtime never reads or writes physical marker xattrs in the union tree.

static const char EUNION_WH_XATTR[]     = "user.union.whiteout";
static const char EUNION_OPAQUE_XATTR[] = "user.union.opaque";

#ifdef TEST
int eunion_test_fail_whiteout;
int eunion_test_fail_xattr;
#endif

// E-UNION reserves the `user.union.` xattr namespace for its own overlay-private
// markers (whiteout/opaque). The guest must never be able to FORGE a marker (a
// setxattr/removexattr that would fabricate or clear a whiteout/opaque and so
// resurrect a deleted name or unhide a lower subtree), nor OBSERVE one (a
// getxattr/listxattr that would leak the union's internal bookkeeping). The
// syscall-emulation xattr sites call this predicate to reject (set/remove ->
// EPERM) or hide (get -> ENOATTR, list -> filtered) any name in the namespace.
// Returns 1 if `name` is in the reserved `user.union.` namespace, else 0.
static const char EUNION_MARKER_NS[] = "user.union.";
int vchroot_xattr_is_marker(const char* name)
{
	if (!name)
		return 0;
	// Reserved iff the name begins with the full "user.union." namespace prefix
	// (the trailing dot is significant: "user.unionX" is a distinct guest-legal
	// name, NOT a marker). strncmp over the prefix length tests exactly that
	// boundary -- a bare "user.union" or "user.unionX" both differ before or at
	// the dot and so are not matched.
	int nslen = (int)sizeof(EUNION_MARKER_NS) - 1; // strlen("user.union.")
	return strncmp(name, EUNION_MARKER_NS, nslen) == 0;
}

#ifndef LINUX_O_DIRECTORY
#define LINUX_O_DIRECTORY 0200000
#endif

static int eunion_resolver_path_status(void* context, const char* host)
{
	stat_t st;
	(void)context;
	return eunion_lstat(host, &st);
}

struct eunion_resolver_scope {
	eunion_sidecar_view view;
	int sidecar_open;
	struct eunion_resolver resolver;
};

static int eunion_resolver_marker_status(void* context, const char* host,
	const char* marker)
{
	struct eunion_resolver_scope* scope = context;
	if (!scope || !scope->sidecar_open)
		return -LINUX_EIO;
	if (strncmp(host, prefix_path, prefix_path_len) != 0 ||
		(host[prefix_path_len] != '\0' &&
		 host[prefix_path_len] != '/'))
		return 0;
	const char* guest = host + prefix_path_len;
	if (*guest == '\0')
		guest = "/";
	struct eunion_sidecar_lookup lookup;
	int result = eunion_sidecar_lookup_path(
		scope->view, guest, &lookup);
	if (result < 0)
		return result;
	if (strcmp(marker, EUNION_WH_XATTR) == 0)
		return lookup.kind == EUNION_SIDECAR_RECORD_WHITEOUT;
	if (strcmp(marker, EUNION_OPAQUE_XATTR) == 0)
		return lookup.kind == EUNION_SIDECAR_RECORD_OPAQUE;
	return -LINUX_EINVAL;
}

static int eunion_resolver_path_kind(void* context, const char* host)
{
	stat_t st;
	(void)context;
	if (eunion_lstat(host, &st) < 0)
		return -LINUX_ENOENT;
	return (st.st_mode & LINUX_S_IFMT) == LINUX_S_IFDIR
		? EUNION_RESOLVER_DIRECTORY
		: EUNION_RESOLVER_NON_DIRECTORY;
}

static struct eunion_resolver eunion_current_resolver(void* context)
{
	return (struct eunion_resolver) {
		.upper_root = prefix_path,
		.lower_root = libexec_path_len > 0 ? libexec_path : NULL,
		.whiteout_marker = EUNION_WH_XATTR,
		.opaque_marker = EUNION_OPAQUE_XATTR,
		.missing_status = -LINUX_ENOENT,
		.not_directory_status = -LINUX_ENOTDIR,
		.ops = {
			.path_status = eunion_resolver_path_status,
			.marker_status = eunion_resolver_marker_status,
			.path_kind = eunion_resolver_path_kind,
		},
		.context = context,
	};
}

static int eunion_resolver_scope_open(struct eunion_resolver_scope* scope)
{
	memset(scope, 0, sizeof(*scope));
	if (eunion_sidecar_path_len <= 0)
		return -LINUX_EIO;
	int result = eunion_sidecar_view_open(scope->view,
		&eunion_anchored_runtime,
		EUNION_SIDECAR_ACCESS_SHARED);
	if (result < 0)
		return result;
	scope->sidecar_open = 1;
	scope->resolver = eunion_current_resolver(scope);
	return 0;
}

static int eunion_resolver_scope_close(struct eunion_resolver_scope* scope)
{
	if (!scope->sidecar_open)
		return 0;
	scope->sidecar_open = 0;
	return eunion_sidecar_view_close(scope->view);
}

// Is the guest path hidden by a typed sidecar whiteout?
static int eunion_is_whiteout(const char* guest)
{
	if (eunion_sidecar_path_len <= 0)
		return -LINUX_EIO;
	eunion_sidecar_view view = {{0}};
	int result = eunion_sidecar_view_open(
		view, &eunion_anchored_runtime,
		EUNION_SIDECAR_ACCESS_SHARED);
	if (result < 0)
		return result;
	struct eunion_sidecar_lookup lookup;
	result = eunion_sidecar_lookup_path(view, guest, &lookup);
	int close_result = eunion_sidecar_view_close(view);
	if (result >= 0 && close_result < 0)
		result = close_result;
	return result < 0 ? result :
		lookup.kind == EUNION_SIDECAR_RECORD_WHITEOUT;
}

// Publish a typed whiteout exclusively in the external sidecar namespace.
int vchroot_whiteout(const char* guest)
{
	if (prefix_path_len < 0)
		return -LINUX_ENOENT;
#ifdef TEST
	if (eunion_test_fail_whiteout > 0)
	{
		eunion_test_fail_whiteout--;
		return -LINUX_EIO;
	}
#endif
	if (eunion_sidecar_path_len <= 0)
		return -LINUX_EIO;
	eunion_sidecar_view view = {{0}};
	int result = eunion_sidecar_view_open(
		view, &eunion_anchored_runtime,
		EUNION_SIDECAR_ACCESS_EXCLUSIVE);
	if (result < 0)
		return result;
	result = eunion_sidecar_publish_whiteout(view, guest);
	int close_result = eunion_sidecar_view_close(view);
	return result < 0 ? result : close_result;
}

// Remove a whiteout marker (the path is being recreated). Removes the
// placeholder file entirely so a subsequent copy-up / create can take its place.
int vchroot_unwhiteout(const char* guest)
{
	if (eunion_sidecar_path_len <= 0)
		return -LINUX_EIO;
	int whiteout = eunion_is_whiteout(guest);
	if (whiteout < 0)
		return whiteout;
	if (!whiteout)
		return 0;
	eunion_sidecar_view view = {{0}};
	int result = eunion_sidecar_view_open(
		view, &eunion_anchored_runtime,
		EUNION_SIDECAR_ACCESS_EXCLUSIVE);
	if (result < 0)
		return result;
	result = eunion_sidecar_clear_whiteout(view, guest);
	int close_result = eunion_sidecar_view_close(view);
	return result < 0 ? result : close_result;
}

// AFTER a successful mkdir: if the new name shadows a LOWER directory, the freshly
// created upper dir must be made opaque, or the resolver/readdir would re-merge the
// stale lower children (delete-recreate of a populated dir resurrects its old
// contents). Set opaque ONLY when the lower namesake is itself a directory -- a
// brand-new name with no lower dir namesake needs no marker (an opaque empty dir is
// harmless but pointless, and we avoid touching the upper for the common case).
// Must run AFTER the mkdir (vchroot_set_opaque copies the dir up, which only exists
// post-mkdir). No-op when unmanaged or when nothing shadows a lower dir.
int vchroot_post_mkdir(const char* guest)
{
	if (!eunion_manage(guest))
		return 0;

	// Does the new name shadow a LOWER directory? Only then is opacity needed --
	// a mkdir of a brand-new name (no lower namesake, or a lower non-dir namesake)
	// has nothing to mask.
	char lo[4096];
	if (eunion_host_path(libexec_path, libexec_path_len, guest, lo, sizeof(lo)) < 0)
		return -LINUX_ENAMETOOLONG;
	stat_t lst;
	if (eunion_lstat(lo, &lst) != 0)
		return 0; // no lower namesake: nothing to mask
	if ((lst.st_mode & LINUX_S_IFMT) != LINUX_S_IFDIR)
		return 0; // lower namesake is not a dir: no dir-merge to suppress

	// The new upper dir shadows a populated lower dir. Mark it opaque so the stale
	// lower children are not re-merged into the recreated dir.
	return vchroot_set_opaque(guest);
}

// Mark an upper directory opaque so its lower namesake is not merged.
int vchroot_set_opaque(const char* guest)
{
	int r = vchroot_copyup(guest); // ensure the dir exists in the upper layer
	if (r < 0)
		return r;
	if (eunion_sidecar_path_len <= 0)
		return -LINUX_EIO;
	eunion_sidecar_view view = {{0}};
	r = eunion_sidecar_view_open(
		view, &eunion_anchored_runtime,
		EUNION_SIDECAR_ACCESS_EXCLUSIVE);
	if (r < 0)
		return r;
	r = eunion_sidecar_publish_opaque(view, guest);
	int close_result = eunion_sidecar_view_close(view);
	return r < 0 ? r : close_result;
}

// -------- E-UNION write-op wiring helpers --------------------------------
//
// Mutating syscall sites use the sidecar transaction entrypoints below.
// Prepare helpers may materialize an upper parent, but never retire semantic
// records or perform the final backing mutation outside the transaction.

// Is this a guest path we union-manage? (absolute, and a prefix is configured)
static int eunion_manage(const char* guest)
{
	return libexec_path_len > 0 && prefix_path_len >= 0
		&& guest && guest[0] == '/';
}

// Before a write/mutate: ensure the target lives in the writable upper layer so
// the real syscall never mutates the shared template. If the path is lower-only
// it is copied up; if it carries a whiteout the marker is cleared first (an
// O_CREAT-style write resurrects a deleted name); absent-in-both and
// already-upper are both no-op successes (the create lands in the upper).
int vchroot_prepare_write(const char* guest)
{
	if (!eunion_manage(guest))
		return 0;

	// a whiteout means the name was deleted; writing it resurrects it
	int whiteout = eunion_is_whiteout(guest);
	if (whiteout < 0)
		return whiteout;
	if (whiteout)
	{
		// Only an actual successful O_CREAT/mkdir transaction may retire the
		// whiteout. Clearing it in a prepare-only path makes a failed backing
		// syscall or SIGKILL resurrect the lower object.
		return 0;
	}

	int r = vchroot_copyup(guest);
	if (r == -LINUX_ENOENT)
		return 0; // absent in both layers: a create will make it fresh in upper
	return r; // 0 if copied up or already upper; negative on real error
}

// Canonicalize a syscall path through the real vchroot resolver and convert the
// resulting host path back to a guest path. AT_FDCWD cannot be passed to
// vchroot_fdpath(), so it must go through vchroot_expand() using the process cwd.
// Returning 1 means the path is outside both union layers and is intentionally
// unmanaged; returning 0 means `out` contains an absolute guest path.
int vchroot_canonical_guest_path(int dfd, const char* path, char* out, int cap)
{
	struct vchroot_expand_args expanded;
	struct eunion_resolver resolver;
	int status;

	if (!path || !out || cap <= 0)
		return -LINUX_EINVAL;
	if ((int)strlen(path) + 1 > (int)sizeof(expanded.path))
		return -LINUX_ENAMETOOLONG;
	memcpy(expanded.path, path, strlen(path) + 1);
	expanded.flags = 0;
	expanded.dfd = dfd;
	status = vchroot_expand(&expanded);
	if (status < 0)
		return status;

	resolver = eunion_current_resolver(NULL);
	status = eunion_guest_path_from_host(&resolver, expanded.path, out, cap);
	if (status < 0)
		return -LINUX_ENAMETOOLONG;
	return status;
}

int vchroot_canonical_guest_create_path(int dfd, const char* path, char* out, int cap)
{
	int status = vchroot_canonical_guest_path(dfd, path, out, cap);
	if (status != -LINUX_ENOENT)
		return status;

	// A whiteouted absolute leaf cannot be expanded through the resolver. The
	// guest spelling is still the canonical create target; prepare_create() will
	// clear its marker after the parent policy has been applied.
	if (path[0] == '/')
	{
		if (eunion_guest_path_safe(path) < 0)
			return -LINUX_EINVAL;
		if ((int)strlen(path) + 1 > cap)
			return -LINUX_ENAMETOOLONG;
		memcpy(out, path, strlen(path) + 1);
		return eunion_manage(path) ? 0 : 1;
	}

	// For a relative target, canonicalize the parent and append the leaf. This
	// preserves dirfd semantics while allowing only the final component to be
	// absent or whiteouted.
	int length = (int)strlen(path);
	int last_slash = -1;
	for (int index = 0; index < length; index++)
		if (path[index] == '/')
			last_slash = index;
	char parent[4096];
	char leaf[4096];
	if (last_slash < 0)
	{
		memcpy(parent, ".", 2);
		memcpy(leaf, path, length + 1);
	}
	else
	{
		if (last_slash >= (int)sizeof(parent) ||
			length - last_slash > (int)sizeof(leaf))
			return -LINUX_ENAMETOOLONG;
		memcpy(parent, path, last_slash);
		parent[last_slash] = '\0';
		memcpy(leaf, path + last_slash + 1, length - last_slash);
	}
	char canonical_parent[4096];
	status = vchroot_canonical_guest_path(dfd, parent,
		canonical_parent, sizeof(canonical_parent));
	if (status != 0)
		return status;
	int parent_length = (int)strlen(canonical_parent);
	int leaf_length = (int)strlen(leaf);
	int separator = parent_length > 1 ? 1 : 0;
	if (parent_length + separator + leaf_length + 1 > cap)
		return -LINUX_ENAMETOOLONG;
	memcpy(out, canonical_parent, parent_length);
	if (separator)
		out[parent_length++] = '/';
	memcpy(out + parent_length, leaf, leaf_length + 1);
	if (eunion_guest_path_safe(out) < 0)
		return -LINUX_EINVAL;
	return eunion_manage(out) ? 0 : 1;
}

// *at() variant: the mutating target is addressed RELATIVE to a directory fd
// (openat/mkdirat/...). The plain vchroot_prepare_write only acts on absolute
// guest paths, so a dirfd-relative write into a lower-only dir would otherwise
// skip copy-up and hit the read-only template. Resolve the dirfd to its guest
// path (vchroot_fdpath already detranslates upper AND lower -> guest), join the
// relative path, and prepare_write the result. An absolute `rel`, AT_FDCWD with
// a relative path we cannot resolve, or any failure falls back to the plain
// absolute path handling (no-op for relative) -- never worse than before.
int vchroot_prepare_write_at(int dfd, const char* rel)
{
	if (!rel)
		return 0;
	if (rel[0] == '/')
		return vchroot_prepare_write(rel); // already absolute

	// AT_FDCWD is represented by -100 and has no /proc/self/fd entry. Resolve it
	// through the process cwd instead of silently skipping copy-up.
	if (dfd == -100)
	{
		char guest[4096];
		int status = vchroot_canonical_guest_path(dfd, rel, guest, sizeof(guest));
		if (status < 0)
			return status;
		return status > 0 ? 0 : vchroot_prepare_write(guest);
	}

	// Other negative descriptors are invalid for a relative path. Preserve the
	// existing unmanaged behavior rather than guessing a base directory.
	if (dfd < 0)
		return 0;

	char base[4096];
	struct vchroot_fdpath_args fp;
	fp.fd = dfd; fp.path = base; fp.maxlen = sizeof(base);
	if (vchroot_fdpath(&fp) < 0)
		return 0; // cannot map the dirfd: leave to the absolute path (no-op)
	if (base[0] != '/')
		return 0; // dirfd resolved outside the guest (escape hatch): no-op

	// join base + "/" + rel into a guest-absolute path
	char guest[4096];
	int bl = (int)strlen(base);
	int rl = (int)strlen(rel);
	if (bl + 1 + rl + 1 > (int)sizeof(guest))
		return -LINUX_ENAMETOOLONG;
	memcpy(guest, base, bl);
	int gi = bl;
	if (gi == 0 || guest[gi-1] != '/')
		guest[gi++] = '/';
	memcpy(guest + gi, rel, rl + 1);

	return vchroot_prepare_write(guest);
}

// fd variant: a metadata op on an fd (fchmod/futimes/fsetxattr) has no path. If
// the fd was opened on a lower-only object the inode is the template's; mutating
// via the fd hits the shared template. Recover the fd's guest path, copy it up,
// and return the guest path in `out` so the caller can RE-OPEN the upper copy and
// retarget the op (the original fd still references the lower inode). Returns the
// guest-path length (>0) on success, 0 if unmanaged / the fd escapes the union
// (caller proceeds with the original fd), or a negative errno.
int vchroot_prepare_write_fd(int fd, char* out, int cap)
{
	if (!out || cap <= 0)
		return 0; // no buffer to return a path in: caller proceeds with the fd
	out[0] = '\0';

	char guest[4096];
	struct vchroot_fdpath_args fp;
	fp.fd = fd; fp.path = guest; fp.maxlen = sizeof(guest);
	if (vchroot_fdpath(&fp) < 0)
		return 0; // cannot map the fd: proceed with the original fd
	if (guest[0] != '/')
		return 0; // not an absolute guest path: not union-managed
	// vchroot_fdpath detranslates a fd that lives OUTSIDE both union layers to the
	// EXIT_PATH escape hatch ("/Volumes/SystemRoot/..."), which is a real absolute
	// path but points at the native host root, NOT the union. Such a fd is not
	// union-managed -- proceed with the original fd. (EXIT_PATH is defined further
	// down; compare against the literal here.)
	{
		static const char esc[] = "/Volumes/SystemRoot";
		int el = (int)sizeof(esc) - 1;
		if (strncmp(guest, esc, el) == 0 && (guest[el] == '\0' || guest[el] == '/'))
			return 0;
	}

	if (!eunion_manage(guest))
		return 0;

	int r = vchroot_prepare_write(guest);
	if (r < 0)
		return r;

	int gl = (int)strlen(guest);
	if (gl + 1 > cap)
		return -LINUX_ENAMETOOLONG;
	memcpy(out, guest, gl + 1);
	return gl;
}

#ifndef LINUX_O_NOFOLLOW
#define LINUX_O_NOFOLLOW 0400000 // Linux O_NOFOLLOW (x86); re-open the object itself
#endif
#ifndef LINUX_O_RDWR
#define LINUX_O_RDWR 02 // Linux O_RDWR; for content-mutating fd ops (ftruncate)
#endif
// High-level helper for the fd-metadata syscall sites (fchmod/fchmod_extended/
// futimes/fsetxattr/fremovexattr). A metadata op on an fd has no path, so if the
// fd was opened on a lower-only object the op hits the SHARED template. This
// copies the object up (via vchroot_prepare_write_fd) and RE-OPENS the upper copy,
// returning a fresh fd the caller must apply the op to -- the original fd still
// references the lower inode after copy-up, so mutating it would still corrupt the
// template.
//
// Caller contract (uniform): apply the metadata op to the RETURNED fd, and close
// the returned fd iff it differs from the original.
//
// Returns:
//   == fd            -> not union-managed / fd escapes the union; caller uses the
//                       ORIGINAL fd and must NOT close it here.
//   >= 0 and != fd   -> a fresh fd on the upper copy (after copy-up if the object
//                       was lower-only; for an already-upper object this just
//                       re-opens the same upper inode). Caller applies the op to
//                       it and MUST close it when done.
//   < 0              -> negative Linux errno.
int vchroot_fd_for_meta_write(int fd)
{
	char guest[4096];
	int r = vchroot_prepare_write_fd(fd, guest, sizeof(guest));
	if (r < 0)
		return r;          // negative errno
	if (r == 0)
		return fd;         // unmanaged / escape / no path: use the original fd

	// The object was copied up; guest now resolves to the UPPER copy. The caller's
	// original fd still references the LOWER inode, so re-open the upper copy and
	// hand back a fresh fd. Expand the guest path (resolves to upper after copy-up)
	// and open it. O_RDONLY is sufficient on Linux for fchmod/utimensat/fsetxattr/
	// fremovexattr (they check inode perms, not the fd's open mode). O_NOFOLLOW so
	// we mutate the object itself, never a symlink target.
	struct vchroot_expand_args vc;
	vc.flags = 0;          // do not follow the final symlink
	vc.dfd = -100;         // AT_FDCWD-equivalent; guest is absolute
	int gl = (int)strlen(guest);
	if (gl + 1 > (int)sizeof(vc.path))
		return -LINUX_ENAMETOOLONG;
	memcpy(vc.path, guest, gl + 1);
	int er = vchroot_expand(&vc);
	if (er < 0)
		return er;

	int nfd = LINUX_SYSCALL(__NR_openat, LINUX_AT_FDCWD, vc.path,
		LINUX_O_RDONLY | LINUX_O_NOFOLLOW, 0);
	if (nfd < 0)
		return nfd;
	return nfd;            // != fd: caller applies the op to nfd and closes it
}

// High-level helper for CONTENT-mutating fd ops (ftruncate). Identical to
// vchroot_fd_for_meta_write but re-opens the upper copy O_RDWR: unlike fchmod/
// utimensat/fsetxattr (which only check inode perms and work on an O_RDONLY fd),
// ftruncate REQUIRES a writable fd (an O_RDONLY fd yields EINVAL). Copy up the
// fd's object if lower-only and hand back a FRESH writable fd on the upper copy
// (caller applies the op and closes it). Returns the ORIGINAL fd unchanged if
// unmanaged/escape/no-copyup, or a negative errno.
int vchroot_fd_for_content_write(int fd)
{
	char guest[4096];
	int r = vchroot_prepare_write_fd(fd, guest, sizeof(guest));
	if (r < 0)
		return r;          // negative errno
	if (r == 0)
		return fd;         // unmanaged / escape / no path: use the original fd

	// Copied up; guest now resolves to the UPPER copy. Re-open it O_RDWR so the
	// caller's content op (ftruncate) has a writable fd. O_NOFOLLOW so we mutate
	// the object itself, never a symlink target.
	struct vchroot_expand_args vc;
	vc.flags = 0;          // do not follow the final symlink
	vc.dfd = -100;         // AT_FDCWD-equivalent; guest is absolute
	int gl = (int)strlen(guest);
	if (gl + 1 > (int)sizeof(vc.path))
		return -LINUX_ENAMETOOLONG;
	memcpy(vc.path, guest, gl + 1);
	int er = vchroot_expand(&vc);
	if (er < 0)
		return er;

	int nfd = LINUX_SYSCALL(__NR_openat, LINUX_AT_FDCWD, vc.path,
		LINUX_O_RDWR | LINUX_O_NOFOLLOW, 0);
	if (nfd < 0)
		return nfd;
	return nfd;            // != fd: caller applies the op to nfd and closes it
}

int vchroot_remove_at(int dfd, const char* path, int remove_directory,
	int* handled)
{
	char guest[4096];
	int result;

	if (!handled)
		return -LINUX_EINVAL;
	*handled = 0;
	result = vchroot_canonical_guest_create_path(dfd, path, guest,
		(int)sizeof(guest));
	if (result < 0)
		return result;
	if (result != 0 || !eunion_manage(guest))
		return 0;

	*handled = 1;
	if (eunion_sidecar_path_len <= 0)
		return -LINUX_EIO;
	return eunion_sidecar_remove_path(
		&eunion_anchored_runtime, guest,
		remove_directory != 0);
}

// Materialize a guest DIRECTORY path in the upper layer, following any symlink at
// the final component to its REAL target dir. A create lands at <parent>/<leaf>,
// and the kernel resolves the parent's symlinks before creating; so it is not
// enough to copy up a symlinked parent as a symlink -- the link's TARGET dir must
// also exist in the upper, or open(O_CREAT) follows the upper symlink into a
// directory that is absent from the upper layer and fails ENOENT. (Real example:
// /tmp -> private/tmp; `touch /tmp/x` copied up the /tmp symlink but never
// materialized private/tmp.) Resolves a chain of dir symlinks (bounded), copying
// up each link and finally its target real dir. Returns 0 on success (or if the
// path is absent in both layers -- the create will make it), negative on error.
static int eunion_copyup_dir_resolved(const char* dir)
{
	char cur[4096];
	int n = (int)strlen(dir);
	if (n + 1 > (int)sizeof(cur))
		return -LINUX_ENAMETOOLONG;
	memcpy(cur, dir, n + 1);

	// bound symlink chains (same limit as the resolver's MAX_SYMLINK_DEPTH, which
	// is defined later in the file).
	#define EUNION_MAX_DIR_SYMLINK_HOPS 10
	for (int hop = 0; hop <= EUNION_MAX_DIR_SYMLINK_HOPS; hop++)
	{
		// copy up this path component as-is (a symlink copies up as a symlink;
		// a real dir copies up as a dir). Absent-in-both -> the create makes it.
		int r = vchroot_copyup(cur);
		if (r < 0 && r != -LINUX_ENOENT)
			return r;

		// inspect the LOWER object to see if it is a symlink we must follow.
		char lo[4096];
		if (eunion_host_path(libexec_path, libexec_path_len, cur, lo, sizeof(lo)) < 0)
			return -LINUX_ENAMETOOLONG;
		stat_t lst;
		if (eunion_lstat(lo, &lst) != 0)
			return 0; // not in the template: nothing more to resolve
		if ((lst.st_mode & LINUX_S_IFMT) != LINUX_S_IFLNK)
			return 0; // a real dir (or file): done

		// read the symlink target and rebase it to a guest-absolute dir path.
		char link[4096];
		#if defined(__NR_readlink)
			int ln = LINUX_SYSCALL(__NR_readlink, lo, link, sizeof(link) - 1);
		#else
			int ln = LINUX_SYSCALL(__NR_readlinkat, LINUX_AT_FDCWD, lo, link, sizeof(link) - 1);
		#endif
		if (ln < 0)
			return ln;
		link[ln] = '\0';

		char next[4096];
		if (link[0] == '/')
		{
			// absolute target: it is already a guest-absolute path
			if (ln + 1 > (int)sizeof(next))
				return -LINUX_ENAMETOOLONG;
			memcpy(next, link, ln + 1);
		}
		else
		{
			// relative target: resolve against cur's PARENT dir
			int slash = -1;
			for (int i = 0; cur[i]; i++)
				if (cur[i] == '/') slash = i;
			int base = (slash <= 0) ? 0 : slash; // keep leading '/'; "" if root-level
			if (base + 1 + ln + 1 > (int)sizeof(next))
				return -LINUX_ENAMETOOLONG;
			memcpy(next, cur, base);
			next[base] = '/';
			memcpy(next + base + 1, link, ln + 1);
		}
		if (eunion_guest_path_safe(next) < 0)
			return -LINUX_EINVAL;
		// loop to materialize the (possibly again-symlinked) target dir
		memcpy(cur, next, strlen(next) + 1);
	}
	return -LINUX_ELOOP; // too many symlink hops
}

// Copy the guest path's PARENT directory up into the writable upper layer. Used
// before a create/rename so the new entry lands in the upper, not the template.
// No-op success if there is no parent (root) or the path is unmanaged.
static int eunion_copyup_parent(const char* guest)
{
	if (!eunion_manage(guest))
		return 0;
	// find the last '/'
	int last = -1;
	for (int i = 0; guest[i]; i++)
		if (guest[i] == '/') last = i;
	if (last <= 0)
		return 0; // parent is "/" (root): always present in upper
	char parent[4096];
	if (last >= (int)sizeof(parent))
		return -LINUX_ENAMETOOLONG;
	memcpy(parent, guest, last);
	parent[last] = '\0';
	// Resolve symlinks at the parent so the link's REAL target dir is materialized
	// in the upper layer, not just a symlink pointing at an absent target (else a
	// create through the symlinked parent would ENOENT). eunion_copyup_dir_resolved
	// already treats absent-in-both as success (the create makes it).
	return eunion_copyup_dir_resolved(parent);
}

// BEFORE a rename's transaction begins, ensure the destination parent is in the
// writable layer. The sidecar transaction owns destination replacement, stale
// marker retirement, source masking, and crash recovery as one unit.
int vchroot_prepare_rename_dest(const char* guest)
{
	if (!eunion_manage(guest))
		return 0;
	return eunion_copyup_parent(guest);
}

int vchroot_upper_guest_path(const char* guest, char* out, int cap)
{
	if (!out || cap <= 0)
		return -LINUX_EINVAL;
	if (!eunion_manage(guest))
		return 1;
	if (eunion_host_path(prefix_path, prefix_path_len, guest, out, cap) < 0)
		return -LINUX_ENAMETOOLONG;
	return 0;
}

// BEFORE creating a new entry (mkdir/mknod/mkfifo/symlink/...): ensure the
// PARENT dir lives in the writable upper layer. The sidecar transaction alone
// owns the backing create and any semantic-record retirement.
int vchroot_prepare_create(const char* guest)
{
	if (!eunion_manage(guest))
		return 0;
	int r = eunion_copyup_parent(guest);
	if (r < 0)
		return r;
	return 0;
}

int vchroot_prepare_create_path(const char* guest, char* out, int cap)
{
	int r = vchroot_prepare_create(guest);
	if (r < 0)
		return r;
	if (!eunion_manage(guest))
		return 0;
	if (eunion_host_path(prefix_path, prefix_path_len, guest, out, cap) < 0)
		return -LINUX_ENAMETOOLONG;
	return 1;
}

static int eunion_runtime(struct eunion_sidecar_runtime* runtime)
{
	if (!runtime || !eunion_anchored_runtime.anchored)
		return -LINUX_EIO;
	*runtime = eunion_anchored_runtime;
	return 0;
}

int vchroot_open_create(
	const char* guest, int linux_flags, unsigned int mode)
{
	if (!eunion_manage(guest))
		return -LINUX_EINVAL;
	struct eunion_sidecar_runtime runtime;
	int result = eunion_runtime(&runtime);
	if (result < 0)
		return result;
	return eunion_sidecar_open_create(
		&runtime, guest, linux_flags, mode);
}

int vchroot_mkdir_create(const char* guest, unsigned int mode)
{
	if (!eunion_manage(guest))
		return -LINUX_EINVAL;
	struct eunion_sidecar_runtime runtime;
	int result = eunion_runtime(&runtime);
	if (result < 0)
		return result;
	return eunion_sidecar_mkdir_create(&runtime, guest, mode);
}

int vchroot_symlink_create(
	const char* target, const char* guest, unsigned int mode)
{
	(void)mode;
	if (!eunion_manage(guest))
		return -LINUX_EINVAL;
	struct eunion_sidecar_runtime runtime;
	int result = eunion_runtime(&runtime);
	if (result < 0)
		return result;
	return eunion_sidecar_symlink_create(&runtime, target, guest);
}

int vchroot_mknod_create(
	const char* guest, unsigned int mode, unsigned int device)
{
	if (!eunion_manage(guest))
		return -LINUX_EINVAL;
	struct eunion_sidecar_runtime runtime;
	int result = eunion_runtime(&runtime);
	if (result < 0)
		return result;
	return eunion_sidecar_mknod_create(
		&runtime, guest, mode, device);
}

int vchroot_link_create(const char* source_guest,
	const char* destination_guest, int flags)
{
	if (!eunion_manage(source_guest) ||
		!eunion_manage(destination_guest))
		return -LINUX_EXDEV;
	struct eunion_sidecar_runtime runtime;
	int result = eunion_runtime(&runtime);
	if (result < 0)
		return result;
	return eunion_sidecar_link_create(
		&runtime, source_guest, destination_guest, flags);
}

int vchroot_socket_bind_create(
	int socket_descriptor, const char* guest)
{
	if (!eunion_manage(guest))
		return -LINUX_EINVAL;
	struct eunion_sidecar_runtime runtime;
	int result = eunion_runtime(&runtime);
	if (result < 0)
		return result;
	return eunion_sidecar_socket_bind_create(
		&runtime, guest, socket_descriptor);
}

int vchroot_rename_path(const char* old_guest, const char* new_guest)
{
	if (!eunion_manage(old_guest) || !eunion_manage(new_guest))
		return -LINUX_EXDEV;
	struct eunion_sidecar_runtime runtime;
	int result = eunion_runtime(&runtime);
	if (result < 0)
		return result;
	return eunion_sidecar_rename_path(&runtime, old_guest, new_guest);
}

struct eunion_name_buffer
{
	char* data;
	int capacity;
	int used;
	int count;
	int growable;
};

static void eunion_name_buffer_release(struct eunion_name_buffer* buffer)
{
	if (buffer->growable && buffer->data)
		free(buffer->data);
	memset(buffer, 0, sizeof(*buffer));
}

static int eunion_name_buffer_grow(
	struct eunion_name_buffer* buffer, int required)
{
	if (!buffer->growable)
		return -LINUX_EOVERFLOW;
	int capacity = buffer->capacity > 0 ? buffer->capacity : 4096;
	while (capacity < required) {
		if (capacity > 0x3fffffff)
			return -LINUX_EOVERFLOW;
		capacity *= 2;
	}
	char* replacement = malloc((__SIZE_TYPE__)capacity);
	if (!replacement)
		return -LINUX_ENOMEM;
	if (buffer->used > 0)
		memcpy(replacement, buffer->data, (__SIZE_TYPE__)buffer->used);
	if (buffer->data)
		free(buffer->data);
	buffer->data = replacement;
	buffer->capacity = capacity;
	return 0;
}

// Append `name` to a NUL-separated buffer if it is not already present.
// Growable buffers have no fixed listing limit; fixed buffers fail closed.
static int eunion_emit_name(
	struct eunion_name_buffer* buffer, const char* name)
{
	const char* p = buffer->data;
	for (int i = 0; i < buffer->count; i++) {
		if (strcmp(p, name) == 0)
			return 0;
		p += strlen(p) + 1;
	}
	int nlen = (int)strlen(name) + 1;
	if (buffer->used > 0x7fffffff - nlen)
		return -LINUX_EOVERFLOW;
	int required = buffer->used + nlen;
	if (required > buffer->capacity) {
		int result = eunion_name_buffer_grow(buffer, required);
		if (result < 0)
			return result;
	}
	memcpy(buffer->data + buffer->used, name, (__SIZE_TYPE__)nlen);
	buffer->used = required;
	++buffer->count;
	return 1;
}

static int name_in_set(
	const struct eunion_name_buffer* buffer, const char* name)
{
	const char* p = buffer->data;
	for (int i = 0; i < buffer->count; i++) {
		if (strcmp(p, name) == 0)
			return 1;
		p += strlen(p) + 1;
	}
	return 0;
}

static int eunion_join_guest_path(const char* parent, const char* name,
	char* output, int capacity)
{
	int parent_length = (int)strlen(parent);
	int name_length = (int)strlen(name);
	int separator = parent_length > 1;
	if (parent_length + separator + name_length + 1 > capacity)
		return -LINUX_ENAMETOOLONG;
	memcpy(output, parent, parent_length);
	if (separator)
		output[parent_length++] = '/';
	memcpy(output + parent_length, name, name_length + 1);
	return 0;
}

// Produce the merged directory listing for guest dir `guest`. Upper layer wins
// on name clash; whiteouts hide the lower namesake; an opaque upper dir is not
// merged with the lower.
static int eunion_readdir_merge(
	const char* guest,
	struct eunion_name_buffer* visible,
	struct eunion_name_buffer* hidden)
{
	if (prefix_path_len < 0)
		return -LINUX_ENOENT;
	struct eunion_resolver_scope sidecar_scope;
	int scope_result = eunion_resolver_scope_open(&sidecar_scope);
	if (scope_result < 0)
		return scope_result;

	char up[4096], lo[4096];
	int have_upper = (eunion_host_path(prefix_path, prefix_path_len, guest, up, sizeof(up)) >= 0);

	// 1. upper layer: emit non-whiteout names; record whiteout names so the
	//    lower namesake is suppressed (tracked in a separate seen-set).
	if (have_upper)
	{
		int dfd = LINUX_SYSCALL(__NR_openat, LINUX_AT_FDCWD, up, LINUX_O_RDONLY | LINUX_O_DIRECTORY, 0);
		if (dfd >= 0)
		{
			char dirents[8192];
			int len;
			while ((len = LINUX_SYSCALL(__NR_getdents64, dfd, dirents, sizeof(dirents))) > 0)
			{
				int pos = 0;
				while (pos < len)
				{
					struct linux_dirent64* de = (struct linux_dirent64*) &dirents[pos];
					pos += de->d_reclen;
					const char* nm = de->d_name;
					if (nm[0] == '.' && (nm[1] == '\0' || (nm[1] == '.' && nm[2] == '\0')))
						continue;

					char child[4096];
					int hl = (int)strlen(up), nl = (int)strlen(nm);
					if (hl + 1 + nl + 1 > (int)sizeof(child)) {
						LINUX_SYSCALL(__NR_close, dfd);
						eunion_resolver_scope_close(&sidecar_scope);
						return -LINUX_ENAMETOOLONG;
					}
					memcpy(child, up, hl); child[hl] = '/'; memcpy(child + hl + 1, nm, nl + 1);

					char child_guest[4096];
					if (eunion_join_guest_path(guest, nm,
						child_guest, sizeof(child_guest)) < 0) {
						LINUX_SYSCALL(__NR_close, dfd);
						eunion_resolver_scope_close(&sidecar_scope);
						return -LINUX_ENAMETOOLONG;
					}
					struct eunion_sidecar_lookup lookup;
					int lookup_result = eunion_sidecar_lookup_path(
						sidecar_scope.view, child_guest, &lookup);
					if (lookup_result < 0) {
						LINUX_SYSCALL(__NR_close, dfd);
						eunion_resolver_scope_close(&sidecar_scope);
						return lookup_result;
					}
					int is_hidden = lookup.kind ==
						EUNION_SIDECAR_RECORD_WHITEOUT;
					int emit_result = eunion_emit_name(
						is_hidden ? hidden : visible, nm);
					if (emit_result < 0) {
						LINUX_SYSCALL(__NR_close, dfd);
						eunion_resolver_scope_close(&sidecar_scope);
						return emit_result;
					}
				}
			}
			if (len < 0) {
				LINUX_SYSCALL(__NR_close, dfd);
				eunion_resolver_scope_close(&sidecar_scope);
				return len;
			}
			LINUX_SYSCALL(__NR_close, dfd);
		}

		// 2. opaque upper dir -> do not merge lower
		struct eunion_sidecar_lookup opaque_lookup;
		int opaque_result = eunion_sidecar_lookup_path(
			sidecar_scope.view, guest, &opaque_lookup);
		if (opaque_result < 0) {
			eunion_resolver_scope_close(&sidecar_scope);
			return opaque_result;
		}
		int opaque = opaque_lookup.kind == EUNION_SIDECAR_RECORD_OPAQUE;
		if (opaque) {
			int close_result =
				eunion_resolver_scope_close(&sidecar_scope);
			if (close_result < 0)
				return close_result;
			return visible->count;
		}
	}

	// 3. lower layer: emit names not already visible (upper wins) and not
	//    whited-out.
	if (libexec_path_len > 0 && eunion_host_path(libexec_path, libexec_path_len, guest, lo, sizeof(lo)) >= 0)
	{
		int dfd = LINUX_SYSCALL(__NR_openat, LINUX_AT_FDCWD, lo, LINUX_O_RDONLY | LINUX_O_DIRECTORY, 0);
		if (dfd >= 0)
		{
			char dirents[8192];
			int len;
			while ((len = LINUX_SYSCALL(__NR_getdents64, dfd, dirents, sizeof(dirents))) > 0)
			{
				int pos = 0;
				while (pos < len)
				{
					struct linux_dirent64* de = (struct linux_dirent64*) &dirents[pos];
					pos += de->d_reclen;
					const char* nm = de->d_name;
					if (nm[0] == '.' && (nm[1] == '\0' || (nm[1] == '.' && nm[2] == '\0')))
						continue;
					// suppressed by a whiteout in the upper?
					if (name_in_set(hidden, nm))
						continue;
					if (sidecar_scope.sidecar_open) {
						char child_guest[4096];
						if (eunion_join_guest_path(guest, nm,
							child_guest, sizeof(child_guest)) < 0) {
							LINUX_SYSCALL(__NR_close, dfd);
							eunion_resolver_scope_close(&sidecar_scope);
							return -LINUX_ENAMETOOLONG;
						}
						struct eunion_sidecar_lookup lookup;
						int lookup_result = eunion_sidecar_lookup_path(
							sidecar_scope.view, child_guest, &lookup);
						if (lookup_result < 0) {
							LINUX_SYSCALL(__NR_close, dfd);
							eunion_resolver_scope_close(&sidecar_scope);
							return lookup_result;
						}
						if (lookup.kind ==
							EUNION_SIDECAR_RECORD_WHITEOUT)
							continue;
					}
					int emit_result = eunion_emit_name(visible, nm);
					if (emit_result < 0) {
						LINUX_SYSCALL(__NR_close, dfd);
						eunion_resolver_scope_close(&sidecar_scope);
						return emit_result;
					}
				}
			}
			if (len < 0) {
				LINUX_SYSCALL(__NR_close, dfd);
				eunion_resolver_scope_close(&sidecar_scope);
				return len;
			}
			LINUX_SYSCALL(__NR_close, dfd);
		}
	}

	int close_result = eunion_resolver_scope_close(&sidecar_scope);
	return close_result < 0 ? close_result : visible->count;
}

// Bounded compatibility API: callers get an explicit overflow error rather
// than a successful truncated listing. The paged getdents path below uses a
// growable buffer and therefore has no 64 KiB aggregate limit.
int vchroot_readdir_merge(const char* guest, char* out, int cap)
{
	if (!out || cap <= 0)
		return -LINUX_EINVAL;
	struct eunion_name_buffer visible = {
		.data = out,
		.capacity = cap,
	};
	struct eunion_name_buffer hidden = {
		.growable = 1,
	};
	int result = eunion_readdir_merge(guest, &visible, &hidden);
	eunion_name_buffer_release(&hidden);
	return result;
}

// -------- E-UNION paged getdents merge (per-fd state) --------------------
//
// getdirentries works on an fd and streams the directory in pages. Duplicated
// descriptors share one open file description and therefore one merged cursor.
// Keep a synchronized descriptor-to-description binding table and one growable
// name stream per description. The emulation site calls:
//   vchroot_getdents_merge(fd, out, cap)  instead of raw getdents64(fd, ...)
//   vchroot_dir_closed(fd)                from close()/closedir() teardown
//   vchroot_dir_dup(oldfd, newfd)          after every fd duplication route
// rewinddir (lseek(fd,0)) resets the shared description, not just one fd.

#define EUNION_MAXDIRS  256

struct eunion_dir_description
{
	int references;
	int ready;
	int cursor;
	char guest[4096];
	struct eunion_name_buffer names;
};

struct eunion_dir_binding
{
	int fd;
	struct eunion_dir_description* description;
};

static struct eunion_dir_binding eunion_dirs[EUNION_MAXDIRS];
static struct eunion_dir_description
	eunion_dir_descriptions[EUNION_MAXDIRS];
static int eunion_dirs_inited = 0;
static int eunion_dirs_lock_word;

static void eunion_dirs_lock(void)
{
	while (__atomic_exchange_n(
			&eunion_dirs_lock_word, 1, __ATOMIC_ACQUIRE) != 0)
		LINUX_SYSCALL(__NR_sched_yield);
}

static void eunion_dirs_unlock(void)
{
	__atomic_store_n(&eunion_dirs_lock_word, 0, __ATOMIC_RELEASE);
}

static void eunion_dirs_init_locked(void)
{
	if (!eunion_dirs_inited) {
		for (int i = 0; i < EUNION_MAXDIRS; ++i)
			eunion_dirs[i].fd = -1;
		eunion_dirs_inited = 1;
	}
}

static struct eunion_dir_binding* eunion_dir_find_locked(int fd)
{
	eunion_dirs_init_locked();
	for (int i = 0; i < EUNION_MAXDIRS; i++)
		if (eunion_dirs[i].fd == fd)
			return &eunion_dirs[i];
	return 0;
}

static void eunion_dir_description_release_locked(
	struct eunion_dir_description* description)
{
	if (!description || description->references <= 0)
		return;
	if (--description->references == 0) {
		eunion_name_buffer_release(&description->names);
		memset(description, 0, sizeof(*description));
	}
}

static void eunion_dir_binding_close_locked(
	struct eunion_dir_binding* binding)
{
	if (!binding)
		return;
	eunion_dir_description_release_locked(binding->description);
	binding->fd = -1;
	binding->description = 0;
}

static struct eunion_dir_binding* eunion_dir_binding_alloc_locked(int fd)
{
	for (int i = 0; i < EUNION_MAXDIRS; ++i) {
		if (eunion_dirs[i].fd == -1) {
			eunion_dirs[i].fd = fd;
			eunion_dirs[i].description = 0;
			return &eunion_dirs[i];
		}
	}
	return 0;
}

static struct eunion_dir_description*
eunion_dir_description_alloc_locked(void)
{
	for (int i = 0; i < EUNION_MAXDIRS; ++i) {
		if (eunion_dir_descriptions[i].references == 0) {
			memset(&eunion_dir_descriptions[i], 0,
				sizeof(eunion_dir_descriptions[i]));
			eunion_dir_descriptions[i].references = 1;
			eunion_dir_descriptions[i].names.growable = 1;
			return &eunion_dir_descriptions[i];
		}
	}
	return 0;
}

// Free one descriptor binding. The shared cursor lives until the last
// descriptor referencing the open file description is closed.
void vchroot_dir_closed(int fd)
{
	eunion_dirs_lock();
	eunion_dir_binding_close_locked(eunion_dir_find_locked(fd));
	eunion_dirs_unlock();
}

void vchroot_dir_rewind(int fd)
{
	eunion_dirs_lock();
	struct eunion_dir_binding* binding = eunion_dir_find_locked(fd);
	if (binding && binding->description) {
		struct eunion_dir_description* description =
			binding->description;
		eunion_name_buffer_release(&description->names);
		description->names.growable = 1;
		description->ready = 0;
		description->cursor = 0;
		description->guest[0] = '\0';
	}
	eunion_dirs_unlock();
}

int vchroot_dir_dup(int oldfd, int newfd)
{
	if (oldfd == newfd)
		return 0;
	eunion_dirs_lock();
	struct eunion_dir_binding* source =
		eunion_dir_find_locked(oldfd);
	struct eunion_dir_description* description =
		source ? source->description : 0;
	struct eunion_dir_binding* target =
		eunion_dir_find_locked(newfd);
	eunion_dir_binding_close_locked(target);
	if (!description) {
		eunion_dirs_unlock();
		return 0;
	}
	target = eunion_dir_binding_alloc_locked(newfd);
	if (!target) {
		eunion_dirs_unlock();
		return -LINUX_EMFILE;
	}
	++description->references;
	target->description = description;
	eunion_dirs_unlock();
	return 0;
}

// append one linux_dirent64 record for `name` into out; returns bytes used or
// 0 if it would not fit (caller stops this page). The ON-WIRE header is the
// fields up to d_name (NOT sizeof(struct), which may be inflated by a fixed
// d_name[] in some copies of the struct in scope).
// Linux DT_* dirent type codes (stable kernel ABI; same values on all arches).
#ifndef EUNION_DT_UNKNOWN
#define EUNION_DT_UNKNOWN  0
#define EUNION_DT_DIR      4
#define EUNION_DT_REG      8
#define EUNION_DT_LNK     10
#endif
#ifndef LINUX_S_IFREG
#define LINUX_S_IFREG 0100000
#endif

// Map a stat st_mode to a DT_* dirent type. Covers the common file kinds; any
// other format (fifo/sock/chr/blk) falls back to DT_UNKNOWN, which is always a
// legal value for a caller to see.
static unsigned char eunion_dt_from_mode(unsigned int mode)
{
	unsigned int fmt = mode & LINUX_S_IFMT;
	if (fmt == LINUX_S_IFDIR) return EUNION_DT_DIR;
	if (fmt == LINUX_S_IFREG) return EUNION_DT_REG;
	if (fmt == LINUX_S_IFLNK) return EUNION_DT_LNK;
	return EUNION_DT_UNKNOWN;
}

// Append one linux_dirent64 record for the merged entry `name` under guest dir
// `dirguest`. overlayfs presents a valid d_type and a real d_ino for each merged
// entry, so we lstat the resolved object (upper layer wins, else lower) and fill
// d_type/d_ino from it instead of synthesizing DT_UNKNOWN/ino=1. If the entry
// cannot be resolved/stat'd (a transient race) we still emit the name with a
// DT_UNKNOWN fallback rather than dropping it -- a missing entry is worse than an
// unknown type a caller can recover from with its own stat.
static int eunion_emit_dirent(char* out, int cap, int used,
		const char* dirguest, const char* name)
{
	int nl = (int)strlen(name) + 1;
	int hdr = (int)__builtin_offsetof(struct linux_dirent64, d_name);
	int reclen = hdr + nl;
	reclen = (reclen + 7) & ~7; // 8-byte align like the kernel
	if (used + reclen > cap)
		return 0;

	// resolve dirguest/name to a host path (upper wins) and lstat for type+ino.
	unsigned char dtype = EUNION_DT_UNKNOWN;
	unsigned long dino = 0;
	{
		char gchild[4096];
		int dl = (int)strlen(dirguest), nm = (int)strlen(name);
		if (dl + 1 + nm + 1 <= (int)sizeof(gchild))
		{
			memcpy(gchild, dirguest, dl);
			int gi = dl;
			if (gi == 0 || gchild[gi-1] != '/')
				gchild[gi++] = '/';
			memcpy(gchild + gi, name, nm + 1);

			stat_t st;
			char host[4096];
			int got = 0;
			if (eunion_host_path(prefix_path, prefix_path_len, gchild, host, sizeof(host)) >= 0
				&& eunion_lstat(host, &st) == 0)
				got = 1;
			else if (libexec_path_len > 0
				&& eunion_host_path(libexec_path, libexec_path_len, gchild, host, sizeof(host)) >= 0
				&& eunion_lstat(host, &st) == 0)
				got = 1;
			if (got)
			{
				dtype = eunion_dt_from_mode((unsigned int)st.st_mode);
				dino = (unsigned long)st.st_ino;
			}
		}
	}

	struct linux_dirent64* de = (struct linux_dirent64*) (out + used);
	de->d_ino = dino ? dino : 1; // real inode; 1 only as a last-resort fallback
	de->d_off = 0;
	de->d_reclen = (unsigned short) reclen;
	de->d_type = dtype;
	memcpy(de->d_name, name, nl);
	return reclen;
}

// Paged merged getdents. `fd` is the UPPER directory fd already opened by the
// emulation. Returns bytes written into out (>0), 0 at end of the merged
// stream, or a negative Linux errno. On first call it materializes the full
// merged listing; subsequent calls page it out.
int vchroot_getdents_merge(int fd, char* out, int cap)
{
	if (prefix_path_len < 0)
		return -LINUX_ENOENT;

	// Union inactive (no template configured for this prefix): pass straight
	// through to the real getdents64 so callers see the kernel's true d_ino /
	// d_type. The merge path synthesizes those (d_ino=1, DT_UNKNOWN), which is
	// fine for a merged listing but must NOT be imposed when there is nothing to
	// merge -- otherwise an EUNION build regresses every readdir even with the
	// union switched off.
	if (libexec_path_len <= 0)
		return LINUX_SYSCALL(__NR_getdents64, fd, out, cap);

	eunion_dirs_lock();
	struct eunion_dir_binding* binding = eunion_dir_find_locked(fd);
	int created_binding = 0;
	if (!binding) {
		binding = eunion_dir_binding_alloc_locked(fd);
		if (!binding) {
			eunion_dirs_unlock();
			return -LINUX_EMFILE;
		}
		binding->description = eunion_dir_description_alloc_locked();
		if (!binding->description) {
			eunion_dir_binding_close_locked(binding);
			eunion_dirs_unlock();
			return -LINUX_EMFILE;
		}
		created_binding = 1;
	}
	struct eunion_dir_description* description = binding->description;

	if (!description->ready)
	{
		// recover the guest dir path from the upper fd, then materialize the
		// merged listing once.
		char guest[4096];
		struct vchroot_fdpath_args fp;
		fp.fd = fd; fp.path = guest; fp.maxlen = sizeof(guest);
		if (vchroot_fdpath(&fp) < 0) {
			if (created_binding)
				eunion_dir_binding_close_locked(binding);
			eunion_dirs_unlock();
			return LINUX_SYSCALL(__NR_getdents64, fd, out, cap);
		}

		struct eunion_name_buffer hidden = {
			.growable = 1,
		};
		int n = eunion_readdir_merge(
			guest, &description->names, &hidden);
		eunion_name_buffer_release(&hidden);
		if (n < 0) {
			eunion_name_buffer_release(&description->names);
			description->names.growable = 1;
			eunion_dirs_unlock();
			return n;
		}

		// remember the guest dir path so the emitter can lstat each entry for a
		// real d_type/d_ino (overlay presents valid types, not DT_UNKNOWN).
		{
			int gl = (int)strlen(guest);
			if (gl + 1 > (int)sizeof(description->guest))
				gl = (int)sizeof(description->guest) - 1;
			memcpy(description->guest, guest, gl);
			description->guest[gl] = '\0';
		}

		description->cursor = 0;
		description->ready = 1;
	}

	// page out from cursor
	int written = 0;
	while (description->cursor < description->names.used)
	{
		const char* name =
			description->names.data + description->cursor;
		int w = eunion_emit_dirent(
			out, cap, written, description->guest, name);
		if (!w)
			break; // page full; resume here next call
		written += w;
		description->cursor += (int)strlen(name) + 1;
	}
	if (written == 0 &&
		description->cursor < description->names.used) {
		eunion_dirs_unlock();
		return -LINUX_EINVAL;
	}
	eunion_dirs_unlock();
	return written; // 0 when cursor reaches used -> end of merged stream
}
#endif

static const char EXIT_PATH[] = "/Volumes/SystemRoot";

static int eunion_path_enters_sidecar(
	const char* path, int path_length)
{
	if (eunion_sidecar_host_path_len <= 0 || !path ||
		path_length < eunion_sidecar_host_path_len)
		return 0;
	return memcmp(path, eunion_sidecar_host_path,
			(size_t)eunion_sidecar_host_path_len) == 0 &&
		(path_length == eunion_sidecar_host_path_len ||
		 path[eunion_sidecar_host_path_len] == '/');
}

// ASCII case-insensitive compare of the first n bytes, with NO dependency on a
// locale_t. The EXIT_PATH escape-hatch check used strncasecmp_l(..., LC_C_LOCALE)
// where LC_C_LOCALE is ((locale_t)NULL); glibc's strncasecmp_l DEREFERENCES the
// locale once the compared bytes match, so a NULL locale SEGVs precisely when the
// path equals EXIT_PATH. EXIT_PATH is a pure-ASCII literal, so the case-fold (kept
// because the prefix is matched case-insensitively, like HFS+) needs no locale at
// all -- fold ASCII A-Z here and avoid the deref entirely. Returns 0 on equal.
static int eunion_ascii_ncasecmp(const char* a, const char* b, __SIZE_TYPE__ n)
{
	for (__SIZE_TYPE__ i = 0; i < n; i++) {
		unsigned char ca = (unsigned char) a[i];
		unsigned char cb = (unsigned char) b[i];
		if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca - 'A' + 'a');
		if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb - 'A' + 'a');
		if (ca != cb)
			return (int) ca - (int) cb;
		if (ca == '\0')
			break; // both NUL at the same spot -> equal so far, stop
	}
	return 0;
}

#ifndef TEST
#ifdef VARIANT_DYLD
#define icase_enabled false
#else
#define icase_enabled true
#endif

#else
static bool icase_enabled = true;
#endif

static const int MAX_SYMLINK_DEPTH = 10;

struct context
{
	const char* current_root;
	int current_root_len;

	char current_path[4096];
	int current_path_len;

	int symlink_depth;
	bool unknown_component;
	bool follow;
#ifdef EUNION
	struct eunion_resolver* eunion_resolver;
#endif
};

static int vchroot_run(const char* path, struct context* ctxt);

#ifndef TEST
VISIBLE
#endif
int __darling_vchroot(int dfd)
{
	int rv;

#ifndef TEST
	rv = errno_linux_to_bsd(dserver_rpc_vchroot(dfd));
	if (rv != 0)
		return rv;
#endif

	char buf[50];

	__simple_sprintf(buf, "/proc/self/fd/%d", dfd);

	#if defined(__NR_readlink)
		rv = LINUX_SYSCALL(__NR_readlink, buf, prefix_path, sizeof(prefix_path) - 1);
	#else
		rv = LINUX_SYSCALL(__NR_readlinkat, LINUX_AT_FDCWD, buf, prefix_path, sizeof(prefix_path) - 1);
	#endif
	prefix_path[rv] = '\0';
	prefix_path_len = rv;

#ifdef EUNION
	rv = eunion_init_from_prefix(dfd);
	if (rv < 0)
		return rv;
#endif

	return 0;
}

#ifndef TEST
VISIBLE
int __darling_vchroot_expand(const char* path, char* out)
{
	struct vchroot_expand_args a = {
		.dfd = -100,
		.flags = 0
	};

	strcpy(a.path, path);

	int rv = vchroot_expand(&a);

	strcpy(out, a.path);
	return rv;
}
#endif

#ifndef TEST
static void init_vchroot_path(void)
{
	uint64_t tmp_len;
	int code = dserver_rpc_vchroot_path(prefix_path, sizeof(prefix_path), &tmp_len);
	if (code < 0) {
		__simple_printf("Failed to get vchroot path: %d\n", code);
		__simple_abort();
	}

	prefix_path_len = (int)tmp_len;

#ifndef TEST
	__simple_printf("init_vchroot_path: %s\n", prefix_path);
#endif
}
#endif

int vchroot_expand(struct vchroot_expand_args* args)
{
	struct context ctxt;

#ifndef TEST
	if (prefix_path_len == -1) {
#ifdef EUNION
		eunion_require_anchored_prefix();
#else
		init_vchroot_path();
#endif
	}
	__simple_printf("vchroot_expand(): input %s\n", args->path);
#endif

	ctxt.unknown_component = false;
	ctxt.symlink_depth = 0;
	ctxt.current_root = prefix_path;
	ctxt.current_root_len = prefix_path_len;
	ctxt.follow = !!(args->flags & VCHROOT_FOLLOW);

	const char* input_path = args->path;

	if (*input_path == '\0')
		return -LINUX_ENOENT;

	if (*input_path != '/')
	{
		char buf[50];

		if (args->dfd != -100)
			__simple_sprintf(buf, "/proc/self/fd/%d", args->dfd);
		else
			strcpy(buf, "/proc/self/cwd");

		#if defined(__NR_readlink)
			int rv = LINUX_SYSCALL(__NR_readlink, buf, ctxt.current_path, sizeof(ctxt.current_path) - 1);
		#else
			int rv = LINUX_SYSCALL(__NR_readlinkat, LINUX_AT_FDCWD, buf, ctxt.current_path, sizeof(ctxt.current_path) - 1);
		#endif

		if (rv < 0)
		{
#ifndef TEST
			__simple_printf("    dfd %d -> err %d!\n", args->dfd, rv);
#endif
			return rv;
		}
		
		// If we got "/", then turn it into "", because our algorithm will add a trailing slash later
		if (rv == 1 && ctxt.current_path[0] == '/')
		{
			ctxt.current_path[0] = '\0';
			ctxt.current_path_len = 0;
		}
		else
		{
			ctxt.current_path_len = rv;
			ctxt.current_path[rv] = '\0';
		}

		// Are we outside the vchrooted area already?
		if (ctxt.current_path_len < ctxt.current_root_len || strncmp(ctxt.current_path, ctxt.current_root, ctxt.current_root_len) != 0)
		{
			ctxt.current_root = "";
			ctxt.current_root_len = 0;
		}
	}

#ifdef EUNION
	struct eunion_resolver_scope resolver_scope;
	int scope_result = eunion_resolver_scope_open(&resolver_scope);
	if (scope_result < 0)
		return scope_result;
	ctxt.eunion_resolver = &resolver_scope.resolver;
#endif
	int rv = vchroot_run(input_path, &ctxt);
#ifdef EUNION
	int scope_close = eunion_resolver_scope_close(&resolver_scope);
	if (rv >= 0 && scope_close < 0)
		rv = scope_close;
#endif
	if (ctxt.current_path_len > 0)
		strcpy(args->path, ctxt.current_path);
	else
		strcpy(args->path, "/");

#ifndef TEST
	__simple_printf("    vchroot_expand(): rv=%d, expanded to %s\n", rv, args->path);
#endif

	return rv;
}

static int vchroot_run(const char* input_path, struct context* ctxt)
{
	if (ctxt->symlink_depth > MAX_SYMLINK_DEPTH)
		return -LINUX_ELOOP;

	if (*input_path == '/')
	{
		strcpy(ctxt->current_path, ctxt->current_root);
		ctxt->current_path_len = strlen(ctxt->current_path);
		input_path++;
	}

	const char* end;
	while (next_component(input_path, &end))
	{
		const unsigned int len = end - input_path;

		if ((len == 1 && input_path[0] == '.') || len == 0) // . or nothing (//)
		{
			// nothing to do
		}
		else
		{
			// append /
			ctxt->current_path[ctxt->current_path_len++] = '/';
			ctxt->current_path[ctxt->current_path_len] = '\0';

			if (len == 2 && input_path[0] == '.' && input_path[1] == '.') // ..
			{
				// Returning back into the vchrooted area
				if (ctxt->current_path_len <= 1)
				{
					strcpy(ctxt->current_path, prefix_path);
					strcat(ctxt->current_path, EXIT_PATH);
					ctxt->current_path_len = prefix_path_len + sizeof(EXIT_PATH);

					ctxt->current_path[ctxt->current_path_len-1] = '/';
					ctxt->current_path[ctxt->current_path_len] = '\0';

					ctxt->current_root = prefix_path;
					ctxt->current_root_len = prefix_path_len;
				}

				// current_path always ends with a slash
				// p points before the last /
				char* p = ctxt->current_path + ctxt->current_path_len - 2;

				while (true)
				{
					if (*p == '/')
					{
						*p = '\0';
						ctxt->current_path_len = p - ctxt->current_path;

						// We cannot exit current_root via ..
						if (ctxt->current_path_len < ctxt->current_root_len)
							return -LINUX_ENOENT;
						break;
					}
					p--;
				}
			}
			else
			{
				if (len + ctxt->current_path_len + 2 > sizeof(ctxt->current_path))
					return -LINUX_ENOENT;
				
				// Append the component
				int prevlen = ctxt->current_path_len;

				memcpy(ctxt->current_path + ctxt->current_path_len, input_path, len);
				ctxt->current_path_len += len;
				ctxt->current_path[ctxt->current_path_len] = '\0';

				// Only analyze the last path component if we haven't had an unresolvent ENOENT before
				if (!ctxt->unknown_component)
				{
					stat_t st;
					#if defined(__NR_lstat)
						int status = LINUX_SYSCALL(__NR_lstat, ctxt->current_path, &st);
					#else
						#if __NR_newfstatat
							int status = LINUX_SYSCALL(__NR_newfstatat, LINUX_AT_FDCWD, ctxt->current_path, &st, LINUX_AT_SYMLINK_NOFOLLOW);
						#else
							int status = LINUX_SYSCALL(__NR_fstatat64, LINUX_AT_FDCWD, ctxt->current_path, &st, LINUX_AT_SYMLINK_NOFOLLOW);
						#endif
					#endif

#ifdef EUNION
					// E-UNION per-component two-layer resolution (.7a). overlay/gVisor
					// consult BOTH layers at EVERY component. The pre-refactor code only
					// did so while still rooted at the upper layer and PERMANENTLY
					// committed current_root to the template after the first lower-only
					// component -- so every check below (whiteout, opaque, upper
					// presence) silently no-op'd once committed to lower, and a deeper
					// object living in the UPPER layer became invisible. Here we instead
					// recompute the canonical upper-wins-then-lower resolution for THIS
					// component regardless of which root earlier components landed on.
					//
					// Applies only while current_path is rooted under one of the two
					// union layers (an EXIT_PATH escape or out-of-union path is left
					// exactly as the baseline resolved it).
					if (libexec_path_len > 0)
					{
						struct eunion_resolver resolver =
							*ctxt->eunion_resolver;
						char relbuf[4096];
						int guest_path_status = eunion_guest_path_from_host(
							&resolver, ctxt->current_path, relbuf, sizeof(relbuf));

						if (guest_path_status == 0)
						{
							struct eunion_resolver_result resolution;
							int root_len;

							if (eunion_resolve_path(&resolver, relbuf, &resolution) != 0)
								return -LINUX_ENAMETOOLONG;
							if (resolution.layer == EUNION_RESOLVER_WHITEOUT)
								return -LINUX_ENOENT;
							if (resolution.layer == EUNION_RESOLVER_ERROR)
								return resolution.error;

							if (resolution.layer == EUNION_RESOLVER_LOWER)
							{
								ctxt->current_root = libexec_path;
								ctxt->current_root_len = libexec_path_len;
							}
							else
							{
								ctxt->current_root = prefix_path;
								ctxt->current_root_len = prefix_path_len;
							}
							root_len = (int)strlen(resolution.host_path);
							memcpy(ctxt->current_path, resolution.host_path, root_len + 1);
							ctxt->current_path_len = root_len;
							// The resolver result contains the complete candidate path,
							// while `prevlen` still points into the pre-resolution lower
							// path. Keep case-insensitive lookup anchored at the final
							// component after switching roots.
							prevlen = root_len - (int)len;
							status = resolution.layer == EUNION_RESOLVER_ERROR
								? resolution.error
								: resolution.layer == EUNION_RESOLVER_MISSING
									? -LINUX_ENOENT
									: eunion_lstat(resolution.host_path, &st);
						}
						else if (guest_path_status < 0)
							return -LINUX_ENAMETOOLONG;
					}
#endif

					if (icase_enabled && status == -LINUX_ENOENT)
					{
						// Case insensitive search

						// Examine the directory above
						ctxt->current_path[prevlen-1] = '\0';
						
						#if defined(__NR_open)
							int dfd = LINUX_SYSCALL(__NR_open, (prevlen > 1) ? ctxt->current_path : "/", LINUX_O_RDONLY);
						#else
							int dfd = LINUX_SYSCALL(__NR_openat, LINUX_AT_FDCWD, (prevlen > 1) ? ctxt->current_path : "/", LINUX_O_RDONLY);
						#endif
						char dirents[4096]; // buffer space for struct linux_dirent64 entries
						int len;

						if (dfd < 0)
						{
							ctxt->unknown_component = true;
							goto done_getdents;
						}
						
						// Get a batch of directory entries
						while ((len = LINUX_SYSCALL(__NR_getdents64, dfd, dirents, sizeof(dirents))) > 0)
						{
							int pos = 0;

							// Iterate through directory entries
							while (pos < len)
							{
								struct linux_dirent64* de = (struct linux_dirent64*) &dirents[pos];
								if (strcasecmp(de->d_name, ctxt->current_path + prevlen) == 0)
								{
									// Fix up the case and be done with it
									strcpy(ctxt->current_path + prevlen, de->d_name);
									goto done_getdents;
								}
								pos += de->d_reclen;
							}
						}
						ctxt->unknown_component = true;
done_getdents:
						// Restore the / we removed a few lines above
						ctxt->current_path[prevlen-1] = '/';
						LINUX_SYSCALL(__NR_close, dfd);
					}
					else if (status == 0 && (st.st_mode & LINUX_S_IFMT) == LINUX_S_IFLNK)
					{
						// Follow symlink if follow is true or if we haven't reached the end of the input path yet
						if (ctxt->follow || *end)
						{
							char link[512];
							int rv;

							#if defined(__NR_readlink)
								rv = LINUX_SYSCALL(__NR_readlink, ctxt->current_path, link, sizeof(link) - 1);
							#else
								rv = LINUX_SYSCALL(__NR_readlinkat, LINUX_AT_FDCWD, ctxt->current_path, link, sizeof(link) - 1);
							#endif

							if (rv < 0)
								return rv;

							link[rv] = '\0';

							// https://github.com/darlinghq/darling/issues/916
							// Special procfs hack due to the presence of broken symlinks in /proc/xxx/fd/ used to
							// point to sockets, pipes or anonymous inodes.
							if (strncmp(ctxt->current_path, "/proc", 5) == 0)
							{
								if (strchr(link, ':') != 0)
								{
									goto ignore_symlink;
								}
							}

							// Remove the last component (because it will be substituted with symlink contents)
							if (link[0] != '/') // Only bother to do that if we know that the symlink is not absolute
							{
								ctxt->current_path_len = prevlen - 1; // kill the last slash as well
								ctxt->current_path[ctxt->current_path_len] = '\0';
							}

							// Symbolic link resolution
							const bool orig_follow = ctxt->follow;

							ctxt->follow = true;
							ctxt->symlink_depth++;

							// resolve absolute symlinks within the prefix
							//
							// however, DON'T resolve `/proc` symlinks within the prefix.
							// anything under `/proc` is from Linux's `/proc` since we bind-mount it, so we can special-case them because we want those to be Linux-root relative.
							// see https://github.com/darlinghq/darling/issues/1052 for the issue this works around.
							if (link[0] == '/' && !(strncmp(link, "/proc/", 6) == 0 || (rv == 5 && strncmp(link, "/proc", 5) == 0))) {
								ctxt->current_root = prefix_path;
								ctxt->current_root_len = prefix_path_len;
							}

							rv = vchroot_run(link, ctxt);

							ctxt->symlink_depth--;
							ctxt->follow = orig_follow;

							if (rv != 0)
								return rv;
						}
					}
				}

ignore_symlink:

				if (ctxt->current_root_len > 0 && ctxt->current_path_len - ctxt->current_root_len == sizeof(EXIT_PATH)-1)
				{
					// locale-free ASCII case-fold compare: the old strncasecmp_l(...,
					// LC_C_LOCALE=NULL) deref'd a NULL locale on glibc the instant the
					// bytes matched -- i.e. exactly here, when the escape hatch fires.
					if (eunion_ascii_ncasecmp(ctxt->current_path + ctxt->current_root_len, EXIT_PATH, sizeof(EXIT_PATH) - 1) == 0)
					{
						// Switch to the real system root
						ctxt->current_path[0] = '\0';
						ctxt->current_path_len = 0;
						ctxt->current_root = "";
						ctxt->current_root_len = 0;
					}
				}
			}
		}

		if (eunion_path_enters_sidecar(
				ctxt->current_path, ctxt->current_path_len))
			return -LINUX_ENOENT;

		// Move on to the next component
		input_path = end;
		while (*input_path == '/')
			input_path++;
	}

	return 0;
}

static bool next_component(const char* from, const char** end)
{
	const char* pos = from;
	while (*pos != '/' && *pos)
		pos++;
	*end = pos;
	return *from;
}

int vchroot_fdpath(struct vchroot_fdpath_args* args)
{
#ifndef TEST
	if (prefix_path_len == -1) {
#ifdef EUNION
		eunion_require_anchored_prefix();
#else
		init_vchroot_path();
#endif
	}
#endif

	char buf[50];
	char link[4096];

	__simple_sprintf(buf, "/proc/self/fd/%d", args->fd);

	#if defined(__NR_readlink)
		int rv = LINUX_SYSCALL(__NR_readlink, buf, link, sizeof(link) - 1);
	#else
		int rv = LINUX_SYSCALL(__NR_readlinkat, LINUX_AT_FDCWD, buf, link, sizeof(link) - 1);
	#endif
	if (rv < 0)
		return rv;

	link[rv] = '\0';

#ifdef EUNION
	char guest_path[sizeof(link)];
	struct eunion_resolver resolver = eunion_current_resolver(NULL);
	int guest_path_status = eunion_guest_path_from_host(&resolver,
		link, guest_path, sizeof(guest_path));
	if (guest_path_status == 0)
	{
		if (args->maxlen <= strlen(guest_path))
			return -LINUX_ENAMETOOLONG;
		strcpy(args->path, guest_path);
	}
	else if (guest_path_status < 0)
		return -LINUX_ENAMETOOLONG;
	else
#endif
	if (rv >= prefix_path_len && strncmp(link, prefix_path, prefix_path_len) == 0)
	{
		if ((int)args->maxlen - 1 < rv - prefix_path_len)
			return -LINUX_ENAMETOOLONG;
		strcpy(args->path, link + prefix_path_len);

		if (args->path[0] == '\0')
			strcpy(args->path, "/");
	}
	else
	{
		if (args->maxlen < sizeof(EXIT_PATH) + rv)
			return -LINUX_ENAMETOOLONG;

		memcpy(args->path, EXIT_PATH, sizeof(EXIT_PATH) - 1);
		memcpy(args->path + sizeof(EXIT_PATH) - 1, link, rv+1);
	}

#ifndef TEST
	__simple_printf("fdpath %d -> %s\n", args->fd, args->path);
#endif

	return 0;
}

int vchroot_unexpand(struct vchroot_unexpand_args* args)
{
#ifdef EUNION
	char guest_path[sizeof(args->path)];
	struct eunion_resolver resolver = eunion_current_resolver(NULL);
	int guest_path_status = eunion_guest_path_from_host(&resolver,
		args->path, guest_path, sizeof(guest_path));
	if (guest_path_status == 0)
	{
		strcpy(args->path, guest_path);
	}
	else if (guest_path_status < 0)
	{
		return -LINUX_ENAMETOOLONG;
	}
	else
#endif
	if (memcmp(args->path, prefix_path, prefix_path_len) == 0)
	{
		int bytes = strlen(args->path + prefix_path_len) + 1;
		memmove(args->path, args->path + prefix_path_len, bytes);

		if (args->path[0] == '\0')
			strcpy(args->path, "/");
	}
	else
	{
		int bytes = strlen(args->path) + 1;
		memmove(args->path + sizeof(EXIT_PATH) - 1, args->path, bytes);
		memcpy(args->path, EXIT_PATH, sizeof(EXIT_PATH) - 1);
	}

	return 0;
}

#ifdef TEST
int main(int argc, const char** argv)
{
	if (argc != 3)
	{
		printf("Usage: vchroot_expand <vchroot_dir> <path_to_expand>\n");
		return 1;
	}

	int dfd = open(argv[1], O_RDONLY | O_DIRECTORY);
	__darling_vchroot(dfd);
	close(dfd);

	if (getenv("ICASE"))
		icase_enabled = true;

	struct vchroot_expand_args args;
	args.dfd = -100;
	strcpy(args.path, argv[2]);

	int rv = vchroot_expand(&args);
	printf("vchroot_expand() rv = %d\n", rv);
	printf("-> path = %s\n", args.path);

	if (rv == 0)
	{
		int fd = open(args.path, O_RDONLY);
		struct vchroot_fdpath_args fdpath_args;
		char buf[4096];

		fdpath_args.path = buf;
		fdpath_args.maxlen = sizeof(buf);
		fdpath_args.fd = fd;

		rv = vchroot_fdpath(&fdpath_args);

		printf("vchroot_fdpath() rv = %d\n", rv);
		if (rv >= 0)
			printf("-> path = %s\n", buf);

		close(fd);
	}
	
	return 0;
}
#endif
