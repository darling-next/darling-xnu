
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#ifdef TEST
#	include <unistd.h>
#	include <sys/stat.h>
#	include <sys/syscall.h>
#	include <stdio.h>
#	include <stdbool.h>
#	include <stdlib.h>
#	include <string.h>
#	include <errno.h>
#	include <dirent.h>
#	include <fcntl.h>

#	define LINUX_SYSCALL(...) ({ int __rv = syscall(__VA_ARGS__); if (__rv == -1) __rv = -errno; __rv; })
#	define LINUX_ENOENT ENOENT
#	define LINUX_ELOOP ELOOP
#	define LINUX_ENAMETOOLONG ENAMETOOLONG

#	define LINUX_S_IFMT S_IFMT
#	define LINUX_S_IFLNK S_IFLNK

#	define LINUX_O_RDONLY O_RDONLY

#	define __simple_sprintf sprintf
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

#include <darlingserver/rpc.h>
#include <darling/emulation/linux_premigration/resources/dserver-ring.h>

typedef struct linux_stat stat_t;

extern __SIZE_TYPE__ strlen(const char* s);
extern char* strcpy(char* dest, const char* src);
extern int strcmp(const char* str1, const char* str2);
extern int strncmp(const char* str1, const char* str2, __SIZE_TYPE__ n);
extern int strcasecmp(const char* str1, const char* str2);
extern char* strcat(char* dest, const char* src);
extern char *strchr(const char *s, int c);
extern void *memcpy(void *dest, const void *src, __SIZE_TYPE__ n);
extern void* memmove(void* dest, const void* src, __SIZE_TYPE__ n);
extern int memcmp(const void* dest, const void* src, __SIZE_TYPE__ n);

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

static void set_libexec_path(const char* p)
{
	if (!p || !*p)
	{
		libexec_path[0] = '\0';
		libexec_path_len = 0;
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

static int eunion_lstat(const char* host, stat_t* st); // defined below

// Activate the union for this prefix iff the server provisioned it in E-UNION
// mode, signalled by the presence of the copy-up staging dir `$prefix/.union-work`
// (the server creates it instead of copying the 7GB template). If the marker is
// absent (route 1 / copy-mode), the template path is left unset so libexec_path_len
// stays <= 0 and every E-UNION code path is inert -- behaviour identical to
// baseline. `prefix` must already be set in prefix_path. Idempotent.
static void eunion_init_from_prefix(void)
{
	if (libexec_path_len > 0) // already initialised
		return;
	if (prefix_path_len <= 0)
		return;

	char marker[4096];
	int n = prefix_path_len;
	if (n + (int)sizeof("/.union-work") > (int)sizeof(marker))
		return;
	memcpy(marker, prefix_path, n);
	strcpy(marker + n, "/.union-work");

	stat_t st;
	if (eunion_lstat(marker, &st) != 0)
		return; // not provisioned for union -> stay inert (copy-mode)

	set_libexec_path(EUNION_LIBEXEC_PATH);
}

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
#ifndef LINUX_S_IFDIR
#define LINUX_S_IFDIR 0040000
#endif
#ifndef LINUX_S_IFREG
#define LINUX_S_IFREG 0100000
#endif

extern int __simple_sprintf(char* str, const char* fmt, ...);

// Build the host path for `guest` (a guest-absolute path, no symlink follow)
// under `root` (prefix_path or libexec_path). Returns length, or -1 on overflow.
static int eunion_host_path(const char* root, int root_len, const char* guest, char* out, int cap)
{
	int glen = (int)strlen(guest);
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

static int eunion_mkdir(const char* host, unsigned int mode)
{
	#if defined(__NR_mkdir)
		return LINUX_SYSCALL(__NR_mkdir, host, mode);
	#else
		return LINUX_SYSCALL(__NR_mkdirat, LINUX_AT_FDCWD, host, mode);
	#endif
}

// Ensure every parent component of guest path `guest` exists in the upper
// layer, recreating lower-only dirs with their lower mode. `guest` includes the
// leaf; only its ancestors are created here.
static int eunion_mkparents_upper(const char* guest)
{
	char up[4096], lo[4096];
	// walk components, creating each ancestor dir in the upper layer
	int i = 0;
	while (guest[i] == '/') i++;
	for (;;)
	{
		// find end of this component
		int start = i;
		while (guest[i] && guest[i] != '/') i++;
		if (guest[i] == '\0')
			break; // reached the leaf; nothing more to create
		// ancestor guest path = guest[0..i)
		char anc[4096];
		memcpy(anc, guest, i);
		anc[i] = '\0';

		if (eunion_host_path(prefix_path, prefix_path_len, anc, up, sizeof(up)) < 0)
			return -LINUX_ENAMETOOLONG;

		stat_t st;
		if (eunion_lstat(up, &st) == 0)
		{
			// already in upper; descend
		}
		else
		{
			// take the lower mode if available, else default 0755
			unsigned int mode = 0755;
			if (eunion_host_path(libexec_path, libexec_path_len, anc, lo, sizeof(lo)) >= 0)
			{
				stat_t ls;
				if (eunion_lstat(lo, &ls) == 0)
					mode = ls.st_mode & 07777;
			}
			int r = eunion_mkdir(up, mode);
			if (r < 0 && r != -LINUX_EEXIST)
				return r;
		}

		while (guest[i] == '/') i++;
	}
	return 0;
}

// Copy extended attributes from src fd to dst fd on copy-up (user.* carry app
// metadata). We DROP security.capability: a file capability is setuid-equivalent,
// and a copy-up must not smuggle privilege into the writable prefix (overlay's
// userxattr mode and gVisor both clear it on a data copy-up). Overlay-private
// markers (our user.union.*) are never present on a lower-layer source, so they
// need no filtering. Best-effort: a failure to copy one xattr does not fail
// copy-up.
static void eunion_copy_xattrs(int sfd, int dfd)
{
#if defined(__NR_flistxattr) && defined(__NR_fgetxattr) && defined(__NR_fsetxattr)
	char names[4096];
	int ln = LINUX_SYSCALL(__NR_flistxattr, sfd, names, sizeof(names));
	if (ln <= 0)
		return; // none, or list too big for the PoC buffer
	char val[1024];
	int off = 0;
	while (off < ln)
	{
		const char* name = names + off;
		int nlen = (int)strlen(name);
		if (nlen == 0) { off++; continue; }
		off += nlen + 1;
		// Drop security.capability: a file capability is setuid-equivalent, so a
		// copy-up must not carry it into the writable prefix (matches the setid
		// strip above; overlay/gVisor clear it on data copy-up).
		if (strcmp(name, "security.capability") == 0)
			continue;
		int vn = LINUX_SYSCALL(__NR_fgetxattr, sfd, name, val, sizeof(val));
		if (vn < 0)
			continue;
		LINUX_SYSCALL(__NR_fsetxattr, dfd, name, val, vn, 0);
	}
#else
	(void)sfd; (void)dfd;
#endif
}

// Atomic copy of a regular file from `src_host` to upper `dst_host`. Copies via
// UPPER/.union-work/<unique> + rename so a concurrent reader never sees a partial
// file. A rename/EEXIST race == someone else won == ok. Preserves permission bits
// and xattrs but STRIPS setuid/setgid (a copy-up must never publish a setid
// binary into the writable prefix -- overlay/gVisor clear setid on data copy).
// mtime (seconds + nanoseconds) accessor: the host struct stat (TEST) exposes
// st_mtim.tv_sec/tv_nsec while the kernel linux_stat exposes flat st_mtime/
// st_mtime_nsec. Normalize to a {sec,nsec} pair so copy-up can re-stamp it.
static void eunion_stat_mtime(const stat_t* st, long* sec, long* nsec)
{
#ifdef TEST
	*sec  = (long) st->st_mtim.tv_sec;
	*nsec = (long) st->st_mtim.tv_nsec;
#else
	*sec  = (long) st->st_mtime;
	*nsec = (long) st->st_mtime_nsec;
#endif
}

static int eunion_copy_regular(const char* src_host, const char* dst_host, const stat_t* src_st)
{
	unsigned int mode = (unsigned int) src_st->st_mode;
	int sfd = LINUX_SYSCALL(__NR_openat, LINUX_AT_FDCWD, src_host, LINUX_O_RDONLY, 0);
	if (sfd < 0)
		return sfd;

	// staging path in the upper work dir
	char work[4096];
	__simple_sprintf(work, "%s/.union-work", prefix_path);
	eunion_mkdir(work, 0700); // best-effort; EEXIST ok

	char tmp[4096];
	static unsigned long seq = 0;
	int tid = (int)LINUX_SYSCALL(__NR_gettid);
	__simple_sprintf(tmp, "%s/.union-work/cu.%d.%lu", prefix_path, tid, (unsigned long)(seq++));

	// strip setid: create with permission bits only (mode & 0777), never 07777.
	int dfd = LINUX_SYSCALL(__NR_openat, LINUX_AT_FDCWD, tmp,
		LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_EXCL, mode & 0777);
	if (dfd < 0)
	{
		LINUX_SYSCALL(__NR_close, sfd);
		return dfd;
	}

	char buf[65536];
	int rv = 0;
	for (;;)
	{
		int n = LINUX_SYSCALL(__NR_read, sfd, buf, sizeof(buf));
		if (n < 0) { rv = n; break; }
		if (n == 0) break;
		int off = 0;
		while (off < n)
		{
			int w = LINUX_SYSCALL(__NR_write, dfd, buf + off, n - off);
			if (w < 0) { rv = w; goto done; }
			off += w;
		}
	}
	// Force the upper copy's mode to the permission bits with setid STRIPPED,
	// independent of how the host honors the open() create mode. open(O_CREAT)
	// does not reliably reproduce S_ISUID/S_ISGID across filesystems, so the
	// `& 0777` create mode above is not a dependable defense on its own. An
	// explicit fchmod makes the strip load-bearing and FS-independent: a copy-up
	// must NEVER publish a setid binary into the writable prefix (overlay/gVisor
	// clear setid on a data copy-up). (mode & 0777 == permission bits only.)
	if (rv == 0)
	{
		// Preserve ownership BEFORE the mode strip: a chown can itself clear setid
		// on some kernels, and our explicit fchmod(mode & 0777) below then re-asserts
		// the stripped permission bits regardless. Best-effort -- an unprivileged
		// translator cannot chown to a foreign uid/gid (EPERM); that is fine, the
		// copy simply keeps the translator's own ownership, exactly like overlay's
		// userxattr/unprivileged mode.
#if defined(__NR_fchown)
		LINUX_SYSCALL(__NR_fchown, dfd, (unsigned int) src_st->st_uid,
			(unsigned int) src_st->st_gid);
#endif
		LINUX_SYSCALL(__NR_fchmod, dfd, mode & 0777);
	}
	// carry xattrs over before publishing (while both fds are open). NOTE:
	// eunion_copy_xattrs deliberately drops security.capability so a file
	// capability cannot survive a copy-up either (it is setuid-equivalent).
	eunion_copy_xattrs(sfd, dfd);
	// Preserve mtime (overlay keeps the source mtime; resetting it to "now" breaks
	// make/ninja/ccache staleness checks). atime is set to the source atime too;
	// ctime cannot be set and will reflect the copy, which matches overlay. The
	// kernel utimensat ABI takes a 2-element {sec,nsec} timespec array [atime,mtime].
	if (rv == 0)
	{
		struct { long tv_sec; long tv_nsec; } ts[2];
		long msec, mnsec;
		eunion_stat_mtime(src_st, &msec, &mnsec);
		ts[0].tv_sec = msec; ts[0].tv_nsec = mnsec; // atime <- source mtime
		ts[1].tv_sec = msec; ts[1].tv_nsec = mnsec; // mtime <- source mtime
#if defined(__NR_utimensat)
		LINUX_SYSCALL(__NR_utimensat, dfd, (const char*)0, ts, 0);
#endif
	}
done:
	LINUX_SYSCALL(__NR_close, sfd);
	LINUX_SYSCALL(__NR_close, dfd);

	if (rv < 0)
	{
		LINUX_SYSCALL(__NR_unlink, tmp);
		return rv;
	}

	// publish atomically
	#if defined(__NR_rename)
		rv = LINUX_SYSCALL(__NR_rename, tmp, dst_host);
	#else
		rv = LINUX_SYSCALL(__NR_renameat, LINUX_AT_FDCWD, tmp, LINUX_AT_FDCWD, dst_host);
	#endif
	if (rv < 0)
	{
		// a racer may have created dst_host first; that is success
		LINUX_SYSCALL(__NR_unlink, tmp);
		stat_t st;
		if (eunion_lstat(dst_host, &st) == 0)
			return 0;
		return rv;
	}
	return 0;
}

// Copy up `guest` (a guest-absolute path) from the lower template into the
// upper layer if it lives only in the lower layer. Returns 0 if the object is
// (now) present in the upper layer, a negative Linux errno otherwise.
int vchroot_copyup(const char* guest)
{
	if (libexec_path_len <= 0 || prefix_path_len < 0)
		return -LINUX_ENOENT;

	char up[4096], lo[4096];
	if (eunion_host_path(prefix_path, prefix_path_len, guest, up, sizeof(up)) < 0)
		return -LINUX_ENAMETOOLONG;

	stat_t ust;
	if (eunion_lstat(up, &ust) == 0)
		return 0; // already in upper layer

	if (eunion_host_path(libexec_path, libexec_path_len, guest, lo, sizeof(lo)) < 0)
		return -LINUX_ENAMETOOLONG;

	stat_t lst;
	if (eunion_lstat(lo, &lst) != 0)
		return -LINUX_ENOENT; // absent in both layers

	// materialize ancestor dirs in the upper layer
	int r = eunion_mkparents_upper(guest);
	if (r < 0)
		return r;

	unsigned int fmt = lst.st_mode & LINUX_S_IFMT;
	if (fmt == LINUX_S_IFDIR)
	{
		// a lower-only directory: recreate (empty) in upper with same mode;
		// merge of contents is handled lazily by the union resolver + readdir.
		r = eunion_mkdir(up, lst.st_mode & 07777);
		if (r < 0 && r != -LINUX_EEXIST)
			return r;
		return 0;
	}
	else if (fmt == LINUX_S_IFREG)
	{
		return eunion_copy_regular(lo, up, &lst);
	}
	else if (fmt == LINUX_S_IFLNK)
	{
		char link[4096];
		#if defined(__NR_readlink)
			int n = LINUX_SYSCALL(__NR_readlink, lo, link, sizeof(link) - 1);
		#else
			int n = LINUX_SYSCALL(__NR_readlinkat, LINUX_AT_FDCWD, lo, link, sizeof(link) - 1);
		#endif
		if (n < 0)
			return n;
		link[n] = '\0';
		#if defined(__NR_symlink)
			r = LINUX_SYSCALL(__NR_symlink, link, up);
		#else
			r = LINUX_SYSCALL(__NR_symlinkat, link, LINUX_AT_FDCWD, up);
		#endif
		if (r < 0 && r != -LINUX_EEXIST)
			return r;
		return 0;
	}

	// FIFO/socket/device: gVisor returns EPERM for fifo/socket. Keep it simple
	// for the PoC and refuse copy-up of special files.
	return -LINUX_EPERM;
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

	int r = vchroot_copyup(guest);
	if (r < 0)
		return (r == -LINUX_ENOENT) ? 0 : r;

	// only directories have descendants to recurse into
	char lo[4096];
	if (eunion_host_path(libexec_path, libexec_path_len, guest, lo, sizeof(lo)) < 0)
		return 0; // not in template: nothing more to pull up
	stat_t lst;
	if (eunion_lstat(lo, &lst) != 0)
		return 0;
	if ((lst.st_mode & LINUX_S_IFMT) != LINUX_S_IFDIR)
		return 0;

	int fd = LINUX_SYSCALL(__NR_openat, LINUX_AT_FDCWD, lo,
		LINUX_O_RDONLY | LINUX_O_DIRECTORY, 0);
	if (fd < 0)
		return 0; // best-effort; the dir itself is already up

	int glen = (int)strlen(guest);
	char dbuf[8192];
	for (;;)
	{
		int n = LINUX_SYSCALL(__NR_getdents64, fd, dbuf, sizeof(dbuf));
		if (n <= 0)
			break;
		int off = 0;
		while (off < n)
		{
			struct linux_dirent64* de = (struct linux_dirent64*)(dbuf + off);
			off += de->d_reclen;
			const char* nm = de->d_name;
			if (nm[0] == '.' && (nm[1] == '\0' || (nm[1] == '.' && nm[2] == '\0')))
				continue;
			// build child guest path = guest + "/" + name
			char child[4096];
			int nl = (int)strlen(nm);
			if (glen + 1 + nl + 1 > (int)sizeof(child))
				continue; // too long: skip (best-effort PoC)
			memcpy(child, guest, glen);
			int ci = glen;
			if (ci == 0 || child[ci-1] != '/')
				child[ci++] = '/';
			memcpy(child + ci, nm, nl + 1);
			int cr = vchroot_copyup_tree(child);
			if (cr < 0) { LINUX_SYSCALL(__NR_close, fd); return cr; }
		}
	}
	LINUX_SYSCALL(__NR_close, fd);
	return 0;
}

// -------- E-UNION whiteout + opaque markers ------------------------------
//
// The translator runs as uid 0 INSIDE the container but is NOT real host root,
// so the overlayfs/gVisor default encodings are unavailable to us:
//   * char-dev(0,0) whiteouts need CAP_MKNOD;
//   * trusted.overlay.* xattrs need CAP_SYS_ADMIN.
// gVisor hit the same wall and falls back to user.overlay.* (its `userxattr`
// mode). We do the same, unprivileged:
//   * whiteout = an empty placeholder REGULAR file at the upper path carrying
//     the xattr `user.union.whiteout=y`. A guest path whose upper object is a
//     whiteout reads as ENOENT and does NOT fall through to the lower layer.
//   * opaque  = the xattr `user.union.opaque=y` on an upper directory; its
//     lower namesake is not merged in.
// user.* xattrs are settable by the file owner without privilege on ext4.

static const char EUNION_WH_XATTR[]     = "user.union.whiteout";
static const char EUNION_OPAQUE_XATTR[] = "user.union.opaque";

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

// returns 1 if host path `host` carries xattr `name` == "y", else 0
static int eunion_has_marker(const char* host, const char* name)
{
	char val[4];
	#if defined(__NR_lgetxattr)
		int n = LINUX_SYSCALL(__NR_lgetxattr, host, name, val, sizeof(val));
	#else
		int n = LINUX_SYSCALL(__NR_getxattr, host, name, val, sizeof(val));
	#endif
	return (n >= 1 && val[0] == 'y');
}

static int eunion_set_marker(const char* host, const char* name)
{
	#if defined(__NR_lsetxattr)
		return LINUX_SYSCALL(__NR_lsetxattr, host, name, "y", 1, 0);
	#else
		return LINUX_SYSCALL(__NR_setxattr, host, name, "y", 1, 0);
	#endif
}

// Is the guest path whited-out in the upper layer? (upper object exists and
// carries the whiteout marker.)
static int eunion_is_whiteout(const char* guest)
{
	char up[4096];
	if (eunion_host_path(prefix_path, prefix_path_len, guest, up, sizeof(up)) < 0)
		return 0;
	stat_t st;
	if (eunion_lstat(up, &st) != 0)
		return 0;
	return eunion_has_marker(up, EUNION_WH_XATTR);
}

// Record deletion of a guest path: leave an empty placeholder regular file in
// the upper layer carrying the whiteout xattr, so the lower object stays hidden.
int vchroot_whiteout(const char* guest)
{
	if (prefix_path_len < 0)
		return -LINUX_ENOENT;

	int r = eunion_mkparents_upper(guest);
	if (r < 0)
		return r;

	char up[4096];
	if (eunion_host_path(prefix_path, prefix_path_len, guest, up, sizeof(up)) < 0)
		return -LINUX_ENAMETOOLONG;

	// If an upper object already exists (e.g. a copied-up file), replace it with
	// the placeholder. Try to create exclusively; if it exists, unlink + retry.
	// NOTE: the placeholder must be owner-writable -- the kernel refuses to set
	// a user.* xattr on a mode-0000 file (EACCES). The placeholder is never
	// exposed to the guest (the resolver maps it to ENOENT), so its mode is
	// irrelevant beyond letting us attach the marker.
	int fd = LINUX_SYSCALL(__NR_openat, LINUX_AT_FDCWD, up,
		LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_EXCL, 0600);
	if (fd == -LINUX_EEXIST)
	{
		LINUX_SYSCALL(__NR_unlink, up);
		fd = LINUX_SYSCALL(__NR_openat, LINUX_AT_FDCWD, up,
			LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_EXCL, 0600);
	}
	if (fd < 0)
		return fd;
	LINUX_SYSCALL(__NR_close, fd);

	int mr = eunion_set_marker(up, EUNION_WH_XATTR);
	if (mr < 0)
	{
		// roll back the placeholder so a failed whiteout doesn't masquerade as
		// an empty file
		LINUX_SYSCALL(__NR_unlink, up);
		return mr;
	}
	return 0;
}

// Remove a whiteout marker (the path is being recreated). Removes the
// placeholder file entirely so a subsequent copy-up / create can take its place.
int vchroot_unwhiteout(const char* guest)
{
	char up[4096];
	if (eunion_host_path(prefix_path, prefix_path_len, guest, up, sizeof(up)) < 0)
		return -LINUX_ENAMETOOLONG;
	if (!eunion_is_whiteout(guest))
		return 0; // nothing to do
	int r = LINUX_SYSCALL(__NR_unlink, up);
	if (r < 0 && r != -LINUX_ENOENT)
		return r;
	return 0;
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
	char up[4096];
	if (eunion_host_path(prefix_path, prefix_path_len, guest, up, sizeof(up)) < 0)
		return -LINUX_ENAMETOOLONG;
	return eunion_set_marker(up, EUNION_OPAQUE_XATTR);
}

// -------- E-UNION write-op wiring helpers --------------------------------
//
// These are the thin entrypoints the syscall-emulation sites call so the union
// policy stays in one place. The pattern at a mutating site is:
//   vchroot_prepare_write(guest);   // BEFORE vchroot_expand -> expand hits upper
//   ... vchroot_expand(); real syscall ...
//   vchroot_post_unlink(guest);     // AFTER a successful unlink/rmdir
// All take an ABSOLUTE guest path (the shared template is addressed absolutely:
// /usr, /System, ...). A relative or out-of-prefix path is a no-op success --
// such writes never touch the read-only template, so there is nothing to do.

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
	if (eunion_is_whiteout(guest))
	{
		int r = vchroot_unwhiteout(guest);
		if (r < 0)
			return r;
		// fall through: nothing to copy up (it was deleted), create-in-upper
		return 0;
	}

	int r = vchroot_copyup(guest);
	if (r == -LINUX_ENOENT)
		return 0; // absent in both layers: a create will make it fresh in upper
	return r; // 0 if copied up or already upper; negative on real error
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

	// need a real dir fd to resolve against
	if (dfd < 0)
		return 0; // AT_FDCWD/relative without a base we can map: PoC no-op

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

// BEFORE an unlink/rmdir: decide the union policy and tell the caller whether to
// run the host delete syscall. The lower template is a SHARED live directory
// (not a read-only mount), so a delete that reaches a lower host path would
// physically remove the object from the template for EVERY prefix. We must never
// let the real syscall touch a lower-only name.
//
//   lower-only name  -> drop a whiteout, return VCHROOT_UNLINK_SKIP: the caller
//                       must NOT call the host syscall (the name is now hidden).
//   upper present    -> return VCHROOT_UNLINK_PROCEED: the caller deletes the
//                       upper object, then calls vchroot_post_unlink() to drop a
//                       whiteout if the name also exists in the template.
//   absent in both / unmanaged -> VCHROOT_UNLINK_PROCEED (let the syscall ENOENT
//                       naturally; nothing to hide).
int vchroot_prepare_unlink(const char* guest)
{
	if (!eunion_manage(guest))
		return VCHROOT_UNLINK_PROCEED;

	// upper object present? then the real delete targets the upper copy -> proceed
	char up[4096];
	if (eunion_host_path(prefix_path, prefix_path_len, guest, up, sizeof(up)) < 0)
		return -LINUX_ENAMETOOLONG;
	stat_t ust;
	if (eunion_lstat(up, &ust) == 0)
		return VCHROOT_UNLINK_PROCEED; // delete the upper; post_unlink handles lower

	// no upper object. is it in the lower template?
	char lo[4096];
	if (eunion_host_path(libexec_path, libexec_path_len, guest, lo, sizeof(lo)) < 0)
		return -LINUX_ENAMETOOLONG;
	stat_t lst;
	if (eunion_lstat(lo, &lst) != 0)
		return VCHROOT_UNLINK_PROCEED; // absent in both: let the syscall ENOENT

	// lower-only: NEVER delete from the shared template. Hide it with a whiteout
	// and tell the caller to skip the host delete entirely.
	int r = vchroot_whiteout(guest);
	if (r < 0)
		return r;
	return VCHROOT_UNLINK_SKIP;
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

// BEFORE a rename's DESTINATION is committed: ensure the move lands in the upper
// layer and never mutates the shared template.
//   * copy up the destination's PARENT dir (if lower-only, the expanded dest
//     would otherwise point into the template and the host rename would move
//     INTO it);
//   * if the destination NAME exists only in the lower template, whiteout it so
//     the old template content is hidden once the renamed object takes the name
//     (the host rename targets the upper path; the lower namesake stays on disk
//     but must be masked).
//   * if a whiteout already sits at the dest, clear it (the rename recreates it).
int vchroot_prepare_rename_dest(const char* guest)
{
	if (!eunion_manage(guest))
		return 0;

	int r = eunion_copyup_parent(guest);
	if (r < 0)
		return r;

	// a stale whiteout at the dest must be cleared so the moved object is visible
	if (eunion_is_whiteout(guest))
	{
		r = vchroot_unwhiteout(guest);
		if (r < 0)
			return r;
		return 0; // it was deleted; nothing in the template to mask
	}

	// dest present in the upper already? the host rename overwrites it -> fine
	char up[4096];
	if (eunion_host_path(prefix_path, prefix_path_len, guest, up, sizeof(up)) < 0)
		return -LINUX_ENAMETOOLONG;
	stat_t ust;
	if (eunion_lstat(up, &ust) == 0)
		return 0;

	// dest only in the lower template: mask it with a whiteout so the old content
	// does not show through after the rename publishes the new upper object.
	char lo[4096];
	if (eunion_host_path(libexec_path, libexec_path_len, guest, lo, sizeof(lo)) < 0)
		return -LINUX_ENAMETOOLONG;
	stat_t lst;
	if (eunion_lstat(lo, &lst) == 0)
		return vchroot_whiteout(guest);

	return 0; // absent in both: a plain create-in-upper
}

// BEFORE creating a new entry (mkdir/mknod/mkfifo/symlink/...): ensure the
// PARENT dir lives in the writable upper layer (else the create lands inside the
// shared template) and clear any whiteout at the new name (an explicit create
// resurrects a previously deleted name). Does NOT create the entry itself.
int vchroot_prepare_create(const char* guest)
{
	if (!eunion_manage(guest))
		return 0;
	int r = eunion_copyup_parent(guest);
	if (r < 0)
		return r;
	if (eunion_is_whiteout(guest))
		return vchroot_unwhiteout(guest);
	return 0;
}

// After a successful unlink/rmdir of the upper object: if the name still exists
// in the lower template, drop a whiteout so it stays deleted. If it was
// upper-only (absent from lower), do nothing -- the unlink already removed it.
int vchroot_post_unlink(const char* guest)
{
	if (!eunion_manage(guest))
		return 0;

	char lo[4096];
	if (eunion_host_path(libexec_path, libexec_path_len, guest, lo, sizeof(lo)) < 0)
		return -LINUX_ENAMETOOLONG;

	stat_t lst;
	if (eunion_lstat(lo, &lst) != 0)
		return 0; // not in the template: nothing to hide

	return vchroot_whiteout(guest);
}

// Before re-creating a name (mkdir/create over a previously deleted name): clear
// any whiteout marker so the new object is visible. No-op if not whited out.
int vchroot_pre_mkdir(const char* guest)
{
	if (!eunion_manage(guest))
		return 0;
	if (!eunion_is_whiteout(guest))
		return 0;
	return vchroot_unwhiteout(guest);
}

// helper: append `name` to a NUL-separated out buffer if it fits and is not a
// duplicate of an already-appended name. Returns 1 if appended, 0 if dup, <0 on
// overflow.
static int eunion_emit_name(char* out, int cap, int* used, int* count, const char* name)
{
	// dedup against already-emitted names
	const char* p = out;
	for (int i = 0; i < *count; i++)
	{
		if (strcmp(p, name) == 0)
			return 0;
		p += strlen(p) + 1;
	}
	int nlen = (int)strlen(name) + 1;
	if (*used + nlen > cap)
		return -LINUX_ENAMETOOLONG;
	memcpy(out + *used, name, nlen);
	*used += nlen;
	(*count)++;
	return 1;
}

// is `name` present in a NUL-separated set of `n` names?
static int name_in_set(const char* buf, int n, const char* name)
{
	const char* p = buf;
	for (int i = 0; i < n; i++)
	{
		if (strcmp(p, name) == 0)
			return 1;
		p += strlen(p) + 1;
	}
	return 0;
}

// Produce the merged directory listing for guest dir `guest` as a NUL-separated
// list of names in `out`. Upper layer wins on name clash; whiteouts hide the
// lower namesake; an opaque upper dir is not merged with the lower. Returns the
// number of names, or a negative Linux errno.
int vchroot_readdir_merge(const char* guest, char* out, int cap)
{
	if (prefix_path_len < 0)
		return -LINUX_ENOENT;

	int used = 0, count = 0;

	char up[4096], lo[4096];
	int have_upper = (eunion_host_path(prefix_path, prefix_path_len, guest, up, sizeof(up)) >= 0);

	// 1. upper layer: emit non-whiteout names; record whiteout names so the
	//    lower namesake is suppressed (tracked in a separate seen-set).
	char whbuf[4096]; int whused = 0, whcount = 0;
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
					if (hl + 1 + nl + 1 > (int)sizeof(child))
						continue;
					memcpy(child, up, hl); child[hl] = '/'; memcpy(child + hl + 1, nm, nl + 1);

					if (eunion_has_marker(child, EUNION_WH_XATTR))
						eunion_emit_name(whbuf, sizeof(whbuf), &whused, &whcount, nm); // hidden
					else
						eunion_emit_name(out, cap, &used, &count, nm); // visible upper entry
				}
			}
			LINUX_SYSCALL(__NR_close, dfd);
		}

		// 2. opaque upper dir -> do not merge lower
		if (eunion_has_marker(up, EUNION_OPAQUE_XATTR))
			return count;
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
					if (name_in_set(whbuf, whcount, nm))
						continue;
					eunion_emit_name(out, cap, &used, &count, nm);
				}
			}
			LINUX_SYSCALL(__NR_close, dfd);
		}
	}

	return count;
}

// -------- E-UNION paged getdents merge (per-fd state) --------------------
//
// getdirentries works on an fd and streams the directory in pages; the kernel
// tracks the offset for the UPPER fd only. To present a MERGED view (upper wins,
// lower merged in, whiteouts subtracted, opaque honoured) across an arbitrary
// number of pages WITHOUT the getdents64 rewind hazards, we materialize the full
// merged name list ONCE per open dir fd (reusing the proven vchroot_readdir_merge
// enumeration) into a small per-fd buffer, then hand it back page by page. The
// emulation site calls:
//   vchroot_getdents_merge(fd, out, cap)  instead of raw getdents64(fd, ...)
//   vchroot_dir_closed(fd)                from close()/closedir() teardown
// rewinddir (lseek(fd,0)) is detected by the emulation, which calls
// vchroot_dir_closed(fd) so the next getdents re-materializes from the start.

#define EUNION_MAXDIRS  256
#define EUNION_NAMEBUF  65536  // per-dir merged name list (NUL-separated)

struct eunion_dir_state
{
	int  fd;                    // upper fd this state tracks (-1 = free slot)
	int  ready;                 // names[] materialized?
	int  count;                 // number of names
	int  cursor;                // byte offset of the next name to emit
	int  used;                  // bytes used in names[]
	char guest[4096];           // guest dir path (for per-entry d_type/d_ino lstat)
	char names[EUNION_NAMEBUF]; // NUL-separated merged listing
};

static struct eunion_dir_state eunion_dirs[EUNION_MAXDIRS];
static int eunion_dirs_inited = 0;

static void eunion_dirs_init(void)
{
	if (eunion_dirs_inited)
		return;
	for (int i = 0; i < EUNION_MAXDIRS; i++)
		eunion_dirs[i].fd = -1;
	eunion_dirs_inited = 1;
}

static struct eunion_dir_state* eunion_dir_find(int fd)
{
	eunion_dirs_init();
	for (int i = 0; i < EUNION_MAXDIRS; i++)
		if (eunion_dirs[i].fd == fd)
			return &eunion_dirs[i];
	return 0;
}

// Free per-fd merge state (call from close()/closedir() and on rewinddir).
// Idempotent.
void vchroot_dir_closed(int fd)
{
	struct eunion_dir_state* s = eunion_dir_find(fd);
	if (!s)
		return;
	s->fd = -1;
	s->ready = 0;
}

static struct eunion_dir_state* eunion_dir_alloc(int fd)
{
	struct eunion_dir_state* s = eunion_dir_find(fd);
	if (!s)
	{
		for (int i = 0; i < EUNION_MAXDIRS; i++)
			if (eunion_dirs[i].fd == -1) { s = &eunion_dirs[i]; break; }
	}
	if (!s)
		return 0; // table full: caller degrades to plain upper stream
	s->fd = fd;
	s->ready = 0;
	s->count = s->cursor = s->used = 0;
	return s;
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

	struct eunion_dir_state* s = eunion_dir_find(fd);
	if (!s)
	{
		s = eunion_dir_alloc(fd);
		if (!s) // table full: degrade gracefully to plain upper stream
			return LINUX_SYSCALL(__NR_getdents64, fd, out, cap);
	}

	if (!s->ready)
	{
		// recover the guest dir path from the upper fd, then materialize the
		// merged listing once.
		char guest[4096];
		struct vchroot_fdpath_args fp;
		fp.fd = fd; fp.path = guest; fp.maxlen = sizeof(guest);
		if (vchroot_fdpath(&fp) < 0) // not under the prefix: no merge to do
			return LINUX_SYSCALL(__NR_getdents64, fd, out, cap);

		int n = vchroot_readdir_merge(guest, s->names, sizeof(s->names));
		if (n < 0) // fall back to the raw stream on any merge error
			return LINUX_SYSCALL(__NR_getdents64, fd, out, cap);

		// remember the guest dir path so the emitter can lstat each entry for a
		// real d_type/d_ino (overlay presents valid types, not DT_UNKNOWN).
		{
			int gl = (int)strlen(guest);
			if (gl + 1 > (int)sizeof(s->guest))
				gl = (int)sizeof(s->guest) - 1;
			memcpy(s->guest, guest, gl);
			s->guest[gl] = '\0';
		}

		s->count = n;
		s->cursor = 0;
		s->used = 0;
		// compute total bytes for cursor walking
		const char* p = s->names;
		for (int i = 0; i < n; i++)
			p += strlen(p) + 1;
		s->used = (int)(p - s->names);
		s->ready = 1;
	}

	// page out from cursor
	int written = 0;
	while (s->cursor < s->used)
	{
		const char* name = s->names + s->cursor;
		int w = eunion_emit_dirent(out, cap, written, s->guest, name);
		if (!w)
			break; // page full; resume here next call
		written += w;
		s->cursor += (int)strlen(name) + 1;
	}
	return written; // 0 when cursor reaches used -> end of merged stream
}
#endif

static const char EXIT_PATH[] = "/Volumes/SystemRoot";

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
	eunion_init_from_prefix();
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

static void init_vchroot_path(void)
{
	uint64_t tmp_len;
	int code;
	// perf #18 D13 (dar-1il.8): warm post-attach site -- try the ring first (fixed 16B body, 8B
	// reply; the prefix path is delivered by the server's writeMemory on our /proc/mem). On any
	// transport miss fall back to UDS, preserving this site's exact result semantics. (The OTHER
	// vchroot_path caller, mldr.c:940, is in the mldr binary which has no ring -> always UDS.)
#ifndef TEST
	int t_code;
	if (__dserver_ring_vchroot_path((uint64_t)(uintptr_t)prefix_path, sizeof(prefix_path), &tmp_len, &t_code) == 0) {
		code = t_code;
	} else
#endif
	{
		code = dserver_rpc_vchroot_path(prefix_path, sizeof(prefix_path), &tmp_len);
	}
	if (code < 0) {
		__simple_printf("Failed to get vchroot path: %d\n", code);
		__simple_abort();
	}

	prefix_path_len = (int)tmp_len;

#ifdef EUNION
	eunion_init_from_prefix();
#endif

#ifndef TEST
	__simple_printf("init_vchroot_path: %s\n", prefix_path);
#endif
}

int vchroot_expand(struct vchroot_expand_args* args)
{
	struct context ctxt;

#ifndef TEST
	if (prefix_path_len == -1)
		init_vchroot_path();
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

	int rv = vchroot_run(input_path, &ctxt);
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
				const int prevlen = ctxt->current_path_len;

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
						// derive the guest-relative suffix from whichever union root
						// current_path currently sits under.
						const char* relstart = 0;
						if (strncmp(ctxt->current_path, prefix_path, prefix_path_len) == 0)
							relstart = ctxt->current_path + prefix_path_len;
						else if (strncmp(ctxt->current_path, libexec_path, libexec_path_len) == 0)
							relstart = ctxt->current_path + libexec_path_len;

						if (relstart)
						{
							char relbuf[4096];
							int rellen = (int)strlen(relstart);
							if (rellen + 1 <= (int)sizeof(relbuf))
							{
								memcpy(relbuf, relstart, rellen + 1);

								// build the UPPER host path for this guest-rel path
								char upper[4096];
								int uok = (prefix_path_len + rellen + 1 <= (int)sizeof(upper));
								if (uok)
								{
									memcpy(upper, prefix_path, prefix_path_len);
									memcpy(upper + prefix_path_len, relbuf, rellen + 1);
								}

								// 1. UPPER layer wins. Stat the upper namesake.
								stat_t ust;
								int ustatus = uok
									? eunion_lstat(upper, &ust)
									: -LINUX_ENOENT;

								if (ustatus == 0 && eunion_has_marker(upper, EUNION_WH_XATTR))
								{
									// upper object is a whiteout: the guest path is
									// deleted -> ENOENT, never fall through to lower.
									return -LINUX_ENOENT;
								}

								if (ustatus == 0)
								{
									// present (non-whiteout) in the upper layer: adopt
									// the upper copy and root the walk at the prefix.
									memcpy(ctxt->current_path, upper, prefix_path_len + rellen + 1);
									ctxt->current_path_len = prefix_path_len + rellen;
									ctxt->current_root = prefix_path;
									ctxt->current_root_len = prefix_path_len;
									st = ust;
									status = 0;
								}
								else
								{
									// 2. Not in upper. Fall back to the LOWER template,
									// unless the parent UPPER dir is opaque (its lower
									// namesake is not merged).
									bool opaque_parent = false;
									if (rellen > 0)
									{
										// parent guest-rel = relbuf minus last comp
										int q = rellen;
										while (q > 0 && relbuf[q-1] != '/') q--;
										if (q > 1) // there is a real parent below root
										{
											char pupper[4096];
											int pl = prefix_path_len + (q - 1);
											if (pl + 1 <= (int)sizeof(pupper))
											{
												memcpy(pupper, prefix_path, prefix_path_len);
												memcpy(pupper + prefix_path_len, relbuf, q - 1);
												pupper[pl] = '\0';
												if (eunion_has_marker(pupper, EUNION_OPAQUE_XATTR))
													opaque_parent = true;
											}
										}
									}

									char lower[4096];
									int lok = (libexec_path_len + rellen + 1 <= (int)sizeof(lower));
									int lstatus = -LINUX_ENOENT;
									if (!opaque_parent && lok)
									{
										memcpy(lower, libexec_path, libexec_path_len);
										memcpy(lower + libexec_path_len, relbuf, rellen + 1);
										lstatus = eunion_lstat(lower, &st);
									}

									if (lstatus == 0 || (lstatus != -LINUX_ENOENT && !opaque_parent))
									{
										// found in (or definitively errored against)
										// the lower layer: adopt it and root at template.
										memcpy(ctxt->current_path, lower, libexec_path_len + rellen + 1);
										ctxt->current_path_len = libexec_path_len + rellen;
										ctxt->current_root = libexec_path;
										ctxt->current_root_len = libexec_path_len;
										status = lstatus;
									}
									else
									{
										// absent in both: leave current_path rooted at
										// the UPPER layer so the case-insensitive search
										// below runs against the prefix as before.
										if (uok)
										{
											memcpy(ctxt->current_path, upper, prefix_path_len + rellen + 1);
											ctxt->current_path_len = prefix_path_len + rellen;
											ctxt->current_root = prefix_path;
											ctxt->current_root_len = prefix_path_len;
										}
										status = -LINUX_ENOENT;
									}
								}
							}
						}
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
	if (prefix_path_len == -1)
		init_vchroot_path();
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

	if (rv >= prefix_path_len && strncmp(link, prefix_path, prefix_path_len) == 0)
	{
		if (args->maxlen-1 < rv - prefix_path_len)
			return -LINUX_ENAMETOOLONG;
		strcpy(args->path, link + prefix_path_len);

		if (args->path[0] == '\0')
			strcpy(args->path, "/");
	}
#ifdef EUNION
	// E-UNION: a fd may resolve into the read-only LOWER template, which lives
	// OUTSIDE the prefix (at libexec_path). Detranslate it to the guest path too
	// -- otherwise it falls through to the EXIT_PATH escape hatch and yields a
	// bogus /Volumes/SystemRoot/<host-template-path> guest path. launchctl uses
	// F_GETPATH on the System/Library/LaunchDaemons dir fd (which resolves to the
	// lower template) to build child plist paths; the escape-hatch path makes
	// every plist lookup fail, so no daemons load and `bootstrap -S System`
	// stalls on services that never check in.
	else if (libexec_path_len > 0 && rv >= libexec_path_len
	         && strncmp(link, libexec_path, libexec_path_len) == 0
	         && (link[libexec_path_len] == '/' || link[libexec_path_len] == '\0'))
	{
		if (args->maxlen-1 < rv - libexec_path_len)
			return -LINUX_ENAMETOOLONG;
		strcpy(args->path, link + libexec_path_len);

		if (args->path[0] == '\0')
			strcpy(args->path, "/");
	}
#endif
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
	if (memcmp(args->path, prefix_path, prefix_path_len) == 0)
	{
		int bytes = strlen(args->path + prefix_path_len) + 1;
		memmove(args->path, args->path + prefix_path_len, bytes);

		if (args->path[0] == '\0')
			strcpy(args->path, "/");
	}
#ifdef EUNION
	// E-UNION: a host path under the read-only LOWER template detranslates to the
	// guest path too (see vchroot_fdpath). Without this it escapes through
	// EXIT_PATH to a bogus /Volumes/SystemRoot/<template-path> guest path.
	else if (libexec_path_len > 0
	         && memcmp(args->path, libexec_path, libexec_path_len) == 0
	         && (args->path[libexec_path_len] == '/' || args->path[libexec_path_len] == '\0'))
	{
		int bytes = strlen(args->path + libexec_path_len) + 1;
		memmove(args->path, args->path + libexec_path_len, bytes);

		if (args->path[0] == '\0')
			strcpy(args->path, "/");
	}
#endif
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
