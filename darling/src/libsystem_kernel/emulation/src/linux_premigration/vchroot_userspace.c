
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

typedef struct linux_stat stat_t;

struct _xlocale;
typedef struct _xlocale* locale_t;

#define LC_C_LOCALE ((locale_t)NULL)

extern __SIZE_TYPE__ strlen(const char* s);
extern char* strcpy(char* dest, const char* src);
extern int strcmp(const char* str1, const char* str2);
extern int strncmp(const char* str1, const char* str2, __SIZE_TYPE__ n);
extern int strncasecmp_l(const char* str1, const char* str2, __SIZE_TYPE__ n, locale_t locale);
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

// Atomic copy of a regular file from `src_host` to upper `dst_host`, preserving
// mode. Copies via UPPER/.union-work/<unique> + rename so a concurrent reader
// never sees a partial file. A rename/EEXIST race == someone else won == ok.
static int eunion_copy_regular(const char* src_host, const char* dst_host, unsigned int mode)
{
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

	int dfd = LINUX_SYSCALL(__NR_openat, LINUX_AT_FDCWD, tmp,
		LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_EXCL, mode & 07777);
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
		return eunion_copy_regular(lo, up, lst.st_mode);
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
#endif

static const char EXIT_PATH[] = "/Volumes/SystemRoot";

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
					// E-UNION whiteout: if the component exists in the upper
					// layer but is a whiteout marker, the path is deleted -- report
					// ENOENT and DO NOT fall back to the lower layer. We detect the
					// marker only when rooted at the upper layer.
					if (status == 0
						&& libexec_path_len > 0
						&& ctxt->current_root_len == prefix_path_len
						&& strncmp(ctxt->current_path, prefix_path, prefix_path_len) == 0
						&& eunion_has_marker(ctxt->current_path, EUNION_WH_XATTR))
					{
						// The guest path is deleted. Report ENOENT to the caller --
						// the whiteout placeholder must never be opened/statted as a
						// real object, and the lower namesake must stay hidden.
						return -LINUX_ENOENT;
					}

					// E-UNION lower-layer fallback: the component does not exist
					// in the writable upper layer (prefix_path). If we are still
					// rooted at the upper layer and a shared read-only template
					// (libexec_path) is configured, retry the SAME guest-relative
					// path against the template. The guest-relative suffix is
					// everything past current_root_len; we swap only the host root
					// prefix so the rest of the resolver is layer-agnostic.
					//
					// Suppressed when the parent upper directory is opaque (lower
					// namesake not merged). (Whiteouts already returned ENOENT above.)
					bool eunion_opaque_parent = false;
					if (status == -LINUX_ENOENT
						&& libexec_path_len > 0
						&& ctxt->current_root_len == prefix_path_len
						&& strncmp(ctxt->current_path, prefix_path, prefix_path_len) == 0)
					{
						// parent upper dir = current_path with the last component
						// (and its leading slash) stripped.
						char parent[4096];
						int plen = prevlen - 1; // drop the '/' before the component
						if (plen <= prefix_path_len)
							plen = prefix_path_len; // parent is the upper root itself
						memcpy(parent, ctxt->current_path, plen);
						parent[plen] = '\0';
						if (plen > prefix_path_len && eunion_has_marker(parent, EUNION_OPAQUE_XATTR))
							eunion_opaque_parent = true;
					}

					if (status == -LINUX_ENOENT
						&& !eunion_opaque_parent
						&& libexec_path_len > 0
						&& ctxt->current_root_len == prefix_path_len
						&& strncmp(ctxt->current_path, prefix_path, prefix_path_len) == 0)
					{
						char relbuf[4096];
						const int rellen = ctxt->current_path_len - prefix_path_len;
						if (libexec_path_len + rellen + 1 <= (int)sizeof(ctxt->current_path))
						{
							// stash the guest-relative suffix, rebuild under libexec
							memcpy(relbuf, ctxt->current_path + prefix_path_len, rellen);
							relbuf[rellen] = '\0';

							memcpy(ctxt->current_path, libexec_path, libexec_path_len);
							memcpy(ctxt->current_path + libexec_path_len, relbuf, rellen + 1);
							ctxt->current_path_len = libexec_path_len + rellen;

							#if defined(__NR_lstat)
								int lstatus = LINUX_SYSCALL(__NR_lstat, ctxt->current_path, &st);
							#else
								#if __NR_newfstatat
									int lstatus = LINUX_SYSCALL(__NR_newfstatat, LINUX_AT_FDCWD, ctxt->current_path, &st, LINUX_AT_SYMLINK_NOFOLLOW);
								#else
									int lstatus = LINUX_SYSCALL(__NR_fstatat64, LINUX_AT_FDCWD, ctxt->current_path, &st, LINUX_AT_SYMLINK_NOFOLLOW);
								#endif
							#endif

							if (lstatus == 0 || lstatus != -LINUX_ENOENT)
							{
								// Found in (or definitively errored against) the
								// lower layer: commit the switch to the template
								// root and adopt the lower-layer stat result.
								ctxt->current_root = libexec_path;
								ctxt->current_root_len = libexec_path_len;
								status = lstatus;
							}
							else
							{
								// Not in lower layer either: restore the upper-layer
								// path so the case-insensitive search below runs
								// against prefix_path as it did originally.
								memcpy(ctxt->current_path, prefix_path, prefix_path_len);
								memcpy(ctxt->current_path + prefix_path_len, relbuf, rellen + 1);
								ctxt->current_path_len = prefix_path_len + rellen;
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
					if (strncasecmp_l(ctxt->current_path + ctxt->current_root_len, EXIT_PATH, sizeof(EXIT_PATH) - 1, LC_C_LOCALE) == 0)
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
