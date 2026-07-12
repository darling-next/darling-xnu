#ifndef _EUNION_RESOLVER_H
#define _EUNION_RESOLVER_H

#include <stddef.h>

#define EUNION_RESOLVER_PATH_MAX 4096

enum eunion_resolver_layer {
	EUNION_RESOLVER_UPPER,
	EUNION_RESOLVER_LOWER,
	EUNION_RESOLVER_WHITEOUT,
	EUNION_RESOLVER_MISSING,
	EUNION_RESOLVER_ERROR,
};

// Filesystem callbacks return zero for a present path, `missing_status` when
// absent, and a negative domain error for every other failure. Marker callbacks
// return one when present, zero when absent, or a negative domain error.
struct eunion_resolver_ops {
	int (*path_status)(void* context, const char* host_path);
	int (*marker_status)(void* context, const char* host_path, const char* marker);
};

struct eunion_resolver {
	const char* upper_root;
	const char* lower_root;
	const char* whiteout_marker;
	const char* opaque_marker;
	int missing_status;
	void* context;
	struct eunion_resolver_ops ops;
};

struct eunion_resolver_result {
	enum eunion_resolver_layer layer;
	int error;
	char host_path[EUNION_RESOLVER_PATH_MAX];
};

// Resolve one absolute guest path component-wise. The caller supplies the
// current guest prefix (for example, /System or /System/Library) and keeps
// walking after an upper/lower result. Upper wins; whiteout is distinct from a
// missing path so callers can stop before case-fold lookup; an opaque parent
// hides lower; non-absence filesystem errors are returned without fallback.
int eunion_resolve_path(const struct eunion_resolver* resolver,
	const char* guest_path, struct eunion_resolver_result* result);

// Convert a host path rooted in either union layer back to its guest path. If
// roots are nested, the longest matching root wins so a lower path is never
// mistaken for a path inside the upper layer. Returns zero on success, one when
// the host path is outside both roots, or -1 for invalid/oversized input.
int eunion_guest_path_from_host(const struct eunion_resolver* resolver,
	const char* host_path, char* guest_path, size_t guest_path_cap);

#endif
