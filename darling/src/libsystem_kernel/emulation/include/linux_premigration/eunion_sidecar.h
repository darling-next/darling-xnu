#ifndef _EUNION_SIDECAR_H
#define _EUNION_SIDECAR_H

#include <stddef.h>
#include <stdint.h>

#define EUNION_SIDECAR_PATH_MAX 4096
#define EUNION_SIDECAR_COMPONENT_MAX 64
#define EUNION_SIDECAR_NAME_MAX 255
#define EUNION_SIDECAR_SUFFIX ".eunion-sidecar-v1"
#define EUNION_SIDECAR_ACTIVATION_NAME "active-v1"
#define EUNION_PREFIX_RECREATE_REQUIRED_ERROR 117

enum eunion_sidecar_phase {
	EUNION_SIDECAR_PHASE_EMPTY = 0,
	EUNION_SIDECAR_PHASE_RESOLVED,
	EUNION_SIDECAR_PHASE_LOCKED,
	EUNION_SIDECAR_PHASE_PREPARED,
	EUNION_SIDECAR_PHASE_LOGICALLY_PUBLISHED,
	EUNION_SIDECAR_PHASE_BACKING_COMMITTED,
	EUNION_SIDECAR_PHASE_ROLLED_BACK,
	EUNION_SIDECAR_PHASE_FORWARD_RECOVERY,
	EUNION_SIDECAR_PHASE_RECOVERY_DELEGATED,
	EUNION_SIDECAR_PHASE_DURABLE,
	EUNION_SIDECAR_PHASE_RELEASED,
	EUNION_SIDECAR_PHASE_INVALID,
};

enum eunion_sidecar_operation {
	EUNION_SIDECAR_OPERATION_REMOVE = 0,
	EUNION_SIDECAR_OPERATION_CREATE,
	EUNION_SIDECAR_OPERATION_RENAME,
	EUNION_SIDECAR_OPERATION_SET_OPAQUE,
	EUNION_SIDECAR_OPERATION_CLEAR_WHITEOUT,
	EUNION_SIDECAR_OPERATION_COPY_UP,
	EUNION_SIDECAR_OPERATION_PREFIX_RECREATE,
	EUNION_SIDECAR_OPERATION_INVALID,
};

enum eunion_sidecar_journal_phase {
	EUNION_SIDECAR_JOURNAL_ABSENT = 0,
	EUNION_SIDECAR_JOURNAL_PREPARED,
	EUNION_SIDECAR_JOURNAL_LOGICALLY_PUBLISHED,
	EUNION_SIDECAR_JOURNAL_BACKING_COMMITTED,
	EUNION_SIDECAR_JOURNAL_DURABLE,
	EUNION_SIDECAR_JOURNAL_INVALID,
};

enum eunion_sidecar_stable_state {
	EUNION_SIDECAR_STABLE_OLD = 0,
	EUNION_SIDECAR_STABLE_NEW,
	EUNION_SIDECAR_STABLE_MIXED,
	EUNION_SIDECAR_STABLE_CORRUPT,
	EUNION_SIDECAR_STABLE_INVALID,
};

enum eunion_sidecar_backing_state {
	EUNION_SIDECAR_BACKING_OLD = 0,
	EUNION_SIDECAR_BACKING_NEW,
	EUNION_SIDECAR_BACKING_REPLACEMENT,
	EUNION_SIDECAR_BACKING_CORRUPT,
	EUNION_SIDECAR_BACKING_INVALID,
};

enum eunion_sidecar_recovery_action {
	EUNION_SIDECAR_RECOVERY_QUIESCENT = 0,
	EUNION_SIDECAR_RECOVERY_DISCARD_PREPARED,
	EUNION_SIDECAR_RECOVERY_ROLL_BACK,
	EUNION_SIDECAR_RECOVERY_FORWARD,
	EUNION_SIDECAR_RECOVERY_REPUBLISH_FORWARD,
	EUNION_SIDECAR_RECOVERY_CORRUPTION,
	EUNION_SIDECAR_RECOVERY_INVALID,
};

enum eunion_sidecar_access {
	EUNION_SIDECAR_ACCESS_SHARED = 0,
	EUNION_SIDECAR_ACCESS_EXCLUSIVE,
	EUNION_SIDECAR_ACCESS_INVALID,
};

enum eunion_sidecar_record_kind {
	EUNION_SIDECAR_RECORD_NONE = 0,
	EUNION_SIDECAR_RECORD_INDEX,
	EUNION_SIDECAR_RECORD_WHITEOUT,
	EUNION_SIDECAR_RECORD_OPAQUE,
	EUNION_SIDECAR_RECORD_INVALID,
};

enum eunion_prefix_format_verdict {
	EUNION_PREFIX_FORMAT_VALID = 0,
	EUNION_PREFIX_FORMAT_UNINITIALIZED,
	EUNION_PREFIX_RECREATE_REQUIRED,
	EUNION_PREFIX_FORMAT_CORRUPT,
	EUNION_PREFIX_FORMAT_INVALID,
};

struct eunion_prefix_format_inspection {
	enum eunion_prefix_format_verdict verdict;
	uint32_t format_version;
	uint64_t uuid[2];
};

struct eunion_sidecar_runtime {
	const char* upper_root;
	const char* lower_root;
	const char* sidecar_root;
	int anchored;
	int upper_descriptor;
	int lower_descriptor;
	int sidecar_descriptor;
};

int eunion_sidecar_runtime_anchor(struct eunion_sidecar_runtime* runtime,
	int upper_descriptor, const char* lower_root, const char* sidecar_root);
int eunion_sidecar_runtime_release(struct eunion_sidecar_runtime* runtime);
int eunion_sidecar_prefix_state_v3_valid(
	const struct eunion_sidecar_runtime* runtime);

struct eunion_sidecar_identity {
	uint32_t present;
	uint32_t mode;
	uint64_t device;
	uint64_t inode;
	int64_t ctime_seconds;
	int64_t ctime_nanoseconds;
};

struct eunion_sidecar_lookup {
	enum eunion_sidecar_record_kind kind;
	uint64_t generation;
	struct eunion_sidecar_identity upper;
	struct eunion_sidecar_identity lower;
};

enum eunion_sidecar_view_phase {
	EUNION_SIDECAR_VIEW_EMPTY = 0,
	EUNION_SIDECAR_VIEW_OPEN,
	EUNION_SIDECAR_VIEW_RELEASED,
};

struct eunion_sidecar_view_storage {
	uintptr_t owner;
	enum eunion_sidecar_view_phase phase;
	enum eunion_sidecar_access access;
	int upper_descriptor;
	int lower_descriptor;
	int sidecar_descriptor;
	int lock_descriptor;
	int tree_descriptor;
	int root_descriptor;
	uint64_t uuid[2];
	uint64_t key[2];
	uint64_t root_generation;
};

// Array ownership is assignment-resistant in C. Runtime owner-address and phase
// checks remain authoritative; a copied array payload fails validation.
typedef struct eunion_sidecar_view_storage eunion_sidecar_view[1];

// Pure transition/recovery policy. Side effects belong to the owning
// capability implementation; all unlisted transitions fail closed.
int eunion_sidecar_transition_allowed(enum eunion_sidecar_phase from,
	enum eunion_sidecar_phase to);
int eunion_sidecar_operation_transition_allowed(
	enum eunion_sidecar_operation operation,
	enum eunion_sidecar_phase from, enum eunion_sidecar_phase to);
enum eunion_sidecar_recovery_action eunion_sidecar_plan_recovery(
	enum eunion_sidecar_journal_phase journal,
	enum eunion_sidecar_stable_state stable,
	enum eunion_sidecar_backing_state backing);
enum eunion_sidecar_recovery_action eunion_sidecar_plan_operation_recovery(
	enum eunion_sidecar_operation operation,
	enum eunion_sidecar_journal_phase journal,
	enum eunion_sidecar_stable_state stable,
	enum eunion_sidecar_backing_state backing);

// Provisioning boundary. The three root directories must already exist as
// non-symlink directories. The external sidecar root must be empty; the upper
// root may already contain the freshly initialized prefix payload and is never
// mutated here. This publishes activation only after the sidecar is durable.
int eunion_sidecar_initialize(const struct eunion_sidecar_runtime* runtime);
int eunion_sidecar_inspect_prefix(
	const struct eunion_sidecar_runtime* runtime,
	struct eunion_prefix_format_inspection* inspection);

// Production views require an anchored runtime and duplicate only retained
// descriptors. The unanchored pathname form exists solely in TEST fixtures.
// Shared views reject a pending journal; exclusive recovery owns it.
int eunion_sidecar_view_open(eunion_sidecar_view view,
	const struct eunion_sidecar_runtime* runtime,
	enum eunion_sidecar_access access);
int eunion_sidecar_view_close(eunion_sidecar_view view);
int eunion_sidecar_lookup_path(eunion_sidecar_view view,
	const char* guest_path, struct eunion_sidecar_lookup* result);
int eunion_sidecar_publish_whiteout(eunion_sidecar_view view,
	const char* guest_path);
int eunion_sidecar_clear_whiteout(eunion_sidecar_view view,
	const char* guest_path);
int eunion_sidecar_publish_opaque(eunion_sidecar_view view,
	const char* guest_path);
int eunion_sidecar_remove_path(const struct eunion_sidecar_runtime* runtime,
	const char* guest_path, int remove_directory);
int eunion_sidecar_open_create(const struct eunion_sidecar_runtime* runtime,
	const char* guest_path, int flags, unsigned int mode);
int eunion_sidecar_mkdir_create(const struct eunion_sidecar_runtime* runtime,
	const char* guest_path, unsigned int mode);
int eunion_sidecar_symlink_create(
	const struct eunion_sidecar_runtime* runtime, const char* target,
	const char* guest_path);
int eunion_sidecar_mknod_create(
	const struct eunion_sidecar_runtime* runtime, const char* guest_path,
	unsigned int mode, unsigned int device);
int eunion_sidecar_link_create(
	const struct eunion_sidecar_runtime* runtime,
	const char* source_guest_path, const char* destination_guest_path,
	int flags);
int eunion_sidecar_socket_bind_create(
	const struct eunion_sidecar_runtime* runtime,
	const char* guest_path, int socket_descriptor);
int eunion_sidecar_copy_up(const struct eunion_sidecar_runtime* runtime,
	const char* guest_path);
int eunion_sidecar_copy_up_tree(const struct eunion_sidecar_runtime* runtime,
	const char* guest_path);
int eunion_sidecar_rename_path(const struct eunion_sidecar_runtime* runtime,
	const char* old_guest_path, const char* new_guest_path);

#ifdef TEST
enum eunion_sidecar_test_checkpoint {
	EUNION_SIDECAR_TEST_INITIALIZE_READY = 1,
	EUNION_SIDECAR_TEST_INITIALIZE_LOCKED,
	EUNION_SIDECAR_TEST_INITIALIZE_FORMAT,
	EUNION_SIDECAR_TEST_INITIALIZE_TREE,
	EUNION_SIDECAR_TEST_INITIALIZE_STAGING,
	EUNION_SIDECAR_TEST_INITIALIZE_ACTIVATED,
	EUNION_SIDECAR_TEST_RESOLVED,
	EUNION_SIDECAR_TEST_JOURNAL_PREPARED,
	EUNION_SIDECAR_TEST_LOGICALLY_PUBLISHED,
	EUNION_SIDECAR_TEST_PRE_BACKING,
	EUNION_SIDECAR_TEST_POST_BACKING_PRE_JOURNAL,
	EUNION_SIDECAR_TEST_BACKING_COMMITTED,
	EUNION_SIDECAR_TEST_DURABLE,
};
extern uint64_t eunion_test_sidecar_key[2];
extern uint64_t eunion_test_sidecar_uuid[2];
extern void (*eunion_test_sidecar_checkpoint_hook)(
	enum eunion_sidecar_test_checkpoint checkpoint,
	const char* guest_path);
extern long eunion_test_sidecar_fail_syscall;
extern unsigned int eunion_test_sidecar_fail_after;
extern int eunion_test_sidecar_fail_errno;
enum eunion_sidecar_test_corruption {
	EUNION_SIDECAR_TEST_CORRUPT_TRUNCATE = 1,
	EUNION_SIDECAR_TEST_CORRUPT_VERSION,
	EUNION_SIDECAR_TEST_CORRUPT_CHECKSUM,
};
int eunion_sidecar_test_transaction_guards(
	const struct eunion_sidecar_runtime* runtime);
int eunion_sidecar_test_corrupt_record(
	const struct eunion_sidecar_runtime* runtime,
	const char* guest_path,
	enum eunion_sidecar_test_corruption corruption);
#endif

#endif
