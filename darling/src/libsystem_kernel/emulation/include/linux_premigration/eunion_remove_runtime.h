#ifndef _EUNION_REMOVE_RUNTIME_H
#define _EUNION_REMOVE_RUNTIME_H

#include <linux_premigration/eunion_remove.h>

struct eunion_remove_runtime {
	const char* upper_root;
	const char* lower_root;
	const char* whiteout_marker;
};

// The guest path is canonical and absolute. This function is the anchoring
// boundary: it opens both roots component-wise, and no raw path or unvalidated
// descriptor crosses back to the caller.
int eunion_remove_path(const struct eunion_remove_runtime* runtime,
	const char* guest_path, enum eunion_operation_intent intent);

enum eunion_remove_test_checkpoint {
	EUNION_REMOVE_TEST_REVALIDATED = 1,
	EUNION_REMOVE_TEST_PREPARED,
	EUNION_REMOVE_TEST_APPLIED,
	EUNION_REMOVE_TEST_PRE_COMMIT,
};

#ifdef TEST
extern int eunion_test_remove_fail_checkpoint;
extern int eunion_test_remove_interrupt_checkpoint;
extern int eunion_test_remove_fail_fsync_ordinal;
extern int eunion_test_remove_fsync_count;
extern void (*eunion_test_remove_checkpoint_hook)(
	enum eunion_remove_test_checkpoint checkpoint,
	const char* guest_path
);
int eunion_test_remove_capability_reopen(
	const struct eunion_remove_runtime* runtime, const char* guest_path,
	enum eunion_operation_intent intent);
#endif

#endif
