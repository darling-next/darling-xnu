#ifndef _EUNION_REMOVE_H
#define _EUNION_REMOVE_H

enum eunion_resolved_presence {
	EUNION_PRESENCE_ABSENT = 0,
	EUNION_PRESENCE_LOWER_ONLY,
	EUNION_PRESENCE_UPPER_ONLY,
	EUNION_PRESENCE_MERGED,
	EUNION_PRESENCE_WHITEOUTED,
	EUNION_PRESENCE_OPAQUE_DIRECTORY,
	EUNION_PRESENCE_INVALID,
};

enum eunion_operation_intent {
	EUNION_INTENT_LOOKUP = 0,
	EUNION_INTENT_READ,
	EUNION_INTENT_CREATE,
	EUNION_INTENT_METADATA,
	EUNION_INTENT_TRUNCATE,
	EUNION_INTENT_REMOVE_FILE,
	EUNION_INTENT_REMOVE_DIRECTORY,
	EUNION_INTENT_LINK,
	EUNION_INTENT_SYMLINK,
	EUNION_INTENT_BIND_SOCKET,
	EUNION_INTENT_RENAME,
};

enum eunion_node_kind {
	EUNION_NODE_NONE = 0,
	EUNION_NODE_REGULAR,
	EUNION_NODE_DIRECTORY,
	EUNION_NODE_SYMLINK,
	EUNION_NODE_OTHER,
	EUNION_NODE_INVALID,
};

enum eunion_ancestor_visibility {
	EUNION_ANCESTORS_VISIBLE = 0,
	EUNION_ANCESTOR_OPAQUE,
	EUNION_ANCESTORS_INVALID,
};

enum eunion_directory_view {
	EUNION_DIRECTORY_NOT_APPLICABLE = 0,
	EUNION_DIRECTORY_EMPTY,
	EUNION_DIRECTORY_NONEMPTY,
	EUNION_DIRECTORY_INVALID,
};

enum eunion_remove_action {
	EUNION_REMOVE_REJECT = 0,
	EUNION_REMOVE_UPPER,
	EUNION_REMOVE_PUBLISH_WHITEOUT,
	EUNION_REMOVE_UPPER_AND_PUBLISH_WHITEOUT,
	EUNION_REMOVE_OPAQUE_DIRECTORY,
};

struct eunion_resolved_remove_state {
	enum eunion_resolved_presence presence;
	enum eunion_node_kind visible_kind;
	enum eunion_ancestor_visibility ancestor_visibility;
	enum eunion_directory_view directory_view;
};

struct eunion_remove_request {
	enum eunion_operation_intent intent;
	struct eunion_resolved_remove_state state;
};

struct eunion_remove_plan {
	enum eunion_remove_action action;
	int error;
};

// Pure, exhaustive remove policy. The caller must reject every nonzero error
// before entering the fd-relative mutation lifecycle.
struct eunion_remove_plan eunion_plan_remove(
	struct eunion_remove_request request);

#endif
