#include <linux_premigration/eunion_remove.h>

#include <errno.h>

static struct eunion_remove_plan reject(int error)
{
	return (struct eunion_remove_plan) {
		.action = EUNION_REMOVE_REJECT,
		.error = error,
	};
}

static int valid_visible_kind(enum eunion_node_kind kind)
{
	switch (kind)
	{
		case EUNION_NODE_REGULAR:
		case EUNION_NODE_DIRECTORY:
		case EUNION_NODE_SYMLINK:
		case EUNION_NODE_OTHER:
			return 1;
		case EUNION_NODE_NONE:
		case EUNION_NODE_INVALID:
		default:
			return 0;
	}
}

struct eunion_remove_plan eunion_plan_remove(
	struct eunion_remove_request request)
{
	switch (request.intent)
	{
		case EUNION_INTENT_REMOVE_FILE:
		case EUNION_INTENT_REMOVE_DIRECTORY:
			break;
		case EUNION_INTENT_LOOKUP:
		case EUNION_INTENT_READ:
		case EUNION_INTENT_CREATE:
		case EUNION_INTENT_METADATA:
		case EUNION_INTENT_TRUNCATE:
		case EUNION_INTENT_LINK:
		case EUNION_INTENT_SYMLINK:
		case EUNION_INTENT_BIND_SOCKET:
		case EUNION_INTENT_RENAME:
		default:
			return reject(-EOPNOTSUPP);
	}

	switch (request.state.presence)
	{
		case EUNION_PRESENCE_ABSENT:
		case EUNION_PRESENCE_WHITEOUTED:
			if (request.state.visible_kind != EUNION_NODE_NONE)
				return reject(-EIO);
			return reject(-ENOENT);
		case EUNION_PRESENCE_INVALID:
			if (request.state.visible_kind != EUNION_NODE_NONE)
				return reject(-EIO);
			return reject(-EIO);
		case EUNION_PRESENCE_OPAQUE_DIRECTORY:
			if (request.state.visible_kind != EUNION_NODE_DIRECTORY)
				return reject(-EIO);
			break;
		case EUNION_PRESENCE_LOWER_ONLY:
		case EUNION_PRESENCE_UPPER_ONLY:
		case EUNION_PRESENCE_MERGED:
			if (!valid_visible_kind(request.state.visible_kind))
				return reject(-EIO);
			break;
		default:
			return reject(-EIO);
	}

	switch (request.state.ancestor_visibility)
	{
		case EUNION_ANCESTORS_VISIBLE:
			break;
		case EUNION_ANCESTOR_OPAQUE:
			if (request.state.presence == EUNION_PRESENCE_LOWER_ONLY ||
				request.state.presence == EUNION_PRESENCE_MERGED)
				return reject(-EIO);
			break;
		case EUNION_ANCESTORS_INVALID:
		default:
			return reject(-EIO);
	}

	if (request.state.visible_kind == EUNION_NODE_DIRECTORY)
	{
		if (request.state.directory_view != EUNION_DIRECTORY_EMPTY &&
			request.state.directory_view != EUNION_DIRECTORY_NONEMPTY)
			return reject(-EIO);
	}
	else if (request.state.directory_view !=
		EUNION_DIRECTORY_NOT_APPLICABLE)
		return reject(-EIO);

	if (request.intent == EUNION_INTENT_REMOVE_FILE &&
		request.state.visible_kind == EUNION_NODE_DIRECTORY)
		return reject(-EISDIR);
	if (request.intent == EUNION_INTENT_REMOVE_DIRECTORY &&
		request.state.visible_kind != EUNION_NODE_DIRECTORY)
		return reject(-ENOTDIR);
	if (request.intent == EUNION_INTENT_REMOVE_DIRECTORY &&
		request.state.directory_view == EUNION_DIRECTORY_NONEMPTY)
		return reject(-ENOTEMPTY);

	switch (request.state.presence)
	{
		case EUNION_PRESENCE_LOWER_ONLY:
			return (struct eunion_remove_plan) {
				.action = EUNION_REMOVE_PUBLISH_WHITEOUT,
				.error = 0,
			};
		case EUNION_PRESENCE_UPPER_ONLY:
			return (struct eunion_remove_plan) {
				.action = EUNION_REMOVE_UPPER,
				.error = 0,
			};
		case EUNION_PRESENCE_MERGED:
			return (struct eunion_remove_plan) {
				.action = EUNION_REMOVE_UPPER_AND_PUBLISH_WHITEOUT,
				.error = 0,
			};
		case EUNION_PRESENCE_OPAQUE_DIRECTORY:
			return (struct eunion_remove_plan) {
				.action = EUNION_REMOVE_OPAQUE_DIRECTORY,
				.error = 0,
			};
		case EUNION_PRESENCE_ABSENT:
		case EUNION_PRESENCE_WHITEOUTED:
		case EUNION_PRESENCE_INVALID:
		default:
			return reject(-EIO);
	}
}
