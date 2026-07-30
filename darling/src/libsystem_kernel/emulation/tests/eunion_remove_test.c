#include <linux_premigration/eunion_remove.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

static int checks;

static void require(int condition, const char* message)
{
	++checks;
	if (!condition)
	{
		fprintf(stderr, "eunion_remove_test: %s\n", message);
		exit(1);
	}
}

static void expect_action(enum eunion_operation_intent intent,
	enum eunion_resolved_presence presence, enum eunion_node_kind visible_kind,
	enum eunion_remove_action expected_action, int expected_error)
{
	struct eunion_remove_plan result = eunion_plan_remove(
		(struct eunion_remove_request) {
			.intent = intent,
			.state = {
				.presence = presence,
				.visible_kind = visible_kind,
				.ancestor_visibility = EUNION_ANCESTORS_VISIBLE,
				.directory_view = visible_kind == EUNION_NODE_DIRECTORY
					? EUNION_DIRECTORY_EMPTY
					: EUNION_DIRECTORY_NOT_APPLICABLE,
			},
		}
	);

	require(result.action == expected_action, "unexpected planner action");
	require(result.error == expected_error, "unexpected planner errno");
}

int main(void)
{
	const enum eunion_resolved_presence presences[] = {
		EUNION_PRESENCE_ABSENT,
		EUNION_PRESENCE_LOWER_ONLY,
		EUNION_PRESENCE_UPPER_ONLY,
		EUNION_PRESENCE_MERGED,
		EUNION_PRESENCE_WHITEOUTED,
		EUNION_PRESENCE_OPAQUE_DIRECTORY,
		EUNION_PRESENCE_INVALID,
	};
	const enum eunion_remove_action file_actions[] = {
		EUNION_REMOVE_REJECT,
		EUNION_REMOVE_PUBLISH_WHITEOUT,
		EUNION_REMOVE_UPPER,
		EUNION_REMOVE_UPPER_AND_PUBLISH_WHITEOUT,
		EUNION_REMOVE_REJECT,
		EUNION_REMOVE_REJECT,
		EUNION_REMOVE_REJECT,
	};
	const enum eunion_remove_action directory_actions[] = {
		EUNION_REMOVE_REJECT,
		EUNION_REMOVE_PUBLISH_WHITEOUT,
		EUNION_REMOVE_UPPER,
		EUNION_REMOVE_UPPER_AND_PUBLISH_WHITEOUT,
		EUNION_REMOVE_REJECT,
		EUNION_REMOVE_OPAQUE_DIRECTORY,
		EUNION_REMOVE_REJECT,
	};
	const int file_errors[] = {
		-ENOENT, 0, 0, 0, -ENOENT, -EISDIR, -EIO,
	};
	const int directory_errors[] = {
		-ENOENT, 0, 0, 0, -ENOENT, 0, -EIO,
	};

	for (size_t index = 0; index < sizeof(presences) / sizeof(presences[0]); ++index)
	{
		enum eunion_node_kind file_kind = EUNION_NODE_REGULAR;
		enum eunion_node_kind directory_kind = EUNION_NODE_DIRECTORY;

		if (presences[index] == EUNION_PRESENCE_ABSENT ||
			presences[index] == EUNION_PRESENCE_WHITEOUTED ||
			presences[index] == EUNION_PRESENCE_INVALID)
		{
			file_kind = EUNION_NODE_NONE;
			directory_kind = EUNION_NODE_NONE;
		}
		else if (presences[index] == EUNION_PRESENCE_OPAQUE_DIRECTORY)
		{
			file_kind = EUNION_NODE_DIRECTORY;
		}
		expect_action(EUNION_INTENT_REMOVE_FILE, presences[index], file_kind,
			file_actions[index], file_errors[index]);
		expect_action(EUNION_INTENT_REMOVE_DIRECTORY, presences[index],
			directory_kind, directory_actions[index], directory_errors[index]);
	}

	expect_action(EUNION_INTENT_REMOVE_FILE, EUNION_PRESENCE_LOWER_ONLY,
		EUNION_NODE_DIRECTORY, EUNION_REMOVE_REJECT, -EISDIR);
	expect_action(EUNION_INTENT_REMOVE_DIRECTORY, EUNION_PRESENCE_LOWER_ONLY,
		EUNION_NODE_REGULAR, EUNION_REMOVE_REJECT, -ENOTDIR);
	expect_action(EUNION_INTENT_REMOVE_FILE, EUNION_PRESENCE_UPPER_ONLY,
		EUNION_NODE_DIRECTORY, EUNION_REMOVE_REJECT, -EISDIR);
	expect_action(EUNION_INTENT_REMOVE_DIRECTORY, EUNION_PRESENCE_MERGED,
		EUNION_NODE_SYMLINK, EUNION_REMOVE_REJECT, -ENOTDIR);

	{
		struct eunion_remove_plan result = eunion_plan_remove(
			(struct eunion_remove_request) {
				.intent = EUNION_INTENT_REMOVE_DIRECTORY,
				.state = {
					.presence = EUNION_PRESENCE_MERGED,
					.visible_kind = EUNION_NODE_DIRECTORY,
					.ancestor_visibility = EUNION_ANCESTORS_VISIBLE,
					.directory_view = EUNION_DIRECTORY_NONEMPTY,
				},
			});
		require(result.action == EUNION_REMOVE_REJECT,
			"non-empty union directory rejected");
		require(result.error == -ENOTEMPTY,
			"non-empty union directory reports ENOTEMPTY");
	}
	{
		struct eunion_remove_plan result = eunion_plan_remove(
			(struct eunion_remove_request) {
				.intent = EUNION_INTENT_REMOVE_FILE,
				.state = {
					.presence = EUNION_PRESENCE_LOWER_ONLY,
					.visible_kind = EUNION_NODE_REGULAR,
					.ancestor_visibility = EUNION_ANCESTOR_OPAQUE,
					.directory_view = EUNION_DIRECTORY_NOT_APPLICABLE,
				},
			});
		require(result.action == EUNION_REMOVE_REJECT,
			"opaque ancestor cannot expose lower-only target");
		require(result.error == -EIO,
			"impossible opaque-ancestor state fails closed");
	}

	expect_action((enum eunion_operation_intent)999,
		EUNION_PRESENCE_LOWER_ONLY, EUNION_NODE_REGULAR,
		EUNION_REMOVE_REJECT, -EOPNOTSUPP);
	expect_action(EUNION_INTENT_REMOVE_FILE,
		(enum eunion_resolved_presence)999, EUNION_NODE_REGULAR,
		EUNION_REMOVE_REJECT, -EIO);
	expect_action(EUNION_INTENT_REMOVE_FILE, EUNION_PRESENCE_ABSENT,
		EUNION_NODE_REGULAR, EUNION_REMOVE_REJECT, -EIO);
	expect_action(EUNION_INTENT_REMOVE_FILE, EUNION_PRESENCE_WHITEOUTED,
		EUNION_NODE_REGULAR, EUNION_REMOVE_REJECT, -EIO);
	expect_action(EUNION_INTENT_REMOVE_DIRECTORY,
		EUNION_PRESENCE_OPAQUE_DIRECTORY, EUNION_NODE_REGULAR,
		EUNION_REMOVE_REJECT, -EIO);
	expect_action(EUNION_INTENT_REMOVE_FILE, EUNION_PRESENCE_MERGED,
		EUNION_NODE_NONE, EUNION_REMOVE_REJECT, -EIO);

	printf("EUNION_REMOVE_PLANNER_OK checks=%d\n", checks);
	return 0;
}
