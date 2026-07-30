#include <linux_premigration/eunion_sidecar.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

static int checks;

static void require(int condition, const char* message)
{
	++checks;
	if (!condition) {
		fprintf(stderr, "eunion_sidecar_state_test: %s\n", message);
		exit(1);
	}
}

static void test_transitions(void)
{
	static const struct {
		enum eunion_sidecar_phase from;
		enum eunion_sidecar_phase to;
	} allowed[] = {
		{EUNION_SIDECAR_PHASE_EMPTY, EUNION_SIDECAR_PHASE_RESOLVED},
		{EUNION_SIDECAR_PHASE_RESOLVED, EUNION_SIDECAR_PHASE_LOCKED},
		{EUNION_SIDECAR_PHASE_RESOLVED, EUNION_SIDECAR_PHASE_RELEASED},
		{EUNION_SIDECAR_PHASE_LOCKED, EUNION_SIDECAR_PHASE_PREPARED},
		{EUNION_SIDECAR_PHASE_LOCKED, EUNION_SIDECAR_PHASE_RELEASED},
		{EUNION_SIDECAR_PHASE_PREPARED,
			EUNION_SIDECAR_PHASE_LOGICALLY_PUBLISHED},
		{EUNION_SIDECAR_PHASE_PREPARED, EUNION_SIDECAR_PHASE_RELEASED},
		{EUNION_SIDECAR_PHASE_LOGICALLY_PUBLISHED,
			EUNION_SIDECAR_PHASE_BACKING_COMMITTED},
		{EUNION_SIDECAR_PHASE_LOGICALLY_PUBLISHED,
			EUNION_SIDECAR_PHASE_ROLLED_BACK},
		{EUNION_SIDECAR_PHASE_LOGICALLY_PUBLISHED,
			EUNION_SIDECAR_PHASE_RECOVERY_DELEGATED},
		{EUNION_SIDECAR_PHASE_BACKING_COMMITTED,
			EUNION_SIDECAR_PHASE_DURABLE},
		{EUNION_SIDECAR_PHASE_BACKING_COMMITTED,
			EUNION_SIDECAR_PHASE_FORWARD_RECOVERY},
		{EUNION_SIDECAR_PHASE_BACKING_COMMITTED,
			EUNION_SIDECAR_PHASE_RECOVERY_DELEGATED},
		{EUNION_SIDECAR_PHASE_ROLLED_BACK,
			EUNION_SIDECAR_PHASE_DURABLE},
		{EUNION_SIDECAR_PHASE_FORWARD_RECOVERY,
			EUNION_SIDECAR_PHASE_DURABLE},
		{EUNION_SIDECAR_PHASE_RECOVERY_DELEGATED,
			EUNION_SIDECAR_PHASE_RELEASED},
		{EUNION_SIDECAR_PHASE_DURABLE, EUNION_SIDECAR_PHASE_RELEASED},
	};

	for (int from = EUNION_SIDECAR_PHASE_EMPTY;
		from < EUNION_SIDECAR_PHASE_INVALID; ++from) {
		for (int to = EUNION_SIDECAR_PHASE_EMPTY;
			to < EUNION_SIDECAR_PHASE_INVALID; ++to) {
			int expected = 0;
			for (unsigned int index = 0;
				index < sizeof(allowed) / sizeof(allowed[0]); ++index)
				if ((int)allowed[index].from == from &&
					(int)allowed[index].to == to)
					expected = 1;
			int result = eunion_sidecar_transition_allowed(
				(enum eunion_sidecar_phase)from,
				(enum eunion_sidecar_phase)to);
			require((result == 0) == expected,
				"transition table is exact and fail-closed");
		}
	}
	require(eunion_sidecar_transition_allowed(
		EUNION_SIDECAR_PHASE_INVALID,
		EUNION_SIDECAR_PHASE_RELEASED) == -EINVAL,
		"invalid source phase rejected");
}

static int backing_first_operation(enum eunion_sidecar_operation operation)
{
	return operation == EUNION_SIDECAR_OPERATION_CREATE ||
		operation == EUNION_SIDECAR_OPERATION_COPY_UP ||
		operation == EUNION_SIDECAR_OPERATION_RENAME ||
		operation == EUNION_SIDECAR_OPERATION_PREFIX_RECREATE;
}

static int expected_operation_transition(
	enum eunion_sidecar_operation operation,
	enum eunion_sidecar_phase from, enum eunion_sidecar_phase to)
{
	if (!backing_first_operation(operation))
		return eunion_sidecar_transition_allowed(from, to) == 0;
	switch (from) {
		case EUNION_SIDECAR_PHASE_PREPARED:
			return to == EUNION_SIDECAR_PHASE_BACKING_COMMITTED ||
				to == EUNION_SIDECAR_PHASE_RECOVERY_DELEGATED ||
				to == EUNION_SIDECAR_PHASE_RELEASED;
		case EUNION_SIDECAR_PHASE_BACKING_COMMITTED:
			return to == EUNION_SIDECAR_PHASE_LOGICALLY_PUBLISHED ||
				to == EUNION_SIDECAR_PHASE_FORWARD_RECOVERY ||
				to == EUNION_SIDECAR_PHASE_RECOVERY_DELEGATED;
		case EUNION_SIDECAR_PHASE_LOGICALLY_PUBLISHED:
			return to == EUNION_SIDECAR_PHASE_DURABLE ||
				to == EUNION_SIDECAR_PHASE_FORWARD_RECOVERY ||
				to == EUNION_SIDECAR_PHASE_RECOVERY_DELEGATED;
		default:
			return eunion_sidecar_transition_allowed(from, to) == 0;
	}
}

static void test_operation_transitions(void)
{
	for (int operation = EUNION_SIDECAR_OPERATION_REMOVE;
			operation < EUNION_SIDECAR_OPERATION_INVALID; ++operation) {
		for (int from = EUNION_SIDECAR_PHASE_EMPTY;
				from < EUNION_SIDECAR_PHASE_INVALID; ++from) {
			for (int to = EUNION_SIDECAR_PHASE_EMPTY;
					to < EUNION_SIDECAR_PHASE_INVALID; ++to) {
				int expected = expected_operation_transition(
					(enum eunion_sidecar_operation)operation,
					(enum eunion_sidecar_phase)from,
					(enum eunion_sidecar_phase)to);
				int result = eunion_sidecar_operation_transition_allowed(
					(enum eunion_sidecar_operation)operation,
					(enum eunion_sidecar_phase)from,
					(enum eunion_sidecar_phase)to);
				require((result == 0) == expected,
					"operation-specific transition table is exhaustive");
			}
		}
	}
	require(eunion_sidecar_operation_transition_allowed(
			EUNION_SIDECAR_OPERATION_INVALID,
			EUNION_SIDECAR_PHASE_EMPTY,
			EUNION_SIDECAR_PHASE_RESOLVED) == -EINVAL,
		"invalid operation transition is rejected");
}

static void test_recovery_matrix(void)
{
	int matrix = 0;
	for (int operation = EUNION_SIDECAR_OPERATION_REMOVE;
		operation < EUNION_SIDECAR_OPERATION_INVALID; ++operation) {
		for (int journal = EUNION_SIDECAR_JOURNAL_ABSENT;
			journal < EUNION_SIDECAR_JOURNAL_INVALID; ++journal) {
			for (int stable = EUNION_SIDECAR_STABLE_OLD;
				stable < EUNION_SIDECAR_STABLE_INVALID; ++stable) {
				for (int backing = EUNION_SIDECAR_BACKING_OLD;
					backing < EUNION_SIDECAR_BACKING_INVALID;
					++backing) {
					enum eunion_sidecar_recovery_action action =
						eunion_sidecar_plan_operation_recovery(
							(enum eunion_sidecar_operation)
								operation,
							(enum eunion_sidecar_journal_phase)
								journal,
							(enum eunion_sidecar_stable_state)
								stable,
							(enum eunion_sidecar_backing_state)
								backing);
					require(action >=
							EUNION_SIDECAR_RECOVERY_QUIESCENT &&
						action <
							EUNION_SIDECAR_RECOVERY_INVALID,
						"every operation x persistent combination"
						" has an explicit decision");
					++matrix;
				}
			}
		}
	}
	require(matrix == 560,
		"complete 7 x 5 x 4 x 4 operation recovery matrix");
	require(eunion_sidecar_plan_recovery(
		EUNION_SIDECAR_JOURNAL_LOGICALLY_PUBLISHED,
		EUNION_SIDECAR_STABLE_NEW,
		EUNION_SIDECAR_BACKING_OLD) ==
			EUNION_SIDECAR_RECOVERY_ROLL_BACK,
		"logical publication before backing commit rolls back");
	require(eunion_sidecar_plan_recovery(
		EUNION_SIDECAR_JOURNAL_BACKING_COMMITTED,
		EUNION_SIDECAR_STABLE_OLD,
		EUNION_SIDECAR_BACKING_NEW) ==
			EUNION_SIDECAR_RECOVERY_REPUBLISH_FORWARD,
		"irreversible backing commit forward-recovers sidecar");
	require(eunion_sidecar_plan_recovery(
		EUNION_SIDECAR_JOURNAL_ABSENT,
		EUNION_SIDECAR_STABLE_MIXED,
		EUNION_SIDECAR_BACKING_OLD) ==
			EUNION_SIDECAR_RECOVERY_CORRUPTION,
		"mixed quiescent state fails closed");
	require(eunion_sidecar_plan_operation_recovery(
		EUNION_SIDECAR_OPERATION_CREATE,
		EUNION_SIDECAR_JOURNAL_PREPARED,
		EUNION_SIDECAR_STABLE_OLD,
		EUNION_SIDECAR_BACKING_NEW) ==
			EUNION_SIDECAR_RECOVERY_REPUBLISH_FORWARD,
		"backing-first create recovers an inode committed before journal"
		" advancement");
	require(eunion_sidecar_plan_operation_recovery(
		EUNION_SIDECAR_OPERATION_RENAME,
		EUNION_SIDECAR_JOURNAL_LOGICALLY_PUBLISHED,
		EUNION_SIDECAR_STABLE_NEW,
		EUNION_SIDECAR_BACKING_OLD) ==
			EUNION_SIDECAR_RECOVERY_CORRUPTION,
		"backing-first rename rejects impossible logical-first phase");
}

int main(void)
{
	test_transitions();
	test_operation_transitions();
	test_recovery_matrix();
	printf("EUNION_SIDECAR_STATE_OK checks=%d matrix=560\n", checks);
	return 0;
}
