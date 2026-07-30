# E-UNION sidecar state and recovery v1

## In-memory owning transaction

The mutation capability is fixed-size C storage with no heap, vtable, or
dynamic dispatch. It owns a validated sidecar view, one phase, one operation
tag, and an exhaustive operation-specific intent union. Owner-address and
phase checks reject direct assignment, reopen and use-after-release.

Common acquisition/release transitions are:

```text
EMPTY -> RESOLVED -> LOCKED
RESOLVED|LOCKED -> RELEASED
DURABLE|ROLLED_BACK|FORWARD_RECOVERY|RECOVERY_DELEGATED -> RELEASED
```

Remove is logical-first:

```text
LOCKED -> PREPARED -> LOGICALLY_PUBLISHED -> BACKING_COMMITTED -> DURABLE
LOGICALLY_PUBLISHED -> ROLLED_BACK -> DURABLE
BACKING_COMMITTED -> FORWARD_RECOVERY -> DURABLE
```

Create, copy-up and rename are backing-first:

```text
LOCKED -> PREPARED -> BACKING_COMMITTED -> LOGICALLY_PUBLISHED -> DURABLE
PREPARED|BACKING_COMMITTED|LOGICALLY_PUBLISHED
  -> RECOVERY_DELEGATED -> RELEASED
```

Recursive materialization of an already-present merged directory retains one
root `COPY_UP` journal. Each lower-only child is built completely in private
staging and atomically published while the exclusive lock prevents guest
lookups. A crash may leave a semantically equivalent prefix of materialized
children; the root journal deterministically resumes the walk before it is
removed. This is why a backing-first `PREPARED` state may delegate recovery.

Persistent recovery, not a guessed boolean combination, resolves delegated
errors and interrupts. The primary error is restored after cleanup.

Legal operation tags are `REMOVE`, `CREATE`, `RENAME`, `SET_OPAQUE`,
`CLEAR_WHITEOUT`, `COPY_UP`, and `PREFIX_RECREATE`. Production transitions are
centralized and have no test-instrumentation branch.

## Persistent transaction

One `journal-v1` is possible under the persistent exclusive lock. It includes:

- magic, schema, exact size, checksum, transaction ID and sidecar UUID;
- operation tag and durable phase;
- old/new canonical guest paths;
- expected backing identities;
- old/new record generations and hashes;
- exact staging names.

Durable phases are:

```text
PREPARED
LOGICALLY_PUBLISHED
BACKING_COMMITTED
DURABLE
```

Every phase update is an atomic record replacement followed by parent fsync.
No journal is the only quiescent state.

## Exhaustive recovery model

Recovery is a pure exhaustive function of `(operation, journal phase, stable
sidecar state, backing state)`. Unlisted and mixed combinations are
corruption.

| Journal | Sidecar | Backing | Result |
| --- | --- | --- | --- |
| absent | old/old or new/new | matching | quiescent |
| absent | mixed/corrupt | any | fail closed |
| `PREPARED` | old | old | discard staging |
| `PREPARED` | old | new | forward only for a backing-first operation whose recorded identity proves the syscall |
| `PREPARED` | new | old | roll back logical state |
| `PREPARED` | new | new | advance and forward-recover |
| `LOGICALLY_PUBLISHED` | new | old | roll back |
| `LOGICALLY_PUBLISHED` | new | new | forward-recover |
| `LOGICALLY_PUBLISHED` | old | new | re-publish exact new state, then forward |
| `BACKING_COMMITTED` | new | new | finish durability and cleanup |
| `BACKING_COMMITTED` | old | new | re-publish exact new state, then finish |
| `BACKING_COMMITTED` | any | old/replacement | fail closed |
| `DURABLE` | new | new | idempotent cleanup |
| `DURABLE` | old/mixed | any | fail closed |

Rename evaluates source and destination products. Second recovery observes no
journal and is a no-op.

The executable contracts cover:

- the complete pure transition/recovery matrix;
- real subprocess SIGKILL and SIGINT after all 24 durable boundaries;
- 48 operation-boundary outcomes, including merged-tree copy-up;
- 48 EINTR/EIO syscall fault cases for remove/create/copy-up/rename;
- 24 phases crossed with six concurrent lookup/open/create/unlink/rmdir/rename
  operations;
- persistent three-process split-lock rejection;
- malformed/truncated/version/identity failures and symlink attacks.

## Prefix lifecycle state

The launcher lifecycle has a distinct durable schema-v3 journal. Its stable
states are `MISSING`, `EMPTY`, `LEGACY_OR_UNVERSIONED`, and `CURRENT_V3`;
operations are `CREATE`, `RECREATE`, and `DELETE`; phases are `PREPARED`,
`REPLACEMENT_STAGED`, `SIDECAR_PUBLISHED`, `PREFIX_PUBLISHED`, and `CLEANUP`.

The executable table covers all 90 operation/phase/stable-state decisions.
Create and recreate are interrupted by both ordinary failure and SIGINT at
each mutation phase; delete is covered at its published deletion boundaries.
All 24 real interruption fixtures must converge to a valid old/new stable
state with no stage or transaction entry.

Legacy/unversioned is never a migration source. Normal prepare returns
`PREFIX_RECREATE_REQUIRED` without mutation. Only the explicitly confirmed
recreate operation may replace it, after persistent lock, process and mount
checks. The result is a fresh sidecar-v1 prefix; no legacy record is imported.

## Durability order

Staged prefix files (`passwd`, `master.passwd`, `group`) are individually
fsynced. Nested directories are fsynced bottom-up, the staged root follows,
then sibling publication and parent fsync. Fault fixtures prove file and
directory fsync failures abort and recover without partial publication.
