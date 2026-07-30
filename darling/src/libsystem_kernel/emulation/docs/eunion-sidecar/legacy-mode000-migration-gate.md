# Prefix format decision: Policy 1 recreate

## Verdict

`AUTHORIZE_POLICY_1_RECREATE`

Legacy physical whiteouts, including unreadable mode-000 parents, are not
migrated in place. The accepted product policy is a versioned format boundary:

- new prefixes are initialized directly as sidecar v1;
- legacy or unversioned prefixes return typed
  `PREFIX_RECREATE_REQUIRED` before boot and mutation;
- no subset is activated as sidecar and no physical marker is imported;
- the runtime never automatically deletes a prefix;
- recreation requires an explicit command and exact confirmation;
- no privileged migrator, live chmod, legacy fallback, or second runtime path
  is retained.

The reason remains fundamental: rootless Linux cannot enumerate a mode-000
directory via `O_PATH`, cannot move it to private storage without parent
permissions, and cannot use `open_tree` without mount authority. Temporary
chmod creates a guest-visible access window, changes ctime, and can overwrite
a concurrent chmod.

## Explicit recreate protocol

The launcher:

1. inspects the retained prefix without mutation;
2. reports `PREFIX_RECREATE_REQUIRED` for legacy/unversioned state;
3. requires `--confirm-prefix-recreate recreate-prefix`;
4. acquires and revalidates the persistent lifecycle lock;
5. rejects a live `.init.pid`, a prefix/subtree mount, a changed prefix name,
   symlink, hostile sidecar, or pending corrupt journal;
6. builds a complete fresh prefix and sidecar in private sibling stages;
7. fsyncs files and directories bottom-up;
8. atomically publishes sidecar and prefix through the versioned journal;
9. recovers by rollback or forward completion after failure/SIGINT;
10. retains the persistent lock filename and removes only transaction stages.

Normal startup never enters this destructive path. A rejected recreate leaves
legacy payload identity and bytes unchanged.

## Downgrade

Sidecar-v1 prefixes are not silently accepted by a physical-marker runtime.
Downgrade requires recreating a separate legacy prefix with a separately
reviewed old runtime. This implementation contains no reverse migration.

The historical permission-window evidence remains useful as rationale, not as
runtime input:

```text
protected_payload_read=1
ctime_preserved=0
concurrent_chmod_lost=1
```

Sidecar acceptance requires the inverse:

```text
protected_payload_read=0
ctime_preserved=1
concurrent_chmod_lost=0
```
