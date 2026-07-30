# E-UNION sidecar threat model

## Protected assets

- lower template bytes and metadata;
- guest-visible upper namespace and inode metadata;
- whiteout/opaque truth;
- transaction journal and lock identity;
- exact mapping between a record and one upper/lower path incarnation.

## Adversary

The adversary can issue concurrent guest lookup, open, create, unlink, rmdir,
rename, chmod, xattr, and readdir operations. It can choose every guest
component byte accepted by Darwin, create symlinks, race path replacement, send
`SIGINT`, and kill a mutating process after any durable boundary. It can set a
hostile umask and can preserve already-open guest FDs.

The adversary cannot modify the lower template or external sidecar by a raw
native Linux syscall outside Darling's syscall boundary. Such native escape is
already outside the vchroot security model. Every Darling path, including the
SystemRoot escape, is nevertheless required to reject the sidecar root.

## Required defenses

- Anchor upper, lower, sidecar, lock, tree, staging, and journal components
  with `O_NOFOLLOW`; reject intermediate and leaf symlinks.
- Never derive an authoritative sidecar FD from a guest-provided host path.
- Bind activation and every record to sidecar UUID, parent generation, and
  exact filesystem identities.
- Detect SipHash collisions by comparing the stored component bytes.
- Treat malformed size, checksum, version, tag, generation, or identity as
  corruption.
- Keep one persistent lock inode; verify the named inode after lock acquisition.
- Hold a shared lock for a complete read operation and an exclusive lock for a
  complete mutation/recovery.
- Never expose a half-written record: temporary object, file fsync, directory
  fsync, atomic rename, parent fsync.
- Never use guest umask to determine sidecar permissions.
- Never chmod a guest-visible inode as part of lookup or removal.
- Never let cleanup replace the primary failure or interrupt.

## Race outcomes

| Race | Required outcome |
| --- | --- |
| Guest leaf or ancestor replaced before anchoring | Resolve the new path normally or fail identity validation. |
| Replacement after anchoring and before publication | `EAGAIN`; no semantic record publication. |
| Replacement after logical publication | Exclusive sidecar lock blocks Darling lookups; journal recovery validates the exact old/new identity before rollback or forward recovery. |
| Concurrent chmod during failed mode-000 rmdir | Chmod remains authoritative; remove returns `ENOTEMPTY`; mode and ctime are not rewritten by remove. |
| Lookup while a journal exists | Recover first; never interpret journal temporary files as stable state. |
| Lock path replaced while a waiter sleeps | Named inode comparison rejects the stale acquired lock. The lock file is never intentionally removed. |
| Record hash collision | Stored component mismatch returns corruption; no second record aliases the first. |
| Recreate after inode reuse | Generation/identity mismatch fails closed; stale descendants are not inherited. |
| Rename over a sidecar subtree | One journal owns backing rename, source whiteout, destination replacement, and subtree move. |

## Explicitly rejected designs

- physical placeholder files or marker xattrs inside guest directories;
- live `fchmod` to make an unreadable directory inspectable or movable;
- `O_PATH` treated as a readable/xattr-capable FD;
- a removable lock filename;
- best-effort cleanup based on independent booleans;
- path-based sidecar reopening after the anchoring boundary;
- privileged helpers, mount tricks, shared ODBs, or hidden object imports;
- downgrade that silently treats a sidecar prefix as legacy union state.

