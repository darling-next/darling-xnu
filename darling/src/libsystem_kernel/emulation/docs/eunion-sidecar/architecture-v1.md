# E-UNION sidecar namespace v1

## Goals and non-goals

Sidecar v1 makes whiteout and opaque state independent of guest-visible
backing inodes. It is rootless, fd-relative after anchoring, fail-closed, and
crash-recoverable. It does not grant authority to read or chmod a mode-000
guest inode. It does not use a privileged helper or retain a legacy physical
marker runtime.

The sidecar is transaction authority, not a cache. Missing, corrupt, stale,
duplicate, mixed, or future-version state fails closed.

## Prefix format and physical layout

A valid runtime prefix uses state schema v3. The regular, mode-0600
`.darling-prefix-state-v3` record inside the upper root binds the exact upper
and sidecar identities, runtime mode, owner, generation, and provenance
`darling-runtime-prefix-sidecar-v1`.

The sidecar itself is a sibling of the upper root and is outside the vchroot
guest namespace:

```text
<upper-parent>/
  <upper-root>/
    .darling-prefix-state-v3
  <upper-root>.eunion-sidecar-v1/
    active-v1
    format-v1
    lock-v1
    tree-v1/
      root-v1/
        node-v1
        children/
          <siphash-hex>/
            node-v1
            children/
    staging-v1/
    journal-v1                 # absent when quiescent
```

`active-v1` is published only after the complete sidecar tree is durable.
The launcher anchors the upper root, its parent, workdir, sidecar and
persistent lifecycle lock component-by-component with `O_NOFOLLOW`. It passes
only retained descriptors to Darlingserver. The server validates every
identity and the named persistent lock inode while taking its shared lifetime
lease. No unvalidated path crosses that boundary.

The SystemRoot escape, symlink traversal, `..`, crafted component names, and
fd-to-path conversion reject both the sidecar root and control records. No
sidecar pathname is returned to guest code.

## Version gate and Policy 1 recreation

New prefixes are constructed directly in sidecar-v1 format. A legacy,
unversioned, partially initialized, or incompatible prefix returns the typed
`PREFIX_RECREATE_REQUIRED` verdict before guest boot and before mutation.
There is no automatic migration, partial sidecar activation, physical-marker
fallback, or privileged migrator.

Recreation is a separate explicit launcher command with exact confirmation.
It takes the persistent lifecycle lock, checks the retained prefix name,
live-process PID state, and `/proc/self/mountinfo`, then stages a completely
fresh prefix and sidecar as siblings. Publication and cleanup are journaled,
fd-relative, atomic, fsynced, rollback/forward-recoverable, and preserve the
primary error. The runtime never deletes a prefix merely because inspection
reported an old format.

## Component keys and records

Every path component is keyed by SipHash-2-4 using a random 128-bit key stored
in `format-v1`. The directory name is a fixed 16-hex digest. `node-v1` stores
the original component bytes and length, so a collision fails closed.

Each fixed-size versioned node contains:

- magic, schema version, exact encoded length, and checksum;
- original component bytes;
- monotonic generation;
- exhaustive tag: `INDEX`, `WHITEOUT`, or `OPAQUE`;
- required upper/lower filesystem identities;
- parent generation and sidecar UUID binding.

Identity includes presence, device, inode, type and ctime. Whiteout validation
uses the full identity because it must continue hiding the exact immutable
lower object. Index and opaque ancestry use device/inode/type identity: adding
or removing a child legitimately changes a directory ctime and must not
invalidate its complete sidecar subtree. Reused inodes and type mismatches
never inherit stale records.

Lookup opens one hashed child per component and never scans the global tree.
Readdir enumerates only the selected node's `children`.

## Locking and capabilities

`lock-v1` is created once and never renamed or removed. Readers take `LOCK_SH`;
mutation and recovery take `LOCK_EX`. After `flock`, the opened inode is
compared with the still-named inode to reject split-lock replacement.

The retained lock capability covers the complete component walk, readdir
materialization, or transaction. A reader observing `journal-v1` releases the
shared capability, obtains exclusive recovery authority, recovers, and
restarts.

The C capabilities use fixed storage, no heap/vtable/dynamic dispatch, an
owner-address cookie, a single typestate enum, and an exhaustive tagged intent
union. They are assignment-resistant owning capabilities with runtime
typestate; C does not provide an absolute compile-time linearity guarantee.
Direct copies and reopen-after-release fail validation.

## Durable publication

Persistent writes use:

1. unique private staging object;
2. explicit permission independent of guest umask;
3. complete checked record write;
4. file and newly created directory fsync bottom-up;
5. atomic fd-relative rename;
6. destination-parent fsync;
7. journal advancement and final cleanup fsync.

No operation follows symlinks. Cleanup never masks the primary error.

Create, socket bind, FIFO/mknod, hardlink, symlink, copy-up, rename and remove
all run through the same persistent transaction authority. Copy-up preserves
mode, ownership, timestamps and non-reserved xattrs without temporarily
changing a live inode. Before a merged directory is renamed, a durable
recursive copy-up journal materializes every visible lower-only descendant
under the exclusive sidecar lock. Rename then moves the complete backing tree
and corresponding sidecar subtree and is idempotently forward-recovered from
the journal.

## Remove and mode-000 directories

Physical upper entries are always guest data; sidecar whiteouts are never
children of a guest directory. The remove planner proves merged visibility
using typed records, including ancestor opacity, and uses fd-relative backing
operations.

- nonempty mode-000 directory: `ENOTEMPTY`, unchanged bytes, mode and ctime;
- empty mode-000 directory: successful `unlinkat(AT_REMOVEDIR)` without read
  permission;
- successful concurrent chmod remains authoritative;
- lower-only deletion publishes only an identity-bound sidecar whiteout.

No live chmod or permission-restoration path exists.
