# E-UNION physical marker retirement audit

## Production authority

No production resolver, readdir, create, copy-up, rename, unlink or rmdir path
reads, creates, removes, or treats a physical `user.union.whiteout` or
`user.union.opaque` object as authoritative.

| Area | Sidecar-v1 implementation |
| --- | --- |
| Component resolution | One anchored shared view; `eunion_resolver_marker_status()` maps resolver tags to typed sidecar records. |
| `eunion_is_whiteout()` | O(1)-per-component typed lookup with identity validation. |
| Readdir/getdents | Physical upper objects are guest data; whiteout child records and opacity come only from the selected sidecar node. |
| Unlink/rmdir | One logical-first remove transaction; merged emptiness and ancestor opacity are typed. |
| Open/mkdir/mknod/FIFO/symlink/hardlink | One backing-first create transaction owns backing creation and record retirement. |
| UNIX socket bind | AF_UNIX filesystem bind is executed by the anchored create transaction against the retained upper-parent FD. |
| Copy-up | One backing-first transaction; staging is private and metadata is preserved without live chmod. |
| Rename | One transaction owns backing rename, source masking, destination replacement, and sidecar-subtree movement. |
| Opaque publication | Exact `OPAQUE` node bound to the matching upper/lower directory incarnation. |

Prepare helpers may materialize an upper parent but cannot clear a record or
perform the final backing mutation. A failed backing create cannot resurrect a
lower object.

The reserved `user.union.*` guest xattr namespace remains a defense against
forgery/leakage and prevents copying historical private marker names. It is not
the storage representation.

## Runtime sources

Canonical production state is implemented by:

- `eunion_sidecar.c`;
- `eunion_resolver.c`;
- `vchroot_userspace.c`;
- the canonical create/remove/rename syscall wrappers.

`eunion_remove.c` and `eunion_remove_runtime.c` remain compiled only by
explicit historical regression tests. They are not linked into the production
premigration source list and are not a retained legacy runtime.

## Format handling

Physical legacy state is forensic input only. Normal startup reports
`PREFIX_RECREATE_REQUIRED`; explicit recreation constructs a clean sidecar-v1
prefix and imports no legacy marker. Mixed physical/sidecar authority has no
valid production state.

## Contract assertions

Normal sidecar fixtures assert:

- lower-only delete creates no upper placeholder;
- no `user.union.*` xattr is emitted;
- hostile umask cannot change sidecar permissions;
- mode-000 failed rmdir does not open a permission window;
- recursive lower-delete/rmdir leaves no internal marker child;
- resolver/readdir ignore physical marker-looking guest objects and consult
  typed records;
- no runtime syscall call site invokes post-unlink or pre-create physical
  marker publication.
