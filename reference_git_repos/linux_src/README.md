# linux_src

This directory contains a small, project-focused subset of Linux kernel OPAL
SED reference files from:

https://github.com/torvalds/linux

These files are reference material only. They are not intended to be built as a
standalone Linux component inside this repository.

## Why these files are here

The project in `../project_specification.md` asks us to judge whether the final
SSD command response in a trajectory is protocol-compliant. That requires
tracking state across earlier command-response pairs, especially:

- session state,
- authentication and authority state,
- locking range state,
- method status and error status,
- table/object identifiers used by TCG OPAL.

Linux's OPAL implementation is useful because it shows one real implementation
of command construction, response parsing, and state-dependent OPAL workflows.

## Files

- `sed-opal.c`
  - Main Linux kernel OPAL SED implementation from `block/sed-opal.c`.
  - Useful for studying `StartSession`, authenticated sessions, locking range
    setup, lock/unlock operations, response parsing, and status handling.

- `opal_proto.h`
  - OPAL protocol constants from `block/opal_proto.h`.
  - Useful for mapping tokens, method IDs, UIDs, status values, table IDs, and
    locking/authentication fields.

- `include/uapi/linux/sed-opal.h`
  - User-facing OPAL ioctl structures and constants from
    `include/uapi/linux/sed-opal.h`.
  - Useful for understanding the operation types Linux exposes to userspace.

- `include/linux/sed-opal.h`
  - Internal Linux OPAL interface from `include/linux/sed-opal.h`.
  - Useful for seeing how the block layer references the OPAL implementation.

## Recommended use

Use these files as implementation references when building prompts, rules, or
features for the verifier. In particular, inspect:

- OPAL method names and UIDs in `opal_proto.h`,
- response token parsing and status extraction in `sed-opal.c`,
- session setup functions in `sed-opal.c`,
- locking range functions in `sed-opal.c`,
- ioctl-level operation definitions in `include/uapi/linux/sed-opal.h`.

Do not treat Linux behavior as the full formal specification. The final
compliance judgment should still be based on the TCG Storage specifications and
the project's command-response log semantics.

## Source snapshot

These files were copied from the `master` branch of `torvalds/linux` on
2026-05-26.

