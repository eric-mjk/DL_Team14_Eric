# Reference Repository Usage

This project keeps external OPAL/TCG implementations under
`reference_git_repos/` as Git submodules. They are reference material, not
runtime dependencies: the solver does not import or build them during grading.
Their value is that they show how real OPAL tools name objects, construct
commands, interpret status codes, and sequence stateful workflows.

## How They Contributed

The current `v5_usereference` source is primarily a deterministic protocol
oracle. The reference repositories helped shape these parts:

- `src/spec_tables.py`: UID constants, authority names, C_PIN objects, Locking
  objects, MBRControl, MediaKey names, and policy vocabulary were cross-checked
  against real OPAL implementations.
- `src/solver.py` and `src/oracle.py`: session lifecycle, credential checking,
  Activate/Revert/RevertSP, GenKey, MBRControl, locking range fields, and
  read/write lock behavior were validated against real workflow code and test
  scripts.
- `customtest_57/generate_synthetic.py`: synthetic workflows such as setup
  TPer, setup user, setup range, unlock/read/write, rekey, and MBR control were
  modeled after real OPAL tool/test flows instead of only public test cases.
- `reference_git_repos/linux_src/`: Linux OPAL constants and ioctl-facing
  operations helped confirm method names, status handling, response parsing, and
  state transitions.

The references were used as engineering evidence. The final compliance rules
still come from the TCG Core and Opal documents under `documents/`, because
implementation behavior can be incomplete or vendor-specific.

## Repository Contents

### `go-tcg-storage`

Go library and tools for TCG Storage devices. Important areas:

- `pkg/core`: low-level TCG method/session abstractions.
- `pkg/core/uid`: UID constants and naming.
- `pkg/core/table`: generated/typed table method helpers.
- `pkg/core/method`: method definitions.
- `pkg/locking`: higher-level locking-range management.
- `cmd/sedlockctl`, `cmd/tcgsdiag`, `cmd/tcgdiskstat`: examples of practical
  OPAL workflows.

Further use:

- Mine UID/table/method mappings to expand `spec_tables.py`.
- Compare method parameter handling against hidden testcase shapes.
- Use typed table helpers as a sanity check for column names and expected
  return values.

### `opal-toolset`

C command-line tools for OPAL devices. Important files:

- `control.c`: management operations such as setup, user/range configuration,
  unlock, MBR operations, and PSID/SID flows.
- `discovery.c`: Discovery and Properties handling.
- `rng.c`: Random method usage.
- `common.c`, `utils.c`: shared command construction/parsing utilities.
- `demo/`: example flows for locking ranges and single-user mode.

Further use:

- Translate command sequences into more synthetic tests.
- Check how tools report/handle method status failures.
- Expand tests around Discovery/Properties, Random, range setup, and MBR flows.

### `opal-test-suite`

Bash/C test suite for behavior analysis of OPAL drives. Important files:

- `test_basic`: baseline ownership and core OPAL workflows.
- `test_lr_defs`: locking range setup, locking, and read/write access control.
- `test_rekey_patterns`: encryption/rekey behavior.
- `test_rng_quality`: Random output behavior.
- `test_psid_suffix`, `test_lbafs`, `test_single_user_mode`: edge-case feature
  checks.
- helper scripts such as `set_user`, `set_locking_range`, `unlock_lr`,
  `lock_lr`, `regenerate_lr_key`.

Further use:

- Turn each destructive drive test into non-destructive JSON trajectories.
- Add PASS/FAIL pairs for locking range boundaries, rekeying, and SUM.
- Use the scripts as scenario templates for hidden-test generalization.

### `sedutil-TCG-OPAL-standard`

Large C/C++ SED management project centered around `sedutil-cli` and pre-boot
authentication images. Important areas:

- `Common/`: shared OPAL command, device, table, and credential logic.
- `linux/CLI`, `windows/CLI`: platform-specific CLI entry points.
- `LinuxPBA/` and `images/`: pre-boot unlock flows and image generation.
- `docs/`: project documentation.

Further use:

- Compare password, SID/Admin1/User authority flows against the solver state
  model.
- Study shadow MBR/PBA behavior if future tests cover MBRDone/MBREnabled more
  deeply.
- Extract additional real-world command orderings for custom tests.

### `linux_src`

Small project-focused snapshot from the Linux kernel OPAL implementation.
Important files:

- `sed-opal.c`: Linux block-layer OPAL implementation.
- `opal_proto.h`: protocol constants, tokens, UIDs, methods, and statuses.
- `include/uapi/linux/sed-opal.h`: user-facing ioctl structures.
- `include/linux/sed-opal.h`: internal Linux OPAL interface.

Further use:

- Verify status-token parsing and error handling assumptions.
- Expand constants in `spec_tables.py` and normalization helpers.
- Compare solver read/write lock behavior with Linux ioctl workflows.

## Practical Rule

Use these repos to discover real command sequences and implementation details.
Then confirm the rule against `documents/core`, `documents/opal`, and the
coverage artifacts before changing solver behavior.
