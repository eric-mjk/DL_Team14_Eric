# Agent G Audit: Opal 4.3 LockingSP

Scope honored: read only `documents/opal/4.3*` for normative requirements, compared against `v6/src/{solver.py,normalizer.py,state.py,oracle.py,spec_docs.py,spec_tables.py}`. No source edits made.

## 1. Document Files Read

Count: 31 files.

- `documents/opal/4.3.txt`
- `documents/opal/4.3.1.txt`
- `documents/opal/4.3.1.1.txt`
- `documents/opal/4.3.1.2.txt`
- `documents/opal/4.3.1.3.txt`
- `documents/opal/4.3.1.4.txt`
- `documents/opal/4.3.1.5.txt`
- `documents/opal/4.3.1.6.txt`
- `documents/opal/4.3.1.7.txt`
- `documents/opal/4.3.1.8.txt`
- `documents/opal/4.3.1.9.txt`
- `documents/opal/4.3.1.10.txt`
- `documents/opal/4.3.2.txt`
- `documents/opal/4.3.3.txt`
- `documents/opal/4.3.4.txt`
- `documents/opal/4.3.4.1.txt`
- `documents/opal/4.3.5.txt`
- `documents/opal/4.3.5.1.txt`
- `documents/opal/4.3.5.2.txt`
- `documents/opal/4.3.5.2.1.txt`
- `documents/opal/4.3.5.2.1.1.txt`
- `documents/opal/4.3.5.2.1.2.txt`
- `documents/opal/4.3.5.2.2.txt`
- `documents/opal/4.3.5.3.txt`
- `documents/opal/4.3.5.3.1.txt`
- `documents/opal/4.3.5.4.txt`
- `documents/opal/4.3.5.5.txt`
- `documents/opal/4.3.6.txt`
- `documents/opal/4.3.7.txt`
- `documents/opal/4.3.8.txt`
- `documents/opal/4.3.8.1.txt`

## 2. Key Normative Requirements Relevant To Final-Response Judging

- All `(M)` tables in section 4.3 are mandatory (`4.3.1`).
- LockingSP MethodID preconfiguration supports `Next`, `GetACL`, `GenKey`, `RevertSP`, `Get`, `Set`, `Authenticate`, and `Random` (`4.3.1.5`).
- AccessControl table cells are read-only with fixed access control, but Get invocation access is `(N)`, and the ACL column is readable only via `GetACL` (`4.3.1.6` lines 13-17).
- Locking range `Get` of RangeStart through ActiveKey is `Admins`; CommonName is `Anybody` (`4.3.1.6` lines 973-1013; `4.3.1.7` lines 156-175).
- Locking range `Set` ACLs for range bounds, lock flags, LockOnReset, and CommonName are all `Admins`; the ACE rows for `ReadLocked` and `WriteLocked` are also `Admins`, not users (`4.3.1.6` lines 1024-1064; `4.3.1.7` lines 177-231).
- `MBRControl.Get` is `ACE_Anybody`; `MBRControl.Set` is `Admins` for Enable/Done/DoneOnReset (`4.3.1.6` lines 1075-1098; `4.3.1.7` lines 233-245).
- `MBR.Get` is `ACE_Anybody`; `MBR.Set` is `ACE_Admin` (`4.3.1.6` lines 1109-1131).
- K_AES `Get` of Mode is `Anybody`; K_AES `GenKey` is `Admins` (`4.3.1.6` lines 1143-1335; `4.3.1.7` lines 107-153).
- DataStore `Get` and `Set` are `Admins`; the table must be at least 10 MB and initial contents are vendor-unique (`4.3.1.6` lines 1347-1369; `4.3.8.1`).
- User1 through User8 shall be implemented; Admin1 is enabled, Admin2-4 are disabled in OFS, User1 and UserMMMM rows are disabled initially (`4.3.1.8`).
- LockingSP C_PIN defaults: Admin1 PIN is SID/MSID depending on lifecycle, Admin2-4/User1/UserMMMM PINs are empty, TryLimit/Tries are 0, Persistence false (`4.3.1.9`).
- ACE_C_PIN_UserMMMM_Set_PIN BooleanExpr must support only `Admins` and `Admins OR UserMMMM`; unsupported values must fail Set with `INVALID_PARAMETER` (`4.3.1.7` lines 3-5).
- LockingInfo alignment columns are read-only and may be retrieved by Anybody; MaxRanges must be at least 8 (`4.3.5.1` lines 33-47, 68-70).
- When `AlignmentRequired` is true, non-global Locking RangeStart/RangeLength updates with non-zero alignment residuals must fail `INVALID_PARAMETER` (`4.3.5.2.1.1`, `4.3.5.2.1.2`).
- LockOnReset and DoneOnReset must support `{0}` and `{0,3}`; `{0,1}` and `{0,1,3}` are optional (`4.3.5.2.2`, `4.3.5.3.1`).
- MBR minimum size is 128 MB and initial contents are vendor-unique (`4.3.5.4`).
- If an unlocked read/write command spans multiple ranges, both success and invalid-command-parameter outcomes can be compliant depending on the Level 0 Discovery Range Crossing Behavior bit (`4.3.7`).

## 3. Implementation Coverage Assessment

- `Solver.predict_one` correctly reduces the trajectory to normalized events, tracks prior state excluding the final step, and judges only the final event (`v6/src/solver.py`, `predict_one`).
- UID/name normalization covers LockingSP tables, Locking/MBR/K_AES/DataStore objects, C_PINs, authorities, and status aliases (`v6/src/normalizer.py`, `canonical_object`, `object_family`, `normalize_status`).
- Column maps cover Locking, LockingInfo, MBRControl, Authority, ACE, C_PIN, MediaKey, and DataStore (`v6/src/spec_docs.py` lines 100-190). This is sufficient for named columns from the assigned tables.
- Default preconfiguration is data-driven from the spec index: locking ranges are loaded from Locking table rows (`v6/src/spec_docs.py` lines 597-620), MBRControl defaults from Table 46 (`v6/src/spec_docs.py` lines 623-636), table rows from JSON preconfiguration (`v6/src/spec_docs.py` lines 639-651), and ACE/AccessControl/Authority/C_PIN policy rows from the indexed JSON blocks (`v6/src/spec_docs.py` lines 953-1015).
- State tracking updates successful Locking `Get`/`Set`, MBRControl `Get`/`Set`, C_PIN values, policy table personalization, key generation, resets, and read/write observations (`v6/src/state.py` lines 594-618, 690-786, 825-835).
- The generic ACE/AccessControl engine evaluates BooleanExpr and column coverage before fallbacks (`v6/src/oracle.py` lines 303-379, 520-579). This covers many UID-based final `Get`, `Set`, and `GenKey` cases directly from 4.3.1.6/4.3.1.7.
- LockingInfo read-only/public access is mostly covered: read-only columns are rejected for Set (`v6/src/oracle.py` lines 1728-1737), and Get is allowed in an open LockingSP session (`v6/src/oracle.py` lines 1621-1628). No edit needed for basic LockingInfo Get/Set mutability.
- MBRControl and MBR access are covered: MBRControl Get is open-session/Anybody, MBRControl Set is admin-only, MBR Get is open-session/Anybody, MBR Set is admin-only (`v6/src/oracle.py` lines 1682-1698, 1830-1851). No edit needed for these ACL basics.
- DataStore admin-only access is covered by policy rows and fallback (`v6/src/oracle.py` lines 1700-1707, 1843-1851). The size requirement is not checked.
- Data read/write lock enforcement is covered for known locked ranges and prior writes/key generations (`v6/src/oracle.py` lines 2308-2325 and following). The range-crossing discovery-bit ambiguity is not modeled.

## 4. Required Edits

### P0: Remove user authority fallback for Locking range `Get`/`Set`

Spec basis: Locking range Get/Set ACEs in `4.3.1.7` use `BooleanExpr: Admins` for RangeStart-to-ActiveKey, ReadLocked, WriteLocked, and Admins RangeStart-to-LOR rows. No assigned 4.3 doc grants UserN authority over Locking range lock bits.

Current issue: `judge_get` allows matching `UserN` to read protected Locking range columns if policy matching fails (`v6/src/oracle.py` lines 1633-1641). `judge_set` allows matching `UserN` to set ReadLocked/WriteLocked on RangeN if policy matching fails (`v6/src/oracle.py` lines 1805-1827). Comments there contradict the assigned spec.

Concrete edit: delete `session_has_locking_user_authority_for_range` authorization from Locking `Get`/`Set` fallbacks. Expected final response for name-only Locking_Range1 protected `Get`/`Set` under User1-only session should be `not_authorized`/auth error, not success.

### P0: Materialize mandatory User1-User8 disabled authorities and empty C_PIN defaults

Spec basis: User1 through User8 shall be implemented, and User1/UserMMMM rows are initially disabled with empty PINs (`4.3.1.8`, `4.3.1.9`).

Current issue: default policy state includes `User1` and a template `UserMMMM`, but not concrete User2-User8. `authority_enabled` returns true when no authority row exists (`v6/src/oracle.py` lines 187-193), so User2-User8 can be treated as enabled/unknown rather than disabled. `initial_state` only seeds `User1` credential (`v6/src/state.py` lines 71-80).

Concrete edit: instantiate User2-User8 authority rows as disabled, class `Users`, operation `Password`, mapped to C_PIN_UserN, with empty credentials. Final StartSession/Authenticate for User2-User8 before an enabling Set should be auth failure/not authorized, not accepted as unknown.

### P1: Validate ACE_C_PIN_UserMMMM_Set_PIN BooleanExpr personalization

Spec basis: only `Admins` and `Admins OR UserMMMM` are required/supported values; unsupported values must fail Set with `INVALID_PARAMETER` (`4.3.1.7` lines 3-5).

Current issue: ACE BooleanExpr Set is authorized by policy, but there is no content validation that rejects unsupported BooleanExpr values for C_PIN User PIN ACEs (`v6/src/state.py` lines 479-497; `v6/src/oracle.py` lines 1783-1785).

Concrete edit: when final `Set` targets `ACE_C_PIN_User1_Set_PIN` or template/concrete `ACE_C_PIN_UserMMMM_Set_PIN` BooleanExpr column, accept only the supported expressions for the corresponding ACE. Any other BooleanExpr should expect `invalid_parameter`.

### P1: Implement alignment checks from LockingInfo when state is known

Spec basis: with `AlignmentRequired=TRUE`, non-global RangeStart/RangeLength Set/CreateRow must fail `INVALID_PARAMETER` when the computed alignment residual is non-zero (`4.3.5.2.1.1`, `4.3.5.2.1.2`).

Current issue: `invalid_locking_range_update` rejects negative/overlapping/global bound changes but does not consult tracked LockingInfo `AlignmentRequired`, `AlignmentGranularity`, or `LowestAlignedLBA` (`v6/src/oracle.py` lines 685-733).

Concrete edit: persist LockingInfo returned columns into a convenient state view, then add modulo validation for non-global Locking `Set` and `CreateRow` when all alignment inputs are known. If inputs are unknown, leave behavior undecided rather than speculating.

### P1: Treat LockOnReset/DoneOnReset mandatory vs optional values precisely

Spec basis: `{0}` and `{0,3}` are mandatory; `{0,1}` and `{0,1,3}` are optional (`4.3.5.2.2`, `4.3.5.3.1`).

Current issue: admin Set of these columns currently expects success for any value that survives generic parsing (`v6/src/oracle.py` lines 1783-1851). That is too strict against compliant devices rejecting optional unsupported values and too permissive for clearly unsupported values.

Concrete edit: for Locking column 9 and MBRControl column 3, require success for mandatory values, accept either success or invalid_parameter for optional values, and require invalid_parameter for unsupported values when the value is parseable.

### P2: Check reported MBR/DataStore minimum sizes when final response exposes them

Spec basis: MBR minimum size is 128 MB (`4.3.5.4`); DataStore Rows must be at least `0x00A00000` (`4.3.8.1`).

Current issue: preconfigured table rows are loaded, but final `Get` responses that report a too-small MBR/DataStore table row are not compared against the minimums. `byte_table_granularity` reads table metadata for write granularity only (`v6/src/oracle.py` lines 784-802).

Concrete edit: when final `Get` returns Table-row metadata for MBR or DataStore, validate `Rows` against the assigned minimums if present.

## 5. Ambiguities / Intentionally Non-Executable Sections

- `4.3`, `4.3.1`, `4.3.3`, `4.3.4`, `4.3.5`, `4.3.6`, and `4.3.8` are section headers or references to other sections; no independent final-response rule is needed.
- `4.3.1.1`, `4.3.1.2`, `4.3.1.3`, `4.3.1.5`, `4.3.1.10`, `4.3.2`, and `4.3.5.5` are mostly preconfiguration/schema inventory. They are executable only through UID/object normalization, policy rows, default state, and method availability; no separate response rule is needed except where rows expose access/size/key behavior.
- `4.3.1.4` Type table is not required by Opal. The OR operator requirement matters indirectly for BooleanExpr evaluation, which is implemented (`v6/src/oracle.py` lines 334-379). AC_element capacity is not visible in normalized traces.
- Optional rows and `VU` values are not deterministic final-response requirements. A compliant device can vary vendor-unique contents and can choose optional K_AES table support as long as at least one AES table exists.
- Range-crossing behavior in `4.3.7` depends on Level 0 Discovery Range Crossing Behavior bit, outside this assigned 4.3 trace state unless discovery data is present. For unlocked multi-range commands, both success and invalid-command-parameter can be compliant.
- LockOnReset/DoneOnReset optional values are vendor/support dependent. The oracle should not force success for optional sets unless prior trajectory established support.
- Initial MBR and DataStore byte contents are vendor-unique; final reads of previously unwritten MBR/DataStore bytes should not be judged against a fixed value.

## 6. Synthetic Tests Recommended

- Locking range protected Get, name-only target: activate LockingSP, authenticate User1 only, final `Get` `Locking_Range1` columns 3-8 returns success. Expected solver output after fix: `fail`.
- Locking range Set, name-only target: User1-only write session, final `Set` `ReadLocked=True` on Range1 returns success. Expected: `fail`; if final returns `not_authorized`, expected `pass`.
- User2 disabled by default: activate LockingSP, attempt StartSession/Auth as User2 before enabling, final success. Expected: `fail`.
- C_PIN User ACE personalization: Admin write session sets `ACE_C_PIN_User1_Set_PIN.BooleanExpr` to `Anybody`; final returns `invalid_parameter`. Expected: `pass`; final success should be `fail`.
- AlignmentRequired known: prior LockingInfo Get reports `AlignmentRequired=True`, `AlignmentGranularity=8`, `LowestAlignedLBA=0`; final Set Range1 `RangeStart=3` by Admin returns `INVALID_PARAMETER`. Expected: `pass`.
- LockOnReset mandatory/optional: Admin Set Locking Range1 LockOnReset to `{0}` and `{0,3}` should require success; Set `{0,1}` should accept success or invalid_parameter; Set `{2}` should require invalid_parameter.
- DoneOnReset mandatory/optional: same matrix for MBRControl DoneOnReset.
- DataStore size reporting: final Get Table row for DataStore reports Rows below `0x00A00000` with success. Expected: `fail`.
- MBR size reporting: final Get Table row for MBR reports Rows below `0x08000000` with success. Expected: `fail`.
- Unlocked multi-range read/write crossing: configure two unlocked ranges and final spanning write returns success or invalid-command-parameter. Expected: both accepted unless discovery bit is known.
