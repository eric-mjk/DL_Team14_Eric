# Agent F Audit: Opal 4.1/4.2 Session Manager and AdminSP

Scope audited: `documents/opal/4.1*` and `documents/opal/4.2*` only, compared against `v6/src/{solver.py,normalizer.py,state.py,oracle.py,spec_docs.py,spec_tables.py}`. I did not edit `v6/src`.

## Document Files Read

Count: 33 files.

- `documents/opal/4.1.txt`
- `documents/opal/4.1.1.txt`
- `documents/opal/4.1.1.1.txt`
- `documents/opal/4.1.1.2.txt`
- `documents/opal/4.1.1.3.txt`
- `documents/opal/4.1.1.4.txt`
- `documents/opal/4.2.txt`
- `documents/opal/4.2.1.txt`
- `documents/opal/4.2.1.1.txt`
- `documents/opal/4.2.1.2.txt`
- `documents/opal/4.2.1.3.txt`
- `documents/opal/4.2.1.4.txt`
- `documents/opal/4.2.1.5.txt`
- `documents/opal/4.2.1.6.txt`
- `documents/opal/4.2.1.7.txt`
- `documents/opal/4.2.1.8.txt`
- `documents/opal/4.2.2.txt`
- `documents/opal/4.2.3.txt`
- `documents/opal/4.2.3.1.txt`
- `documents/opal/4.2.3.2.txt`
- `documents/opal/4.2.3.3.txt`
- `documents/opal/4.2.4.txt`
- `documents/opal/4.2.5.txt`
- `documents/opal/4.2.5.1.txt`
- `documents/opal/4.2.6.txt`
- `documents/opal/4.2.6.1.txt`
- `documents/opal/4.2.6.1.1.txt`
- `documents/opal/4.2.6.1.2.txt`
- `documents/opal/4.2.7.txt`
- `documents/opal/4.2.7.1.txt`
- `documents/opal/4.2.8.txt`
- `documents/opal/4.2.9.txt`
- `documents/opal/4.2.9.1.txt`

## Key Normative Requirements

- Properties: Opal devices SHALL support `Properties`; mandatory TPer properties and minimum values include `MaxComPacketSize >= 2048`, `MaxResponseComPacketSize >= 2048`, `MaxPacketSize >= 2028`, `MaxIndTokenSize >= 1992`, `MaxPackets >= 1`, `MaxSubpackets >= 1`, `MaxMethods >= 1`, `MaxSessions >= 1`, `MaxAuthentications >= 2`, `MaxTransactionLimit >= 1`, and `DefSessionTimeout` VU. Host property acceptance has mandatory minimums for most host properties, while `MaxResponseComPacketSize` may be ignored.
- StartSession: Opal SHALL support `HostSessionID`, `SPID`, `Write`, `HostChallenge`, and `HostSigningAuthority`; `Write=True` SHALL be supported; `Write=False` may or may not be supported. Optional `SessionTimeout`, if supported and present, must satisfy TPer max/min and SPInfo `SPSessionTimeout` bounds or StartSession SHALL fail as defined by core.
- SyncSession: Opal SHALL support `HostSessionID` and `SPSessionID`.
- CloseSession: Opal MAY support `CloseSession`; an unsupported response can be compliant.
- AdminSP includes Base and Admin templates. All listed 4.2.1 tables are mandatory. AdminSP MethodID preconfiguration lists `Next`, `GetACL`, `Get`, `Set`, `Authenticate`, conditional `Revert`, conditional `Activate`, and `Random`.
- AdminSP SPInfo: `SPSessionTimeout` is ignored if absent or zero.
- AdminSP Table table: must include AdminSP tables listed in Table 20; `DataRemovalMechanism` row SHALL NOT exist if the feature descriptor is unsupported.
- AccessControl/ACE: table rows define executable access control. `InvokingID`, `MethodID`, and `GetACLACL` are special: though read-only/fixed, their access control for `Get` is `(N)`. The `ACL` column is readable only through `GetACL`.
- AdminSP C_PIN: `C_PIN_SID`, `C_PIN_MSID`, `C_PIN_Admin1`, and optional `C_PIN_AdminXX` rows exist. Automated take-ownership environments SHALL set initial `C_PIN_SID.PIN` to `C_PIN_MSID.PIN`; otherwise `C_PIN_SID.PIN` may be VU.
- AdminSP Authority: `Anybody`, `Admins`, `Makers`, `SID`, mandatory `Admin1`, and optional `AdminXX` are preconfigured. `Admin1` is initially disabled; additional admins are optional and disabled. `SID` uses password credential `C_PIN_SID`.
- TPerInfo: Opal adds boolean `ProgrammaticResetEnable`; if true, `TPER_RESET` is enabled; if false, it is not. It is readable by Anybody and modifiable by SID. `SSC` SHALL include `Opal`.
- DataRemovalMechanism: table has exactly one row UID `00 00 11 01 00 00 00 01` when supported; `UID` is not host-modifiable. `ActiveDataRemovalMechanism` selects the mechanism used by Revert/RevertSP/GenKey. Setting it to an unsupported `data_removal_mechanism` value SHALL fail with `INVALID_PARAMETER`. Enum values: 0, 1, 2, and 5 are defined; 3-4 and 6-7 are reserved.
- Random: TPer SHALL implement `Random`; `Count` is mandatory; unsupported parameters SHALL produce `INVALID_PARAMETER`; Count values `<= 32` SHALL be supported.
- Crypto template tables are not required.

## Implementation Coverage Assessment

- `Solver.predict_one` in `v6/src/solver.py:63-83` correctly normalizes all steps, tracks state over prior steps only, and returns lowercase `pass`/`fail` through `judge_final`.
- Basic Session Manager support is partially implemented. `METHOD_FAILURE_MATRIX` in `v6/src/oracle.py:818-825` requires parameters and open-session/write-session conditions. `judge_start_session` in `v6/src/oracle.py:1357-1457`, `judge_sync_session` in `v6/src/oracle.py:2381-2388`, and `judge_close_session` in `v6/src/oracle.py:2401-2408` implement core state expectations. No source edit is needed for malformed unsigned session parameters or malformed `Write` boolean, because `method_preflight` handles them in `v6/src/oracle.py:1132-1292`.
- Properties is under-covered. `invalid_host_properties` only checks shape in `v6/src/oracle.py:926-934`, and `judge_final` only checks the Session Manager target in `v6/src/oracle.py:2446-2453`. It does not validate mandatory TPer property presence/minimums or host property accepted ranges from Table 17.
- StartSession `SessionTimeout` is under-covered. The implementation rejects malformed unsigned integer values in `v6/src/oracle.py:1150-1156`, but does not infer `MaxSessionTimeout`, `MinSessionTimeout`, or SPInfo `SPSessionTimeout` limits. It also treats unauthenticated starts as expected success in `v6/src/oracle.py:1454-1457`, which is too strict for `Write=False`, because read-only sessions are optional.
- `CloseSession` is over-strict. `METHOD_FAILURE_MATRIX` and `judge_close_session` expect success when a session is open, but Opal marks `CloseSession` optional. The solver should not fail a final unsupported/non-success response solely because `CloseSession` is not implemented.
- AdminSP access policy extraction exists. `spec_docs.build_access_policy_from_index` in `v6/src/spec_docs.py:953-1015` extracts ACE, AccessControl, Authority, and C_PIN rows, and `state.initial_state` stores them in `v6/src/state.py:66-104`. `oracle.ace_policy_decision` in `v6/src/oracle.py:507-554` evaluates matching AccessControl rows and ACE BooleanExpr/columns. No source edit is needed for many AdminSP C_PIN NOPIN cases: `WRITE_ONLY_COLUMNS["C_PIN"]` in `v6/src/spec_docs.py:255-258`, the C_PIN_MSID exception in `v6/src/oracle.py:1580-1588`, and generic C_PIN Get/Set logic in `v6/src/oracle.py:1597-1619` and `v6/src/oracle.py:1787-1803` cover the core PIN-column visibility rule.
- AdminSP AccessControl special columns are not covered. `policy_status_result` allows policy-matched `Get` based on ACE rows in `v6/src/oracle.py:557-579`; it does not enforce that AccessControl `InvokingID`, `MethodID`, and `GetACLACL` have `(N)` access for `Get`, nor that the `ACL` column is readable only through `GetACL`.
- `GetACL` is under-covered and partly wrong. `judge_meta_acl` in `v6/src/oracle.py:2176-2188` only requires an AccessControl target and any authenticated authority. It does not evaluate the matched row's `GetACLACL`, so it rejects unauthenticated/Anybody-authorized `GetACL` cases and may allow cases whose `GetACLACL` is empty.
- AdminSP method support is not constrained to Table 21. `METHOD_NAMES` in `v6/src/spec_docs.py:13-70` and `METHOD_FAILURE_MATRIX` in `v6/src/oracle.py:818-875` include many methods outside AdminSP Table 21. Without SP-specific method support filtering, an AdminSP final invocation such as `CreateTable`, `Delete`, `AddACE`, or `SetPackage` can be judged by generic rules even though the assigned AdminSP MethodID preconfiguration does not list it. No edit is needed for `Random` Count > 32, because `judge_random` rejects it in `v6/src/oracle.py:1966-1979`.
- Random unsupported-parameter handling is missing. `Random` requires `Count`, and the source checks missing/malformed Count, but it does not fail success responses that include extra unsupported parameters, contrary to `documents/opal/4.2.9.1.txt`.
- TPerInfo is not modeled as a first-class table. `normalizer.canonical_object` and `object_family` in `v6/src/normalizer.py:234-377` do not recognize `TPerInfo` or UID prefix `00 00 02 01`. `COLUMN_NAME_NUMBERS` in `v6/src/spec_docs.py:100-229` has no `TPerInfo` schema or `ProgrammaticResetEnable` column. As a result, `ProgrammaticResetEnable` Set/Get access and boolean validation fall through to generic behavior.
- DataRemovalMechanism is not modeled as a first-class table. `normalizer.py:234-377` does not recognize `DataRemovalMechanism` table/row UIDs, and `spec_docs.py:100-229` has no schema for `UID` or `ActiveDataRemovalMechanism`. The AccessControl row is present in the generated artifact, but the ACE reference for `ACE_DataRemovalMechanism_Set_ActiveDataRemovalMechanism` can be mis-normalized as hex-like text, and the ACE column list is not parsed to column 1. No current code validates unsupported enum values with `INVALID_PARAMETER`.
- AdminSP Authority/C_PIN normalization is fragile. `normalizer.canonical_authority` in `v6/src/normalizer.py:176-196` recognizes LockingSP Admin1 UID `00 00 00 09 00 01 00 01`, but not AdminSP Admin1 UID `00 00 00 09 00 00 02 01`, so AdminSP Admin1 becomes `Authority_000201`. `spec_docs.authority_name_from_uid` has the same gap at `v6/src/spec_docs.py:831-847`. ACE policy can sometimes still work through extracted rows, but family fallbacks such as `session_has_admin_authority` in `v6/src/oracle.py:266-272` do not treat `Authority_000201` as an AdminSP admin.
- Table, SPInfo, SPTemplates, MethodID, SP, C_PIN, Authority, ACE, and AccessControl discovery rows are mostly handled through table schema/family and ACE policy. No source edit is needed for ordinary AdminSP public `Get`/`Next` rows where Table 22 grants `ACE_Anybody`, except for the AccessControl special-column and `GetACL` issues above.

## Required Edits

Priority P0:

- Enforce AdminSP AccessControl special-column behavior. For `Get` on `AccessControl`, a request for `InvokingID`, `MethodID`, or `GetACLACL` should be non-success because their Get access is `(N)`, and a request for `ACL` should be non-success unless the method is `GetACL`. `GetACL` should evaluate the target AccessControl row's `GetACLACL`, not the row's normal invocation `ACL`.
- Add first-class `DataRemovalMechanism` recognition and schema. Map table UID `00 00 00 01 00 00 11 01` and row UID `00 00 11 01 00 00 00 01`, add columns `{0: UID, 1: ActiveDataRemovalMechanism}`, make UID non-modifiable, and enforce `Set ActiveDataRemovalMechanism` as AdminSP SID/Admins per ACE. Reject unsupported/reserved enum values with `INVALID_PARAMETER`.
- Add first-class `TPerInfo` recognition and schema. Map UID `00 00 02 01 00 03 00 01`, add `ProgrammaticResetEnable` column 8 as boolean, allow Get by Anybody in AdminSP, allow Set only by SID, and reject malformed boolean values.
- Validate `Properties` successful responses against Table 17: mandatory properties must be present when the response reports TPer properties, and numeric minimums must be enforced. Also validate HostProperties requests for mandatory accepted property ranges where the host supplied those properties.

Priority P1:

- Make `CloseSession` optional-aware. If the final method is `CloseSession` and the device returns an unsupported/non-success status because it does not implement CloseSession, the verdict should be `pass`; if it does implement and succeeds with an open session, also `pass`.
- Make `StartSession Write=False` optional-aware. For read-only session attempts, accept either compliant success or a compliant unsupported/error response; keep `Write=True` as required-supported.
- Implement `SessionTimeout` bounds when the trajectory exposes TPer `MinSessionTimeout`/`MaxSessionTimeout` properties or SPInfo `SPSessionTimeout`; AdminSP empty/zero `SPSessionTimeout` must be ignored.
- Add SP-specific method support filtering for AdminSP based on Table 21. In AdminSP, final methods outside `Next`, `GetACL`, `Get`, `Set`, `Authenticate`, `Random`, and supported conditional `Revert`/`Activate` should not be judged by generic permissive rules as if they were listed AdminSP methods.
- Fix AdminSP Admin1/AdminXX authority and C_PIN naming. Normalize `00 00 00 09 00 00 02 01` to an AdminSP-scoped `Admin1` or equivalent admin token, map `00 00 00 0B 00 00 02 01` to its credential, and preserve SP scope so it is not confused with LockingSP Admin1.

Priority P2:

- For `Random`, reject success responses when unsupported parameters beyond `Count` are supplied; expected status is `INVALID_PARAMETER`.
- Add explicit checks for AdminSP preconfiguration `Get` responses where final response returns contradictory fixed values that are directly executable: SPInfo `Enabled=T`, AdminSP SP `LifeCycle=Manufactured`, AdminSP `Frozen=FALSE`, C_PIN/Admin authority initial enabled/disabled flags, and TPerInfo `SSC` containing `Opal`. These are useful only when the final output includes those columns.
- Treat the Table table's `DataRemovalMechanism` row conditionally: if the implementation learns the Data Removal Mechanism feature descriptor is unsupported, a returned row for that table is non-compliant; if the feature is supported, absence/non-existence is non-compliant.

## Ambiguities and Non-Executable Sections

- Several preconfiguration columns are VU, empty, optional, or informative only (`GUDID`, firmware, table sizes, row counts, template instance counts). These should not drive fail/pass unless the final response directly contradicts a mandatory fixed value or a learned state value.
- `C_PIN_SID.PIN` may equal MSID for automated take ownership, but may also be VU for alternate take ownership. The solver should keep the current behavior of seeding SID from observed MSID only when SID is unknown; it should not require equality in all trajectories.
- `Revert` and `Activate` are marked with references to later sections for support requirements. Since this audit scope excludes those later sections, AdminSP Table 21 should be used to identify the methods as conditionally listed, but exact lifecycle side effects remain outside this assigned scope.
- DataRemovalMechanism support is described both conditionally in Table 20 and as SHALL-supported in 4.2.7.1. A practical solver should key off explicit feature-descriptor evidence when present and otherwise treat the row/table as expected under Opal 4.2.7.1.
- Crypto template tables are expressly not required, so absence of Crypto template tables should never be a failure under this scope. Random, however, is a required method.

## Synthetic Tests Recommended

- Properties final success missing `MaxComPacketSize`, or returning `MaxPacketSize=1024`, should be `fail`; valid minimum values should be `pass`.
- StartSession with `Write=True` and valid unauthenticated AdminSP parameters should require success; StartSession with `Write=False` returning unsupported/non-success should be accepted.
- StartSession with `SessionTimeout` greater than a previously learned nonzero SPInfo `SPSessionTimeout` should require failure; the same value with empty/zero `SPSessionTimeout` should not fail for that reason.
- CloseSession in an open session returning `unsupported` should be `pass`; CloseSession success in an open session should also be `pass`.
- AdminSP unauthenticated session `GetACL` for a row whose `GetACLACL=ACE_Anybody` should be `pass`; `Get` of AccessControl `ACL` column should be `fail` unless performed through `GetACL`.
- AdminSP `Get` of AccessControl `InvokingID`, `MethodID`, or `GetACLACL` should be `fail` because their Get access is `(N)`.
- AdminSP `Set` TPerInfo `ProgrammaticResetEnable=True` under SID write session should be `pass`; same Set under Admin1 or unauthenticated session should be `fail`; malformed boolean should require `INVALID_PARAMETER`.
- AdminSP `Set` DataRemovalMechanism `ActiveDataRemovalMechanism=5` under SID/Admins write session should be `pass` if supported; value `4` or `7` should require `INVALID_PARAMETER`; setting UID column should require non-success.
- Random with `Count=32` should pass; `Count=33` should require `INVALID_PARAMETER`; `Count=8` plus an extra unsupported parameter should require `INVALID_PARAMETER`.
- AdminSP final `CreateTable` or `SetPackage` should be rejected/unsupported under Table 21 method support rather than accepted by generic write-session fallback.
- Authenticate/StartSession as AdminSP Admin1 UID `00 00 00 09 00 00 02 01` after SID enables it should authorize AdminSP Admins ACEs, without being confused with LockingSP Admin1 UID `00 00 00 09 00 01 00 01`.
