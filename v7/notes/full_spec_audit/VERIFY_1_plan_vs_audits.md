# Verification 1: Implementation Plan vs Audit Files

Scope: compared `IMPLEMENTATION_PLAN.md` against the eight audit files `AGENT_A_*` through `AGENT_H_*`. I did not inspect source beyond audit-provided file/function names and did not edit `v6/src` or testcase files.

## Summary

The plan is grounded for the items it explicitly covers, including repeated `Activate`, inactive LockingSP revert key bumps, `KeepGlobalRangeKey` scoping, ActiveKey mutability, SecretProtect schema, ClockTime schema, LockingSP User fallback removal, User2-User8 default disabled state, object-table Get omission, MBR shadowing, several deferred ACL/auth/lifecycle/log/reset/discovery items, and DataRemovalMechanism/TPerInfo/AccessControl special-column work.

However, the plan omits several important P0/P1 audit findings and misclassifies a few items as lower-risk or only generic when the audits called out concrete P0/P1 behavior. The largest gaps are Agent B session response/UID validation, Agent C GenKey validation, Agent F Properties/AdminSP session semantics, Agent G LockingSP validation details, Agent H SP lifecycle Get validation, and Agent D IssueSP/SP deletion/frozen behavior.

## Findings

### High: Agent B P1 session response validation omitted

- Audit reference: `AGENT_B_core_status_sessions.md:250-254`, spec `core/5.2.3.2.1`, `core/5.2.3.2.2`, `core/5.1.4.2.18`, `core/5.2.3.1.2`, `core/5.2.3.1.5`, `core/5.2.3.1.7`
- Plan section: only `B-P1: Numeric status encoding` at `IMPLEMENTATION_PLAN.md:270-281`
- Issue: Agent B has three P1 edits: numeric status encoding, `StartSession`/`SyncSession` returned `HostSessionID`/`SPSessionID` validation and persistence, and exact 8-byte UID validation for SPID/authority parameters. The plan includes only numeric status encoding, so important P1 session conformance findings are omitted.
- Recommended correction: add two deferred or validate-tier plan items for `StartSession`/`SyncSession` response ID validation and UID length validation, with Agent B P1/spec references.

### High: Agent C P0 GenKey validation omitted

- Audit reference: `AGENT_C_core_methods.md:501-506`, spec `core/5.3.3.16.*`, `core/5.3.4.1.1.1`, `core/5.3.4.1.1.2`
- Plan section: no matching section; closest is `C-P0-1`, `C-P0-2`, `C-P0-5`, and `C-P1-4`
- Issue: Agent C marks full GenKey parameter validation and C_PIN GenKey behavior as P0. The plan does not include it as implemented, validated, or deferred.
- Recommended correction: add a plan item for C-P0 GenKey parameter validation: `PinLength` only for C_PIN, max 32, `PublicExponent` only for C_RSA, bad RSA exponent rejection, and explicit Base-vs-Opal policy handling for C_PIN GenKey.

### High: Agent F P0 Properties response validation omitted

- Audit reference: `AGENT_F_opal_adminsp.md:79-84`, spec `opal/4.1.1.*`
- Plan section: no matching section
- Issue: Agent F marks successful `Properties` response validation as P0: mandatory TPer properties, numeric minimums, and HostProperties accepted ranges. The plan omits it entirely. Agent E has a P2 response-overflow/properties item, but that is not the same as Opal Table 17 property presence/minimum validation.
- Recommended correction: add a P0 or deferred item for Opal Properties response validation, with Table 17 mandatory property and minimum-value checks.

### High: Agent F P1 AdminSP session/method semantics omitted

- Audit reference: `AGENT_F_opal_adminsp.md:86-92`, specs `opal/4.1.1.*`, `opal/4.2.1.5`, `opal/4.2.1.6`
- Plan section: no matching section, except generic AccessControl and TPerInfo/DataRemovalMechanism sections
- Issue: Agent F P1 findings are absent: `CloseSession` optional-aware judging, `StartSession Write=False` optional-aware judging, `SessionTimeout` bounds when exposed, AdminSP method support filtering to Table 21, and AdminSP Admin1/AdminXX authority/C_PIN UID normalization.
- Recommended correction: add explicit deferred items for these AdminSP P1 behaviors. Do not rely on generic Core lifecycle or AccessControl sections to cover them.

### High: Agent D P1 IssueSP/SP deletion/frozen behavior omitted or over-generalized

- Audit reference: `AGENT_D_core_templates_crypto_clock_log.md:57-61`, specs `core/5.4.3.1`, `core/5.4.3.1.7`, `core/5.4.4.2`, `core/5.4.2.4.8`
- Plan section: `A-P1: Generic Core SP lifecycle` at `IMPLEMENTATION_PLAN.md:251-266`
- Issue: the plan covers generic Disabled/Frozen lifecycle, but omits concrete Agent D P1 requirements for `IssueSP` normalization/judging and SP deletion pending-until-successful-close. Agent D classified this as P1, not merely a generic lifecycle subcase.
- Recommended correction: add a separate D-P1 deferred item for `IssueSP`, pending SP deletion semantics, and frozen SP session behavior, or expand A-P1 to explicitly include those Agent D requirements and spec references.

### Medium: Agent H P0 SP lifecycle Get validation omitted

- Audit reference: `AGENT_H_opal_lifecycle_psid.md:84-86`, spec `opal/5.1.1`, `opal/5.1.2`, lifecycle enum values in `opal/5.*`
- Plan section: no matching section; nearest is `A-P1: Generic Core SP lifecycle`
- Issue: Agent H P0 #2 requires validating final `Get` of AdminSP `SP.LifeCycleState` against tracked lifecycle state. The plan implements H-P0-1 but omits H-P0-2.
- Recommended correction: add an H-P0 item for final SP table `LifeCycleState` Get validation, including stale/reserved value rejection.

### Medium: Agent G P1 LockingSP validation details omitted

- Audit reference: `AGENT_G_opal_lockingsp.md:92-114`, specs `opal/4.3.1.7`, `opal/4.3.5.2.1.1`, `opal/4.3.5.2.1.2`, `opal/4.3.5.2.2`, `opal/4.3.5.3.1`
- Plan section: `G-P0-1` and `G-P0-2` only at `IMPLEMENTATION_PLAN.md:143-171`
- Issue: the plan covers the two Agent G P0 findings but omits all Agent G P1 findings: `ACE_C_PIN_UserMMMM_Set_PIN` BooleanExpr content validation, LockingInfo alignment checks when known, and precise mandatory/optional `LockOnReset`/`DoneOnReset` value handling.
- Recommended correction: add deferred G-P1 items for these three behaviors. Alignment should remain conditional on known LockingInfo state, matching Agent G's ambiguity note.

### Medium: Agent A P1/P2 status alias and concurrency details under-specified

- Audit reference: `AGENT_A_core_arch_types.md:280-304`, specs `core/4.1`-`core/4.5.5`, `core/3.4.1.1`, `core/3.3.7.1`
- Plan section: `A-P1: Generic Core SP lifecycle` at `IMPLEMENTATION_PLAN.md:251-266`
- Issue: A-P1 mostly reflects generic lifecycle but omits the explicit `sp_fail` alias and does not mention DeleteSP/AdminSP Delete state transitions. Agent A also has P2 session concurrency and object-row deletion/UID uniqueness work absent from the plan. These are lower priority than the P0/P1 omissions above, but the plan is incomplete relative to Agent A.
- Recommended correction: expand A-P1 with `sp_fail` normalization and DeleteSP/SP-row deletion state; add P2 deferred items for per-SP session concurrency and object-table deletion/UID uniqueness if the plan aims to cover all audit recommendations.

### Medium: Plan labels several deferred items as done while their sections still say "implement later"

- Audit reference: not an audit-file contradiction; internal plan consistency issue
- Plan section: tracker at `IMPLEMENTATION_PLAN.md:24-33` vs deferred introduction and item text at `IMPLEMENTATION_PLAN.md:207-214`
- Issue: many DEFER rows are marked `✅ Done`, but the DEFER section says these should be saved for later and each subsection says "Implementation plan when ready." This is ambiguous: either the tracker reflects post-plan implementation, or the plan body is stale.
- Recommended correction: either split "tier" from "implementation status" explicitly, or update completed deferred sections from future-tense implementation plans to actual completed-change summaries plus validation evidence.

### Low: Agent F P0 DataRemovalMechanism/TPerInfo plan has a likely object-scope typo

- Audit reference: `AGENT_F_opal_adminsp.md:81-83`, specs `opal/4.2.7`, `opal/4.2.3`
- Plan section: `F-P0: DataRemovalMechanism + TPerInfo first-class tables` at `IMPLEMENTATION_PLAN.md:285-297`
- Issue: the plan says to add `DataRemovalMechanism` and `TPerInfo` to `LOCKING_TABLE_UIDS` / `canonical_object`. These are AdminSP/TPerInfo surfaces in Agent F, not LockingSP table UIDs. The audit requires correct UID recognition and AdminSP access control, not LockingSP scoping.
- Recommended correction: revise the implementation note to add them to the correct canonical UID/object mapping for AdminSP/TPerInfo, preserving SP scope and SID/Anybody access rules.

### Low: Some implemented/validate tier "safe" statements are stronger than the audits justify

- Audit reference: Agent D ActiveKey at `AGENT_D_core_templates_crypto_clock_log.md:81-85`; Agent H KeepGlobalRangeKey at `AGENT_H_opal_lifecycle_psid.md:87-88`
- Plan section: `IMPLEMENTATION_PLAN.md:69-79`, `IMPLEMENTATION_PLAN.md:97-107`
- Issue: the plan repeatedly claims low or no breakage risk based on current tests, but the audits themselves generally identify spec correctness, not safety against hidden/public test assumptions. ActiveKey is especially noted as a Core-vs-SSC conflict that may need an Opal-specific override.
- Recommended correction: keep the spec references, but phrase risk as "requires validation" where a change makes the oracle more permissive or where Core/Opal policy can diverge.

## Items Correctly Reflected

- Agent H P0 repeated `Activate`: reflected in `H-P0-1`.
- Agent H P1 Revert known SP restriction, inactive LockingSP key bump guard, and `KeepGlobalRangeKey` scoping: reflected in `H-P1-3`, `H-P1-4`, `H-P1-5`.
- Agent D P0 MBR shadowing: reflected in `D-P0`.
- Agent D P1 ClockTime schema and ActiveKey mutability: reflected, with the ActiveKey caveat above.
- Agent D P1 re-encryption restrictions and D P2 log/crypto checks: reflected as deferred.
- Agent C P0 two-step Authenticate, object-table Get omission, ACL mutation, and P1 SecretProtect schema: reflected.
- Agent E P1 reset abort and Level 0 Discovery: reflected.
- Agent F P0 AccessControl `(N)` behavior and DataRemovalMechanism/TPerInfo: reflected, with omissions around Properties and scope wording.
- Agent G P0 Locking User fallback and User2-User8 disabled defaults: reflected.
