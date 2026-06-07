#!/usr/bin/env python3
"""Generate Core-Opal crossover gap cases in the project JSON trajectory format.

These cases specifically probe behaviors that sit at the boundary between the
Core and Opal specs: places where one spec defines a rule the other overrides,
specializes, or depends on. Each case needs knowledge of BOTH specs at once.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import json
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
V7_CUSTOM = ROOT / "new_datasets" / "customtest_84"
if str(V7_CUSTOM) not in sys.path:
    sys.path.insert(0, str(V7_CUSTOM))

from generate_synthetic import (  # noqa: E402
    C_PIN_ADMIN1,
    C_PIN_SID,
    C_PIN_USER1,
    DATARMV_UID,
    K_AES_RANGE1,
    ADMIN_SP,
    LOCKING_SP,
    ADMIN1_UID,
    SID_UID,
    USER1_UID,
    USERS_UID,
    activate,
    activate_locking_sp,
    authenticate_step,
    end_session,
    gen_key,
    get_cpin,
    make_step,
    revert_sp,
    set_cpin,
    setup_tper,
    setup_user,
    start_session,
)


OUT_DIR = Path(__file__).resolve().parent
TESTCASE_DIR = OUT_DIR / "testcases"
LABELS = OUT_DIR / "label.jsonl"
MANIFEST = OUT_DIR / "manifest.json"

SID = "SIDVAL"
MSID = "MSIDVAL"
USER_PIN = "USER1PIN"
NEW_SID = "NEWSIDPIN"


@dataclass(frozen=True)
class Scenario:
    name: str
    label: str
    steps: list[dict]
    concept: str
    refs: tuple[str, ...]


def scen(name: str, label: str, steps: list[dict], concept: str, *refs: str) -> Scenario:
    normalized = deepcopy(steps)
    for index, step in enumerate(normalized, start=1):
        if isinstance(step, dict):
            step["index"] = index
    return Scenario(name, label, normalized, concept, tuple(refs))


# ---- Local helpers ----------------------------------------------------------

def sid_admin_session(*, write: int = 1) -> list[dict]:
    """Open an AdminSP session authenticated as SID (leaves session open)."""
    return setup_tper(MSID, SID) + [
        start_session(ADMIN_SP, write=write, authority=SID_UID, challenge=SID),
    ]


def sid_admin_session_unauth() -> list[dict]:
    """Open an AdminSP session without authentication (leaves session open)."""
    return setup_tper(MSID, SID) + [
        start_session(ADMIN_SP, write=1),
    ]


def active_locking_prefix() -> list[dict]:
    """Set up TPer and activate LockingSP; all sessions closed at end."""
    return setup_tper(MSID, SID) + activate_locking_sp(SID)


def locking_admin_session(*, write: int = 1) -> list[dict]:
    """Open a LockingSP session authenticated as Admin1 (leaves session open)."""
    return active_locking_prefix() + [
        start_session(LOCKING_SP, write=write, authority=ADMIN1_UID, challenge=SID),
    ]


def revert_step(target_uid: str = LOCKING_SP, status: str = "SUCCESS") -> dict:
    return make_step("Revert", target_uid, {}, {}, status, invoking_name="SP")


def set_cpin_col(cpin_uid: str, columns: dict, status: str = "SUCCESS") -> dict:
    return make_step("Set", cpin_uid, {}, {"Values": [columns]}, status, invoking_name="C_PIN")


# ---- Scenarios --------------------------------------------------------------

def scenarios() -> list[Scenario]:
    out: list[Scenario] = []

    # 01 — TryLimit cross-SP isolation
    # Core rule: TryLimit is per C_PIN object. Opal: SID (AdminSP) and Admin1
    # (LockingSP) live in separate C_PIN objects with independent counters.
    out += [
        scen(
            "cross_pass_01_trylimit_cross_sp_isolation",
            "pass",
            setup_tper(MSID, SID) + activate_locking_sp(SID) + [
                start_session(ADMIN_SP, authority=SID_UID, challenge="WRONGPIN",
                              status="NOT_AUTHORIZED"),
                start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=SID,
                              status="SUCCESS"),
            ],
            "C_PIN TryLimit is per-object; failing SID auth in AdminSP must not affect Admin1 TryLimit in LockingSP.",
            "core/5.3.4.1.14", "opal/4.2.1.8", "opal/4.3.1.9",
        ),
        scen(
            "cross_fail_01_trylimit_cross_sp_spillover",
            "fail",
            setup_tper(MSID, SID) + activate_locking_sp(SID) + [
                start_session(ADMIN_SP, authority=SID_UID, challenge="WRONGPIN",
                              status="NOT_AUTHORIZED"),
                start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=SID,
                              status="AUTHORITY_LOCKED_OUT"),
            ],
            "AdminSP SID failure cannot lock out LockingSP Admin1; TryLimit counters are SP-local.",
            "core/5.3.4.1.14", "opal/4.2.1.8", "opal/4.3.1.9",
        ),
    ]

    # 02 — SID_UID is AdminSP-only; not a valid LockingSP StartSession authority
    out += [
        scen(
            "cross_pass_02_sid_not_valid_locking_sp_authority",
            "pass",
            active_locking_prefix() + [
                start_session(LOCKING_SP, authority=SID_UID, challenge=SID,
                              status="NOT_AUTHORIZED"),
            ],
            "SID authority only exists in AdminSP; StartSession to LockingSP with SID_UID must fail.",
            "core/5.2.3.1", "opal/4.2", "opal/4.3.1",
        ),
        scen(
            "cross_fail_02_sid_accepted_by_locking_sp",
            "fail",
            active_locking_prefix() + [
                start_session(LOCKING_SP, authority=SID_UID, challenge=SID,
                              status="SUCCESS"),
            ],
            "SID is an AdminSP-only authority and cannot authenticate a LockingSP session.",
            "core/5.2.3.1", "opal/4.2", "opal/4.3.1",
        ),
    ]

    # 03 — Activate(LockingSP) requires SID auth in AdminSP (Core Activate + Opal mandate)
    out += [
        scen(
            "cross_pass_03_activate_requires_sid_auth",
            "pass",
            sid_admin_session() + [activate(LOCKING_SP, "SUCCESS")],
            "Activate(LockingSP) succeeds only from an authenticated AdminSP SID session.",
            "core/5.4.3.2", "opal/5.1.1.1", "opal/5.1.1.2",
        ),
        scen(
            "cross_fail_03_activate_without_sid_auth",
            "fail",
            sid_admin_session_unauth() + [activate(LOCKING_SP, "SUCCESS")],
            "Activate without SID authentication cannot succeed; unauthenticated AdminSP session lacks authority.",
            "core/5.4.3.2", "opal/5.1.1.1", "opal/5.1.1.2",
        ),
    ]

    # 04 — Revert(LockingSP) requires AdminSP SID auth (Opal Revert path + Core ACE lookup)
    out += [
        scen(
            "cross_pass_04_revert_requires_adminsp_sid",
            "pass",
            setup_tper(MSID, SID) + activate_locking_sp(SID) + [
                start_session(ADMIN_SP, authority=SID_UID, challenge=SID),
                revert_step(LOCKING_SP, "SUCCESS"),
            ],
            "Revert(LockingSP) is valid from an authenticated AdminSP SID session after activation.",
            "opal/5.1.2.1", "opal/5.2.2.2.2", "core/5.3.3.11",
        ),
        scen(
            "cross_fail_04_revert_without_sid_auth",
            "fail",
            setup_tper(MSID, SID) + activate_locking_sp(SID) + [
                start_session(ADMIN_SP, write=1),   # no auth
                revert_step(LOCKING_SP, "SUCCESS"),
            ],
            "Revert(LockingSP) without SID authentication cannot succeed.",
            "opal/5.1.2.1", "core/5.3.3.11",
        ),
    ]

    # 05 — SID PIN change after Activate does NOT update Admin1 PIN (Opal one-time copy)
    # Opal/5.1.1.2: SID PIN is copied to Admin1 only at initial Activate, never again.
    out += [
        scen(
            "cross_pass_05_sid_pin_change_no_admin1_update",
            "pass",
            setup_tper(MSID, SID) + activate_locking_sp(SID) + [
                start_session(ADMIN_SP, authority=SID_UID, challenge=SID),
                set_cpin_col(C_PIN_SID, {3: NEW_SID}),
                end_session(),
                # Admin1 should still authenticate with the original SID (not NEW_SID)
                start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=SID,
                              status="SUCCESS"),
            ],
            "SID PIN copy to Admin1 happens only at initial Activate; later SID PIN changes do not update Admin1.",
            "opal/5.1.1.2", "opal/5.2.2.3.2", "opal/4.2.1.8",
        ),
        scen(
            "cross_fail_05_sid_pin_change_propagates_to_admin1",
            "fail",
            setup_tper(MSID, SID) + activate_locking_sp(SID) + [
                start_session(ADMIN_SP, authority=SID_UID, challenge=SID),
                set_cpin_col(C_PIN_SID, {3: NEW_SID}),
                end_session(),
                # Incorrect: uses NEW_SID for Admin1, implying PIN propagated
                start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=NEW_SID,
                              status="SUCCESS"),
            ],
            "Admin1 PIN is frozen at Activate time; it must not track subsequent SID PIN changes.",
            "opal/5.1.1.2", "opal/5.2.2.3.2",
        ),
    ]

    # 06 — TryLimit=0 means unlimited retries (Core spec word + Opal User table)
    out += [
        scen(
            "cross_pass_06_trylimit_zero_means_unlimited",
            "pass",
            setup_tper(MSID, SID) + activate_locking_sp(SID) + setup_user(SID, USER_PIN) + [
                start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=SID),
                set_cpin_col(C_PIN_USER1, {5: 0}),   # TryLimit=0 (unlimited)
                end_session(),
                start_session(LOCKING_SP, authority=USER1_UID, challenge="WRONG1",
                              status="NOT_AUTHORIZED"),
                start_session(LOCKING_SP, authority=USER1_UID, challenge="WRONG2",
                              status="NOT_AUTHORIZED"),
                start_session(LOCKING_SP, authority=USER1_UID, challenge="WRONG3",
                              status="NOT_AUTHORIZED"),
                start_session(LOCKING_SP, authority=USER1_UID, challenge=USER_PIN,
                              status="SUCCESS"),
            ],
            "TryLimit=0 means no limit on failures; authentication must succeed after any number of bad attempts.",
            "core/5.3.4.1.14", "opal/4.2.1.8", "opal/4.3.1.9",
        ),
        scen(
            "cross_fail_06_trylimit_zero_still_locks_out",
            "fail",
            setup_tper(MSID, SID) + activate_locking_sp(SID) + setup_user(SID, USER_PIN) + [
                start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=SID),
                set_cpin_col(C_PIN_USER1, {5: 0}),
                end_session(),
                start_session(LOCKING_SP, authority=USER1_UID, challenge="WRONG1",
                              status="NOT_AUTHORIZED"),
                start_session(LOCKING_SP, authority=USER1_UID, challenge="WRONG2",
                              status="NOT_AUTHORIZED"),
                start_session(LOCKING_SP, authority=USER1_UID, challenge="WRONG3",
                              status="NOT_AUTHORIZED"),
                # Incorrect: TryLimit=0 cannot cause AUTHORITY_LOCKED_OUT
                start_session(LOCKING_SP, authority=USER1_UID, challenge=USER_PIN,
                              status="AUTHORITY_LOCKED_OUT"),
            ],
            "AUTHORITY_LOCKED_OUT cannot occur when TryLimit=0 (unlimited).",
            "core/5.3.4.1.14", "opal/4.2.1.8",
        ),
    ]

    # 07 — Successful authentication resets Tries counter (Core rule + Opal LockingSP)
    out += [
        scen(
            "cross_pass_07_auth_success_resets_tries",
            "pass",
            setup_tper(MSID, SID) + activate_locking_sp(SID) + setup_user(SID, USER_PIN) + [
                start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=SID),
                set_cpin_col(C_PIN_USER1, {5: 2}),   # TryLimit=2
                end_session(),
                start_session(LOCKING_SP, authority=USER1_UID, challenge="WRONG",
                              status="NOT_AUTHORIZED"),   # Tries=1
                start_session(LOCKING_SP, authority=USER1_UID, challenge=USER_PIN,
                              status="SUCCESS"),           # Tries resets to 0
            ],
            "Successful authentication resets Tries to 0; a single prior failure cannot lock out with TryLimit=2.",
            "core/5.3.4.1.14", "core/5.3.4.1.1.2", "opal/4.3.1.9",
        ),
        scen(
            "cross_fail_07_auth_success_does_not_reset_tries",
            "fail",
            setup_tper(MSID, SID) + activate_locking_sp(SID) + setup_user(SID, USER_PIN) + [
                start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=SID),
                set_cpin_col(C_PIN_USER1, {5: 2}),
                end_session(),
                start_session(LOCKING_SP, authority=USER1_UID, challenge="WRONG",
                              status="NOT_AUTHORIZED"),
                # Incorrect: one failure with TryLimit=2 cannot cause locked-out status
                start_session(LOCKING_SP, authority=USER1_UID, challenge=USER_PIN,
                              status="AUTHORITY_LOCKED_OUT"),
            ],
            "With TryLimit=2, a single preceding failure cannot lock out the authority.",
            "core/5.3.4.1.14", "core/5.3.4.1.1.2",
        ),
    ]

    # 08 — GenKey on LockingSP range key requires a LockingSP session (Core dispatch + Opal scope)
    out += [
        scen(
            "cross_pass_08_genkey_in_locking_sp_session",
            "pass",
            locking_admin_session() + [gen_key(K_AES_RANGE1, "SUCCESS")],
            "GenKey on a LockingSP range media key succeeds in an authenticated LockingSP session.",
            "core/5.6.3.3", "opal/4.3.7",
        ),
        scen(
            "cross_fail_08_genkey_from_admin_sp_on_locking_range",
            "fail",
            sid_admin_session() + [gen_key(K_AES_RANGE1, "SUCCESS")],
            "GenKey on a LockingSP media key UID cannot succeed in an AdminSP session; UID is not in AdminSP table.",
            "core/5.6.3.3", "opal/4.3.7",
        ),
    ]

    # 09 — RevertSP(LockingSP) requires Admin1 auth; KeepGlobalRangeKey is a valid Opal parameter here
    out += [
        scen(
            "cross_pass_09_revertsp_locking_admin1_keep_global",
            "pass",
            locking_admin_session() + [revert_sp(LOCKING_SP, "SUCCESS", keep_global=True)],
            "RevertSP(LockingSP, KeepGlobalRangeKey=True) is valid from an authenticated LockingSP Admin1 session.",
            "opal/5.1.3.1", "opal/5.1.3.3", "opal/5.1.3.4",
        ),
        scen(
            "cross_fail_09_revertsp_locking_unauthenticated",
            "fail",
            active_locking_prefix() + [
                start_session(LOCKING_SP, write=1),   # no auth
                revert_sp(LOCKING_SP, "SUCCESS"),
            ],
            "RevertSP(LockingSP) without Admin1 authentication cannot succeed.",
            "opal/5.1.3.1", "opal/5.1.3.2",
        ),
    ]

    # 10 — Revert(LockingSP) is an AdminSP+SID method; calling it from LockingSP session is wrong path
    # Opal defines two separate methods: Revert (inter-SP, via AdminSP) and RevertSP (intra-SP).
    out += [
        scen(
            "cross_pass_10_revert_from_adminsp_correct_path",
            "pass",
            setup_tper(MSID, SID) + activate_locking_sp(SID) + [
                start_session(ADMIN_SP, authority=SID_UID, challenge=SID),
                revert_step(LOCKING_SP, "SUCCESS"),
            ],
            "Revert(LockingSP) issued from an AdminSP SID session is the correct Opal path.",
            "opal/5.1.2.1", "opal/5.2.2.2.2",
        ),
        scen(
            "cross_fail_10_revert_from_locking_sp_session",
            "fail",
            locking_admin_session() + [revert_step(LOCKING_SP, "SUCCESS")],
            "Revert(LockingSP) from within a LockingSP session uses the wrong path; RevertSP is the intra-SP method.",
            "opal/5.1.2.1", "opal/5.1.3.1",
        ),
    ]

    # 11 — Users class authority cannot be directly authenticated (Core class rule + Opal Users table)
    out += [
        scen(
            "cross_pass_11_users_class_not_directly_authenticated",
            "pass",
            active_locking_prefix() + [
                start_session(LOCKING_SP),
                authenticate_step(USERS_UID, auth_result=None, status="INVALID_PARAMETER"),
            ],
            "Users is a class authority; Authenticate must target an instance (User1-User8), not the class row.",
            "core/5.3.4.1.2", "opal/4.2.1.7", "opal/4.3.1.8",
        ),
        scen(
            "cross_fail_11_users_class_authenticate_succeeds",
            "fail",
            active_locking_prefix() + [
                start_session(LOCKING_SP),
                authenticate_step(USERS_UID, auth_result=True, status="SUCCESS"),
            ],
            "Authenticating directly as the Users class cannot succeed.",
            "core/5.3.4.1.2", "opal/4.2.1.7",
        ),
    ]

    # 12 — Authenticate with SID_UID inside a LockingSP session returns result=False (wrong SP authority)
    # Core: Authenticate on a non-existent or inapplicable authority returns SUCCESS result=False.
    # Opal: SID is AdminSP-only; it is not in LockingSP's authority table.
    out += [
        scen(
            "cross_pass_12_authenticate_sid_in_locking_sp_returns_false",
            "pass",
            active_locking_prefix() + [
                start_session(LOCKING_SP),
                authenticate_step(SID_UID, proof=SID, auth_result=False, status="SUCCESS"),
            ],
            "Authenticate with SID_UID in LockingSP returns result=False; SID is not a LockingSP authority.",
            "core/5.3.4.1.14", "core/5.3.4.1.14.1", "opal/4.2", "opal/4.3.1",
        ),
        scen(
            "cross_fail_12_authenticate_sid_in_locking_sp_returns_true",
            "fail",
            active_locking_prefix() + [
                start_session(LOCKING_SP),
                authenticate_step(SID_UID, proof=SID, auth_result=True, status="SUCCESS"),
            ],
            "Authenticate with SID_UID in LockingSP cannot return result=True; SID is not a valid LockingSP authority.",
            "core/5.3.4.1.14", "opal/4.2",
        ),
    ]

    # 13 — DataRemovalMechanism Set requires an authenticated write session (Opal table + Core Set)
    out += [
        scen(
            "cross_pass_13_datarmv_set_active_mech_authorized",
            "pass",
            sid_admin_session() + [
                make_step("Set", DATARMV_UID, {}, {"Values": [{2: 2}]}, "SUCCESS",
                          invoking_name="DataRemovalMechanism"),
            ],
            "Set DataRemovalMechanism.ActiveDataRemovalMechanism succeeds in an authenticated AdminSP write session.",
            "opal/3.1.1.6", "opal/4.2.6.1.1", "core/5.3.3.7",
        ),
        scen(
            "cross_fail_13_datarmv_set_readonly_session",
            "fail",
            sid_admin_session(write=0) + [
                make_step("Set", DATARMV_UID, {}, {"Values": [{2: 2}]}, "SUCCESS",
                          invoking_name="DataRemovalMechanism"),
            ],
            "DataRemovalMechanism Set cannot succeed in a read-only session; Core write authorization is required.",
            "opal/3.1.1.6", "opal/4.2.6.1.1", "core/5.3.3.7",
        ),
    ]

    # 14 — C_PIN.PIN Get always returns NOPIN regardless of authority (Core NOPIN + Opal Admin1 table)
    # Core/5.3.4.2.1: PIN column always returns NOPIN sentinel.
    # Opal/4.2.1.7: applies to all C_PIN rows in both AdminSP and LockingSP.
    out += [
        scen(
            "cross_pass_14_admin1_pin_get_returns_nopin",
            "pass",
            locking_admin_session() + [
                get_cpin(C_PIN_ADMIN1, "SUCCESS", pin_value=None),  # None → NOPIN
            ],
            "Get on Admin1 C_PIN.PIN returns SUCCESS with NOPIN sentinel, never the actual PIN value.",
            "core/5.3.4.2.1", "opal/4.2.1.7", "opal/4.3.1.8",
        ),
        scen(
            "cross_fail_14_admin1_pin_get_reveals_actual_pin",
            "fail",
            locking_admin_session() + [
                get_cpin(C_PIN_ADMIN1, "SUCCESS", pin_value=SID),   # Returns actual PIN — violation
            ],
            "C_PIN.PIN must never return the actual PIN value; returning actual bytes violates the NOPIN rule.",
            "core/5.3.4.2.1", "opal/4.2.1.7",
        ),
    ]

    # 15 — After Revert(LockingSP), SP returns to Manufactured-Inactive; new sessions fail
    # Full lifecycle: Activate (Core method, Opal lifecycle) → Revert (Opal inter-SP) → inactive again
    out += [
        scen(
            "cross_pass_15_revert_returns_locking_sp_inactive",
            "pass",
            setup_tper(MSID, SID) + activate_locking_sp(SID) + [
                start_session(ADMIN_SP, authority=SID_UID, challenge=SID),
                revert_step(LOCKING_SP, "SUCCESS"),
                end_session(),
                start_session(LOCKING_SP, status="FAIL"),
            ],
            "After Revert(LockingSP), the SP returns to Manufactured-Inactive and rejects new sessions.",
            "opal/5.1.2.1", "opal/5.2.1.2", "opal/5.2.2.2",
        ),
        scen(
            "cross_fail_15_revert_session_still_works",
            "fail",
            setup_tper(MSID, SID) + activate_locking_sp(SID) + [
                start_session(ADMIN_SP, authority=SID_UID, challenge=SID),
                revert_step(LOCKING_SP, "SUCCESS"),
                end_session(),
                start_session(LOCKING_SP, status="SUCCESS"),
            ],
            "LockingSP cannot accept sessions immediately after Revert without re-activation.",
            "opal/5.1.2.1", "opal/5.2.1.2",
        ),
    ]

    return out


def write_dataset() -> list[Scenario]:
    TESTCASE_DIR.mkdir(parents=True, exist_ok=True)
    for old in TESTCASE_DIR.glob("*.json"):
        old.unlink()

    rows = []
    manifest = []
    all_scenarios = scenarios()
    for scenario in all_scenarios:
        filename = f"{scenario.name}.json"
        (TESTCASE_DIR / filename).write_text(json.dumps(scenario.steps, indent=2) + "\n")
        rows.append({"filename": filename, "label": scenario.label})
        manifest.append({
            "filename": filename,
            "label": scenario.label,
            "concept": scenario.concept,
            "refs": list(scenario.refs),
        })

    LABELS.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n")
    return all_scenarios


def check_with_v7() -> int:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from v7.src.solver import Solver

    solver = Solver()
    rows = [json.loads(line) for line in LABELS.read_text().splitlines() if line.strip()]
    total = len(rows)
    correct = 0
    misses = []
    for row in rows:
        steps = json.loads((TESTCASE_DIR / row["filename"]).read_text())
        pred = solver.predict_one(steps)
        if pred == row["label"]:
            correct += 1
        else:
            misses.append((row["filename"], row["label"], pred))
    print(f"v7 accuracy on cross_gap_cases: {correct}/{total} ({correct / total * 100:.1f}%)")
    if misses:
        print("misses:")
        for filename, label, pred in misses:
            print(f"  {filename}: expected={label} predicted={pred}")
    return 0 if correct == total else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()

    if not args.check_only:
        generated = write_dataset()
        pass_count = sum(1 for s in generated if s.label == "pass")
        fail_count = len(generated) - pass_count
        print(f"Generated {len(generated)} cases ({pass_count} pass, {fail_count} fail)")
        print(f"  -> {TESTCASE_DIR}")
        print(f"  -> {LABELS}")
        print(f"  -> {MANIFEST}")

    if args.check or args.check_only:
        return check_with_v7()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
