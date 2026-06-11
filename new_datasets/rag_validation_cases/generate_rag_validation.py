#!/usr/bin/env python3
"""Generate a focused RAG-validation dataset package.

The package is intentionally separate from the saturated Core/Opal/Cross suites.
It contains:
- clean controls for deterministic state-machine regression,
- parser-drift probes for RAG retrieval/action-routing validation,
- out-of-band state_effect sentinels for unsupported future workflow behavior.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
BASE = Path(__file__).resolve().parent
TESTCASE_DIR = BASE / "testcases"
LABELS = BASE / "label.jsonl"
MANIFEST = BASE / "manifest.json"

SOURCE_DATASETS = {
    "core": ROOT / "new_datasets" / "core_gap_cases",
    "opal": ROOT / "new_datasets" / "opal_gap_cases",
    "cross": ROOT / "new_datasets" / "cross_gap_cases",
}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def source_manifest(dataset: str) -> dict[str, dict[str, Any]]:
    return {row["filename"]: row for row in load_json(SOURCE_DATASETS[dataset] / "manifest.json")}


def load_source_case(dataset: str, filename: str) -> tuple[list[dict[str, Any]], str, dict[str, Any]]:
    labels = {}
    for line in (SOURCE_DATASETS[dataset] / "label.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            labels[row["filename"]] = row["label"]
    steps = load_json(SOURCE_DATASETS[dataset] / "testcases" / filename)
    manifest = source_manifest(dataset)[filename]
    return steps, labels[filename], manifest


def renumber(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cloned = deepcopy(steps)
    for index, step in enumerate(cloned, start=1):
        if isinstance(step, dict):
            step["index"] = index
    return cloned


def final_method_step(steps: list[dict[str, Any]]) -> dict[str, Any]:
    for step in reversed(steps):
        if isinstance(step, dict) and isinstance(step.get("input"), dict) and isinstance(step["input"].get("method"), dict):
            return step
    raise ValueError("source case has no method step")


def add_probe_hint(step: dict[str, Any], hint: str) -> None:
    step.setdefault("input", {})["rag_probe_hint"] = hint


def drift_unknown_method_name(steps: list[dict[str, Any]], alias: str, hint: str) -> list[dict[str, Any]]:
    cloned = renumber(steps)
    step = final_method_step(cloned)
    step["input"]["method"]["name"] = alias
    add_probe_hint(step, hint)
    return cloned


def drift_string_args(steps: list[dict[str, Any]], hint: str) -> list[dict[str, Any]]:
    cloned = renumber(steps)
    step = final_method_step(cloned)
    method = step["input"]["method"]
    original = method.get("args", {})
    method["args"] = "flattened required/optional parameters: " + json.dumps(original, sort_keys=True)
    add_probe_hint(step, hint)
    return cloned


def drift_name_uid_conflict(steps: list[dict[str, Any]], wrong_name: str, hint: str) -> list[dict[str, Any]]:
    cloned = renumber(steps)
    step = final_method_step(cloned)
    invoking = step.setdefault("input", {}).setdefault("invoking_id", {})
    invoking["name"] = wrong_name
    add_probe_hint(step, hint)
    return cloned


def drift_status_text(steps: list[dict[str, Any]], status_text: str, hint: str) -> list[dict[str, Any]]:
    cloned = renumber(steps)
    step = final_method_step(cloned)
    step.setdefault("output", {})["status_codes"] = status_text
    add_probe_hint(step, hint)
    return cloned


def sentinel_command(name: str, result: str, hint: str) -> list[dict[str, Any]]:
    return [
        {
            "index": 1,
            "input": {
                "command": name,
                "args": {"Reason": "out-of-band sentinel", "rag_probe_hint": hint},
            },
            "output": {"command": name, "result": result},
        }
    ]


def case_from_source(
    *,
    filename: str,
    source_dataset: str,
    source_file: str,
    family: str,
    probe_class: str,
    drift_pattern: str,
    rag_targets: list[str],
    expected_repair_action: str,
    metric_scope: str = "primary",
    mutation: str | None = None,
    mutation_arg: str | None = None,
    retrieval_query_hint: str = "",
    concept_suffix: str = "",
) -> dict[str, Any]:
    steps, label, source = load_source_case(source_dataset, source_file)
    hint = retrieval_query_hint or " ".join(rag_targets)
    if mutation == "unknown_method_name":
        steps = drift_unknown_method_name(steps, mutation_arg or "UnknownSpecMethod", hint)
    elif mutation == "string_args":
        steps = drift_string_args(steps, hint)
    elif mutation == "name_uid_conflict":
        steps = drift_name_uid_conflict(steps, mutation_arg or "WrongObjectName", hint)
    elif mutation == "status_text":
        steps = drift_status_text(steps, mutation_arg or "ambiguous successful completion", hint)
    else:
        steps = renumber(steps)
    return {
        "filename": filename,
        "label": label,
        "steps": steps,
        "concept": (source.get("concept", "") + concept_suffix).strip(),
        "refs": list(source.get("refs", [])),
        "family": family,
        "probe_class": probe_class,
        "drift_pattern": drift_pattern,
        "rag_targets": rag_targets,
        "expected_repair_action": expected_repair_action,
        "metric_scope": metric_scope,
        "base_case": f"{source_dataset}/{source_file}",
        "retrieval_query_hint": retrieval_query_hint,
    }


def build_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    add = cases.append

    # Clean controls: deterministic state-machine hard gate only.
    add(case_from_source(filename="rv_control_core_start_session.json", source_dataset="core", source_file="core_pass_01_sync_after_start.json", family="control_core", probe_class="control", drift_pattern="none", rag_targets=["core/5.2.3.2", "core/5.3.4.1.5"], expected_repair_action="no_repair", retrieval_query_hint="StartSession SyncSession session startup HostSessionID SPSessionID"))
    add(case_from_source(filename="rv_control_core_auth_trylimit.json", source_dataset="core", source_file="core_pass_43_trylimit_locks_user.json", family="control_core", probe_class="control", drift_pattern="none", rag_targets=["core/5.3.4.1.14", "core/5.3.4.1.1.2"], expected_repair_action="no_repair", retrieval_query_hint="Authenticate C_PIN TryLimit authority locked out"))
    add(case_from_source(filename="rv_control_core_table_set.json", source_dataset="core", source_file="core_pass_86_set_without_values_noop_success.json", family="control_core", probe_class="control", drift_pattern="none", rag_targets=["core/5.3.4.2.6"], expected_repair_action="no_repair", retrieval_query_hint="Set method table values modify table"))
    add(case_from_source(filename="rv_control_opal_activate.json", source_dataset="opal", source_file="opal_pass_01_activate_sid_adminsp.json", family="control_opal", probe_class="control", drift_pattern="none", rag_targets=["opal/5.1.1", "opal/4.2.1.5"], expected_repair_action="no_repair", retrieval_query_hint="Activate Admin SP SID AccessControl LockingSP"))
    add(case_from_source(filename="rv_control_opal_mbr.json", source_dataset="opal", source_file="opal_pass_59_mbr_byte_set_bytes.json", family="control_opal", probe_class="control", drift_pattern="none", rag_targets=["opal/4.3.5.4", "core/5.7.3.6"], expected_repair_action="no_repair", retrieval_query_hint="MBR byte table write locking range global"))
    add(case_from_source(filename="rv_control_cross_sid_scope.json", source_dataset="cross", source_file="cross_pass_02_sid_not_valid_locking_sp_authority.json", family="control_cross", probe_class="control", drift_pattern="none", rag_targets=["opal/4.2", "opal/4.3.1", "core/5.2.3.1"], expected_repair_action="no_repair", retrieval_query_hint="SID AdminSP only LockingSP authority StartSession"))
    add(case_from_source(filename="rv_control_cross_revertsp.json", source_dataset="cross", source_file="cross_pass_09_revertsp_locking_admin1_keep_global.json", family="control_cross", probe_class="control", drift_pattern="none", rag_targets=["opal/5.1.3.2", "opal/5.1.3.3"], expected_repair_action="no_repair", retrieval_query_hint="RevertSP KeepGlobalRangeKey global range key"))

    add(case_from_source(filename="rv_control_core_close_session.json", source_dataset="core", source_file="core_pass_03_close_open_session.json", family="control_core", probe_class="control", drift_pattern="none", rag_targets=["core/5.2.3.5"], expected_repair_action="no_repair", retrieval_query_hint="CloseSession open session valid close session"))
    add(case_from_source(filename="rv_control_core_getclock.json", source_dataset="core", source_file="core_pass_100_getclock_readonly.json", family="control_core", probe_class="control", drift_pattern="none", rag_targets=["core/5.5.4.1"], expected_repair_action="no_repair", retrieval_query_hint="GetClock read only ClockTime method"))
    add(case_from_source(filename="rv_control_opal_locking_get.json", source_dataset="opal", source_file="opal_pass_26_locking_get_reflects_state.json", family="control_opal", probe_class="control", drift_pattern="none", rag_targets=["opal/4.3.5.2", "opal/4.3.1.7"], expected_repair_action="no_repair", retrieval_query_hint="Locking Get ReadLocked WriteLocked state"))
    add(case_from_source(filename="rv_control_opal_mbr_get.json", source_dataset="opal", source_file="opal_pass_83_mbr_byte_get_readonly.json", family="control_opal", probe_class="control", drift_pattern="none", rag_targets=["opal/4.3.5.3.1", "opal/5.3.1.2"], expected_repair_action="no_repair", retrieval_query_hint="MBR byte table Get readonly anybody authorized"))
    add(case_from_source(filename="rv_control_cross_auth_resets_tries.json", source_dataset="cross", source_file="cross_pass_07_auth_success_resets_tries.json", family="control_cross", probe_class="control", drift_pattern="none", rag_targets=["core/5.3.4.1.14", "core/5.3.4.1.1.2", "opal/4.3.1.9"], expected_repair_action="no_repair", retrieval_query_hint="Authenticate success resets tries C_PIN TryLimit"))
    add(case_from_source(filename="rv_control_cross_dataremoval.json", source_dataset="cross", source_file="cross_pass_13_datarmv_set_active_mech_authorized.json", family="control_cross", probe_class="control", drift_pattern="none", rag_targets=["opal/4.2.6.1.1", "core/5.3.3.7"], expected_repair_action="no_repair", retrieval_query_hint="DataRemovalMechanism ActiveDataRemovalMechanism Set authorized"))

    add(case_from_source(filename="rv_control_core_synctrusted.json", source_dataset="core", source_file="core_pass_74_synctrusted_after_starttrusted.json", family="control_core", probe_class="control", drift_pattern="none", rag_targets=["core/5.2.3.3", "core/5.2.3.4", "core/3.3.7.1.4"], expected_repair_action="no_repair", retrieval_query_hint="SyncTrustedSession StartTrustedSession trusted session startup"))
    add(case_from_source(filename="rv_control_core_startsession_sync_ids.json", source_dataset="core", source_file="core_pass_96_startsession_sync_ids_present.json", family="control_core", probe_class="control", drift_pattern="none", rag_targets=["core/5.2.3.1", "core/5.2.3.2", "core/5.2.3.2.1"], expected_repair_action="no_repair", retrieval_query_hint="StartSession SyncSession HostSessionID SPSessionID sync identifiers"))
    add(case_from_source(filename="rv_control_core_discovery_optional_lengths.json", source_dataset="core", source_file="core_pass_136_discovery_optional_descriptor_lengths.json", family="control_core", probe_class="control", drift_pattern="none", rag_targets=["opal/3.1.1.4", "opal/3.1.1.5"], expected_repair_action="no_repair", retrieval_query_hint="Level 0 Discovery optional Geometry DataRemoval descriptor lengths"))
    add(case_from_source(filename="rv_control_opal_lockonreset.json", source_dataset="opal", source_file="opal_pass_66_lockonreset_locks_range.json", family="control_opal", probe_class="control", drift_pattern="none", rag_targets=["opal/4.3.5.2.2", "opal/3.3.5.1"], expected_repair_action="no_repair", retrieval_query_hint="LockOnReset sets ReadLocked WriteLocked reset event"))
    add(case_from_source(filename="rv_control_opal_discovery_enabled.json", source_dataset="opal", source_file="opal_pass_70_discovery_enabled_active.json", family="control_opal", probe_class="control", drift_pattern="none", rag_targets=["opal/3.1.1.3", "opal/3.1.1.3.1"], expected_repair_action="no_repair", retrieval_query_hint="Level 0 Discovery LockingEnabled active LockingSP"))
    add(case_from_source(filename="rv_control_cross_sid_pin_copy_boundary.json", source_dataset="cross", source_file="cross_pass_05_sid_pin_change_no_admin1_update.json", family="control_cross", probe_class="control", drift_pattern="none", rag_targets=["opal/5.1.1.2", "opal/5.2.2.3.2", "opal/4.2.1.8"], expected_repair_action="no_repair", retrieval_query_hint="SID PIN copy Admin1 initial Activate only later SID change boundary"))

    # Repair-positive parser drift: labels stay source-invariant; metric is parser/RAG behavior.
    add(case_from_source(filename="rv_probe_core_startsession_alias.json", source_dataset="core", source_file="core_pass_01_sync_after_start.json", family="probe_core", probe_class="repair_positive", drift_pattern="unknown_method_name_with_uid", rag_targets=["core/5.2.3.1", "core/5.3.4.1.5"], expected_repair_action="repair_event", mutation="unknown_method_name", mutation_arg="Start Session Negotiation", retrieval_query_hint="StartSession session startup HostSessionID SPID Write core 5.3.4.1.5"))
    add(case_from_source(filename="rv_probe_core_auth_flat_args.json", source_dataset="core", source_file="core_pass_43_trylimit_locks_user.json", family="probe_core", probe_class="repair_positive", drift_pattern="args_serialized_as_string", rag_targets=["core/5.3.4.1.14", "core/5.3.4.1.1.2"], expected_repair_action="repair_event", mutation="string_args", retrieval_query_hint="Authenticate explicit authentication C_PIN TryLimit AuthorityLockedOut"))
    add(case_from_source(filename="rv_probe_core_set_object_conflict.json", source_dataset="core", source_file="core_pass_86_set_without_values_noop_success.json", family="probe_core", probe_class="repair_positive", drift_pattern="object_name_uid_conflict", rag_targets=["core/5.3.4.2.6", "core/5.3.4.2"], expected_repair_action="repair_event", mutation="name_uid_conflict", mutation_arg="MBRControl", retrieval_query_hint="Set Method table modification Values Where object table"))
    add(case_from_source(filename="rv_probe_core_random_status_text.json", source_dataset="core", source_file="core_pass_25_random_negative_count.json", family="probe_core", probe_class="repair_positive", drift_pattern="ambiguous_status_text", rag_targets=["core/5.6.4.1", "core/5.6.4.1.2"], expected_repair_action="repair_event", mutation="status_text", mutation_arg="STATUS_CODE_DRIFT_UNKNOWN", retrieval_query_hint="Random Count invalid parameter fails random number method"))

    add(case_from_source(filename="rv_probe_opal_activate_alias.json", source_dataset="opal", source_file="opal_pass_01_activate_sid_adminsp.json", family="probe_opal", probe_class="repair_positive", drift_pattern="unknown_method_name_with_uid", rag_targets=["opal/5.1.1", "opal/5.1.1.2"], expected_repair_action="repair_event", mutation="unknown_method_name", mutation_arg="Activate Locking SP", retrieval_query_hint="Activate Admin Template SP Object Method side effects of Activate"))
    add(case_from_source(filename="rv_probe_opal_revertsp_flat_args.json", source_dataset="opal", source_file="opal_pass_14_revertsp_keep_global_ok.json", family="probe_opal", probe_class="repair_positive", drift_pattern="args_serialized_as_string", rag_targets=["opal/5.1.3.2", "opal/5.1.3.3"], expected_repair_action="repair_event", mutation="string_args", retrieval_query_hint="RevertSP KeepGlobalRangeKey effects of RevertSP Locking Template"))
    add(case_from_source(filename="rv_probe_opal_locking_name_conflict.json", source_dataset="opal", source_file="opal_pass_82_done_on_reset_power_cycle.json", family="probe_opal", probe_class="repair_positive", drift_pattern="object_name_uid_conflict", rag_targets=["opal/4.3.5.2.2", "core/5.7.2.2.10"], expected_repair_action="repair_event", mutation="name_uid_conflict", mutation_arg="C_PIN_SID", retrieval_query_hint="LockOnReset restrictions Locking object table ReadLocked WriteLocked"))
    add(case_from_source(filename="rv_probe_opal_mbr_status_text.json", source_dataset="opal", source_file="opal_pass_59_mbr_byte_set_bytes.json", family="probe_opal", probe_class="repair_positive", drift_pattern="ambiguous_status_text", rag_targets=["opal/4.3.5.4", "core/5.7.3.6"], expected_repair_action="repair_event", mutation="status_text", mutation_arg="STATUS_CODE_DRIFT_UNKNOWN", retrieval_query_hint="MBR byte table write data locking range global unlocked"))

    add(case_from_source(filename="rv_probe_cross_sid_alias.json", source_dataset="cross", source_file="cross_pass_02_sid_not_valid_locking_sp_authority.json", family="probe_cross", probe_class="repair_positive", drift_pattern="unknown_method_name_with_uid", rag_targets=["opal/4.2", "opal/4.3.1", "core/5.2.3.1"], expected_repair_action="repair_event", mutation="unknown_method_name", mutation_arg="Open LockingSP As SID", retrieval_query_hint="SID authority AdminSP only LockingSP StartSession not valid authority"))
    add(case_from_source(filename="rv_probe_cross_trylimit_conflict.json", source_dataset="cross", source_file="cross_pass_01_trylimit_cross_sp_isolation.json", family="probe_cross", probe_class="repair_positive", drift_pattern="object_name_uid_conflict", rag_targets=["core/5.3.4.1.14", "core/5.2.3.1", "opal/4.2.1.8", "opal/4.3.1.9"], expected_repair_action="repair_event", mutation="name_uid_conflict", mutation_arg="Locking_GlobalRange", retrieval_query_hint="Authenticate TryLimit C_PIN AdminSP LockingSP isolation"))
    add(case_from_source(filename="rv_probe_cross_revertsp_flat_args.json", source_dataset="cross", source_file="cross_pass_09_revertsp_locking_admin1_keep_global.json", family="probe_cross", probe_class="repair_positive", drift_pattern="args_serialized_as_string", rag_targets=["opal/5.1.3.2", "opal/5.1.3.3", "core/5.7.3.7.2"], expected_repair_action="repair_event", mutation="string_args", retrieval_query_hint="RevertSP KeepGlobalRangeKey ActiveKey global range preservation"))

    add(case_from_source(filename="rv_probe_core_close_alias.json", source_dataset="core", source_file="core_pass_03_close_open_session.json", family="probe_core", probe_class="repair_positive", drift_pattern="unknown_method_name_with_uid", rag_targets=["core/5.2.3.5"], expected_repair_action="repair_event", mutation="unknown_method_name", mutation_arg="Terminate Secure Session", retrieval_query_hint="CloseSession method open session close session core 5.2.3.5"))
    add(case_from_source(filename="rv_probe_core_hash_flat_args.json", source_dataset="core", source_file="core_pass_111_hash_after_init_succeeds.json", family="probe_core", probe_class="repair_positive", drift_pattern="args_serialized_as_string", rag_targets=["core/5.6.4.12", "core/5.6.4.11"], expected_repair_action="repair_event", mutation="string_args", retrieval_query_hint="Hash method after HashInit data stream hash object"))
    add(case_from_source(filename="rv_probe_core_next_conflict.json", source_dataset="core", source_file="core_pass_106_next_count_zero_valid.json", family="probe_core", probe_class="repair_positive", drift_pattern="object_name_uid_conflict", rag_targets=["core/5.3.3.8", "core/5.3.3.8.2"], expected_repair_action="repair_event", mutation="name_uid_conflict", mutation_arg="Locking_GlobalRange", retrieval_query_hint="Next method object table Count zero valid iteration"))
    add(case_from_source(filename="rv_probe_core_getclock_status_text.json", source_dataset="core", source_file="core_pass_100_getclock_readonly.json", family="probe_core", probe_class="repair_positive", drift_pattern="ambiguous_status_text", rag_targets=["core/5.5.4.1", "core/5.5.4"], expected_repair_action="repair_event", mutation="status_text", mutation_arg="STATUS_CODE_DRIFT_UNKNOWN", retrieval_query_hint="GetClock readonly ClockTime status success method"))

    add(case_from_source(filename="rv_probe_opal_revert_alias.json", source_dataset="opal", source_file="opal_pass_09_revert_lockingsp_inactive.json", family="probe_opal", probe_class="repair_positive", drift_pattern="unknown_method_name_with_uid", rag_targets=["opal/5.1.2", "opal/5.2.2.2.2"], expected_repair_action="repair_event", mutation="unknown_method_name", mutation_arg="Factory Reset Locking SP", retrieval_query_hint="Revert LockingSP Manufactured Inactive SID PSID AdminSP opal 5.1.2 Revert method"))
    add(case_from_source(filename="rv_probe_opal_auth_flat_args.json", source_dataset="opal", source_file="opal_pass_50_authenticate_wrong_pin.json", family="probe_opal", probe_class="repair_positive", drift_pattern="args_serialized_as_string", rag_targets=["core/5.3.4.1.14", "opal/4.3.1.8"], expected_repair_action="repair_event", mutation="string_args", retrieval_query_hint="Authenticate wrong PIN returns false User authority C_PIN"))
    add(case_from_source(filename="rv_probe_opal_locking_set_conflict.json", source_dataset="opal", source_file="opal_pass_21_locking_admin_set_flags.json", family="probe_opal", probe_class="repair_positive", drift_pattern="object_name_uid_conflict", rag_targets=["opal/4.3.5.2", "opal/4.3.1.7"], expected_repair_action="repair_event", mutation="name_uid_conflict", mutation_arg="C_PIN_SID", retrieval_query_hint="Locking range Set RangeStart RangeLength ReadLocked WriteLocked"))
    add(case_from_source(filename="rv_probe_opal_genkey_status_text.json", source_dataset="opal", source_file="opal_pass_68_genkey_changes_range_data.json", family="probe_opal", probe_class="repair_positive", drift_pattern="ambiguous_status_text", rag_targets=["opal/4.3.5.5", "opal/4.3.7", "opal/4.3.5.2", "core/5.3.3.16", "core/5.7.3.5"], expected_repair_action="repair_event", mutation="status_text", mutation_arg="STATUS_CODE_DRIFT_UNKNOWN", retrieval_query_hint="GenKey range key changes data reads media key locking range opal 4.3.5.5"))

    add(case_from_source(filename="rv_probe_cross_activate_alias.json", source_dataset="cross", source_file="cross_pass_03_activate_requires_sid_auth.json", family="probe_cross", probe_class="repair_positive", drift_pattern="unknown_method_name_with_uid", rag_targets=["opal/5.1.1.1", "opal/5.1.1.2", "core/5.4.3.2"], expected_repair_action="repair_event", mutation="unknown_method_name", mutation_arg="Manufacture Locking SP", retrieval_query_hint="Activate LockingSP authenticated AdminSP SID activation copies PIN"))
    add(case_from_source(filename="rv_probe_cross_sid_auth_status_text.json", source_dataset="cross", source_file="cross_pass_12_authenticate_sid_in_locking_sp_returns_false.json", family="probe_cross", probe_class="repair_positive", drift_pattern="ambiguous_status_text", rag_targets=["core/5.3.4.1.14", "opal/4.2", "opal/4.3.1"], expected_repair_action="repair_event", mutation="status_text", mutation_arg="STATUS_CODE_DRIFT_UNKNOWN", retrieval_query_hint="Authenticate SID_UID in LockingSP returns false SID not LockingSP authority"))
    add(case_from_source(filename="rv_probe_cross_dataremoval_flat_args.json", source_dataset="cross", source_file="cross_pass_13_datarmv_set_active_mech_authorized.json", family="probe_cross", probe_class="repair_positive", drift_pattern="args_serialized_as_string", rag_targets=["opal/4.2.6.1.1", "core/5.3.3.7"], expected_repair_action="repair_event", mutation="string_args", retrieval_query_hint="DataRemovalMechanism ActiveDataRemovalMechanism Set authorized"))
    add(case_from_source(filename="rv_probe_cross_userclass_alias.json", source_dataset="cross", source_file="cross_pass_11_users_class_not_directly_authenticated.json", family="probe_cross", probe_class="repair_positive", drift_pattern="unknown_method_name_with_uid", rag_targets=["core/5.3.4.1.2", "opal/4.3.1.8"], expected_repair_action="repair_event", mutation="unknown_method_name", mutation_arg="Authenticate Users Class", retrieval_query_hint="Users class authority Authenticate must target User instance"))

    add(case_from_source(filename="rv_probe_core_startsession_bad_host_status_text.json", source_dataset="core", source_file="core_pass_71_startsession_negative_host_id_rejected.json", family="probe_core", probe_class="repair_positive", drift_pattern="ambiguous_status_text", rag_targets=["core/5.2.3.1", "core/5.2.3.1.1", "core/5.1.3.82"], expected_repair_action="repair_event", mutation="status_text", mutation_arg="STATUS_CODE_DRIFT_UNKNOWN", retrieval_query_hint="StartSession HostSessionID unsigned integer negative rejected"))
    add(case_from_source(filename="rv_probe_core_object_set_flat_args.json", source_dataset="core", source_file="core_pass_80_object_table_set_missing_where_rejected.json", family="probe_core", probe_class="repair_positive", drift_pattern="args_serialized_as_string", rag_targets=["core/5.3.3.7.1", "core/5.3.3.7.1.1", "core/5.3.4.2.6", "core/5.1.4.2.3", "opal/5.3.1.2.2"], expected_repair_action="repair_event", mutation="string_args", retrieval_query_hint="Object table Set requires Where UID Cellblock table row"))
    add(case_from_source(filename="rv_probe_core_getacl_conflict.json", source_dataset="core", source_file="core_pass_97_getacl_missing_methodid_rejected.json", family="probe_core", probe_class="repair_positive", drift_pattern="object_name_uid_conflict", rag_targets=["core/5.3.3.13", "core/5.3.3.13.1", "core/5.3.3.13.2"], expected_repair_action="repair_event", mutation="name_uid_conflict", mutation_arg="Locking_GlobalRange", retrieval_query_hint="GetACL requires InvokingID MethodID UID parameters"))
    add(case_from_source(filename="rv_probe_core_dynamic_acl_alias.json", source_dataset="core", source_file="core_pass_132_dynamic_getsetacl_anybody_set.json", family="probe_core", probe_class="repair_positive", drift_pattern="unknown_method_name_with_uid", rag_targets=["core/5.3.3.1", "core/5.3.3.7", "core/5.3.4.2", "opal/4.3.1.6", "core/5.1.3.2"], expected_repair_action="repair_event", mutation="unknown_method_name", mutation_arg="Dynamic ACL Set", retrieval_query_hint="dynamic table GetSetACL ACE Anybody Set authorization"))

    add(case_from_source(filename="rv_probe_opal_revertsp_readonly_status_text.json", source_dataset="opal", source_file="opal_pass_75_revert_sp_readonly_fails.json", family="probe_opal", probe_class="repair_positive", drift_pattern="ambiguous_status_text", rag_targets=["opal/5.1.3.1", "opal/5.1.3.2", "core/5.3.3.11"], expected_repair_action="repair_event", mutation="status_text", mutation_arg="STATUS_CODE_DRIFT_UNKNOWN", retrieval_query_hint="RevertSP requires authenticated write session readonly fails"))
    add(case_from_source(filename="rv_probe_opal_user_trylimit_flat_args.json", source_dataset="opal", source_file="opal_pass_78_user1_trylimit_lockout.json", family="probe_opal", probe_class="repair_positive", drift_pattern="args_serialized_as_string", rag_targets=["opal/4.3.1.9", "core/5.3.4.1.14", "core/5.3.4.1.14.1", "core/5.3.4.1.1.2"], expected_repair_action="repair_event", mutation="string_args", retrieval_query_hint="User1 TryLimit wrong PIN lockout Authenticate C_PIN"))
    add(case_from_source(filename="rv_probe_opal_authority_disable_conflict.json", source_dataset="opal", source_file="opal_pass_81_authority_disable_mid_trajectory.json", family="probe_opal", probe_class="repair_positive", drift_pattern="object_name_uid_conflict", rag_targets=["opal/4.3.1.7", "opal/4.3.1.8", "core/5.3.4.1.5", "core/5.2.3.1", "opal/4.1.1.2"], expected_repair_action="repair_event", mutation="name_uid_conflict", mutation_arg="MBRControl", retrieval_query_hint="Authority disable mid trajectory StartSession later rejected"))
    add(case_from_source(filename="rv_probe_opal_revertsp_write_locked_flat_args.json", source_dataset="opal", source_file="opal_pass_87_revertsp_keepglobal_only_write_locked.json", family="probe_opal", probe_class="repair_positive", drift_pattern="args_serialized_as_string", rag_targets=["opal/5.1.3.1", "opal/5.1.3.2", "opal/5.1.3.3"], expected_repair_action="repair_event", mutation="string_args", retrieval_query_hint="RevertSP KeepGlobalRangeKey succeeds only WriteLocked Global Range"))

    add(case_from_source(filename="rv_probe_cross_revert_adminsp_status_text.json", source_dataset="cross", source_file="cross_pass_04_revert_requires_adminsp_sid.json", family="probe_cross", probe_class="repair_positive", drift_pattern="ambiguous_status_text", rag_targets=["opal/5.1.2.1", "opal/5.2.2.2.2", "core/5.3.3.11"], expected_repair_action="repair_event", mutation="status_text", mutation_arg="STATUS_CODE_DRIFT_UNKNOWN", retrieval_query_hint="Revert LockingSP requires AdminSP SID authenticated path"))
    add(case_from_source(filename="rv_probe_cross_trylimit_zero_flat_args.json", source_dataset="cross", source_file="cross_pass_06_trylimit_zero_means_unlimited.json", family="probe_cross", probe_class="repair_positive", drift_pattern="args_serialized_as_string", rag_targets=["core/5.3.4.1.14", "opal/4.2.1.8", "opal/4.3.1.9", "core/5.2.3.1", "core/5.1.5.2"], expected_repair_action="repair_event", mutation="string_args", retrieval_query_hint="TryLimit zero means unlimited failures Authenticate succeeds"))
    add(case_from_source(filename="rv_probe_cross_admin1_pin_get_conflict.json", source_dataset="cross", source_file="cross_pass_14_admin1_pin_get_returns_not_authorized.json", family="probe_cross", probe_class="repair_positive", drift_pattern="object_name_uid_conflict", rag_targets=["core/5.3.4.2.1", "opal/4.2.1.7", "opal/4.3.1.8"], expected_repair_action="repair_event", mutation="name_uid_conflict", mutation_arg="Locking_GlobalRange", retrieval_query_hint="C_PIN_Admin1 PIN Get returns NOT_AUTHORIZED protected PIN column"))
    add(case_from_source(filename="rv_probe_cross_sid_pin_copy_alias.json", source_dataset="cross", source_file="cross_pass_05_sid_pin_change_no_admin1_update.json", family="probe_cross", probe_class="repair_positive", drift_pattern="unknown_method_name_with_uid", rag_targets=["opal/5.1.1.2", "opal/5.2.2.3.2", "opal/4.2.1.8", "core/5.3.4.1.5"], expected_repair_action="repair_event", mutation="unknown_method_name", mutation_arg="Refresh Admin1 From SID", retrieval_query_hint="SID PIN copy Admin1 only initial Activate later SID update no copy"))

    # Primary no-repair and needs-rule-patch probes: visible to parser_debug, not state_machine gate.
    add(case_from_source(filename="rv_probe_no_repair_core_clean_decoy.json", source_dataset="core", source_file="core_pass_17_get_package_credential.json", family="probe_core", probe_class="no_repair", drift_pattern="clean_lexical_decoy", rag_targets=["core/5.3.4.2", "core/5.3.4.2.6"], expected_repair_action="no_repair", retrieval_query_hint="Get package credential clean successful no parser drift"))
    add(case_from_source(filename="rv_probe_no_repair_opal_clean_decoy.json", source_dataset="opal", source_file="opal_pass_62_datastore_byte_set_auth.json", family="probe_opal", probe_class="no_repair", drift_pattern="clean_lexical_decoy", rag_targets=["opal/4.3.8.1", "opal/5.3"], expected_repair_action="no_repair", retrieval_query_hint="DataStore byte table successful clean no parser drift"))
    add(case_from_source(filename="rv_probe_rule_patch_core_table_delete.json", source_dataset="core", source_file="core_pass_68_deletesp_authorized.json", family="probe_core", probe_class="needs_rule_patch", drift_pattern="semantic_rule_gap_sentinel", rag_targets=["core/5.3.4.4", "core/4.3"], expected_repair_action="needs_rule_patch", retrieval_query_hint="DeleteSP authorized life cycle state transition semantic rule"))
    add(case_from_source(filename="rv_probe_rule_patch_cross_genkey.json", source_dataset="cross", source_file="cross_pass_08_genkey_in_locking_sp_session.json", family="probe_cross", probe_class="needs_rule_patch", drift_pattern="semantic_rule_gap_sentinel", rag_targets=["core/5.7.3.7.2", "opal/4.3.5.5"], expected_repair_action="needs_rule_patch", retrieval_query_hint="GenKey media key locking range ActiveKey semantic rule"))

    add(case_from_source(filename="rv_probe_no_repair_core_getclock_decoy.json", source_dataset="core", source_file="core_pass_100_getclock_readonly.json", family="probe_core", probe_class="no_repair", drift_pattern="clean_lexical_decoy", rag_targets=["core/5.5.4.1"], expected_repair_action="no_repair", retrieval_query_hint="GetClock readonly clean no parser drift"))
    add(case_from_source(filename="rv_probe_no_repair_core_getfreespace_decoy.json", source_dataset="core", source_file="core_pass_48_get_free_space_readonly.json", family="probe_core", probe_class="no_repair", drift_pattern="clean_lexical_decoy", rag_targets=["core/5.3.3.9"], expected_repair_action="no_repair", retrieval_query_hint="GetFreeSpace readonly clean no parser drift"))
    add(case_from_source(filename="rv_probe_no_repair_opal_mbr_get_decoy.json", source_dataset="opal", source_file="opal_pass_83_mbr_byte_get_readonly.json", family="probe_opal", probe_class="no_repair", drift_pattern="clean_lexical_decoy", rag_targets=["opal/4.3.5.3.1", "opal/5.3.1.2"], expected_repair_action="no_repair", retrieval_query_hint="MBR byte Get readonly clean no parser drift"))
    add(case_from_source(filename="rv_probe_no_repair_cross_auth_reset_decoy.json", source_dataset="cross", source_file="cross_pass_07_auth_success_resets_tries.json", family="probe_cross", probe_class="no_repair", drift_pattern="clean_lexical_decoy", rag_targets=["core/5.3.4.1.14", "core/5.3.4.1.1.2"], expected_repair_action="no_repair", retrieval_query_hint="Authenticate success resets tries clean no parser drift"))
    add(case_from_source(filename="rv_probe_rule_patch_core_delete_deferred.json", source_dataset="core", source_file="core_pass_70_delete_sp_deferred_then_session_rejected.json", family="probe_core", probe_class="needs_rule_patch", drift_pattern="semantic_rule_gap_sentinel", rag_targets=["core/5.4.4.2", "core/5.3.4.4"], expected_repair_action="needs_rule_patch", retrieval_query_hint="Delete SP deferred session close lifecycle semantic rule"))
    add(case_from_source(filename="rv_probe_rule_patch_opal_genkey_repeated.json", source_dataset="opal", source_file="opal_pass_84_genkey_repeated_changes_data.json", family="probe_opal", probe_class="needs_rule_patch", drift_pattern="semantic_rule_gap_sentinel", rag_targets=["opal/4.3.5.5", "opal/4.3.7", "core/5.3.3.16"], expected_repair_action="needs_rule_patch", retrieval_query_hint="Repeated GenKey invalidates prior data media key semantic rule"))
    add(case_from_source(filename="rv_probe_rule_patch_cross_revert_inactive.json", source_dataset="cross", source_file="cross_pass_15_revert_returns_locking_sp_inactive.json", family="probe_cross", probe_class="needs_rule_patch", drift_pattern="semantic_rule_gap_sentinel", rag_targets=["opal/5.1.2.1", "opal/5.2.2.2"], expected_repair_action="needs_rule_patch", retrieval_query_hint="Revert LockingSP returns Manufactured Inactive semantic state rule"))

    add(case_from_source(filename="rv_probe_no_repair_core_synctrusted_decoy.json", source_dataset="core", source_file="core_pass_74_synctrusted_after_starttrusted.json", family="probe_core", probe_class="no_repair", drift_pattern="clean_lexical_decoy", rag_targets=["core/5.2.3.3", "core/5.2.3.4"], expected_repair_action="no_repair", retrieval_query_hint="SyncTrustedSession clean no parser drift"))
    add(case_from_source(filename="rv_probe_no_repair_core_discovery_decoy.json", source_dataset="core", source_file="core_pass_136_discovery_optional_descriptor_lengths.json", family="probe_core", probe_class="no_repair", drift_pattern="clean_lexical_decoy", rag_targets=["opal/3.1.1.4", "opal/3.1.1.5"], expected_repair_action="no_repair", retrieval_query_hint="Level 0 Discovery optional descriptors clean no parser drift"))
    add(case_from_source(filename="rv_probe_no_repair_opal_lockonreset_decoy.json", source_dataset="opal", source_file="opal_pass_66_lockonreset_locks_range.json", family="probe_opal", probe_class="no_repair", drift_pattern="clean_lexical_decoy", rag_targets=["opal/4.3.5.2.2", "opal/3.3.5.1"], expected_repair_action="no_repair", retrieval_query_hint="LockOnReset clean no parser drift"))
    add(case_from_source(filename="rv_probe_no_repair_opal_discovery_decoy.json", source_dataset="opal", source_file="opal_pass_70_discovery_enabled_active.json", family="probe_opal", probe_class="no_repair", drift_pattern="clean_lexical_decoy", rag_targets=["opal/3.1.1.3", "opal/3.1.1.3.1"], expected_repair_action="no_repair", retrieval_query_hint="LockingEnabled Discovery clean no parser drift"))
    add(case_from_source(filename="rv_probe_no_repair_cross_sid_copy_decoy.json", source_dataset="cross", source_file="cross_pass_05_sid_pin_change_no_admin1_update.json", family="probe_cross", probe_class="no_repair", drift_pattern="clean_lexical_decoy", rag_targets=["opal/5.1.1.2", "opal/5.2.2.3.2"], expected_repair_action="no_repair", retrieval_query_hint="SID PIN copy boundary clean no parser drift"))
    add(case_from_source(filename="rv_probe_rule_patch_core_trusted_session_pair.json", source_dataset="core", source_file="core_pass_74_synctrusted_after_starttrusted.json", family="probe_core", probe_class="needs_rule_patch", drift_pattern="semantic_rule_gap_sentinel", rag_targets=["core/5.2.3.3", "core/5.2.3.4", "core/3.3.7.1.4"], expected_repair_action="needs_rule_patch", retrieval_query_hint="Trusted session StartTrusted SyncTrusted sequence semantic rule"))
    add(case_from_source(filename="rv_probe_rule_patch_core_dynamic_acl_effect.json", source_dataset="core", source_file="core_pass_132_dynamic_getsetacl_anybody_set.json", family="probe_core", probe_class="needs_rule_patch", drift_pattern="semantic_rule_gap_sentinel", rag_targets=["core/5.3.3.1", "core/5.3.4.3.1"], expected_repair_action="needs_rule_patch", retrieval_query_hint="Dynamic AddACE GetSetACL Anybody grants Set semantic ACL rule"))
    add(case_from_source(filename="rv_probe_rule_patch_opal_lockonreset_effect.json", source_dataset="opal", source_file="opal_pass_66_lockonreset_locks_range.json", family="probe_opal", probe_class="needs_rule_patch", drift_pattern="semantic_rule_gap_sentinel", rag_targets=["opal/4.3.5.2.2", "opal/3.3.5.1"], expected_repair_action="needs_rule_patch", retrieval_query_hint="LockOnReset sets locked flags on reset semantic state rule"))
    add(case_from_source(filename="rv_probe_rule_patch_cross_sid_copy_once.json", source_dataset="cross", source_file="cross_pass_05_sid_pin_change_no_admin1_update.json", family="probe_cross", probe_class="needs_rule_patch", drift_pattern="semantic_rule_gap_sentinel", rag_targets=["opal/5.1.1.2", "opal/5.2.2.3.2"], expected_repair_action="needs_rule_patch", retrieval_query_hint="SID PIN copied to Admin1 only on initial Activate semantic rule"))

    # Out-of-band unsupported state-effect sentinels.
    sentinels = [
        ("rv_sentinel_state_effect_power_cycle.json", "TCG_RESET", "pass", ["opal/3.3.5.2", "opal/3.3.6"], "TCG Reset Events storage device reset reset_like_event"),
        ("rv_sentinel_state_effect_stack_reset.json", "STACK_RESET", "pass", ["opal/3.3.6", "core/3.3.4.7"], "Protocol Stack Reset Commands reset_like_event close sessions"),
        ("rv_sentinel_state_effect_if_recv.json", "IF_RECV", "pass", ["core/3.3.6.2", "opal/3.1.1"], "Level 0 Discovery IF_RECV feature descriptors state effect"),
        ("rv_sentinel_state_effect_hot_reset.json", "HOT_RESET", "pass", ["opal/3.3.5.1", "opal/3.3.6"], "Hot reset abort sessions lock on reset state effect"),
        ("rv_sentinel_state_effect_psid_revert.json", "PSID_REVERT", "pass", ["opal/5.1.2", "opal/5.2.2.2"], "PSID Revert out of band administrative reset state effect"),
        ("rv_sentinel_state_effect_firmware_activate.json", "FIRMWARE_ACTIVATE", "pass", ["core/3.3.4.7", "opal/3.3.6"], "Firmware activation out of band reset-like state effect"),
        ("rv_sentinel_state_effect_media_rekey.json", "MEDIA_REKEY", "pass", ["opal/4.3.5.5", "opal/4.3.7"], "Out of band media rekey changes locking range data state effect"),
    ]
    for filename, command, label, refs, hint in sentinels:
        cases.append(
            {
                "filename": filename,
                "label": label,
                "steps": sentinel_command(command, label, hint),
                "concept": f"Out-of-band state_effect sentinel for {command}; not a primary threshold case.",
                "refs": refs,
                "family": "state_effect_sentinel",
                "probe_class": "state_effect_sentinel",
                "drift_pattern": "unsupported_state_effect",
                "rag_targets": refs,
                "expected_repair_action": "state_effect",
                "metric_scope": "out_of_band",
                "base_case": None,
                "retrieval_query_hint": hint,
            }
        )

    return cases


def manifest_row(case: dict[str, Any]) -> dict[str, Any]:
    return {
        "filename": case["filename"],
        "label": case["label"],
        "concept": case["concept"],
        "refs": case["refs"],
        "family": case["family"],
        "probe_class": case["probe_class"],
        "drift_pattern": case["drift_pattern"],
        "rag_targets": case["rag_targets"],
        "expected_repair_action": case["expected_repair_action"],
        "metric_scope": case["metric_scope"],
        "base_case": case["base_case"],
        "retrieval_query_hint": case["retrieval_query_hint"],
    }


def write_cases(cases: list[dict[str, Any]]) -> None:
    TESTCASE_DIR.mkdir(parents=True, exist_ok=True)
    for stale in TESTCASE_DIR.glob("*.json"):
        stale.unlink()
    labels = []
    manifest = []
    for case in cases:
        (TESTCASE_DIR / case["filename"]).write_text(json.dumps(case["steps"], indent=2) + "\n", encoding="utf-8")
        labels.append({"filename": case["filename"], "label": case["label"]})
        manifest.append(manifest_row(case))
    LABELS.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in labels), encoding="utf-8")
    MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def check() -> list[str]:
    errors: list[str] = []
    if not LABELS.is_file():
        return [f"missing {LABELS}"]
    if not MANIFEST.is_file():
        return [f"missing {MANIFEST}"]
    labels = [json.loads(line) for line in LABELS.read_text(encoding="utf-8").splitlines() if line.strip()]
    manifest = load_json(MANIFEST)
    label_names = [row.get("filename") for row in labels]
    manifest_names = [row.get("filename") for row in manifest]
    if len(label_names) != len(set(label_names)):
        errors.append("duplicate filenames in label.jsonl")
    if label_names != manifest_names:
        errors.append("label.jsonl order/names do not match manifest.json")
    for row in labels:
        if row.get("label") not in {"pass", "fail"}:
            errors.append(f"invalid label for {row.get('filename')}: {row.get('label')}")
        path = TESTCASE_DIR / str(row.get("filename"))
        if not path.is_file():
            errors.append(f"missing testcase {path}")
            continue
        steps = load_json(path)
        indexes = [step.get("index") for step in steps if isinstance(step, dict)]
        if indexes != list(range(1, len(steps) + 1)):
            errors.append(f"non-contiguous indexes in {path.name}: {indexes}")
    required_fields = {"family", "probe_class", "drift_pattern", "rag_targets", "expected_repair_action", "metric_scope", "base_case"}
    for row in manifest:
        missing = sorted(required_fields - row.keys())
        if missing:
            errors.append(f"manifest {row.get('filename')} missing fields: {missing}")
        if row.get("metric_scope") == "primary" and row.get("probe_class") != "control":
            if not row.get("rag_targets") or not row.get("expected_repair_action"):
                errors.append(f"primary probe lacks RAG metadata: {row.get('filename')}")
        if row.get("probe_class") == "state_effect_sentinel" and row.get("metric_scope") != "out_of_band":
            errors.append(f"state_effect sentinel not out_of_band: {row.get('filename')}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="check existing generated files instead of rewriting")
    args = parser.parse_args()
    if not args.check:
        cases = build_cases()
        write_cases(cases)
        print(f"wrote {len(cases)} cases to {BASE}")
    errors = check()
    if errors:
        print("generation check failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    print("generation check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
