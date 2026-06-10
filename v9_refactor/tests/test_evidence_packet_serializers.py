import json
import unittest
from types import SimpleNamespace

from src.oracle import RuleResult
from src.packet_serializer import (
    ALLOWED_RISK_CODES,
    build_evidence_packet,
    make_risk_flag,
    serialize_normalized_events,
    serialize_llm_override_provenance,
    serialize_repair_provenance,
)
from src.state import initial_state
from src.state_facts_extractor import extract_state_facts


class StateFactsExtractorTest(unittest.TestCase):
    def test_extract_state_facts_is_strict_whitelist(self):
        state = initial_state()
        state["credentials"]["SID"] = "supersecret-pin"
        state["history"] = [{"raw": "leak"}]
        state["failed_observations"] = [{"raw_status": "leak"}]
        state["tables"] = {"secret": "leak"}
        state["session"]["pending_auth_challenge"] = "leak"

        facts = extract_state_facts(state)

        self.assertEqual(facts["meta"]["source_whitelist_version"], "state_facts_v1")
        self.assertEqual(
            set(facts),
            {
                "meta",
                "session",
                "credentials",
                "sp_lifecycle",
                "locking_sp_active",
                "locking_ranges",
                "key_generations_by_range",
                "capacity",
                "issued_sps",
            },
        )
        self.assertEqual(
            set(facts["session"]),
            {
                "open",
                "sp",
                "authority",
                "authorities",
                "write",
                "had_failure",
                "trusted",
                "host_session_id",
                "sp_session_id",
            },
        )
        blob = json.dumps(facts)
        for forbidden in ("history", "failed_observations", "tables", "_state_snapshot", "raw_status", "pending_auth_challenge"):
            self.assertNotIn(forbidden, blob)
        self.assertNotIn("supersecret-pin", blob)
        self.assertEqual(facts["credentials"]["SID"], "<redacted>")

    def test_extract_state_facts_exposes_bounded_capacity_facts(self):
        state = initial_state()
        state["sp_byte_space"]["AdminSP"] = {
            "sp": "AdminSP",
            "size": 1000,
            "size_in_use": 750,
            "free": 250,
            "source": "SPInfo.Get",
            "raw": "leak",
        }
        state["sp_issuance_space"] = {"free": 4096, "source": "TPerInfo.SpaceForIssuance", "raw": "leak"}
        state["table_capacity"]["0000000100000001"] = {
            "uid": "0000000100000001",
            "rows": 10,
            "rows_free": 2,
            "max_size": 12,
            "source": "Table.Get",
            "raw": "leak",
        }

        facts = extract_state_facts(state)

        self.assertEqual(
            facts["capacity"]["sp_byte_space"]["AdminSP"],
            {
                "sp": "AdminSP",
                "size": 1000,
                "size_in_use": 750,
                "free": 250,
                "source": "SPInfo.Get",
            },
        )
        self.assertEqual(
            facts["capacity"]["sp_issuance_space"],
            {"free": 4096, "source": "TPerInfo.SpaceForIssuance"},
        )
        self.assertEqual(
            facts["capacity"]["table_capacity"]["0000000100000001"],
            {
                "uid": "0000000100000001",
                "rows": 10,
                "rows_free": 2,
                "max_size": 12,
                "source": "Table.Get",
            },
        )
        self.assertNotIn("raw", json.dumps(facts))

    def test_extract_state_facts_preserves_concrete_issued_sp_size_blocks(self):
        state = initial_state()
        state["issued_sps"]["00000205000000AB"] = {
            "uid": "00000205000000AB",
            "sp": "SP_00AB",
            "size": 1024,
            "size_blocks": 1024,
            "source": "IssueSP",
        }

        facts = extract_state_facts(state)

        self.assertEqual(facts["issued_sps"]["00000205000000AB"]["size"], 1024)
        self.assertEqual(facts["issued_sps"]["00000205000000AB"]["size_blocks"], 1024)


class ProvenanceSerializationSafetyTest(unittest.TestCase):
    def test_repair_provenance_redacts_raw_model_reason(self):
        decision = SimpleNamespace(
            action="no_repair",
            confidence=0.0,
            reason="LLM repair output failed validation; raw=SECRET_MODEL_RESPONSE PIN_MARKER",
            event_patch={},
            state_patch={},
        )

        provenance = serialize_repair_provenance(enabled=True, attempted=True, decision=decision)
        blob = json.dumps(provenance)

        self.assertNotIn("SECRET_MODEL_RESPONSE", blob)
        self.assertNotIn("PIN_MARKER", blob)
        self.assertNotIn("raw=", blob)

    def test_llm_override_provenance_redacts_sensitive_decision_reason(self):
        decision = SimpleNamespace(
            verdict="fail",
            confidence=0.9,
            reason="contains challenge SECRET_MODEL_RESPONSE",
        )

        provenance = serialize_llm_override_provenance(
            enabled=True,
            considered=True,
            attempted=True,
            decision=decision,
            from_verdict="pass",
            to_verdict="pass",
        )
        blob = json.dumps(provenance)

        self.assertNotIn("SECRET_MODEL_RESPONSE", blob)
        self.assertNotIn("challenge", blob.lower())
        self.assertEqual(provenance["reason"], "<redacted>")

    def test_extract_state_facts_bounds_capacity_collections(self):
        state = initial_state()
        for index in range(3):
            state["sp_byte_space"][f"SP_{index}"] = {
                "sp": f"SP_{index}",
                "size": 100,
                "size_in_use": index,
                "free": 100 - index,
                "source": "SPInfo.Get",
            }

        facts = extract_state_facts(state, max_sp_byte_space_entries=2)

        self.assertTrue(facts["meta"]["facts_truncated"])
        self.assertTrue(facts["meta"]["truncation"]["sp_byte_space"])
        self.assertEqual(list(facts["capacity"]["sp_byte_space"]), ["SP_0", "SP_1"])

    def test_extract_state_facts_exposes_bounded_issued_sp_facts(self):
        state = initial_state()
        state["issued_sps"]["00000205000000AB"] = {
            "uid": "00000205000000AB",
            "sp": "SP_00AB",
            "name": "Issued One",
            "size": 400,
            "size_blocks": 1,
            "requested_size_blocks": 1,
            "size_evidence": "returned_size",
            "size_is_exact": True,
            "templates": ["0000020400000001"],
            "enabled": True,
            "source": "IssueSP",
            "raw": "leak",
        }
        state["sp_lifecycle"]["SP_00AB"] = "Issued"

        facts = extract_state_facts(state)

        self.assertEqual(
            facts["issued_sps"]["00000205000000AB"],
            {
                "uid": "00000205000000AB",
                "sp": "SP_00AB",
                "name": "Issued One",
                "size": 400,
                "size_blocks": 1,
                "requested_size_blocks": 1,
                "size_evidence": "returned_size",
                "size_is_exact": True,
                "templates": ["0000020400000001"],
                "enabled": True,
                "source": "IssueSP",
                "lifecycle": "Issued",
                "deleted": None,
                "deleted_by": None,
            },
        )
        self.assertNotIn("raw", json.dumps(facts))

    def test_extract_state_facts_bounds_issued_sp_collection(self):
        state = initial_state()
        for index in range(3):
            uid = f"000002050000000{index}"
            state["issued_sps"][uid] = {
                "uid": uid,
                "sp": f"SP_000{index}",
                "name": f"Issued {index}",
                "source": "IssueSP",
            }

        facts = extract_state_facts(state, max_issued_sps=2)

        self.assertTrue(facts["meta"]["facts_truncated"])
        self.assertTrue(facts["meta"]["truncation"]["issued_sps"])
        self.assertEqual(list(facts["issued_sps"]), ["0000020500000000", "0000020500000001"])


class NormalizedEventsSerializerTest(unittest.TestCase):
    def test_under_cap_emits_full_sequence(self):
        events = [{"index": i, "kind": "method", "method": "Get", "raw_step": "forbidden"} for i in range(3)]

        serialized = serialize_normalized_events(events)

        self.assertEqual(serialized["policy"]["version"], "normalized_events_v1")
        self.assertEqual(serialized["policy"]["mode"], "full")
        self.assertFalse(serialized["truncated"])
        self.assertEqual([item["index"] for item in serialized["items"]], [0, 1, 2])
        self.assertEqual(set(serialized["items"][0]), {"index", "kind", "method", "command", "object", "object_family", "status", "reason", "confidence", "verdict"})
        self.assertIsNone(serialized["items"][0]["command"])
        self.assertNotIn("raw_step", json.dumps(serialized))

    def test_over_cap_emits_bounded_head_tail_with_omitted_span(self):
        events = [{"index": i, "kind": "method", "method": "Get"} for i in range(20)]

        serialized = serialize_normalized_events(events)

        self.assertEqual(serialized["policy"]["mode"], "bounded_head_tail")
        self.assertTrue(serialized["truncated"])
        self.assertEqual(serialized["included_count"], 16)
        self.assertEqual([item["index"] for item in serialized["items"]], list(range(8)) + list(range(12, 20)))
        self.assertEqual(serialized["policy"]["omitted_span"], {"start_index": 8, "end_index": 11, "count": 4})


class RiskFlagTaxonomyTest(unittest.TestCase):
    def test_unknown_risk_code_is_rejected(self):
        self.assertIn("packet.normalized_events_truncated", ALLOWED_RISK_CODES)
        with self.assertRaises(ValueError):
            make_risk_flag("unknown.code", "must fail")

    def test_serializer_does_not_invent_solver_owned_missing_spec_flag(self):
        packet = build_evidence_packet(
            events=[{"index": 0, "kind": "method", "method": "Get"}],
            state_facts=extract_state_facts(initial_state()),
            rule_result=RuleResult("pass", 1.0, "ok", spec_refs=()),
        )

        self.assertNotIn("deterministic.missing_spec_refs", {flag["code"] for flag in packet["risk_flags"]})


class EvidencePacketSerializerTest(unittest.TestCase):
    def test_packet_top_level_shape_and_versions(self):
        state_facts = extract_state_facts(initial_state())
        packet = build_evidence_packet(
            trajectory_id="case-1",
            events=[{"index": 0, "kind": "method", "method": "Properties", "status": "success"}],
            state_facts=state_facts,
            rule_result=RuleResult("pass", 1.0, "ok", spec_refs=("spec/core",)),
        )

        self.assertEqual(
            set(packet),
            {
                "schema_version",
                "identity",
                "final_view",
                "normalized_events",
                "state_facts",
                "rule_trace",
                "spec_references",
                "risk_flags_taxonomy_version",
                "risk_flags",
                "provenance",
                "subsystem_flags",
            },
        )
        self.assertEqual(packet["schema_version"], "v2")
        self.assertEqual(packet["risk_flags_taxonomy_version"], "risk_flags_v1")
        self.assertEqual(packet["normalized_events"]["policy"]["version"], "normalized_events_v1")
        self.assertEqual(packet["state_facts"]["meta"]["source_whitelist_version"], "state_facts_v1")
        self.assertEqual(packet["identity"]["trajectory_id"], "case-1")
        self.assertEqual(packet["spec_references"], ["spec/core"])

    def test_no_verdict_changes_defaults_from_llm_override_provenance(self):
        changed = build_evidence_packet(
            events=[{"index": 0, "kind": "method", "method": "Get"}],
            state_facts=extract_state_facts(initial_state()),
            rule_result=RuleResult("fail", 1.0, "ok", spec_refs=()),
            llm_override_provenance={
                "delta": {
                    "verdict_changed": True,
                    "from_verdict": "pass",
                    "to_verdict": "fail",
                }
            },
        )
        unchanged = build_evidence_packet(
            events=[{"index": 0, "kind": "method", "method": "Get"}],
            state_facts=extract_state_facts(initial_state()),
            rule_result=RuleResult("pass", 1.0, "ok", spec_refs=()),
            llm_override_provenance={"delta": {"verdict_changed": False}},
        )

        self.assertTrue(changed["final_view"]["verdict_changed_by_llm"])
        self.assertFalse(changed["subsystem_flags"]["no_verdict_changes"])
        self.assertFalse(unchanged["final_view"]["verdict_changed_by_llm"])
        self.assertTrue(unchanged["subsystem_flags"]["no_verdict_changes"])


if __name__ == "__main__":
    unittest.main()
