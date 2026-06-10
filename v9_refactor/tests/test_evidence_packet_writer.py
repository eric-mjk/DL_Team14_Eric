import json
import tempfile
import unittest
from pathlib import Path

from src.evidence_packet_writer import write_evidence_packet


class EvidencePacketWriterTest(unittest.TestCase):
    def test_write_evidence_packet_appends_jsonl_with_record_id(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "packet.jsonl"

            status = write_evidence_packet({"identity": {}, "schema_version": "v2"}, path)

            self.assertTrue(status.attempted)
            self.assertTrue(status.recorded)
            self.assertIsNone(status.error)
            packet = json.loads(path.read_text().splitlines()[0])
            self.assertEqual(packet["identity"]["record_id"], status.record_id)

    def test_empty_path_is_noop_status(self):
        status = write_evidence_packet({"identity": {}}, None)

        self.assertFalse(status.attempted)
        self.assertFalse(status.recorded)


if __name__ == "__main__":
    unittest.main()
