import unittest

from src.solver import Solver


def _start_session(index, spid, write, authority=None, challenge=None):
    optional = {}
    if authority:
        optional["HostSigningAuthority"] = authority
    if challenge:
        optional["HostChallenge"] = challenge
    return {
        "index": index,
        "input": {
            "method": {
                "name": "StartSession",
                "args": {
                    "required": {"HostSessionID": 1, "SPID": spid, "Write": write},
                    "optional": optional,
                },
            },
            "invoking_id": {"uid": "00 00 00 00 00 00 00 FF", "name": "SMUID"},
        },
        "output": {
            "return_values": {"HostSessionID": "00000001", "SPSessionID": "00001234"},
            "status_codes": "SUCCESS",
        },
    }


def _method(index, name, invoking_uid, invoking_name, required=None, optional=None):
    return {
        "index": index,
        "input": {
            "method": {"name": name, "args": {"required": required or {}, "optional": optional or {}}},
            "invoking_id": {"uid": invoking_uid, "name": invoking_name},
        },
        "output": {"return_values": [], "status_codes": "SUCCESS"},
    }


def _spec_example(with_authenticate):
    """The project specification's Example 1/2: anonymous LockingSP session,
    optional in-session Authenticate(Admin1), then Set on the Global range."""
    steps = [
        _start_session(1, "0000020500000001", 1, authority="0000000900000006", challenge="SIDPW"),
        _method(2, "Activate", "00 00 02 05 00 00 00 02", "SP"),
        _method(3, "EndSession", "00 00 00 00 00 00 00 FF", "SMUID"),
        _start_session(4, "0000020500000002", 1),
    ]
    if with_authenticate:
        steps.append(
            _method(
                5,
                "Authenticate",
                "00 00 00 00 00 00 00 FF",
                "SMUID",
                required={"Authority": "0000000900010001"},
                optional={"Proof": "ADMIN1PW"},
            )
        )
    steps.append(
        _method(6, "Set", "00 00 08 02 00 00 00 01", "Locking_GlobalRange", optional={"Values": [{"6": True}]})
    )
    return steps


class SpecExampleTwoStepAuthTest(unittest.TestCase):
    """The assignment PDF's own worked examples (section 1.2). Local datasets
    contain ZERO prefix Authenticate steps, so this flow is only covered here."""

    def test_example_1_authenticated_set_passes(self):
        self.assertEqual(Solver().predict_one(_spec_example(with_authenticate=True)), "pass")

    def test_example_2_unauthenticated_set_fails(self):
        self.assertEqual(Solver().predict_one(_spec_example(with_authenticate=False)), "fail")

    def test_explicit_false_result_withholds_credit(self):
        steps = _spec_example(with_authenticate=True)
        # challenge-response style rejection: SUCCESS with Result=False
        steps[4]["output"]["return_values"] = [{"Result": False}]
        self.assertEqual(Solver().predict_one(steps), "fail")


if __name__ == "__main__":
    unittest.main()
