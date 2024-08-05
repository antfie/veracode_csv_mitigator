import unittest
from utils.mitigation_candidate import MitigationCandidate

mitigation_text = "text_text_text"
mitigation_text_2 = "text_text_text"
cwe = 123
flaw_id = 456


class TestMitigationCandidate(unittest.TestCase):
    def test_no_matching_flaw_by_id(self):
        candidate = MitigationCandidate(
            "", "", cwe, flaw_id, mitigation_text, None, None, None, None
        )

        candidate.populate_actions(
            [
                {
                    "finding_details": {"cwe": {"id": str(cwe)}},
                    "issue_id": "990",
                }
            ]
        )

        self.assertEqual(0, len(candidate.actions))

    def test_no_matching_flaw_by_cwe(self):
        candidate = MitigationCandidate(
            "", "", cwe, flaw_id, mitigation_text, None, None, None, None
        )

        candidate.populate_actions(
            [
                {
                    "finding_details": {"cwe": {"id": "88"}},
                    "issue_id": str(flaw_id),
                }
            ]
        )

        self.assertEqual(0, len(candidate.actions))

    def test_mitigate_by_design_as_first_action(self):
        candidate = MitigationCandidate(
            "", "", cwe, flaw_id, mitigation_text, None, None, None, None
        )

        candidate.populate_actions(
            [
                {
                    "finding_details": {"cwe": {"id": str(cwe)}},
                    "issue_id": str(flaw_id),
                    "finding_status": {
                        "status": "OPEN",
                        "resolution": "UNRESOLVED",
                        "mitigation_review_status": "NONE",
                        "resolution_status": "NONE",
                    },
                }
            ]
        )

        self.assertEqual(1, len(candidate.actions))
        self.assertEqual(mitigation_text, candidate.actions["APPDESIGN"])

    def test_update_existing_mitigate_by_design(self):
        candidate = MitigationCandidate(
            "", "", cwe, flaw_id, mitigation_text, None, None, None, None
        )

        candidate.populate_actions(
            [
                {
                    "finding_details": {"cwe": {"id": str(cwe)}},
                    "issue_id": str(flaw_id),
                    "finding_status": {
                        "status": "OPEN",
                        "resolution": "UNRESOLVED",
                        "mitigation_review_status": "NONE",
                        "resolution_status": "PROPOSED",
                    },
                    "annotations": [
                        {
                            "comment": "text",
                            "action": "APPDESIGN",
                            "created": "2023-03-07T19:17:45.175Z",
                        },
                    ],
                }
            ]
        )

        self.assertEqual(1, len(candidate.actions))
        self.assertEqual(mitigation_text, candidate.actions["APPDESIGN"])

    def test_update_mitigate_by_design_if_it_is_not_the_same_mitigation(self):
        candidate = MitigationCandidate(
            "", "", cwe, flaw_id, mitigation_text, None, None, None, None
        )

        candidate.populate_actions(
            [
                {
                    "finding_details": {"cwe": {"id": str(cwe)}},
                    "issue_id": str(flaw_id),
                    "finding_status": {
                        "status": "OPEN",
                        "resolution": "UNRESOLVED",
                        "mitigation_review_status": "NONE",
                        "resolution_status": "PROPOSED",
                    },
                    "annotations": [
                        {
                            "comment": mitigation_text,
                            "action": "APPDESIGN",
                            "created": "2023-03-07T19:17:45.175Z",
                        },
                    ],
                }
            ]
        )

        self.assertEqual(0, len(candidate.actions))

    def test_change_to_mitigate_by_design_from_false_positive(self):
        candidate = MitigationCandidate(
            "", "", cwe, flaw_id, mitigation_text, None, None, None, None
        )

        # Same as if MBD proposed?
        candidate.populate_actions(
            [
                {
                    "finding_details": {"cwe": {"id": str(cwe)}},
                    "issue_id": str(flaw_id),
                    "finding_status": {
                        "status": "OPEN",
                        "resolution": "UNRESOLVED",
                        "mitigation_review_status": "NONE",
                        "resolution_status": "PROPOSED",
                    },
                }
            ]
        )

        self.assertEqual(
            1,
            len(candidate.actions),
        )
        self.assertEqual(mitigation_text, candidate.actions["APPDESIGN"])

    def test_mitigate_by_design_as_first_action_then_approve(self):
        candidate = MitigationCandidate(
            "", "", cwe, flaw_id, mitigation_text, None, None, mitigation_text_2, None
        )

        candidate.populate_actions(
            [
                {
                    "finding_details": {"cwe": {"id": str(cwe)}},
                    "issue_id": str(flaw_id),
                    "finding_status": {
                        "status": "OPEN",
                        "resolution": "UNRESOLVED",
                        "mitigation_review_status": "NONE",
                        "resolution_status": "NONE",
                    },
                }
            ]
        )

        self.assertEqual(2, len(candidate.actions))
        self.assertEqual(
            mitigation_text,
            candidate.actions["APPDESIGN"],
        )
        self.assertEqual(
            mitigation_text_2,
            candidate.actions["ACCEPTED"],
        )

    def test_false_positive_as_first_action_then_approve(self):
        candidate = MitigationCandidate(
            "", "", cwe, flaw_id, None, mitigation_text, None, mitigation_text_2, None
        )

        candidate.populate_actions(
            [
                {
                    "finding_details": {"cwe": {"id": str(cwe)}},
                    "issue_id": str(flaw_id),
                    "finding_status": {
                        "status": "OPEN",
                        "resolution": "UNRESOLVED",
                        "mitigation_review_status": "NONE",
                        "resolution_status": "NONE",
                    },
                }
            ]
        )

        self.assertEqual(2, len(candidate.actions))
        self.assertEqual(
            mitigation_text,
            candidate.actions["FP"],
        )
        self.assertEqual(
            mitigation_text_2,
            candidate.actions["ACCEPTED"],
        )

    def test_accept_the_risk_as_first_action_then_approve(self):
        candidate = MitigationCandidate(
            "", "", cwe, flaw_id, None, None, mitigation_text, mitigation_text_2, None
        )

        candidate.populate_actions(
            [
                {
                    "finding_details": {"cwe": {"id": str(cwe)}},
                    "issue_id": str(flaw_id),
                    "finding_status": {
                        "status": "OPEN",
                        "resolution": "UNRESOLVED",
                        "mitigation_review_status": "NONE",
                        "resolution_status": "NONE",
                    },
                }
            ]
        )

        self.assertEqual(2, len(candidate.actions))
        self.assertEqual(
            mitigation_text,
            candidate.actions["ACCEPTRISK"],
        )
        self.assertEqual(
            mitigation_text_2,
            candidate.actions["ACCEPTED"],
        )

    def test_approve_mitigation_by_design(self):
        candidate = MitigationCandidate(
            "", "", cwe, flaw_id, None, None, None, mitigation_text, None
        )

        candidate.populate_actions(
            [
                {
                    "finding_details": {"cwe": {"id": str(cwe)}},
                    "issue_id": str(flaw_id),
                    "finding_status": {
                        "status": "OPEN",
                        "resolution": "UNRESOLVED",
                        "mitigation_review_status": "NONE",
                        "resolution_status": "PROPOSED",
                    },
                    "annotations": [
                        {
                            "comment": "text",
                            "action": "APPDESIGN",
                            "created": "2023-03-07T19:17:45.175Z",
                        },
                    ],
                }
            ]
        )

        self.assertEqual(1, len(candidate.actions))
        self.assertEqual(mitigation_text, candidate.actions["ACCEPTED"])

    def test_reject_mitigation_by_design(self):
        candidate = MitigationCandidate(
            "", "", cwe, flaw_id, None, None, None, None, mitigation_text
        )

        candidate.populate_actions(
            [
                {
                    "finding_details": {"cwe": {"id": str(cwe)}},
                    "issue_id": str(flaw_id),
                    "finding_status": {
                        "status": "CLOSED",
                        "resolution": "MITIGATED",
                        "mitigation_review_status": "NONE",
                        "resolution_status": "APPROVED",
                    },
                    "annotations": [
                        {
                            "comment": "text",
                            "action": "APPDESIGN",
                            "created": "2023-03-07T19:17:45.175Z",
                        },
                    ],
                }
            ]
        )

        self.assertEqual(1, len(candidate.actions))
        self.assertEqual(mitigation_text, candidate.actions["REJECTED"])

    def test_reject_approved_mitigation(self):
        candidate = MitigationCandidate(
            "", "", cwe, flaw_id, None, None, None, None, mitigation_text
        )

        candidate.populate_actions(
            [
                {
                    "finding_details": {"cwe": {"id": str(cwe)}},
                    "issue_id": str(flaw_id),
                    "finding_status": {
                        "status": "OPEN",
                        "resolution": "UNRESOLVED",
                        "mitigation_review_status": "NONE",
                        "resolution_status": "PROPOSED",
                    },
                    "annotations": [
                        {
                            "comment": "text",
                            "action": "APPDESIGN",
                            "created": "2023-03-07T19:17:45.175Z",
                        },
                    ],
                }
            ]
        )

        self.assertEqual(1, len(candidate.actions))
        self.assertEqual(mitigation_text, candidate.actions["REJECTED"])

    def test_attempt_to_reject_an_already_rejected_mitigation(self):
        candidate: MitigationCandidate = MitigationCandidate(
            "", "", cwe, flaw_id, None, None, None, None, mitigation_text
        )

        candidate.populate_actions(
            [
                {
                    "finding_details": {"cwe": {"id": str(cwe)}},
                    "issue_id": str(flaw_id),
                    "finding_status": {
                        "status": "OPEN",
                        "resolution": "UNRESOLVED",
                        "mitigation_review_status": "NONE",
                        "resolution_status": "REJECTED",
                    },
                    "annotations": [
                        {
                            "comment": "text",
                            "action": "REJECTED",
                            "created": "2023-03-07T19:17:45.175Z",
                        },
                    ],
                }
            ]
        )

        self.assertEqual(0, len(candidate.actions))

    def test_attempt_to_reject_an_unmitigated_flaw(self):
        candidate: MitigationCandidate = MitigationCandidate(
            "", "", cwe, flaw_id, None, None, None, None, mitigation_text
        )

        candidate.populate_actions(
            [
                {
                    "finding_details": {"cwe": {"id": str(cwe)}},
                    "issue_id": str(flaw_id),
                    "finding_status": {
                        "status": "OPEN",
                        "resolution": "UNRESOLVED",
                        "mitigation_review_status": "NONE",
                        "resolution_status": "NONE",
                    },
                }
            ]
        )

        self.assertEqual(0, len(candidate.actions))

    def test_attempt_to_approve_an_unmitigated_flaw(self):
        candidate: MitigationCandidate = MitigationCandidate(
            "", "", cwe, flaw_id, None, None, None, mitigation_text, None
        )

        candidate.populate_actions(
            [
                {
                    "finding_details": {"cwe": {"id": str(cwe)}},
                    "issue_id": str(flaw_id),
                    "finding_status": {
                        "status": "OPEN",
                        "resolution": "UNRESOLVED",
                        "mitigation_review_status": "NONE",
                        "resolution_status": "NONE",
                    },
                }
            ]
        )

        self.assertEqual(0, len(candidate.actions))

    def test_attempt_to_approve_an_approved_mitigation(self):
        candidate: MitigationCandidate = MitigationCandidate(
            "", "", cwe, flaw_id, None, None, None, mitigation_text, None
        )

        candidate.populate_actions(
            [
                {
                    "finding_details": {"cwe": {"id": str(cwe)}},
                    "issue_id": str(flaw_id),
                    "finding_status": {
                        "status": "CLOSED",
                        "resolution": "MITIGATED",
                        "mitigation_review_status": "deviates",
                        "resolution_status": "APPROVED",
                    },
                }
            ]
        )

        self.assertEqual(0, len(candidate.actions))
