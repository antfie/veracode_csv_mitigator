from utils.time import parse_from_veracode_date_time
from collections import OrderedDict


class MitigationCandidate:
    def __init__(
        self,
        application_name: str,
        sandbox_name: str,
        cwe: int,
        flaw_id: int,
        mitigate_by_design: str,
        false_positive: str,
        accept_risk: str,
        approve: str,
        reject: str,
    ):
        self.application_name = application_name
        self.application_guid = None
        self.sandbox_name = sandbox_name
        self.sandbox_guid = None
        self.cwe = cwe
        self.flaw_id = flaw_id
        self.mitigate_by_design = mitigate_by_design
        self.false_positive = false_positive
        self.accept_risk = accept_risk
        self.approve = approve
        self.reject = reject
        self.actions = OrderedDict()

    def findings_key(self) -> str:
        return f"{self.application_guid}:{self.sandbox_guid}"

    def flaw_key(self) -> str:
        return f"{self.application_name.lower().strip()}:{self.flaw_id}"

    def get_formatted_actions_to_perform(self):
        formatted_action_names = {
            "APPDESIGN": "Mitigate By Design",
            "FP": "False Positive",
            "ACCEPTRISK": "Accept The Risk",
            "ACCEPTED": "Accept",
            "REJECTED": "Reject",
        }

        return ",".join(
            [formatted_action_names[action] for action in self.actions.keys()]
        )

    def find_matching_flaw(self, findings: dict):
        for finding in findings:
            if int(finding["finding_details"]["cwe"]["id"]) != self.cwe:
                continue

            if int(finding["issue_id"]) != self.flaw_id:
                continue

            return finding

    def populate_actions(self, findings: dict):
        finding = self.find_matching_flaw(findings)

        if not finding:
            return

        status = finding["finding_status"]

        # Only check the status if we are not rejecting
        if self.reject is not None:
            # Flaw must be in a proposed or approved state for us to reject it
            if status["resolution_status"] in ["REJECTED", "NONE"]:
                return
        else:
            # This can be "OPEN" or "CLOSED"
            if status["status"] != "OPEN":
                return

            # This can be "PROPOSED", "APPROVED", "REJECTED" or "NONE"
            if status["resolution_status"] == "APPROVED":
                return

            # "mitigation_review_status" can be: "defer", "deviates" or "NONE"

            # This can be "MITIGATED", "UNRESOLVED" or "POTENTIAL_FALSE_POSITIVE"
            if status["resolution"] != "UNRESOLVED":
                return

        if self.approve is not None and not (
            self.accept_risk is not None
            or self.false_positive is not None
            or self.mitigate_by_design is not None
        ):
            # Flaw is rejected, there must be some other mitigation action before it can be approved
            if status["resolution_status"] in ["REJECTED", "NONE"]:
                return

        last_annotation = self.get_last_annotation(finding)

        # There is a specific order in which to apply multiple mitigation actions
        if self.mitigate_by_design is not None:
            self.add_action("APPDESIGN", self.mitigate_by_design, last_annotation)

        if self.false_positive is not None:
            self.add_action("FP", self.false_positive, last_annotation)

        if self.accept_risk is not None:
            self.add_action("ACCEPTRISK", self.accept_risk, last_annotation)

        if self.approve is not None:
            self.add_action("ACCEPTED", self.approve, last_annotation)

        if self.reject is not None:
            self.add_action("REJECTED", self.reject, last_annotation)

    def add_action(self, action: str, comment: str, last_annotation):
        # Was this already mitigated?
        if (
            last_annotation["action"] == action
            and last_annotation["comment"] == comment
        ):
            return

        self.actions[action] = comment

    @staticmethod
    def get_last_annotation(finding):
        if "annotations" in finding:
            return sorted(
                finding["annotations"],
                key=lambda x: parse_from_veracode_date_time(x["created"]),
                reverse=True,
            )[0]

        return {"action": "", "comment": ""}
