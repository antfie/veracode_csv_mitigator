from json import dumps, load
from os.path import exists
from rich.console import Console

from utils.api import API
from utils.mitigation_candidate import MitigationCandidate
from utils.parallel import parallel_execute_tasks_with_progress


def get_flaws(
    console: Console,
    api: API,
    candidates: list[MitigationCandidate],
    number_of_threads: int,
    debug: bool = False,
) -> dict[str, dict]:
    if debug and exists("data/findings.json"):
        with open("data/findings.json", "r") as d:
            return load(d)

    scans_to_find = list(set([x.findings_key() for x in candidates]))
    flaws = {}

    def process_application(scan: str):
        application_guid, sandbox_guid = scan.split(":")

        if sandbox_guid == str(None):
            sandbox_guid = None

        findings = api.get_findings(
            application_guid,
            sandbox_guid,
        )

        if findings:
            flaws[scan] = findings

    scan_count_pluralised = "" if len(scans_to_find) == 1 else "s"

    parallel_execute_tasks_with_progress(
        console,
        f"Processing {len(scans_to_find)} scan{scan_count_pluralised}...",
        process_application,
        scans_to_find,
        number_of_threads,
    )

    if debug:
        with open("data/findings.json", "w") as d:
            d.write(dumps(flaws, indent=4))

    return flaws


def process_candidates(
    console: Console,
    candidates: list[MitigationCandidate],
    findings: dict[str, dict],
):
    for candidate in candidates:
        found_findings = findings[candidate.findings_key()]

        if found_findings is None:
            sandbox_text = ""

            if candidate.sandbox_guid:
                sandbox_text = f', sandbox: "{candidate.sandbox_name}"'

            console.log(
                f'No SAST findings found for app profile: "{candidate.application_name}"{sandbox_text}.'
            )
            continue

        candidate.populate_actions(found_findings)
