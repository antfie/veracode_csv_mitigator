from utils.api import API
from utils.mitigation_candidate import MitigationCandidate
from utils.parallel import parallel_execute_tasks_with_progress
from rich.console import Console
from html import escape


def bulk_mitigate(
    console: Console,
    api: API,
    candidates: list[MitigationCandidate],
    number_of_threads: int,
):
    def perform_actions(candidate: MitigationCandidate):
        console.log(
            f"Mitigating flaw #{candidate.flaw_id} in application profile '{candidate.application_name}'..."
        )

        for action, comment in candidate.actions.items():
            api.add_mitigation(
                candidate.application_guid,
                candidate.flaw_id,
                action,
                escape(comment),
                candidate.sandbox_guid,
            )
            pass

    mitigation_count_pluralised = "" if len(candidates) == 1 else "s"

    parallel_execute_tasks_with_progress(
        console,
        f"Mitigating {len(candidates)} flaw{mitigation_count_pluralised}...",
        perform_actions,
        candidates,
        number_of_threads,
    )
