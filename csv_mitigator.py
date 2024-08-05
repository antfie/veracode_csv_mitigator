import click
from rich.console import Console
from rich.table import Table
from rich.prompt import Confirm

from utils.api import API
from utils.bulk_mitigate import bulk_mitigate
from utils.list_of_applications import acquire_application_info
from utils.mitigation_candidate import MitigationCandidate
from utils.processor import get_flaws, process_candidates
from utils.csv_parser import parse_csv

console = Console(log_path=False)


def print_summary(candidates: list[MitigationCandidate]):
    console.log(
        "There "
        + ("is 1 flaw" if len(candidates) == 1 else f"are {len(candidates)} flaws")
        + " to mitigate:"
    )

    table = Table()
    table.add_column("Application Profile")
    table.add_column("Sandbox")
    table.add_column("Flaw ID")
    table.add_column("Actions To Take")

    for candidate in candidates:
        table.add_row(
            candidate.application_name,
            candidate.sandbox_name or "",
            str(candidate.flaw_id),
            candidate.get_formatted_actions_to_perform(),
        )

    console.print(table)


@click.command()
@click.option(
    "--mappings-file-path",
    default="data/csv_field_mappings.csv",
    type=click.STRING,
    help="A CSV file containing field mappings.",
)
@click.option(
    "--data-file-path",
    default="data/test_data.csv",
    type=click.STRING,
    help="A CSV file containing data to process.",
)
@click.option(
    "--number-of-threads",
    default=10,
    type=click.INT,
    help="Number of threads to use.",
)
@click.option(
    "--application-cache-file-path",
    default=None,
    type=click.STRING,
    help="A text file containing application name to guid mappings, one per line.",
)
@click.option(
    "--auto-apply-mitigations",
    default=False,
    type=click.BOOL,
    help="Set this to true to skip the prompt and apply the mitigations. Use caution with this flag.",
)
def main(
    mappings_file_path: str,
    data_file_path: str,
    number_of_threads: int,
    application_cache_file_path: str,
    auto_apply_mitigations: bool,
):
    thread_count_pluralised = "" if number_of_threads == 1 else "s"
    console.log(f"Using {number_of_threads} thread{thread_count_pluralised}")

    candidates = parse_csv(console, mappings_file_path, data_file_path)

    if len(candidates) < 1:
        console.log("There were no candidates to process.")
        return

    api = API(console)

    acquire_application_info(
        console,
        api,
        candidates,
        application_cache_file_path,
        number_of_threads,
    )

    # Filter any apps we could not get application GUIDs for
    candidates = [c for c in candidates if c.application_guid is not None]

    if len(candidates) < 1:
        console.log("No apps could be resolved.")
        return

    flaws = get_flaws(
        console,
        api,
        candidates,
        number_of_threads,
        debug=False,
    )

    process_candidates(
        console,
        candidates,
        flaws,
    )

    # Filter not found flaws
    candidates = [c for c in candidates if len(c.actions) > 0]

    if len(candidates) < 1:
        console.log("No mitigation actions to take.")
        return

    print_summary(candidates)

    if not auto_apply_mitigations:
        if not Confirm.ask("Apply mitigations?"):
            return

    bulk_mitigate(console, api, candidates, number_of_threads)


if __name__ == "__main__":
    main()
