import csv
from rich.console import Console
from utils.mitigation_candidate import MitigationCandidate


def get_csv_field_mappings(console: Console, mappings_file_path: str) -> dict[str, str]:
    field_names = [
        "application_name",
        "sandbox_name",
        "cwe",
        "flaw_id",
        "mitigate_by_design",
        "false_positive",
        "accept_risk",
        "approve",
        "reject",
    ]

    with open(mappings_file_path, newline="", encoding="utf-8") as mappings:
        for row in csv.DictReader(mappings):
            if not str(list(row.keys())) == str(field_names):
                console.log("Error: Mapping file is invalid.")
                exit(1)

            return row


def parse_csv(
    console: Console, mappings_file_path: str, data_file_path: str
) -> list[MitigationCandidate]:
    field_mappings = get_csv_field_mappings(console, mappings_file_path)
    data: list[MitigationCandidate] = []

    # Deal with UTF-8 and BOM if on Windows - https://stackoverflow.com/questions/17912307/u-ufeff-in-python-string
    encoding = "utf-8"
    with open(data_file_path, newline="", encoding="utf-8") as file_data:
        if "\ufeff" in file_data.read():
            encoding = "utf-8-sig"

    with open(data_file_path, newline="", encoding=encoding) as file_data:
        row_number = 1
        processed_flaws = []
        for row in csv.DictReader(file_data):
            row_number = row_number + 1
            load_row(console, data, field_mappings, row, row_number, processed_flaws)

    return data


def load_row(
    console,
    data,
    field_mappings: dict[str, str],
    row,
    row_number: int,
    processed_flaws: list[str],
):
    def parse_bail(message):
        console.log(f"Error on row {row_number}: {message}.")
        exit(1)

    def field_value_or_none(key):
        if field_mappings[key] not in row:
            return None
        formatted = row[field_mappings[key]].strip()

        return None if len(formatted) < 1 else formatted

    application_name = row[field_mappings["application_name"]].strip()

    if len(application_name) < 1:
        parse_bail("Application name is missing")

    sandbox_name = row[field_mappings["sandbox_name"]].strip()

    if len(sandbox_name) < 1:
        sandbox_name = None

    try:
        cwe = int(row[field_mappings["cwe"]].strip())
        if cwe < 1 or cwe > 5000:
            raise
    except:
        parse_bail("CWE is invalid")

    try:
        flaw_id = int(row[field_mappings["flaw_id"]].strip())
        if flaw_id < 1:
            raise
    except:
        parse_bail("Flaw ID is invalid")

    mitigate_by_design = field_value_or_none("mitigate_by_design")
    false_positive = field_value_or_none("false_positive")
    accept_risk = field_value_or_none("accept_risk")
    approve = field_value_or_none("approve")
    reject = field_value_or_none("reject")

    # Ignore the row if there is no action to take
    if (
        mitigate_by_design is None
        and false_positive is None
        and accept_risk is None
        and approve is None
        and reject is None
    ):
        return

    if mitigate_by_design is not None and false_positive is not None:
        parse_bail(
            'Cannot specify both "mitigate_by_design" and "false_positive"',
        )

    if approve is not None and reject is not None:
        parse_bail('Cannot specify both "approve" and "reject"')

    if false_positive is not None and reject is not None:
        parse_bail('Cannot specify both "false_positive" and "reject"')

    if accept_risk is not None and reject is not None:
        parse_bail('Cannot specify both "accept_risk" and "reject"')

    if mitigate_by_design is not None and reject is not None:
        parse_bail('Cannot specify both "mitigate_by_design" and "reject"')

    candidate = MitigationCandidate(
        application_name,
        sandbox_name,
        cwe,
        flaw_id,
        mitigate_by_design,
        false_positive,
        accept_risk,
        approve,
        reject,
    )

    if candidate.flaw_key() in processed_flaws:
        parse_bail(
            f'Flaw ID {candidate.flaw_id} was detected on more than one row for application "{candidate.application_name}".',
        )

    data.append(candidate)
    processed_flaws.append(candidate.flaw_key())
