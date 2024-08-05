from csv import reader as csv_reader, writer as csv_writer
from pathlib import Path
from rich.console import Console
from utils.api import API
from utils.mitigation_candidate import MitigationCandidate
from utils.parallel import parallel_execute_tasks_with_progress
from threading import Lock


class AppSandboxInfo:
    def __init__(
        self,
        application_name: str,
        application_guid: str,
        sandbox_name: str = None,
        sandbox_guid: str = None,
    ):
        self.application_name: str = application_name
        self.application_guid: str = application_guid
        self.sandbox_name: str = sandbox_name
        self.sandbox_guid: str = sandbox_guid


class ApplicationCache:
    def __init__(self, file_path: str):
        self._path = None if file_path is None else Path(file_path)
        self._entries: list[AppSandboxInfo] = []
        self._lock = Lock()
        self.load()

    def load(self):
        if self._path is None:
            return

        if not self._path.exists():
            return

        with self._path.open("r") as cache_file:
            rows = csv_reader(cache_file)
            for row in rows:
                self._entries.append(
                    AppSandboxInfo(
                        row[0],
                        row[1],
                        None if len(row[2]) < 1 else row[2],
                        None if len(row[3]) < 1 else row[3],
                    )
                )

    def add(self, info: AppSandboxInfo) -> None:
        if self._path is None:
            return

        with self._lock:
            with self._path.open("a") as cache_file:
                writer = csv_writer(cache_file)
                writer.writerow(
                    [
                        info.application_name,
                        info.application_guid,
                        info.sandbox_name,
                        info.sandbox_guid,
                    ]
                )
                self._entries.append(info)

    def get_by_application_name(self, application_name: str) -> AppSandboxInfo:
        for entry in self._entries:
            if entry.application_name == application_name:
                return entry

        return None


def load_applications_from_file(applications_file_path: str) -> list[str]:
    application_names = []

    with open(applications_file_path, "r") as applications_file:
        for line in applications_file.readlines():
            # Trim
            application_name = line.strip()

            # Ignore empty lines
            if len(application_name) < 1:
                continue

            application_names.append(application_name)

    return application_names


def acquire_application_info(
    console: Console,
    api: API,
    candidates: list[MitigationCandidate],
    application_cache_file_path: str,
    number_of_threads: int,
):
    cache = ApplicationCache(application_cache_file_path)
    app_and_sandbox_guids: list[AppSandboxInfo] = []
    applications_to_resolve = []

    for application_name in set([c.application_name for c in candidates]):
        cached = cache.get_by_application_name(application_name)

        if cached is not None:
            app_and_sandbox_guids.append(cached)
        else:
            applications_to_resolve.append(application_name)

    if len(applications_to_resolve) > 0:

        def resolve_application_guid(application_name):
            applications = []

            # The API can return results for similar named applications
            applications_to_consider = api.get_applications_by_name(application_name)

            for application in applications_to_consider:
                if application["profile"]["name"].lower() == application_name.lower():
                    applications.append(application)

            if len(applications) < 1:
                console.log(
                    f'Skipping not found app profile named: "{application_name}". Make sure this application name has been entered fully and correctly.'
                )
                return

            if len(applications) > 1:
                console.log(
                    f'Skipping ambiguous app profile named: "{application_name}". Make sure this application name has been entered fully and correctly.'
                )
                return

            application_guid = applications[0]["guid"]

            for sandbox in api.get_sandboxes(application_guid):
                app_info = AppSandboxInfo(
                    application_name,
                    application_guid,
                    sandbox["name"],
                    sandbox["guid"],
                )

                app_and_sandbox_guids.append(app_info)
                cache.add(app_info)

        application_count_pluralised = "" if len(applications_to_resolve) == 1 else "s"

        parallel_execute_tasks_with_progress(
            console,
            f"Identifying {len(applications_to_resolve)} application{application_count_pluralised}...",
            resolve_application_guid,
            applications_to_resolve,
            number_of_threads,
        )

    # Update the candidates with the GUIDs
    for i in app_and_sandbox_guids:
        for c in candidates:
            if c.application_name != i.application_name:
                continue

            c.application_guid = i.application_guid

            if c.sandbox_name == i.sandbox_name:
                c.sandbox_guid = i.sandbox_guid
