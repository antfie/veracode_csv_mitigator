import unittest

from utils.list_of_applications import AppSandboxInfo, populate_app_details
from utils.mitigation_candidate import MitigationCandidate


class TestListOfApplications(unittest.TestCase):
    def test_populate_app_details_app_has_sandbox(self):
        application_name = "abc"
        application_guid = "d67b6d7e-0d2a-427b-a9e1-a73ae5f34b36"
        sandbox_name = "123"
        sandbox_guid = "1236bcd3-0ee6-46a3-9493-73e920a4e953"

        candidates = [
            MitigationCandidate(
                application_name, sandbox_name, 1, 1, None, None, None, None, None
            )
        ]

        app_infos = [
            AppSandboxInfo(
                application_name, application_guid, sandbox_name, sandbox_guid
            )
        ]

        populate_app_details(candidates, app_infos)

        self.assertEqual(application_guid, candidates[0].application_guid)
        self.assertEqual(sandbox_guid, candidates[0].sandbox_guid)

    def test_populate_app_details_app_does_not_have_sandbox(self):
        application_name = "abc"
        application_guid = "d67b6d7e-0d2a-427b-a9e1-a73ae5f34b36"

        candidates = [
            MitigationCandidate(
                application_name, None, 1, 1, None, None, None, None, None
            )
        ]

        app_infos = [AppSandboxInfo(application_name, application_guid)]

        populate_app_details(candidates, app_infos)

        self.assertEqual(application_guid, candidates[0].application_guid)
        self.assertEqual(None, candidates[0].sandbox_guid)
