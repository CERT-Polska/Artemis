from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.domain_controller_detector import DomainControllerDetector


class DomainControllerDetectorTest(ArtemisModuleTestCase):
    karton_class = DomainControllerDetector  # type: ignore

    def _make_task(self, port: int) -> Task:
        return Task(
            {"type": TaskType.SERVICE.value, "service": Service.UNKNOWN.value},
            payload={"host": "1.2.3.4", "port": port},
        )

    def test_ldap_flagged(self) -> None:
        self.run_task(self._make_task(389))
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertIn("LDAP", call.kwargs["status_reason"])
        self.assertNotIn("domain controller", call.kwargs["status_reason"])

    def test_kerberos_flagged(self) -> None:
        self.run_task(self._make_task(88))
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertIn("Kerberos", call.kwargs["status_reason"])
        self.assertNotIn("domain controller", call.kwargs["status_reason"])

    def test_smb_flagged(self) -> None:
        self.run_task(self._make_task(445))
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertIn("SMB", call.kwargs["status_reason"])
        self.assertNotIn("domain controller", call.kwargs["status_reason"])

    def test_ldaps_flagged(self) -> None:
        self.run_task(self._make_task(636))
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertIn("LDAPS", call.kwargs["status_reason"])
        self.assertNotIn("domain controller", call.kwargs["status_reason"])

    def test_global_catalog_ldap_flagged(self) -> None:
        self.run_task(self._make_task(3268))
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertIn("Global Catalog", call.kwargs["status_reason"])

    def test_rpc_endpoint_mapper_flagged(self) -> None:
        self.run_task(self._make_task(135))
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertIn("RPC Endpoint Mapper", call.kwargs["status_reason"])

    def test_kerberos_password_change_flagged(self) -> None:
        self.run_task(self._make_task(464))
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertIn("Kerberos Password Change", call.kwargs["status_reason"])

    def test_rpc_over_http_flagged(self) -> None:
        self.run_task(self._make_task(593))
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertIn("RPC over HTTP", call.kwargs["status_reason"])

    def test_dfsr_flagged(self) -> None:
        self.run_task(self._make_task(5722))
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertIn("DFSR", call.kwargs["status_reason"])

    def test_ad_web_services_flagged(self) -> None:
        self.run_task(self._make_task(9389))
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertIn("Active Directory Web Services", call.kwargs["status_reason"])

    def test_unrelated_port_ignored(self) -> None:
        self.run_task(self._make_task(8080))
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.OK)

