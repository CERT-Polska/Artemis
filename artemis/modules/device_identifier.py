from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Device, Service, TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_host, get_target_url


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class DeviceIdentifier(ArtemisBase):
    """
    Tries to identify the device (FortiOS, ...) and produces a DEVICE task with proper type (e.g. Device.FORTIOS)
    """

    identity = "device_identifier"

    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def _identify(self, url: str) -> Device:
        response = self.http_get(url, allow_redirects=True)
        if "xxxxxxxx-xxxxx" in response.headers.get("Server", ""):
            response = self.http_get(f"{url}/remote/login", allow_redirects=True)
            if response.status_code == 200 and "/remote/login" in response.url:
                return Device.FORTIOS
        if "/global-protect/login.esp" in response.url:
            return Device.PANOSGP

        return Device.UNKNOWN

    def _process(self, current_task: Task, url: str, host: str, port: int) -> None:
        device = self._identify(url)

        new_task = Task(
            {
                "type": TaskType.DEVICE,
                "device": device,
            },
            payload={"host": host, "port": int(port), "ssl": current_task.get_payload("ssl")},
        )
        self.add_task(current_task, new_task)

        self.db.save_task_result(task=current_task, status=TaskStatus.OK, data=device)

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)
        host = get_target_host(current_task)
        port = current_task.get_payload("port")

        self.log.info(f"device identifier scanning {url}")

        self._process(current_task, url, host, port)


if __name__ == "__main__":
    DeviceIdentifier().loop()
