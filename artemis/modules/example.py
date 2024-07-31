from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class Example(ArtemisBase):
    """
    An example Artemis module that shows how to implement one.
    Look into artemis/reporting/modules/example/ to know how to add findings
    from this module to the HTML reports.
    """

    # Module name that will be displayed
    identity = "example"

    # Types of tasks that will be consumed by the module - here, open ports that were identified
    # to contain a HTTP/HTTPS service. To know what types are possible, look at other modules' source:
    # https://github.com/CERT-Polska/Artemis/tree/main/artemis/modules
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)
        self.log.info(f"example module running {url}")

        url_length = len(url)

        if url_length % 2 == 0:
            # On the default task result view only the interesting task results will be displayed
            status = TaskStatus.INTERESTING
            status_reason = "The URL has even number of characters!"
        else:
            status = TaskStatus.OK
            status_reason = "The URL has odd number of characters."

        self.db.save_task_result(
            task=current_task,
            status=status,
            status_reason=status_reason,
            # In the data dictionary, you may provide any additional results - the user will be able to view them
            # in the interface on the single task result page.
            data={"url_length": url_length},
        )


if __name__ == "__main__":
    Example().loop()
