Writing custom modules
======================

Since Artemis uses the Karton framework (https://github.com/CERT-Polska/karton) underneath, modules are karton services:

.. code-block:: python

    from karton.core import Task
    from artemis.binds import Service, TaskStatus, TaskType
    from artemis.module_base import ArtemisBase
    from artemis.task_utils import get_target_url

    class CustomScanner(ArtemisBase):
        """
        My first custom Artemis module
        """

        # Module name that will be displayed
        identity = "custom"

        # Types of tasks that will be consumed by the module - here, open ports that were identified
        # to contain a HTTP/HTTPS service. To know what types are possible, look at other modules' source:
        # https://github.com/CERT-Polska/Artemis/tree/main/artemis/modules
        filters = [
            {"type": TaskType.SERVICE, "service": Service.HTTP},
        ]

        def run(self, current_task: Task) -> None:
            url = get_target_url(current_task)
            self.log.info(f"custom module running {url}")

            status = TaskStatus.OK
            status_reason = None

            if "sus" in url:
                # On the default task result view only the interesting task results will be displayed
                status = TaskStatus.INTERESTING
                status_reason = "suspicious link detected!"

            # In the data dictionary, you may provide any additional results - the user will be able to view them
            # in the interface on the single task result page.
            self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data={})

    if __name__ == "__main__":
        CustomScanner().loop()

.. warning::
    If you know how to use Karton you might know the ``self.send_task`` method on Karton producers that creates
    a new task.

    Since Artemis saves all task information in the database, you need to use a wrapper - ``self.add_task``.


However, Artemis adds a few helpers to make your job easier.

Database
--------

Artemis uses MongoDB to save task results - this feature is available via ``self.save_task_result``.

Cache
-----

Modules often perform long running tasks, which we want to cache. Such example may be port scanning. Artemis provides simple Redis-based
cache API for each module. The cache is available under ``self.cache``. Rather than describing how it works it's easier to read
`redis_cache.py <https://github.com/CERT-Polska/Artemis/blob/main/artemis/redis_cache.py>`_.

Resource Locking
----------------

You may want to lock a resource. An example can be the Shodan module
(https://github.com/CERT-Polska/Artemis/blob/main/artemis/modules/shodan_vulns.py), which requests
a lock using ``self.lock`` to prevent hitting API request limits.

HTTP requests
-------------

To perform a HTTP request, use the ``artemis.http_requests`` module that:

 - provides correct user-agent,
 - doesn't verify the SSL certificate as many interesting findings are on sites with expired SSL certificates,
 - reads only the first ``Config.CONTENT_PREFIX_SIZE`` to save bandwidth.

To perform a request use ``http_requests.get`` or ``http_requests.post`` functions.


DNS requests
------------

DNS requests should be performed using ``ip_lookup`` from `resolvers.py <https://github.com/CERT-Polska/Artemis/blob/main/artemis/resolvers.py>`_.

Outgoing requests limiting
--------------------------

To prevent Artemis from disrupting scanned services, Artemis introduces request limiting. This is why all modules should use ``throttle_request`` function from ``artemis.utils`` while performing requests.

.. code-block:: python

    throttle_request(lambda: ftp.login(username, password))

This method ensures that it will take at least ``Config.SECONDS_PER_REQUEST_FOR_ONE_IP`` seconds, sleeping if needed.
