Writing custom modules
======================

Since Artemis uses karton underneath, modules are karton services:

.. code-block:: python

    from karton.core import Task
    from artemis.binds import Service, TaskStatus, TaskType
    from artemis.module_base import ArtemisBase
    from artemis.task_utils import get_target_url
    
    class CustomScanner(ArtemisBase):
        """
        My first custom artemis module
        """
    
        identity = "custom"
        filters = [
            {"type": TaskType.SERVICE, "service": Service.HTTP},
        ]
    
        def run(self, current_task: Task) -> None:
            url = get_target_url(current_task)
            self.log.info(f"custom module running {url}")
    
            status = TaskStatus.OK
            status_reason = None
    
            if "sus" in url:
                status = TaskStatus.INTERESTING
                status_reason = "suspicious link detected!"
    
            self.db.save_task_result(task=current_task, status=status, status_reason=status_reason)
    
    if __name__ == "__main__":
        ReverseDNSLookup().loop()

.. warning::
    If you know how to use karton you might know ``self.send_task`` method on karton producers.
    Since Artemis saves all task information in the database, you need to use a wrapper - ``self.add_task``.


However, Artemis adds a few helpers to make your job easier.

Database
--------

Artemis uses MongoDB to save task results and is available via ``self.save_task_result``.

Cache
-----

Modules often perform long running tasks, which we want to cache. Such example may be port scanning. Artemis provides simple redis based cache API to each karton service which extends ``ArtemisBase`` class under ``self.cache``. Rather than describing how it works it's easier to read `redis_cache.py <https://github.com/CERT-Polska/Artemis/blob/main/artemis/redis_cache.py>`_.

Resource Locking
----------------

You may want to create resource locks during development. Such example is shodan module, which requests a lock using ``self.lock`` to prevent hitting API request limit.

HTTP requests
-------------


DNS requests
------------

All DNS requests are performed by default using DNS-Over-HTTPS. This is done to avoid leaking DNS queries in case of tunneling Artemis requests via TCP proxy such as SOCKS5. DNS requests should be performed using ``ip_lookup`` from `resolvers.py <https://github.com/CERT-Polska/Artemis/blob/main/artemis/resolvers.py>`_.

Outgoing requests limiting
--------------------------

To prevent Artemis from disrupting scanned services, Artemis introduces request limiting. This is why all modules should use ``throttle_request`` function from ``artemis.utils`` while performing requests.

.. code-block:: python

    throttle_request(lambda: ftp.login(username, password))


Artemis provides helper functions for HTTP requests: ``get`` and ``post`` methods from `http_requests.py <https://github.com/CERT-Polska/Artemis/blob/main/artemis/http_requests.py>`_.

Going even further
------------------

You can always read more at `karton documentation <https://karton-core.readthedocs.io/en/latest/>`_.
