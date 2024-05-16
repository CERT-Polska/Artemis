Writing custom modules
======================
.. note ::

   Before writing an Artemis module, make sure that simpler tools aren't sufficient.

   If you have a simple task (e.g. performing some HTTP requests and checking their results), you may instead
   add a custom Nuclei (https://github.com/projectdiscovery/nuclei/) module to ``artemis/modules/data/nuclei_templates_custom/``.

Artemis contains an example module (https://github.com/CERT-Polska/Artemis/blob/main/artemis/modules/example.py) that
checks whether the URL length is even. It also contains a component that adds findings from the example module to
the :ref:`HTML reports<generating-reports>`: https://github.com/CERT-Polska/Artemis/blob/main/artemis/reporting/modules/example/.
Feel free to copy this module to implement a real one. Remember to start the module in
https://github.com/CERT-Polska/Artemis/blob/main/docker-compose.yaml.

Since Artemis uses the Karton framework (https://github.com/CERT-Polska/karton) underneath, modules are Karton services.

Artemis provides a few helpers to make writing a module easier.

Adding tasks
------------
If you know how to use Karton you might know the ``self.send_task`` method on Karton producers that creates
a new task.

Since Artemis saves some additional task information in the database, you need to use a wrapper - ``self.add_task``.

Cache
-----
Modules often perform long running tasks, where we want to cache the results. Such example may be port scanning. Artemis provides simple Redis-based
cache API for each module. The cache is available under ``self.cache``. Rather than describing how it works it's easier to read
`redis_cache.py <https://github.com/CERT-Polska/Artemis/blob/main/artemis/redis_cache.py>`_.

Database
--------
Artemis uses PostgreSQL to save task results - this feature is available via ``self.save_task_result``.

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
DNS requests should be performed using ``lookup`` from `resolvers.py <https://github.com/CERT-Polska/Artemis/blob/main/artemis/resolvers.py>`_.

Outgoing requests limiting
--------------------------
To prevent Artemis from disrupting scanned services, Artemis introduces request limiting. This is why all modules should use ``throttle_request`` function from ``artemis.utils`` while performing requests.

.. code-block:: python

    throttle_request(lambda: ftp.login(username, password))

This method ensures that it will take at least ``Config.SECONDS_PER_REQUEST`` seconds, sleeping if needed.
