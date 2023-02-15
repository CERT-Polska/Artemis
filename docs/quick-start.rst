Quick Start
===========

The fastest way to try out Artemis is to use Docker Compose based deployment.
Such deployment is discouraged in production, as it is slow and unreliable.
The proper way to deploy Artemis is to use :ref:`kubernetes <k8s-deployment>`.

Using Docker Compose
--------------------

To start Artemis simply execute following 2 commands in your terminal:

.. code-block:: console

   cp env.example .env  # you may also configure the settings (e.g. by providing a User-Agent to override the default one)
   docker compose up

After that you should be able to access Artemis dashboard at ``localhost:5000``.

.. note ::
   If you get error that ``docker compose`` is not a valid command, try ``docker-compose``.

Adding targets to scan
---------------------

Select ``Add URLs`` from navigation bar at the top. Artemis takes input in form
of newline separated entries. No specific format is required, Artemis should parse
both ``1.1.1.1`` and ``hxxps://cert.pl``.

Viewing results
---------------

Results are available on the Artemis homepage (select ``Artemis`` from top navbar).
