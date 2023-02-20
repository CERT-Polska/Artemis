Quick Start
===========

The fastest way to try out Artemis is to use Docker Compose based deployment.
Such deployment is discouraged in production.
The proper way to deploy Artemis would be to use Kubernetes - you may follow
the progress or help with that task on: https://github.com/CERT-Polska/Artemis/issues/204.

Using Docker Compose
--------------------

To start Artemis simply execute following 2 commands in your terminal:

.. code-block:: console

   cp env.example .env  # you may also configure the settings (e.g. by providing a User-Agent to override the default one)
   docker compose up --build

After that you should be able to access the Artemis dashboard at ``localhost:5000``.

**If you want to start multiple instances of a module to speed up scanning, use a command such as:**

.. code-block:: console

   docker compose up \
       --scale=karton-nuclei=10 \
       --scale=karton-bruter=10 \
       --scale=karton-port_scanner=10

.. note ::
   If you get an error that ``docker compose`` is not a valid command, try ``docker-compose``.

.. note ::
   In case of the ``no available IPv4 addresses on this network's address pools: artemis_default`` error
   try increasing the network size either by editing docker daemon config or recreating the network manually.

Adding targets to scan
----------------------

Select ``Add URLs`` from the top navigation bar. Artemis takes input in the form
of entries separated with newlines. No specific format is required, Artemis works with
both IPs and domains and should parse both ``1.1.1.1`` and ``hxxps://cert.pl``.

Viewing results
---------------

Results are available on the Artemis homepage (click the Artemis logo in the top navbar).
