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

   docker compose up --build \
       --scale=karton-nuclei=10 \
       --scale=karton-bruter=10 \
       --scale=karton-port_scanner=10

.. note ::
   If you get an error that ``docker compose`` is not a valid command, try ``docker-compose``.

Adding targets to scan
----------------------

Select ``Add targets`` from the top navigation bar. Artemis takes input in the form
of entries separated with newlines. Artemis works with both IPs and domains. If
a URL is provided, the domain from this URL will be scanned.

Viewing results
---------------

To view results, click the ``View results`` link in the top navigation bar.
