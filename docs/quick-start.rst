Quick Start
===========

Currently, only Docker Compose based deployment is supported.

More production-ready way to deploy Artemis will be to use Kubernetes - you may follow
the progress or help with that task on: https://github.com/CERT-Polska/Artemis/issues/204.

Using Docker Compose
--------------------

To start Artemis simply execute following 2 commands in your terminal:

.. code-block:: console

   cp env.example .env  # you may also configure the settings (e.g. by providing a User-Agent to override the default one)
   docker compose up --build

After that you should be able to access the Artemis dashboard at ``localhost:5000``.

**You can also add additional Artemis modules from** https://github.com/CERT-Polska/Artemis-modules-extra/ -
these modules haven't been included in core due to licensing reasons, but provide additional features such
as e.g. SSL verification (certificate validity, proper redirect, etc.), subdomain takeover check or
SQL injection check.

To do that, clone https://github.com/CERT-Polska/Artemis-modules-extra/ inside
the Artemis directory and use:

.. code-block:: console

  docker compose -f docker-compose.yaml -f Artemis-modules-extra/docker-compose.yml up --build


**If you want to start multiple instances of a module to speed up scanning, use a command such as:**

.. code-block:: console

   docker compose up --build \
       --scale=karton-nuclei=10 \
       --scale=karton-bruter=10 \
       --scale=karton-port_scanner=10

For the full list of available configuration options you may set in the ``.env`` file, see :doc:`user-guide/configuration`.

.. note ::
   If you get an error that ``docker compose`` is not a valid command, that means that Docker Compose
   plugin is not installed. Please follow the instructions from https://docs.docker.com/compose/install/linux/#install-using-the-repository

   The old ``docker-compose`` syntax is not recommended.

Adding targets to scan
----------------------

Select ``Add targets`` from the top navigation bar. Artemis takes input in the form
of entries separated with newlines. Artemis works with both IPs and domains. It also supports
IP ranges, both in the form of `127.0.0.1-127.0.0.10` or `127.0.0.0/30`.

If a URL is provided, the host from this URL will be scanned.

To be later able to filter various types of targets, provide a tag in the `Tag` field.

Viewing results
---------------

To view results, click the ``View results`` link in the top navigation bar.

Advanced usage
--------------
Besides viewing the raw results, you may want to generate e-mail reports containing
descriptions of found vulnerabilities, so thay you can notify the administrators to get
the vulnerabilities fixed.

To do that, please refer to :ref:`generating-e-mails`.
