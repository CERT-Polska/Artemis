Uninstalling Artemis
====================

To fully uninstall Artemis, use:

``docker compose -f docker-compose.yaml down --rmi local --volumes``

or, if you decided to run the extra modules as well:

.. code-block:: console

   docker compose \
    -f docker-compose.yaml \
    -f Artemis-modules-extra/docker-compose.yml \
    down --rmi local --volumes

Remember, that this will remove all information about Artemis pending tasks and results.
