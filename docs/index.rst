.. image:: ../static/images/logo.png
   :width: 300px

.. raw:: html

   <div style="height: 15px"></div>

Welcome to Artemis documentation!
=================================

Artemis is a modular web reconnaisance tool and vulnerability scanner based on Karton
(https://github.com/CERT-Polska/karton).

**Artemis is experimental software, under active development - use at your own risk.**

Artemis is built with scalability in mind -- different scanners are separate microservices
and can be scaled independently if such a need arises.

To chat about Artemis, join the Discord server:

.. image:: https://dcbadge.vercel.app/api/server/GfUW4mZmy9
   :target: https://discord.gg/GfUW4mZmy9

.. warning::
  Artemis doesn't yet support proxying the requests and will leak your IP address.

  If you wish to add such a feature, remember to proxy the DNS resolving (e.g. in the Nuclei module
  that currently uses the system DNS resolvers).


.. toctree::
   :maxdepth: 2
   :caption: Contents:

   quick-start
   features
   architecture
   user-guide/configuration
   user-guide/writing-a-module
