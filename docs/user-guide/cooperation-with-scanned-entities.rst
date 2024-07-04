Cooperation with scanned entities
=================================
We strongly encourage you to be as transparent to the scanned entities as possible.

This can be achieved by setting the User-Agent header (in Artemis, you can do this by setting
the ``CUSTOM_USER_AGENT`` variable in the ``.env`` file) to information about which
entity is performing the scans and how to contact you.

We also recommend you to rate-limit the scanning. To do that, please refer to :ref:`rate-limiting`.

At CERT PL we also:

- created a site describing who are we scanning, why and from which IP addresses,
- added a link to that site to the User-Agent header so that scanned entities can easily learn more about the scanning,
- set up a reverse DNS from the scanned IPs to a descriptive domain (e.g. scanning.[your-csirt].tld) that hosts the site with more information about Artemis.
