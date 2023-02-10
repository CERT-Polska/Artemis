Configuration Options
=====================

.. note ::
   The newest configuration options are always available in `config.py <https://github.com/CERT-Polska/Artemis/blob/main/artemis/config.py>`_.

Karton configuration
--------------------

Artemis is based on karton project. Refer to `karton documentation <https://karton-core.readthedocs.io/en/latest/getting_started.html#configuration>`_ for more information.


Artemis configuration
---------------------

Artemis is configured by setting environment variables.

Required
~~~~~~~~

* ``DB_CONN_STR`` (string)

  | Connection string to MongoDB database.

* ``REDIS_CONN_STR`` (string)

  | Connection string to Redis store.

Random
~~~~~~

* ``SHODAN_API_KEY`` (string)

  | Shodan API key

* ``CUSTOM_USER_AGENT`` (string)

  | User-Agent string used by Artemis.

* ``POSTMAN_MAIL_FROM`` (string)

  | ``FROM`` e-mail address used for testing SMTP servers.

* ``POSTMAN_MAIL_TO`` (string)

  | ``TO`` e-mail address used for testing SMTP servers.

* ``CONTENT_PREFIX_SIZE`` (int)

  | Amount of bytes to save in case of interesting responses.

* ``CUSTOM_PORT_SCANNER_PORTS`` (CSV comma separated string)

  | Custom ports list to scan (replaces default list).


Scope Limiting
~~~~~~~~~~~~~~~

* ``ALLOW_SCANNING_PUBLIC_SUFFIXES`` (boolean)

  | TODO

* ``ADDITIONAL_PUBLIC_SUFFIXES`` (string)

  | Additional domains that will be treated as public suffixes (even though they're not on the default Public Suffix List)

* ``NOT_INTERESTING_PATHS`` (CSV comma separated string)

  | Paths to ignore when performing HTTP requests.

* ``VERIFY_REVDNS_IN_SCOPE`` (boolean)

  | By default, Artemis will check whether the reverse DNS lookup for an IP matches
  | the original domain. For example, if we encounter the 1.1.1.1 ip which resolves to
  | new.example.com, Artemis will check whether it is a subdomain of the original task
  | domain.
  |
  | This is to prevent Artemis from randomly walking through the internet after encountering
  | a misconfigured Reverse DNS record (e.g. pointing to a completely different domain).
  |
  | The downside of that is that when you don't provide original domain (e.g. provide
  | an IP to be scanned), the domain from the reverse DNS lookup won't be scanned. Therefore this
  | behavior is configurable and may be turned off.


Rate Limiting
~~~~~~~~~~~~~

* ``SECONDS_PER_REQUEST_FOR_ONE_IP``

  | TODO

* ``SCANNING_PACKETS_PER_SECOND_PER_IP``

  | TODO

* ``LOCK_SLEEP_MIN_SECONDS`` (int)

  | Minimum delay in before trying again to take a lock.

* ``LOCK_SLEEP_MAX_SECONDS``

  | Maximum delay in before trying again to take a lock.

* ``SCAN_DESTINATION_LOCK_MAX_TRIES`` (int)

  | Amount of times module will try to get a lock (with sleeps inbetween) before rescheduling task.

* ``REQUEST_TIMEOUT_SECONDS`` (int)

  | Request timeout (for all protocols).

* ``DEFAULT_LOCK_EXPIRY_SECONDS`` (int)

  | Locks are not permanent, because a service that has acquired a lock may get restarted or killed.
  | This is the lock default expiry time.

Modules
~~~~~~~

* ``BRUTER_FALSE_POSITIVE_THRESHOLD`` (float)

  | A threshold in case the server reports too much files with 200 status code,
  | and we want to skip this as a false positive. 0.1 means 10%.

* ``BRUTER_NUM_TOP_PATHS_TO_USE`` (int)

  | Amount of most popular paths to use.

* ``BRUTER_NUM_RANDOM_PATHS_TO_USE`` (int)

  | Amount of random paths to use (used to learn popular paths).

* ``BRUTER_FOLLOW_REDIRECTS`` (boolean)

  | If set to True, bruter will follow redirects. If to False, a redirect will be interpreted that a URL
  | doesn't exist, thus decreasing the number of false positives at the cost of losing some true positives.
