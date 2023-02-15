# Artemis
A modular web reconnaisance tool and vulnerability scanner based on Karton
(https://github.com/CERT-Polska/karton).

The Artemis project has been initiated by the [KN Cyber](https://kncyber.pl/) science club of [Warsaw University of Technology](https://pw.edu.pl) and is currently being maintained by [CERT Polska](https://cert.pl).

## [Quick Start 🔨](https://artemis-scanner.readthedocs.io/en/latest/quick-start.html) | [Docs 📚](https://artemis-scanner.readthedocs.io/en/latest/) |

**Artemis is experimental software, under active development - use at your own risk.**

To chat about Artemis, join the Discord server:

[![](https://dcbadge.vercel.app/api/server/GfUW4mZmy9)](https://discord.gg/GfUW4mZmy9)

## Features
For an up-to-date list of features, please refer to [the documentation](https://artemis-scanner.readthedocs.io/en/latest/features.html).

## Screenshots
![Artemis - scan](.github/screenshots/scan.png)

## Getting started
If you plan using Artemis on production highly consider kubernetes deployment. Development
environment doesn't scale properly and has hardcoded credentials.

For development / testing pruposes a docker-compose configuration exists. Some modules (e.g. downloading
vulnerability information from Shodan) are not available because the credentials aren't provided.

To run simply:

 - clone the repo,
 - copy `env.example` to `.env` and configure it (e.g. by providing a User-Agent to override the default one),
 - run `docker compose up`,
 - browse to `localhost:5000`.

URLs you provide don't have to follow any strict rules (e.g. `hxxp://127.0.0.1:1337/someurl` should work as well).

## FAQ
### Does Artemis support proxying the requests?
Not yet. If you wish to add such a feature, remember to proxy the DNS resolving (e.g. in the Nuclei module
that currently uses the system DNS resolvers).

### Artemis takes a long time to run - what is the reason?
By default, the requests are limitted to **one in 5 seconds** for a single IP (and, separately, **two packets
per second for port scanning** for a single IP). To change that to more aggressive values, change the
`SECONDS_PER_REQUEST_FOR_ONE_IP` and `SCANNING_PACKETS_PER_SECOND_PER_IP` environment variables.

## Development

### Tests
To run the tests, use:

```
./scripts/test
```

### Code formatting
Artemis uses `pre-commit` to run linters and format the code.
`pre-commit` is executed on CI to verify that the code is formatted properly.

To run it locally, use:

```
pre-commit run --all-files
```

To setup `pre-commit` so that it runs before each commit, use:

```
pre-commit install
```

### Building the docs

To build the documentation, use:

```
cd docs
python3 -m venv venv
. venv/bin/activate
pip install -r requirements.txt
make html
```

## How do I write my own module?

[Karton documentation](https://karton-core.readthedocs.io/en/latest/) as well
as [existing modules](artemis/modules) are great place to start.

If you want to contribute a new module to Artemis, remember to write a good test - one
that spawns an application and checks that Artemis would find the vulnerability there.
An example could be `test/modules/test_vcs.py`.
