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

## FAQ
### Does Artemis support proxying the requests?
Not yet. If you wish to add such a feature, remember to proxy the DNS resolving (e.g. in the Nuclei module
that currently uses the system DNS resolvers).

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
