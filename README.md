<h1>
    <picture>
        <source media="(prefers-color-scheme: dark)" srcset="static/images/logo_dark.png">
        <img alt="logo" width="400px" src="static/images/logo.png">
    </picture>
</h1>

Artemis is a modular vulnerability scanner. This is the tool that powers CERT PL scanning activities, not only
[checking various aspects of website security](https://artemis-scanner.readthedocs.io/en/latest/features.html)
but also [building easy-to-read messages that are sent to institutions to improve their
security](https://artemis-scanner.readthedocs.io/en/latest/generating-emails.html).

The Artemis project has been initiated by the [KN Cyber](https://kncyber.pl/) science club of [Warsaw University of Technology](https://pw.edu.pl) and is currently being developed by [CERT Polska](https://cert.pl).

## [Quick Start 🔨](https://artemis-scanner.readthedocs.io/en/latest/quick-start.html) | [Docs 📚](https://artemis-scanner.readthedocs.io/en/latest/)

If you want to use additional modules that weren't included here due to non-BSD-compatible licenses, browse to the [Artemis-modules-extra](https://github.com/CERT-Polska/Artemis-modules-extra) repository.

**Artemis is experimental software, under active development - use at your own risk.**

To chat about Artemis, join the Discord server:

[![](https://dcbadge.vercel.app/api/server/GfUW4mZmy9)](https://discord.gg/GfUW4mZmy9)

## Features
For an up-to-date list of features, please refer to [the documentation](https://artemis-scanner.readthedocs.io/en/latest/features.html).

## Screenshots
![Artemis - scan](.github/screenshots/scan.png)

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

Please refer to [the documentation](https://artemis-scanner.readthedocs.io/en/latest/user-guide/writing-a-module.html).

## Contributing
Contributions are welcome! We will appreciate both ideas for new Artemis modules (added as [GitHub issues](https://github.com/CERT-Polska/Artemis/issues)) as well as pull requests with new modules or code improvements.

However obvious it may seem we kindly remind you that by contributing to Artemis you agree that the BSD 3-Clause License shall apply to your input automatically, without the need for any additional declarations to be made.
