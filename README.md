<h1>
    <picture>
        <source media="(prefers-color-scheme: dark)" srcset="static/images/logo_dark.png">
        <img alt="logo" width="400px" src="static/images/logo.png">
    </picture>
</h1>

Artemis is a modular vulnerability scanner. This is the tool that powers CERT PL scanning activities, not only
[checking various aspects of website security](https://artemis-scanner.readthedocs.io/en/latest/features.html)
but also [building easy-to-read messages that are sent to organizations to improve their
security](https://artemis-scanner.readthedocs.io/en/latest/generating-reports.html).

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

## Contributors
Huge thanks to the following people that contributed to Artemis development!

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tbody>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/kazet"><img src="https://avatars.githubusercontent.com/u/1233067?v=4?s=100" width="100px;" alt="kazet"/><br /><sub><b>kazet</b></sub></a><br /><a href="https://github.com/CERT-Polska/Artemis/commits?author=kazet" title="Code">💻</a> <a href="https://github.com/CERT-Polska/Artemis/commits?author=kazet" title="Documentation">📖</a> <a href="#ideas-kazet" title="Ideas, Planning, & Feedback">🤔</a> <a href="#infra-kazet" title="Infrastructure (Hosting, Build-Tools, etc)">🚇</a> <a href="https://github.com/CERT-Polska/Artemis/pulls?q=is%3Apr+reviewed-by%3Akazet" title="Reviewed Pull Requests">👀</a> <a href="#talk-kazet" title="Talks">📢</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/BonusPlay"><img src="https://avatars.githubusercontent.com/u/8405359?v=4?s=100" width="100px;" alt="Adam Kliś"/><br /><sub><b>Adam Kliś</b></sub></a><br /><a href="#question-BonusPlay" title="Answering Questions">💬</a> <a href="https://github.com/CERT-Polska/Artemis/commits?author=BonusPlay" title="Code">💻</a> <a href="#ideas-BonusPlay" title="Ideas, Planning, & Feedback">🤔</a> <a href="https://github.com/CERT-Polska/Artemis/pulls?q=is%3Apr+reviewed-by%3ABonusPlay" title="Reviewed Pull Requests">👀</a> <a href="#talk-BonusPlay" title="Talks">📢</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/anna1492"><img src="https://avatars.githubusercontent.com/u/142449177?v=4?s=100" width="100px;" alt="anna1492"/><br /><sub><b>anna1492</b></sub></a><br /><a href="https://github.com/CERT-Polska/Artemis/issues?q=author%3Aanna1492" title="Bug reports">🐛</a> <a href="https://github.com/CERT-Polska/Artemis/commits?author=anna1492" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/ELOOLE"><img src="https://avatars.githubusercontent.com/u/75997374?v=4?s=100" width="100px;" alt="Michał M."/><br /><sub><b>Michał M.</b></sub></a><br /><a href="https://github.com/CERT-Polska/Artemis/commits?author=ELOOLE" title="Code">💻</a> <a href="#ideas-ELOOLE" title="Ideas, Planning, & Feedback">🤔</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/cyberamt"><img src="https://avatars.githubusercontent.com/u/154326307?v=4?s=100" width="100px;" alt="cyberamt"/><br /><sub><b>cyberamt</b></sub></a><br /><a href="https://github.com/CERT-Polska/Artemis/commits?author=cyberamt" title="Code">💻</a> <a href="#ideas-cyberamt" title="Ideas, Planning, & Feedback">🤔</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/martclau"><img src="https://avatars.githubusercontent.com/u/7753513?v=4?s=100" width="100px;" alt="martclau"/><br /><sub><b>martclau</b></sub></a><br /><a href="https://github.com/CERT-Polska/Artemis/commits?author=martclau" title="Code">💻</a> <a href="#ideas-martclau" title="Ideas, Planning, & Feedback">🤔</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/szymsid"><img src="https://avatars.githubusercontent.com/u/26324394?v=4?s=100" width="100px;" alt="szymsid"/><br /><sub><b>szymsid</b></sub></a><br /><a href="https://github.com/CERT-Polska/Artemis/commits?author=szymsid" title="Code">💻</a> <a href="https://github.com/CERT-Polska/Artemis/pulls?q=is%3Apr+reviewed-by%3Aszymsid" title="Reviewed Pull Requests">👀</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/bulkowy"><img src="https://avatars.githubusercontent.com/u/25008387?v=4?s=100" width="100px;" alt="bulek"/><br /><sub><b>bulek</b></sub></a><br /><a href="https://github.com/CERT-Polska/Artemis/commits?author=bulkowy" title="Code">💻</a> <a href="https://github.com/CERT-Polska/Artemis/pulls?q=is%3Apr+reviewed-by%3Abulkowy" title="Reviewed Pull Requests">👀</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/mimi89999"><img src="https://avatars.githubusercontent.com/u/8530546?v=4?s=100" width="100px;" alt="Michel Le Bihan"/><br /><sub><b>Michel Le Bihan</b></sub></a><br /><a href="https://github.com/CERT-Polska/Artemis/commits?author=mimi89999" title="Code">💻</a></td>
    </tr>
  </tbody>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->
