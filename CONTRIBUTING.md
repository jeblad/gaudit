# Contributing

Contributions are welcome: code, tests, translations, bug reports and ideas. gAudit is for ordinary users who want to keep their computer secure, so changes should make the app clearer, more honest or more reliable for them.

## License of contributions

gAudit is licensed under the [GNU General Public License v3.0 only](LICENSE) (`GPL-3.0-only`).

By submitting a contribution to gAudit itself, you agree that it is licensed under the same license, and you confirm that you have the right to submit it. There is no separate contributor agreement, and you keep the copyright to your work.

Plugins are separate works. They talk to gAudit only through processes and documented data formats, and they may use any license you choose.

## Security issues

Please do not report security vulnerabilities in public issues. Use GitHub's private vulnerability reporting for the repository instead.

## Before you start

Read [AGENTS.md](AGENTS.md). It records the design decisions, the threat model and the conventions. Please do not reopen a settled decision without a concrete reason. For larger changes, open an issue first, so we can agree on the approach before you spend time on it.

## Making a change

1. Fork the repository and create a branch for your change.
2. Build and run the tests:

   ```sh
   cmake --preset dev
   cmake --build --preset dev
   ctest --preset dev
   ```

3. Follow the project conventions:
   - Code comments and documentation are written in English.
   - Every new code or build file starts with `SPDX-License-Identifier: GPL-3.0-only`.
   - Read system state directly from files. Never parse the output of other tools.
   - When a check cannot tell, its result is *unknown*. It never guesses.
   - Add targeted tests with fixtures for new behaviour. There is no test framework, and none is wanted.
4. Write commit messages in the [Conventional Commits](https://www.conventionalcommits.org/) format (`feat:`, `fix:`, `docs:`, `build:` …). The changelog and version numbers are generated from them.
5. Open a pull request that describes what changed and why.

## Translations

User-facing strings are translated with gettext in `po/`. A wrong word in a security app can make a warning read as harmless. New translations and larger changes to existing ones therefore need a native speaker to review them before they are merged. Mention in the pull request which language you speak natively.

## Code of conduct

This project follows its [Code of Conduct](CODE_OF_CONDUCT.md). By taking part, you agree to follow it.
