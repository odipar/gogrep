# Notices

gogrep is Copyright (C) 2026 Robbert van Dalen and is licensed under the
GNU Lesser General Public License v2.1 (see [LICENSE](LICENSE)), the same
license as opengrep.

Release builds of gogrep (`-tags bundled`) also contain the third-party
components below, each under its own license. Their versions are pinned in
[opengrep.json](opengrep.json).

## opengrep

- Source: https://github.com/opengrep/opengrep
- License: GNU Lesser General Public License v2.1

gogrep embeds the unmodified opengrep release binary for each platform and
runs it as a separate program.

## opengrep-rules

- Source: https://github.com/opengrep/opengrep-rules (fork of
  https://github.com/semgrep/semgrep-rules as of December 13, 2024)
- License: GNU Lesser General Public License v2.1 with the
  "Commons Clause" License Condition v1.0
- Licensor: Semgrep, Inc.

The Commons Clause does not grant the right to sell a product or service
whose value derives entirely or substantially from these rules. The full
license text is embedded with the rules and written next to them as
`opengrep-rules/LICENSE` when gogrep extracts them.
