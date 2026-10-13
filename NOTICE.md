# Notices

gogrep is Copyright (C) 2026 Robbert van Dalen and is licensed under the
GNU Lesser General Public License v2.1 (see [LICENSE](LICENSE)), the same
license as opengrep.

The gogrep module and every build contain the rule sets below; release
builds (`-tags gogrep_bundled`) also contain the opengrep binary. Each of
these third-party components is under its own license, and their versions
are pinned in [opengrep.json](opengrep.json).

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
license text is the `LICENSE` file in the rules' archive,
[internal/rulesets/opengrep-rules.tar.gz](internal/rulesets), which every
build embeds.

## 0xdea/semgrep-rules (rule set `0xdea`)

- Source: https://github.com/0xdea/semgrep-rules
- License: MIT, Copyright (c) 2022 raptor (Marco Ivaldi)

## dgryski/semgrep-go (rule set `semgrep-go`)

- Source: https://github.com/dgryski/semgrep-go
- License: MIT, Copyright (c) 2020 Damian Gryski

Each rule set's license file travels with it as `LICENSE` in its archive,
`internal/rulesets/<rule set>.tar.gz`.
