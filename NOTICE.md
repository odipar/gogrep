# Notices

gogrep is Copyright (C) 2026 Robbert van Dalen and is licensed under the
GNU Lesser General Public License v2.1 (see [LICENSE](LICENSE)), the same
license as opengrep.

The gogrep module and every build contain the rule sets below and the Go
module gopkg.in/yaml.v3; release builds (`-tags gogrep_bundled`) also
contain the opengrep binary. Each of these third-party components is under
its own license. The versions of opengrep and the rule sets are pinned in
[opengrep.json](opengrep.json), and that of gopkg.in/yaml.v3 in
[go.mod](go.mod).

A Go program that imports the package `github.com/odipar/gogrep` contains
gogrep, the rule sets and gopkg.in/yaml.v3, as Go links packages
statically, but not opengrep, unless the program embeds it itself
(`Config.EmbeddedOpengrep`). Whoever distributes such a program as a binary
must meet the conditions of LGPL-2.1 for a work that uses the library,
among them passing on this notice, the license and gogrep's source code,
and letting recipients relink the program with a modified gogrep, as well
as the conditions of each license below. This notice does not cover Go
itself or the program's other dependencies.

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

## gopkg.in/yaml.v3

- Source: https://github.com/go-yaml/yaml
- License: MIT for the files ported from libyaml (Copyright (c) 2006-2011
  Kirill Simonov), and the Apache License, Version 2.0 for the rest

gogrep parses rules and suites with it. The full license text is the
`LICENSE` file of the module gopkg.in/yaml.v3, and its `NOTICE` file reads:

```
Copyright 2011-2016 Canonical Ltd.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
