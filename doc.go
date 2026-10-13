// Package gogrep scans source trees with opengrep and gogrep's pinned rule
// sets, selected with CodeQL-style query suites under stable rule ids, and
// returns the results as SARIF and as typed findings. The gogrep command is
// a thin layer over it.
//
// One [Engine], made by [New], serves a whole program:
//
//	eng, err := gogrep.New(gogrep.Config{})
//	if _, err := eng.Opengrep(ctx); errors.Is(err, gogrep.ErrNoOpengrep) {
//		_, err = eng.InstallOpengrep(ctx, nil) // the only network access
//	}
//	res, err := eng.Scan(ctx, "/abs/clone", &gogrep.ScanOptions{
//		Selection:      gogrep.Selection{Suites: []string{"security-extended"}},
//		NoProjectRules: true, // an untrusted clone
//	})
//	for _, f := range res.Findings {
//		fmt.Println(f.RuleID, f.Path, f.StartLine, f.Level, f.Suppressed)
//	}
//
// # Obtaining opengrep
//
// The rule sets travel with this module, but the opengrep executable (46 to
// 53 MB per platform) does not. [Engine.Opengrep] finds it, without using the
// network, in this order:
//
//  1. [Config].Opengrep, whatever its version;
//  2. [Config].EmbeddedOpengrep, an executable compiled into the program,
//     which must be the pinned build and is written to the cache;
//  3. the pinned executable in [Config].CacheDir, as
//     opengrep-<sha16>/opengrep[.exe];
//  4. opengrep on PATH, if its SHA-256 is the pinned one or
//     [Config].AllowUnpinned is set.
//
// Without one, the methods that run opengrep return an error wrapping
// [ErrNoOpengrep]. [Engine.InstallOpengrep] downloads the pinned release
// asset from GitHub into the cache, verified against the SHA-256 that this
// module's opengrep.json pins; `gogrep install-opengrep` fills the same
// default cache. Machines without network access can install from a local
// copy of the asset ([InstallOptions].From), from a mirror
// ([InstallOptions].BaseURL), by running a gogrep release executable once
// (it extracts the opengrep it embeds into the default cache), by copying
// the cache's opengrep-<sha16> directory from another machine, or with
// [Config].Opengrep. Platforms without a pinned build, such as FreeBSD, run
// opengrep through [Config].Opengrep or [Config].AllowUnpinned.
//
// The first time an executable is used with a cache, opengrep unpacks its
// runtime (about 245 MB, in about 8 s). On Linux and macOS this happens
// once, privately, and the complete runtime is then published in the cache,
// so that concurrent opengrep processes, in this process or others, never
// start from a half-written one; on Windows, gogrep lets one opengrep
// unpack it alone, where opengrep keeps it. opengrep 1.30.2 runs nothing
// when its runtime is under a path that is not ASCII, so on Linux and macOS
// a [Config].CacheDir that is not ASCII leaves it where opengrep keeps it.
//
// On macOS, files that Go writes carry no quarantine attribute, so
// Gatekeeper is not involved. A host application that sets
// LSFileQuarantineEnabled would quarantine the cached executable, which
// Gatekeeper then blocks, as opengrep is not notarised; the package never
// removes the attribute, so set [Config].Opengrep instead.
//
// # Offline use
//
// Only [Engine.InstallOpengrep] opens network connections, and only when it
// must download. [Engine.Rules], [Engine.Suites], [Engine.AcceptTests],
// [Selection.Validate] and [Engine.PruneCache] never run opengrep.
// [Engine.Scan], [Engine.Test] and [Engine.Command] with a Selection pass
// --disable-version-check, and Scan and Test remove opengrep's environment
// variables, so their rules and targets are local files and opengrep checks
// for no new version. [Engine.Command] without a Selection passes its
// arguments through unchanged: "scan --config auto" downloads rules.
//
// # Rule sets, suites and rule ids
//
// Every build has gogrep's rule sets:
//
//   - opengrep-rules, 0xdea and semgrep-go, third-party rules pinned to a
//     git commit each in opengrep.json, together the group "bundled";
//   - gogrep, this module's own rules;
//   - project, the rules under [ProjectRulesDir] of the directory a call
//     names, without its rule test fixtures ([ProjectTestsDir]).
//
// "all" names every set. A [Selection] picks rules from them by suite, by
// rule id and by field. The built-in suites are code-scanning (the
// [DefaultSuite]), security-extended, security-and-quality and all; a
// project adds its own, or replaces a built-in one, in [ProjectSuitesDir].
// The suite format is described at
// https://github.com/odipar/gogrep/blob/main/suites/README.md.
//
// Every rule has a stable qualified id, <set>.<dir>.<id>, such as
// opengrep-rules.go.lang.security.audit.dangerous-exec-command: its rule
// set, the directories of its rule file and its id there. Findings carry it
// as their RuleID, so results keep their identity across machines and rule
// updates.
//
// # Untrusted repositories
//
// By default, as in the gogrep command, a directory's own rules and suites
// take part in a call. Set NoProjectRules on [ScanOptions], [RulesOptions],
// [SuitesOptions] and [CommandOptions], per call, for repositories you do
// not trust; [Engine.Test] always loads them, since testing them is its
// purpose, so use [TestOptions].ReadOnly for clones. What a repository
// controls:
//
//   - opengrep/gogrep/rules adds rules that run. opengrep rules are patterns
//     and run no code, but they can add noise or cost CPU (pattern-regex).
//     NoProjectRules ignores them; RuleTimeout, MaxMemoryMB and a ctx
//     deadline bound the cost.
//   - A project rule file may be a symlink, which gogrep follows (it never
//     enters a symlinked directory), so a repository can make gogrep read a
//     file outside it as rule YAML, and parse errors may quote it.
//     NoProjectRules ignores them.
//   - opengrep/gogrep/suites can replace the default suite with one that
//     selects nothing. NoProjectRules ignores them.
//   - opengrep/gogrep/rules/test is left out of scans that run gogrep's
//     rules; under NoProjectRules it is scanned like any other directory.
//   - nosemgrep comments suppress matches. Their findings stay in
//     [Result].Findings with Suppressed set; whether they count is the
//     caller's choice.
//   - .semgrepignore and .gitignore hide files from a scan, as opengrep
//     reads them in the scanned directory. This cannot be turned off.
//   - .git/config: opengrep runs git in the scanned directory, and git
//     honours the repository's configuration. Scan only directories whose
//     .git your own git clone created; a clone never copies the remote's
//     configuration.
//   - Symlinks in the scanned tree are not followed.
//   - Large or many files cost memory and time: use MaxTargetBytes,
//     RuleTimeout, MaxMemoryMB and ctx.
//
// # Concurrency and memory
//
// An Engine is safe for concurrent use: create one per process and share it.
// The built-in rule sets are parsed once per process (about 0.13 s for 2,121
// rules) and shared read-only; a directory's project rules are parsed per
// call, so each call sees them as they are at that moment. Scan, Rules,
// Suites and Command never write into the directory they are given, so
// scans of one directory may run at once. Test (unless ReadOnly) and
// AcceptTests write fixture files: do not run two of them on one directory
// at once. Several Engines and several processes may share one CacheDir.
//
// [TestOptions].Progress runs on the goroutine that called Test;
// [ScanOptions].Stderr is written from another goroutine, so a writer shared
// by concurrent scans must be safe for concurrent use.
//
// The package limits no concurrency itself. One scan's opengrep processes
// take about 250 to 360 MB together; a program that scans N directories at
// once bounds N itself and sets [ScanOptions].Jobs so that N × Jobs is about
// the number of CPUs. Test runs one opengrep process per CPU unless
// [TestOptions].Jobs says otherwise.
//
// # Cancellation and signals
//
// Methods that run opengrep take a context. When it is done, they kill the
// opengrep processes they started, with every process those started, and
// return an error for which errors.Is(err, context.Canceled) (or
// context.DeadlineExceeded) holds; Test also returns the tests reported so
// far. Waits for locks, downloads and runtime preparation stop with the
// context too. A deadline therefore bounds a call.
//
// opengrep runs in a process group of its own (on Windows, as a process tree
// that taskkill ends), so a terminal's Ctrl-C reaches only the host program.
// A done context sends that group SIGINT, as Ctrl-C would, so that opengrep
// can show the terminal's cursor again and remove its temporary files, and
// SIGKILL a second later. The package installs no signal handlers: a
// program that wants Ctrl-C to stop its scans cancels the context itself,
// for example with signal.NotifyContext. A host that dies without
// cancelling, from SIGKILL or a signal it does not handle, leaves its
// opengrep processes to finish their scans.
//
// # Files
//
// Everything the package writes is under [Config].CacheDir, by default
// gogrep in os.UserCacheDir (~/Library/Caches/gogrep on macOS,
// $XDG_CACHE_HOME/gogrep or ~/.cache/gogrep on Linux, %LocalAppData%\gogrep
// on Windows), which the gogrep command shares. Directories are 0o700 and
// files 0o600:
//
//   - opengrep-<sha16>/opengrep[.exe], the executable (0o700);
//   - runtime-<sha16>/, opengrep's unpacked runtime (Linux, macOS), or
//     runtime-<sha16>.ready, which marks it as unpacked (Windows);
//   - selections/<sha16>.yaml, the rules of a selection, named by their
//     content, so that the command lines in TestResult.Command can be run
//     again;
//   - logs/opengrep-*.log, opengrep's log for one process of Scan, Test or
//     runtime preparation, removed when it ends;
//   - locks/, and temporaries that are removed on every path.
//
// [Engine.PruneCache] removes the selections, and the executables and
// runtimes of other opengrep builds, that no run has used for 30 days. It
// never runs by itself. The only
// files written elsewhere are the fixture files of [Engine.Test] (unless
// ReadOnly) and [Engine.AcceptTests]. opengrep run by [Engine.Command] keeps
// its own log, ~/.opengrep/semgrep.log.
//
// # What the package reads from the process
//
// PATH, through exec.LookPath; os.Environ (when [Config].Env is nil) and
// os.UserCacheDir (when [Config].CacheDir is empty), once each, in New;
// HTTPS_PROXY and NO_PROXY, only in the default client of
// [Engine.InstallOpengrep]; and on Linux, which C library's loader exists,
// to pick the glibc or musl build. It never changes the working directory,
// installs no signal handler, never touches the standard streams, and never
// reads OPENGREP_BIN or SEMGREP_RULES, which only the gogrep command
// honours. Every directory argument must be the absolute path of an
// existing directory.
//
// # Errors
//
// Findings are data, never errors: a scan that finds something succeeds.
// gogrep never passes --error to opengrep. The errors are:
//
//   - a [*SelectionError], [ErrNoRules] or an error wrapping
//     [ErrUnknownSuite] for a bad selection;
//   - an error wrapping [ErrNoOpengrep], or an [*IntegrityError], when no
//     usable opengrep is found or it cannot be started;
//   - an [*ExitError] when opengrep exits non-zero, with the
//     [ExitError].Result it still wrote, if any;
//   - an [*OutputError], which is [ErrNoSARIF], when it exits 0 without a
//     valid SARIF log;
//   - an error wrapping [ErrNoTestRoot] from Test and AcceptTests for a
//     project without rule test fixtures;
//   - an error wrapping ctx.Err() when the context ends a call;
//   - a plain error for an invalid argument, such as a directory that is
//     relative, missing or not a directory, which names it.
//
// The gogrep command exits with opengrep's code after a scan, 1 when it
// finds no opengrep, 2 for a bad selection or usage, and 130 when
// interrupted; [ExitError] shows how a program can do the same.
//
// # Stability
//
// gogrep's Go API is new in v0.4.0 and is v0: a minor release (v0.x.0) may
// change it, and its release notes list every change under "API changes";
// a patch release never does. Anything deprecated keeps working, marked
// "Deprecated:", for at least one minor release. Identifiers marked
// "Experimental:" ([Engine.Command], [CommandOptions], [Cmd]) may change in
// any minor release. New options are added only as fields whose zero value
// keeps the old behaviour; no exported function gains parameters.
// Re-pinning opengrep or a rule set happens only in minor releases and can
// change findings; rule ids stay stable. [OpengrepInfo] reports which
// opengrep a call runs.
//
// # Licensing
//
// gogrep is licensed under the GNU Lesser General Public License v2.1, like
// opengrep. Go links packages statically, so a program that imports this
// package contains gogrep's code: whoever distributes that program as a
// binary must meet LGPL-2.1's conditions for a work that uses the library.
// In short, they must give recipients the license and gogrep's notices,
// gogrep's source code (with any changes made to it), and a way to relink
// the program with a modified gogrep, such as the program's source code or
// its object files. A program that embeds opengrep through
// [Config].EmbeddedOpengrep also distributes opengrep, under the same
// license.
//
// Every program that imports this package also contains the rule sets.
// opengrep-rules is licensed under LGPL-2.1 with the Commons Clause, which
// grants no right to sell a product or service whose value derives entirely
// or substantially from those rules; 0xdea and semgrep-go are MIT-licensed.
// NOTICE.md in this module lists every component and its license; ship it
// with the program.
package gogrep
