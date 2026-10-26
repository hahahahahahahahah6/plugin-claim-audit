# plugin-claim-audit

An offline static audit of documented third-party extensibility promises.
Version 0.1.0. Requires Python 3.9 or later; runtime dependencies are limited
to the Python standard library. Licensed under MIT.

Install with `python3 -m pip install .` and run:

```sh
plugin-claim-audit [ROOT] --json --verbose --ignore 'vendor/*' --fail-on HIGH
python3 -m plugin_claim_audit .
```

ROOT defaults to the current directory. Output is text or JSON with `status`,
`evidence`, `claims`, and `findings`. Text lists rule and severity; verbose
mode adds the relative path. Exit codes are 0 for success at the selected
threshold, 2 for findings at that threshold, and 1 for input or usage errors.
The default threshold is MEDIUM; HIGH still reports lower severity findings.
`--version` prints the version. `--ignore` accepts one or more POSIX relative
path globs and can be repeated.

The scanner reads root README.md and Markdown files beneath any docs path
component. It excludes fenced blocks, counts inline code, joins lines within
paragraphs, normalizes case and hyphens, and matches exact phrases at word
boundaries. Negative spans are removed before positive matching. One finding
per family is emitted, preferring a document outside tests. Documents beneath
tests produce MEDIUM findings; other documents produce HIGH findings.

Python files are parsed with AST without execution. Files beneath tests and
files whose names start with test_ are excluded. Symlinks are skipped and
.env files are never opened. Unreadable inputs and invalid Python are errors.

Evidence requires calls in the same module: metadata discovery paired with
loading, a Pluggy manager paired with registration, a Stevedore manager,
a directory scan containing a relevant literal paired with a variable module
import, or registry mutation paired with a module import. Ordinary import
aliases are resolved. Packaging declarations, fixed imports alone, comments,
and docstrings do not constitute evidence. This is a static heuristic: it does
not prove runtime reachability, data flow, or successful execution.

With no source, positive promises produce a finding and negative promises
pass. With no documented promise, the audit passes regardless of source.

The complete phrase vocabulary follows:

```text
PLUGIN
plugin support
supports plugins
supports plugin
plugin system
plugins supported
plugin supported
third party plugins
third party plugin
custom plugins
custom plugin
plugin api
plugin architecture
plugin framework
plugin based
plugin model
extensible through plugins
extensible via plugins
extensible with plugins
extendable with plugins
extendable through plugins
extend with plugins
write plugins
write your own plugin
write your own plugins
install plugins
install third party plugins
load plugins
loads plugins
loading plugins
plugin discovery
discovers plugins
pluggable architecture
pluggable system
supports third party extensions

NOPLUGIN
no plugin support
does not support plugins
does not support plugin
no plugins
no plugin system
plugins are not supported
plugin support is not available
not extensible
not extendable
cannot be extended
no third party plugins
no custom plugins
does not load plugins
no plugin api
```

Run tests with `python3 -m unittest discover`. Build distributions with
`python3 -m build` (requires the build frontend).
