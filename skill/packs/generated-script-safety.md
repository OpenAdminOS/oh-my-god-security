# Generated script safety

Hunt places where data becomes code: templates that emit PowerShell, shell, SQL, or configuration that another interpreter executes. Generated script injection is a recurring class where untrusted values must remain data.

## What to hunt

- Data inserted into script literals without escaping for the target quoting context.
- Double-quoted PowerShell strings containing data: subexpressions `$(...)`, backtick escapes, and variable expansion evaluate data as code.
- `Invoke-Expression`, `iex`, `eval`, `ScriptBlock.Create`, and AST-extent evaluation applied to text from project files, manifests, metadata, or imports.
- Shell commands built by interpolation (`sh -c`, `zsh -c`, `cmd /c`) instead of argv APIs, including inside supposedly harmless lookups like process searches.
- Metadata from files a tool imports (installer property tables, manifests, project databases) flowing into generated scripts that a different operator later runs, possibly elevated or fleet-wide.

## Source patterns that matter

- Generation paths that insert untrusted values without context-correct escaping at the sink.
- Escaping helpers that handle double quotes but not the quote character actually used at the sink.
- Generators that treat action parameters, names, paths, or folder names as code fragments instead of literal strings.
- Elevation on the generated path: the same injection is a different finding when the script runs as SYSTEM or deploys to many machines.

## Proof shape

Use a synthetic generator fixture with a value containing quote characters. Parse its output in the sandbox and assert that the value remains data and does not become a statement. Include an ordinary-value control that round-trips unchanged.

## False leads a verifier should kill

- Values that pass through a real serializer whose output is parsed back as data by the consumer, never evaluated.
- Script literals where values are escaped correctly for the target quoting context before insertion.
- Argv-style process APIs where each value stays a separate argument and no shell parses it.
- Code the same principal fully controls end to end, with no import, sharing, or deployment step crossing a boundary.

## Intent questions

When a record turns on intent, set its `intent_id` to one of these library questions instead of writing a new one, so one recorded answer resolves every record that asks it (`omgs intent list` shows them all):

- `script.manifest-supplier`: Who is allowed to supply the manifest, project, or configuration file whose values reach a generated script?
- `script.dry-run-executes`: Must a dry run be free of side effects, including executing commands built from input?
