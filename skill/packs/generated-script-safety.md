# Generated script safety

Hunt places where data becomes code: templates that emit PowerShell, shell, SQL, or configuration that another interpreter executes. This was the dominant candidate class in the first OMGS field reviews.

## What to hunt

- Serialized data (JSON, XML) string-replaced into a quoted script literal. JSON does not escape the apostrophe that ends a PowerShell single-quoted string.
- Double-quoted PowerShell strings containing data: subexpressions `$(...)`, backtick escapes, and variable expansion evaluate data as code.
- `Invoke-Expression`, `iex`, `eval`, `ScriptBlock.Create`, and AST-extent evaluation applied to text from project files, manifests, metadata, or imports.
- Shell commands built by interpolation (`sh -c`, `zsh -c`, `cmd /c`) instead of argv APIs, including inside supposedly harmless lookups like process searches.
- Metadata from files a tool imports (installer property tables, manifests, project databases) flowing into generated scripts that a different operator later runs, possibly elevated or fleet-wide.

## Source patterns that matter

- A placeholder inside quotes in a template, replaced with serialized user data at generation time.
- Escaping helpers that handle double quotes but not the quote character actually used at the sink.
- Generators that treat action parameters, names, paths, or folder names as code fragments instead of literal strings.
- Elevation on the generated path: the same injection is a different finding when the script runs as SYSTEM or deploys to many machines.

## Proof shape

Write a test with a value containing the sink's quote character and a harmless marker subexpression. Generate the script through the real generator inside `omgs prove`, then parse the generated script without executing side effects, or execute it against dummy state and assert the marker value stayed data. The authorized control is an ordinary value round-tripping unchanged.

## False leads a verifier should kill

- Values that pass through a real serializer whose output is parsed back as data by the consumer, never evaluated.
- Single-quoted PowerShell literals where apostrophes are doubled correctly before insertion.
- Argv-style process APIs where each value stays a separate argument and no shell parses it.
- Code the same principal fully controls end to end, with no import, sharing, or deployment step crossing a boundary.
