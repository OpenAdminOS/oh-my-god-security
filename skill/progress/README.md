# Pipeline progress (optional live view)

`dashboard.html` is a self-contained progress view for a running OMGS review. It polls a sibling
`pipeline-status.json` (schema: `status.schema.json`) every 2 seconds. It shows plain-language review
steps, a "Happening now" summary, which part of the system is working, sandbox controls, timers,
counters and an activity log. Leads found are possibilities, not findings. Proven problems, Still
checking and Ruled out reflect the existing schema counters without changing their meaning.
Updates older than 2 minutes and failed polls show a stale indicator. It loads no external resources.

The view is optional and never changes a verdict. `findings.json`, SARIF and `REPORT.html` remain
the record. Status recording is mandatory, even without this view: follow the transition commands
in [PIPELINE.md](../PIPELINE.md#required-progress-at-every-transition). Use `omgs status` with a
plain-language detail, never hand-write the JSON.

At run start, ask once whether to open the live view. Only after an explicit yes in an interactive
session, start watch in the background and open its printed URL with the default OS browser opener.
Never open a browser without that explicit yes. With no answer, no, or a headless or non-interactive
session, do not open a browser; starting watch and printing the URL remains allowed. See
[HANDOFF-AND-PROGRESS.md](../HANDOFF-AND-PROGRESS.md#status-updates-and-optional-live-view)
for opener commands and the full consent flow. To serve the view:

    omgs watch --run <run-dir>

It binds 127.0.0.1 on an ephemeral port and prints the URL, serves only this page and
`pipeline-status.json` (never findings, reports, or anything else in the run directory), rejects
foreign Host headers, and exits shortly after `omgs report` marks the run complete. Status
requests need the per-run token from the URL fragment (`#token=...`) in an `X-OMGS-Token` header,
so other local users and processes cannot read it, and the status never quotes finding or lead
titles. The server
itself never opens a browser. Never bind a non-loopback interface or serve the run directory with a
generic file server.

Live status works on macOS, Linux and Windows using the shared protected run-artifact reader. It
rejects linked or non-private status files and bounds reads to 1 MiB. A missing file yields empty
status; a file that fails protected-read checks returns HTTP 500 instead of empty status. Other
platforms fail closed when contained reads are unavailable.
