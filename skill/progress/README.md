# Pipeline progress (optional live view)

`dashboard.html` is a self-contained, offline progress view for a running OMGS pipeline. It polls a
sibling `pipeline-status.json` (schema: `status.schema.json`) that the orchestrator writes at each
milestone, and renders the stages (map, the parallel red hunters, blue verify, prove, adjudicate,
report) with live states, timers, counters, and an activity log. It loads no external resources and
runs no scripts beyond its own inline polling.

This view is optional and never changes a verdict. The deterministic `findings.json`, SARIF, and
`REPORT.html` remain the record. Serve it with:

    omgs watch --run <run-dir>

It binds 127.0.0.1 on an ephemeral port and prints the URL, serves only this page and
`pipeline-status.json` (never findings, reports, or anything else in the run directory), rejects
foreign Host headers, and exits shortly after `omgs report` marks the run complete. Update the status
file with `omgs status --run <run-dir> --stage <id> --state active` rather than writing it by hand.
Do not serve the run directory with a generic file server: that would expose the findings. Never
auto-open a browser and never bind a non-loopback interface: the page describes vulnerabilities.
