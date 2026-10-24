# Pipeline progress (optional live view)

`dashboard.html` is a self-contained, offline progress view for a running OMGS pipeline. It polls a
sibling `pipeline-status.json` (schema: `status.schema.json`) that the orchestrator writes at each
milestone, and renders the stages (map, the parallel red hunters, blue verify, prove, adjudicate,
report) with live states, timers, counters, and an activity log. It loads no external resources and
runs no scripts beyond its own inline polling.

This view is optional and never changes a verdict. The deterministic `findings.json`, SARIF, and
`REPORT.html` remain the record. If you serve it over HTTP, bind loopback only and shut it down when
the run ends:

    python3 -m http.server 0 --bind 127.0.0.1 --directory <run-dir>

Never auto-open a browser and never bind a non-loopback interface: the page describes vulnerabilities.
