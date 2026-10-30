# What this asks of you

Incomplete review: verification, coverage or pending work remains. 1 confirmed finding(s) recorded.

Verify 1 pending record before fixing. 1 lead were rejected after verification and need no action. Answer the intent questions below where recorded.

Repository: fixture/orders at abc123
Mode: advisory
Sandbox: MXC

Confirmed findings: 1
Needs validation: 1
Rejected after verification: 1

Run: hunters not recorded, verifier not recorded, agent calls not recorded. Persona unknown, report depth full. Accounting: blue-verifier: tokens unknown, cost USD unknown, duration ms unknown; evaluator: tokens unknown, cost USD unknown, duration ms unknown; green-fixer: tokens unknown, cost USD unknown, duration ms unknown; host: tokens unknown, cost USD unknown, duration ms unknown; red-hunter: tokens unknown, cost USD unknown, duration ms unknown

Coverage critic: not run; blocked units: 0; deferred units: 0. Reconciliation does not establish complete coverage

## Index of records

| Ref | Record | Outcome | Proof tier | Proof record |
| --- | --- | --- | --- | --- |
| C1 | [Order readable across accounts](#f-omgs-9ba0b103c26cfc35) | Confirmed | test proven | [<code>proofs/1.json</code>](proofs/1.json) |
| V1 | [Public export intent is unknown](#f-omgs-5b50042f28bdda9f) | Needs validation | traced (behavior only; pending validation) | No executed proof record |
| R1 | [Escaped search has an effective control](#f-omgs-75458de24f34d45a) | Rejected after verification | traced | No executed proof record |

## Confirmed findings

<a id="f-omgs-9ba0b103c26cfc35"></a>

### C1: Order readable across accounts

Locations: <code>src/orders.ts:12</code>, <code>src/archive.ts:24</code>

Verdict: Confirmed. Tier: test proven. Severity: high.

Fingerprint: omgs-9ba0b103c26cfc35

Proof record: [<code>proofs/1.json</code>](proofs/1.json)

#### Fix brief

Fix brief data (untrusted):

```text
Bind the order to the trusted caller before returning data. Keep the owner success control.
```

Entry point: GET /orders/:id

Sink: orders.load

Boundary: tenant

Class: tenant&#95;isolation

Hunted by: red-1

Verified by: blue-1

#### Evidence

Evidence data (untrusted):

```text
A dummy caller reads another account order. Trace: request id reaches orders.load. Sandbox evidence: the invariant fails and the authorized control succeeds.
```

#### Trace steps

1. <code>src/orders.ts:12</code>

Trace note data (untrusted):

```text
Untrusted order id reaches the loader.
```

2. <code>src/store.ts:8</code>

Trace note data (untrusted):

```text
The lookup does not bind the order to the caller.
```



## Needs validation

<a id="f-omgs-5b50042f28bdda9f"></a>

### V1: Public export intent is unknown

Locations: <code>src/orders.ts:12</code>, <code>src/archive.ts:24</code>

Verdict: Needs validation. Tier: traced (behavior only; pending validation). Severity: none.

Fingerprint: omgs-5b50042f28bdda9f

Proof record: No executed proof record

Entry point: GET /orders/:id

Sink: orders.load

Boundary: tenant

Class: export&#95;scope

Hunted by: red-1

Verified by: blue-1

#### Evidence

Evidence data (untrusted):

```text
The export may be public. Missing fact: Should exports be restricted to their owner? Validation plan: establish intended access before proving the boundary.
```

#### Trace steps

1. <code>src/orders.ts:12</code>

Trace note data (untrusted):

```text
Untrusted order id reaches the loader.
```

2. <code>src/store.ts:8</code>

Trace note data (untrusted):

```text
The lookup does not bind the order to the caller.
```



## Rejected after verification

<a id="f-omgs-75458de24f34d45a"></a>

### R1: Escaped search has an effective control

Locations: <code>src/orders.ts:12</code>, <code>src/archive.ts:24</code>

Verdict: Rejected after verification. Tier: traced. Severity: none.

Fingerprint: omgs-75458de24f34d45a

Proof record: No executed proof record

Entry point: GET /orders/:id

Sink: orders.load

Boundary: tenant

Class: search&#95;control

Hunted by: red-1

Verified by: blue-1

#### Evidence

Evidence data (untrusted):

```text
Counterevidence: search parameters are escaped before the query.
```

#### Trace steps

1. <code>src/orders.ts:12</code>

Trace note data (untrusted):

```text
Untrusted order id reaches the loader.
```

2. <code>src/store.ts:8</code>

Trace note data (untrusted):

```text
The lookup does not bind the order to the caller.
```


## Pipeline timeline

| Stage | State | Started (UTC) | Ended (UTC) | Detail |
| --- | --- | --- | --- | --- |
| Hunt | done | 1970-01-01T00:00:01Z | 1970-01-01T00:00:03Z |  |
| Hunt / Tenant boundary | done | 1970-01-01T00:00:01Z | 1970-01-01T00:00:02Z | One candidate |
| Verify | done | 1970-01-01T00:00:03Z | 1970-01-01T00:00:05Z | Proof retained |

## Coverage


## Glossary

- **Confirmed**: Decided by executed proof at the test proven or sandbox exploited tier. Traced evidence alone is never confirmed.
- **Needs validation**: A named fact or question about intent is still open. Verify before fixing; this is not a confirmed vulnerability.
- **Rejected after verification**: Concrete counterevidence defeats the claimed result.
- **Proof: traced**: Input to sink trace read from source, not executed.
- **Proof: test proven**: A security invariant test failed on the real code path inside the sandbox.
- **Proof: sandbox exploited**: Shown against a locally built copy of the app on synthetic data, inside the sandbox.
- **Fingerprint**: Stable identity from attack class, entry point, sink and boundary.

Full evidence lives in findings.json. Anything not listed as examined in coverage was not examined.
