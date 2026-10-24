# OMGS field test: next 20 Awesome Intune projects

Traced reviews only, run 2026-10-16 against a seeded random sample of 20 further Awesome Intune projects, excluding the six from the first field test. No target code was executed and no finding below is confirmed. Each report was rendered by the OMGS CLI from validated findings, and every cited location was checked to exist in the reviewed commit.

Totals across 20 projects: 41 needs validation, 15 rejected after hunter verification, 0 confirmed. Combined with the first six projects: 26 projects reviewed, still 0 confirmed, which is the single clearest product signal in this document.

| Project | Type | Stacks detected | Pending | Rejected | Strongest pending title |
| --- | --- | --- | --- | --- | --- |
| [Windows LAPS Self‑Service Portal](https://github.com/daniel-fraubaum/laps-self-service-portal) | web-app | powershell | 2 | 0 | Display-name credential lookup may return a different device password after ownership passes |
| [FixMyADMX](https://github.com/MHimken/FixMyADMX) | other | powershell | 0 | 2 | none, clean at traced level |
| [IntuneDeviceInventory](https://github.com/FlorianSLZ/IntuneDeviceInventory) | powershell-module | powershell | 2 | 0 | Runbook inventory fields may redirect a validated device update to another device |
| [Win32 App Migration Tool](https://github.com/byteben/Win32App-Migration-Tool) | powershell-module | powershell | 3 | 0 | Existing Graph context can redirect migration writes away from the requested tenant |
| [AutopilotGroupTagger](https://github.com/ennnbeee/AutopilotGroupTagger) | powershell-script | powershell | 3 | 0 | An existing Graph session can direct requested-tenant tag changes to another tenant |
| [Intune Win32 Retry Reset Script](https://github.com/fatihturkoglu/intune-win32-retry-reset) | other | powershell | 2 | 0 | Matching a shared IME key can delete state for apps outside the requested reset |
| [IntuneFirewallMigration](https://github.com/ennnbeee/IntuneFirewallMigration) | powershell-script | powershell | 3 | 0 | Settings Catalog conversion replaces restricted interface types with all interfaces |
| [Intuneomator](https://github.com/gilburns/Intuneomator) | desktop-app | swift | 3 | 0 | Unverified XPC clients may retrieve the stored Entra client secret |
| [Windows Media Creation CLI](https://github.com/niklasrst/windows-mediacreation-cli) | powershell-script | powershell | 2 | 1 | Existing image cache may substitute attacker-controlled installation content |
| [Company Portal Icons](https://github.com/MrtnRQL/Companyportaliconsdotcom) | web-app | static-web | 1 | 2 | An Intune app display name may execute markup in the signed-in status panel |
| [Wintuner GUI](https://github.com/manuelhoefler17-gif/WinTuner-GUI) | other | powershell | 1 | 2 | A writer to reused package storage may substitute an Intune upload |
| [Get-IntuneManagementExtensionDiagnostics](https://github.com/petripaavola/Get-IntuneManagementExtensionDiagnostics) | powershell-script | powershell | 2 | 1 | Imported diagnostic text can become active HTML in the report |
| [Autopilot Monitor](https://github.com/okieselbach/Autopilot-Monitor) | web-app | aspnet, powershell | 2 | 1 | A same-tenant device may claim another device bootstrap session using its serial |
| [macOS Defender Check](https://github.com/SSMacAdmin/macOS_DefenderCheck) | other | none | 3 | 0 | Transport or tool errors can be reported as successful Defender blocking |
| [Intune Admin Center Tools](https://github.com/UniverseCitiz3n/Intune-Admin-Center-Tools) | browser-extension | none | 2 | 1 | Tenant-controlled member names may insert deceptive HTML into the extension popup |
| [InToolz](https://github.com/Kvikku/IntuneTools) | desktop-app | aspnet | 1 | 2 | Imported metadata may become spreadsheet formulas after CSV export |
| [IntuneWin32AppUninstall](https://github.com/mertozsoy/IntuneWin32AppUninstall) | powershell-script | powershell | 2 | 1 | Registry display names can become executable expressions in generated Intune scripts |
| [EntraDeviceAuth](https://github.com/FlorianSLZ/EntraDeviceAuth) | powershell-module | powershell | 3 | 0 | Caller-selected RSA key may authenticate as a different enrolled device |
| [TenuVault](https://github.com/ugurkocde/TenuVault) | desktop-app | nextjs-app-router, powershell, python | 1 | 2 | Legacy TVB1 files may be presented as authenticated snapshots of another tenant |
| [IntuneGet](https://github.com/ugurkocde/IntuneGet) | web-app | nextjs-app-router, powershell, python | 3 | 0 | Managed-identity inventory requests can cross from caller tenant to identity tenant |

## Patterns across the 20

- Identity substitution is the recurring shape: a display name, serial, stored note, CSV row, existing Graph session, or shared captured token stands in for the device, tenant, or admin that authorization was actually checked against. At least seven projects produced a candidate of this shape.
- Fail-open security semantics: firewall rule conversion broadening restrictions in three variants, health checks reporting success on transport or tool errors, and a password disclosure that may proceed when its audit write fails.
- Values becoming code stayed dominant: generated script injection and feed-to-policy classes tied as the most frequent attack classes in this batch.
- One project returned rejected records only at traced level. A clean result with counterevidence is a valid review outcome and useful calibration data.

## OMGS learnings at this scale

1. Proof execution is now the bottleneck, not hunting. The sandbox backend works, but hunters in traced mode never call it. The default flow should attempt a sandbox proof for every candidate whose runtime exists locally (PowerShell, Node, Swift, shell) and record the exact blocker when it does not.
2. Sensor triage needs path classes. Seventy-five gitleaks hits across this batch concentrated in docs, tests, and catalog data. OMGS should classify hits as code, test, docs, or data, require a disposition record for code hits, and baseline the rest visibly instead of leaving raw counts in metadata.
3. Stack detection needs shell and browser-extension stacks, subdirectory awareness for monorepos (a Node backend beside PowerShell was missed), and a data-versus-code file classification: one target carried roughly sixty-five thousand catalog files and another a few hundred icon assets, all currently counted as first party files.
4. Batch mode is no longer optional. Twenty reviews were orchestrated by hand: clone, init, five-at-a-time hunters, render, aggregate. The CLI needs a batch command that owns this queue and writes one aggregate index.
5. Per-repo record caps make counts incomparable. Hunters capped at three records returned two or three almost everywhere regardless of repository size. Benchmark reporting must normalize by budget and coverage, never by raw counts.
6. Hunter cost is still invisible. No child review recorded calls, tokens, or duration into run metadata, so cost per run cannot be computed for this batch. The runner must capture accounting from the agent host instead of trusting hunters to self-report.
7. A new pack shape emerged: identity binding. Shown-versus-acted-on identifiers, session tenant pinning, and approval screens that display one key while the write uses another deserve a dedicated pack alongside a fail-closed semantics pack for security tooling exit codes and health reporting.
