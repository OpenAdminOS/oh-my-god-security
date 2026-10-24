// Vulnerable install-decision logic.
//
// Mirrors the field-run defects: an optional expected signing team that is
// enforced only when present, and no version or downgrade enforcement at all.
// When `expectedTeam` is nil the signer is never checked, so any payload, even
// unsigned or unnotarized, is authorized and its root install hooks would run.

func decide(_ r: InstallRequest) -> InstallDecision {
    // Team is checked only when the caller demands a specific one. A nil
    // expected team skips verification entirely rather than failing closed.
    if let expected = r.expectedTeam {
        guard r.payloadTeam == expected else {
            return .refused("team mismatch")
        }
    }
    // The payload version and the caller-claimed version are never bound, and a
    // downgrade over a newer install is never refused.
    return .authorized
}
