// Fixed install-decision logic.
//
// Fails closed on signer identity and binds the version to the payload. A nil
// expected team no longer disables verification: the payload must still carry a
// verified signer and, with no specific team demanded, must be notarized. The
// claimed version must match the payload, and a downgrade is refused.

func decide(_ r: InstallRequest) -> InstallDecision {
    // A verified signer is always required.
    guard let team = r.payloadTeam, !team.isEmpty else {
        return .refused("no verified signer")
    }
    if let expected = r.expectedTeam {
        guard team == expected else {
            return .refused("team mismatch")
        }
    } else {
        // No specific team demanded: notarization is the backstop.
        guard r.payloadNotarized else {
            return .refused("unnotarized payload with no expected team")
        }
    }
    // Bind the claimed version to the payload and refuse downgrades.
    guard r.expectedVersion == r.payloadVersion else {
        return .refused("version mismatch")
    }
    if let installed = r.installedVersion, versionLess(r.payloadVersion, installed) {
        return .refused("downgrade")
    }
    return .authorized
}
