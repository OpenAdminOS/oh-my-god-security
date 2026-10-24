// Invariant harness for the installer-trust fixture.
//
// This is a synthetic reproducer of a privileged updater's install-decision
// logic, modelled on a real macOS root-helper field run. It carries no real
// signing material and performs no install; it only exercises the pure decision
// function `decide(_:)` provided by the target source in vulnerable/ or fixed/.
//
// Run one snapshot through the sandbox, writing the binary to scratch:
//   omgs prove --cwd benchmark/fixtures/installer-trust \
//     --cmd 'swiftc main.swift vulnerable/Verifier.swift -o "$TMPDIR/probe" && "$TMPDIR/probe"'
// The vulnerable snapshot violates the invariants and exits non-zero; swap
// vulnerable for fixed and it upholds them plus the authorized control and exits
// zero. See README.md. Keep compile and execution inside `omgs prove`.

import Foundation

enum InstallDecision: Equatable {
    case authorized
    case refused(String)
}

/// One install request. All fields are synthetic, dummy values.
struct InstallRequest {
    /// Signing team actually found on the payload, nil when unsigned.
    let payloadTeam: String?
    /// Whether the payload is notarized (the backstop when no team is demanded).
    let payloadNotarized: Bool
    /// Team the caller demands, nil meaning "no specific team".
    let expectedTeam: String?
    /// Version contained in the payload.
    let payloadVersion: String
    /// Version already installed at the destination, nil when absent.
    let installedVersion: String?
    /// Version the caller claims to be installing.
    let expectedVersion: String
}

/// True when `a` is an earlier version than `b`, by dotted numeric components.
func versionLess(_ a: String, _ b: String) -> Bool {
    let lhs = a.split(separator: ".").map { Int($0) ?? 0 }
    let rhs = b.split(separator: ".").map { Int($0) ?? 0 }
    for i in 0..<max(lhs.count, rhs.count) {
        let l = i < lhs.count ? lhs[i] : 0
        let r = i < rhs.count ? rhs[i] : 0
        if l != r { return l < r }
    }
    return false
}

func isAuthorized(_ r: InstallRequest) -> Bool { decide(r) == .authorized }

var failures: [String] = []
func check(_ name: String, _ holds: Bool) {
    if holds {
        print("PASS \(name)")
    } else {
        failures.append(name)
        print("FAIL \(name)")
    }
}

let trusted = "TEAMTRUSTED"
let attacker = "TEAMATTACKER"

// INV1: a mismatched or unverified signer must be refused even when no expected
// team is demanded. A nil expected team must never mean "accept anything".
check(
    "nil expected team must not accept an unnotarized mismatched signer",
    !isAuthorized(InstallRequest(
        payloadTeam: attacker, payloadNotarized: false, expectedTeam: nil,
        payloadVersion: "2.0", installedVersion: nil, expectedVersion: "2.0"))
)

// INV2: an explicit wrong expected team is refused. Control that the existing
// check still works, so a fix does not simply disable team matching.
check(
    "explicit wrong expected team is refused",
    !isAuthorized(InstallRequest(
        payloadTeam: attacker, payloadNotarized: false, expectedTeam: trusted,
        payloadVersion: "2.0", installedVersion: nil, expectedVersion: "2.0"))
)

// INV3: a downgrade over a newer installed version must be refused.
check(
    "downgrade over a newer install is refused",
    !isAuthorized(InstallRequest(
        payloadTeam: trusted, payloadNotarized: true, expectedTeam: trusted,
        payloadVersion: "1.0", installedVersion: "2.0", expectedVersion: "1.0"))
)

// INV4: the caller-claimed version must match the payload actually installed.
check(
    "expected version must match the payload version",
    !isAuthorized(InstallRequest(
        payloadTeam: trusted, payloadNotarized: true, expectedTeam: trusted,
        payloadVersion: "1.0", installedVersion: nil, expectedVersion: "2.0"))
)

// Authorized control: a matching signer installing a forward version is
// accepted, so the fixed logic is not merely refusing everything.
check(
    "authorized control: matching signer and forward version is accepted",
    isAuthorized(InstallRequest(
        payloadTeam: trusted, payloadNotarized: true, expectedTeam: trusted,
        payloadVersion: "2.0", installedVersion: "1.0", expectedVersion: "2.0"))
)

if failures.isEmpty {
    print("INVARIANTS HOLD")
    exit(0)
} else {
    print("INVARIANTS VIOLATED: \(failures.count)")
    exit(1)
}
