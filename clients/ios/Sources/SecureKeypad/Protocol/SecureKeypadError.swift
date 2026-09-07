import Foundation

/// Errors raised by the SecureKeypad client. None of them ever carry key material, coordinates, or
/// characters.
public enum SecureKeypadError: Error, Equatable {
    /// The server response did not match the protocol schema.
    case invalidResponse(String)
    /// The server signature over the session did not verify against the configured public key.
    case badSignature
    /// A server public key is required (`strict`) but none is configured.
    case serverKeyRequired
    /// Protocol version other than 1.
    case unsupportedVersion(Int)
    /// A cryptographic primitive failed (key agreement, AEAD).
    case cryptoFailure(String)
    /// The decrypted frame is structurally invalid.
    case malformedFrame
    /// More taps than the session's `maxLen`.
    case tooManyTaps
    /// The session has not been opened yet (still loading, or failed).
    case sessionNotReady
    /// `submit()` was already called; start a new session with `reset()`.
    case sessionConsumed
    /// The session passed its expiry; start a new session with `reset()`.
    case expired
    /// Transport failure (message only, no body).
    case transport(String)
    /// Non-2xx HTTP status from the integrator's endpoint.
    case httpStatus(Int)
    /// Relayout is impossible because the session is not open or no relayout URL is configured.
    case relayoutUnavailable
}
