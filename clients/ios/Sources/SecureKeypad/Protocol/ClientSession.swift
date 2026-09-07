import CryptoKit
import Foundation

/// One keypad session on the client: an ephemeral X25519 key, the derived direction keys, the decrypted
/// layout set and sprites, and the encrypted input batch. Contains no characters at any point.
///
/// Not thread safe; the controller drives it from the main thread.
public final class ClientSession {
    public enum State: Equatable {
        case fresh
        case open
        case consumed
    }

    public private(set) var state: State = .fresh
    private let privateKey: Curve25519.KeyAgreement.PrivateKey
    /// Raw X25519 public key (32 bytes).
    public let clientPublicKey: Data
    /// Standard base64 of `clientPublicKey`, the request's `kp`.
    public var clientPublicKeyBase64: String { Base64.encode(clientPublicKey) }

    public private(set) var sid = Data()
    public private(set) var kid = ""
    private var kS2C = Data()
    private var kC2S = Data()
    private var s2cCounter: UInt64 = 0
    public private(set) var layoutSet: KeypadLayoutSet?
    public private(set) var tiles = Data()
    public private(set) var popups = Data()

    private static var warnedOnce = false

    public init(privateKey: Curve25519.KeyAgreement.PrivateKey = Curve25519.KeyAgreement.PrivateKey()) {
        self.privateKey = privateKey
        self.clientPublicKey = privateKey.publicKey.rawRepresentation
    }

    deinit {
        wipe()
    }

    /// Session request body (spec/PROTOCOL.md §4.1).
    public func requestJSON(type: KeypadType, viewport: Viewport, maxLen: Int?) throws -> Data {
        var body: [String: Any] = [
            "v": 1,
            "kp": clientPublicKeyBase64,
            "type": type.rawValue,
            "viewport": viewport.json,
        ]
        if let maxLen = maxLen { body["opts"] = ["maxLen": maxLen] }
        return try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys])
    }

    /// Relayout request body (spec/PROTOCOL.md §6).
    public func relayoutRequestJSON(viewport: Viewport) throws -> Data {
        guard state == .open else { throw SecureKeypadError.sessionNotReady }
        let body: [String: Any] = ["v": 1, "sid": Base64.encodeURL(sid), "viewport": viewport.json]
        return try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys])
    }

    /// Verifies (when `serverPublicKey` is given), derives the direction keys, decrypts and parses the
    /// session response. `serverPublicKey` is the raw 32-byte Ed25519 key.
    public func open(_ response: SessionResponse, serverPublicKey: Data?, strict: Bool = false) throws {
        guard state == .fresh else { throw SecureKeypadError.sessionConsumed }
        guard response.v == 1 else { throw SecureKeypadError.unsupportedVersion(response.v) }
        guard let sidBytes = Base64.decodeURL(response.sid), sidBytes.count == 16,
              let serverPublic = Base64.decode(response.sp), serverPublic.count == 32,
              let signature = Base64.decode(response.sig), signature.count == 64,
              let ct = Base64.decode(response.ct), ct.count >= ClientCrypto.tagLength,
              response.kid.utf8.count == 8
        else { throw SecureKeypadError.invalidResponse("session fields") }

        if let pk = serverPublicKey {
            let msg = ClientCrypto.signatureMessage(kid: response.kid, sid: sidBytes, clientPublic: clientPublicKey,
                                                    serverPublic: serverPublic, ct: ct)
            guard ClientCrypto.verify(signature: signature, message: msg, publicKey: pk) else {
                throw SecureKeypadError.badSignature
            }
        } else if strict {
            throw SecureKeypadError.serverKeyRequired
        } else {
            #if DEBUG
            if !Self.warnedOnce {
                Self.warnedOnce = true
                NSLog("[SecureKeypad] no serverPublicKey configured: the keypad origin is not verified beyond TLS")
            }
            #endif
        }

        let keys = try ClientCrypto.deriveKeys(privateKey: privateKey, serverPublic: serverPublic, sid: sidBytes)
        var plain = try ClientCrypto.open(ct, key: keys.s2c, counter: 0, aad: ClientCrypto.aadSession + sidBytes)
        defer { plain.wipe() }
        let frame = try InnerFrame.parse(plain)
        let set = try KeypadLayoutSet.decode(frame.json)
        guard set.gen == 0 else { throw SecureKeypadError.invalidResponse("gen") }

        sid = sidBytes
        kid = response.kid
        kS2C = keys.s2c
        kC2S = keys.c2s
        s2cCounter = 1
        layoutSet = set
        tiles = frame.tiles
        popups = frame.popups
        state = .open
    }

    /// Decrypts a relayout response with the next server→client counter and replaces the layout set.
    public func openRelayout(_ response: RelayoutResponse) throws {
        guard state == .open else { throw SecureKeypadError.sessionNotReady }
        guard response.v == 1 else { throw SecureKeypadError.unsupportedVersion(response.v) }
        guard let sidBytes = Base64.decodeURL(response.sid), sidBytes == sid,
              let ct = Base64.decode(response.ct)
        else { throw SecureKeypadError.invalidResponse("relayout fields") }
        var plain = try ClientCrypto.open(ct, key: kS2C, counter: s2cCounter, aad: ClientCrypto.aadRelayout + sidBytes)
        defer { plain.wipe() }
        let frame = try InnerFrame.parse(plain)
        let set = try KeypadLayoutSet.decode(frame.json)
        guard set.gen == response.gen, set.gen > 0 else { throw SecureKeypadError.invalidResponse("gen") }
        s2cCounter += 1
        layoutSet = set
        tiles = frame.tiles
        popups = frame.popups
    }

    /// Builds the encrypted input payload for the recorded taps and consumes the session: the direction
    /// keys and sprites are wiped, and no further calls succeed.
    public func buildInputPayload(taps: [Tap]) throws -> String {
        guard state == .open, let set = layoutSet else {
            throw state == .consumed ? SecureKeypadError.sessionConsumed : SecureKeypadError.sessionNotReady
        }
        defer { wipe(); state = .consumed }
        return try InputBatch.payload(taps: taps, maxLen: set.maxLen, key: kC2S, sid: sid)
    }

    /// Zeroes the direction keys and drops the sprites. Called automatically on consume and deinit.
    public func wipe() {
        kS2C.wipe()
        kC2S.wipe()
        tiles.wipe()
        popups.wipe()
        layoutSet = nil
        if state == .open { state = .consumed }
    }
}
