import CryptoKit
import Foundation

/// The cryptographic steps of spec/PROTOCOL.md on the client side. Pure functions, no state.
enum ClientCrypto {
    static let sessionSalt = Data("skp/v1".utf8)
    static let aadSession = Data("skp/v1/session".utf8)
    static let aadRelayout = Data("skp/v1/relayout".utf8)
    static let aadInput = Data("skp/v1/input".utf8)
    static let signatureLabel = Data("skp/v1/session".utf8)
    static let tagLength = 16

    /// `NONCE(ctr) = 0x00000000 || u64be(ctr)`
    static func nonce(_ counter: UInt64) -> Data {
        var d = Data([0, 0, 0, 0])
        d.appendUInt64BE(counter)
        return d
    }

    /// `ss = X25519(c_sk, s_pk)`, `prk = HKDF-Extract("skp/v1" || sid, ss)`,
    /// `k_s2c = HKDF-Expand(prk, "s2c" || c_pk || s_pk)`, `k_c2s = HKDF-Expand(prk, "c2s" || c_pk || s_pk)`.
    static func deriveKeys(privateKey: Curve25519.KeyAgreement.PrivateKey, serverPublic: Data, sid: Data) throws
        -> (s2c: Data, c2s: Data)
    {
        guard serverPublic.count == 32, sid.count == 16 else { throw SecureKeypadError.invalidResponse("sp/sid") }
        let serverKey: Curve25519.KeyAgreement.PublicKey
        do {
            serverKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: serverPublic)
        } catch {
            throw SecureKeypadError.invalidResponse("sp")
        }
        let shared: SharedSecret
        do {
            shared = try privateKey.sharedSecretFromKeyAgreement(with: serverKey)
        } catch {
            throw SecureKeypadError.cryptoFailure("x25519")
        }
        var ss = shared.withUnsafeBytes { Data($0) }
        defer { ss.wipe() }
        // reject the all-zero shared secret (low-order point), as libsodium does
        if ss.allSatisfy({ $0 == 0 }) { throw SecureKeypadError.cryptoFailure("x25519 low-order point") }
        var prk = HKDF.extract(salt: sessionSalt + sid, ikm: ss)
        defer { prk.wipe() }
        let clientPublic = privateKey.publicKey.rawRepresentation
        let s2c = HKDF.expand(prk: prk, info: Data("s2c".utf8) + clientPublic + serverPublic, length: 32)
        let c2s = HKDF.expand(prk: prk, info: Data("c2s".utf8) + clientPublic + serverPublic, length: 32)
        return (s2c, c2s)
    }

    /// `"skp/v1/session" || kid || sid || c_pk || s_pk || SHA-256(ct)`
    static func signatureMessage(kid: String, sid: Data, clientPublic: Data, serverPublic: Data, ct: Data) -> Data {
        var m = signatureLabel
        m.append(Data(kid.utf8))
        m.append(sid)
        m.append(clientPublic)
        m.append(serverPublic)
        m.append(Data(SHA256.hash(data: ct)))
        return m
    }

    static func verify(signature: Data, message: Data, publicKey: Data) -> Bool {
        guard signature.count == 64, publicKey.count == 32,
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey)
        else { return false }
        return key.isValidSignature(signature, for: message)
    }

    /// ChaCha20-Poly1305 open of `ciphertext || tag`.
    static func open(_ ct: Data, key: Data, counter: UInt64, aad: Data) throws -> Data {
        guard ct.count >= tagLength, key.count == 32 else { throw SecureKeypadError.cryptoFailure("aead input") }
        let body = ct.prefix(ct.count - tagLength)
        let tag = ct.suffix(tagLength)
        do {
            let box = try ChaChaPoly.SealedBox(nonce: ChaChaPoly.Nonce(data: nonce(counter)), ciphertext: body, tag: tag)
            return try ChaChaPoly.open(box, using: SymmetricKey(data: key), authenticating: aad)
        } catch {
            throw SecureKeypadError.cryptoFailure("aead open")
        }
    }

    /// ChaCha20-Poly1305 seal producing `ciphertext || tag`.
    static func seal(_ plaintext: Data, key: Data, counter: UInt64, aad: Data) throws -> Data {
        guard key.count == 32 else { throw SecureKeypadError.cryptoFailure("aead key") }
        do {
            let box = try ChaChaPoly.seal(plaintext, using: SymmetricKey(data: key),
                                          nonce: ChaChaPoly.Nonce(data: nonce(counter)), authenticating: aad)
            return box.ciphertext + box.tag
        } catch {
            throw SecureKeypadError.cryptoFailure("aead seal")
        }
    }
}

/// `u32 len | json | u32 len | png(tiles) | u32 len | png(popups)` (big-endian).
struct InnerFrame {
    let json: Data
    let tiles: Data
    let popups: Data

    static func parse(_ data: Data) throws -> InnerFrame {
        var parts: [Data] = []
        var pos = 0
        for _ in 0..<3 {
            guard let n = data.readUInt32BE(at: pos) else { throw SecureKeypadError.malformedFrame }
            pos += 4
            let len = Int(n)
            guard pos + len <= data.count else { throw SecureKeypadError.malformedFrame }
            parts.append(Data(data[(data.startIndex + pos)..<(data.startIndex + pos + len)]))
            pos += len
        }
        guard pos == data.count else { throw SecureKeypadError.malformedFrame }
        return InnerFrame(json: parts[0], tiles: parts[1], popups: parts[2])
    }
}
