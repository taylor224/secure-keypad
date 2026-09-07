import CryptoKit
import Foundation

/// RFC 5869 HKDF with SHA-256, written out explicitly so the byte layout matches spec/PROTOCOL.md §4.2.
enum HKDF {
    static func extract(salt: Data, ikm: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: ikm, using: SymmetricKey(data: salt)))
    }

    static func expand(prk: Data, info: Data, length: Int) -> Data {
        let key = SymmetricKey(data: prk)
        var out = Data()
        var t = Data()
        var counter: UInt8 = 1
        while out.count < length {
            var msg = t
            msg.append(info)
            msg.append(counter)
            t = Data(HMAC<SHA256>.authenticationCode(for: msg, using: key))
            out.append(t)
            counter &+= 1
        }
        return out.prefix(length)
    }
}
