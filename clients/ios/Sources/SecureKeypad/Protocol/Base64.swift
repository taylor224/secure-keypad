import Foundation

/// RFC 4648 §4 (standard, padded) and §5 (URL-safe, unpadded) helpers.
enum Base64 {
    static func encode(_ data: Data) -> String {
        data.base64EncodedString()
    }

    static func decode(_ string: String) -> Data? {
        Data(base64Encoded: string)
    }

    static func encodeURL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func decodeURL(_ string: String) -> Data? {
        var s = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while s.count % 4 != 0 {
            s.append("=")
        }
        return Data(base64Encoded: s)
    }
}

extension Data {
    /// Big-endian 32-bit read; nil when out of range.
    func readUInt32BE(at offset: Int) -> UInt32? {
        guard offset >= 0, offset + 4 <= count else { return nil }
        let i = startIndex + offset
        return UInt32(self[i]) << 24 | UInt32(self[i + 1]) << 16 | UInt32(self[i + 2]) << 8 | UInt32(self[i + 3])
    }

    mutating func appendUInt16BE(_ v: UInt16) {
        append(UInt8(v >> 8))
        append(UInt8(v & 0xFF))
    }

    mutating func appendUInt64BE(_ v: UInt64) {
        for shift in stride(from: 56, through: 0, by: -8) {
            append(UInt8((v >> UInt64(shift)) & 0xFF))
        }
    }

    /// Overwrites the bytes with zeros. Best effort: `Data` may have been copied by the runtime.
    mutating func wipe() {
        let n = count
        guard n > 0 else { return }
        withUnsafeMutableBytes { buf in
            if let base = buf.baseAddress {
                memset(base, 0, n)
            }
        }
        removeAll(keepingCapacity: false)
    }
}
