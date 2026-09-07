import Foundation

/// spec/PROTOCOL.md §7: the fixed-size input batch and its encrypted payload.
enum InputBatch {
    static let recordSize = 8

    /// `u8 1 | u8 0 | u16 count | maxLen × (u16 seq | u8 layout_id | u8 0 | u16 x | u16 y)`, zero padded.
    static func build(taps: [Tap], maxLen: Int) throws -> Data {
        guard taps.count <= maxLen, maxLen <= 0xFFFF else { throw SecureKeypadError.tooManyTaps }
        var d = Data(capacity: 4 + recordSize * maxLen)
        d.append(1)
        d.append(0)
        d.appendUInt16BE(UInt16(taps.count))
        for (i, tap) in taps.enumerated() {
            guard (0...255).contains(tap.layoutID), (0...0xFFFF).contains(tap.x), (0...0xFFFF).contains(tap.y) else {
                throw SecureKeypadError.tooManyTaps
            }
            d.appendUInt16BE(UInt16(i))
            d.append(UInt8(tap.layoutID))
            d.append(0)
            d.appendUInt16BE(UInt16(tap.x))
            d.appendUInt16BE(UInt16(tap.y))
        }
        d.append(Data(count: recordSize * (maxLen - taps.count)))
        return d
    }

    /// Encrypts the batch under `k_c2s` (counter 0, aad `"skp/v1/input" || sid`) and returns the payload JSON.
    static func payload(taps: [Tap], maxLen: Int, key: Data, sid: Data) throws -> String {
        var batch = try build(taps: taps, maxLen: maxLen)
        defer { batch.wipe() }
        let ct = try ClientCrypto.seal(batch, key: key, counter: 0, aad: ClientCrypto.aadInput + sid)
        return "{\"v\":1,\"sid\":\"\(Base64.encodeURL(sid))\",\"ct\":\"\(Base64.encode(ct))\"}"
    }
}
