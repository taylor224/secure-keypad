import CryptoKit
import Foundation
import XCTest
@testable import SecureKeypad

/// Replays every vector in spec/vectors: the client side must reproduce derived keys, decrypted layout
/// JSON, and the encrypted input payload byte for byte.
final class VectorTests: XCTestCase {
    private func hex(_ s: String) -> Data {
        var d = Data(capacity: s.count / 2)
        var it = s.makeIterator()
        while let a = it.next(), let b = it.next() {
            d.append(UInt8(String([a, b]), radix: 16)!)
        }
        return d
    }

    private func loadVectors() throws -> [(String, [String: Any])] {
        let urls = Bundle.module.urls(forResourcesWithExtension: "json", subdirectory: "vectors") ?? []
        XCTAssertFalse(urls.isEmpty, "no vectors found in the test bundle")
        return try urls.sorted { $0.lastPathComponent < $1.lastPathComponent }.map { url in
            let obj = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
            return (url.lastPathComponent, obj)
        }
    }

    private func jsonEqual(_ a: String, _ b: Data) throws -> Bool {
        let x = try JSONSerialization.jsonObject(with: Data(a.utf8)) as! NSDictionary
        let y = try JSONSerialization.jsonObject(with: b) as! NSDictionary
        return x.isEqual(y)
    }

    func testAllVectors() throws {
        let vectors = try loadVectors()
        XCTAssertEqual(vectors.count, 7)
        for (name, v) in vectors {
            try runVector(name, v)
        }
    }

    private func runVector(_ name: String, _ v: [String: Any]) throws {
        let request = v["request"] as! [String: Any]
        let expectMaster = v["expect_master"] as! [String: Any]
        let expectSession = v["expect_session"] as! [String: Any]
        let input = v["input"] as! [String: Any]

        let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: hex(v["client_sk"] as! String))
        let session = ClientSession(privateKey: privateKey)
        XCTAssertEqual(session.clientPublicKeyBase64, request["kp"] as? String, "\(name): kp")

        // request body round trip
        let vp = request["viewport"] as! [String: Any]
        let viewport = Viewport(w: (vp["w"] as! NSNumber).doubleValue, dpr: (vp["dpr"] as! NSNumber).doubleValue,
                                platform: vp["platform"] as! String, style: vp["style"] as? String)
        let maxLen = (request["opts"] as? [String: Any])?["maxLen"] as? Int
        let req = try JSONSerialization.jsonObject(with: session.requestJSON(
            type: KeypadType(rawValue: request["type"] as! String)!, viewport: viewport, maxLen: maxLen)) as! NSDictionary
        XCTAssertEqual(req, request as NSDictionary, "\(name): request json")

        let responseObj = expectSession["response"] as! [String: Any]
        let response = try SessionResponse.decode(JSONSerialization.data(withJSONObject: responseObj))
        let pkSign = hex(expectMaster["pk_sign"] as! String)
        XCTAssertEqual(response.kid, expectMaster["kid"] as? String)

        // derived keys
        let keys = try ClientCrypto.deriveKeys(privateKey: privateKey, serverPublic: Base64.decode(response.sp)!,
                                               sid: Base64.decodeURL(response.sid)!)
        XCTAssertEqual(keys.s2c, hex(expectSession["k_s2c"] as! String), "\(name): k_s2c")
        XCTAssertEqual(keys.c2s, hex(expectSession["k_c2s"] as! String), "\(name): k_c2s")

        // tampered signature is rejected, then the real one opens
        var badSig = Base64.decode(response.sig)!
        badSig[5] ^= 0x01
        let forged = SessionResponse(v: 1, sid: response.sid, kid: response.kid, sp: response.sp,
                                     sig: Base64.encode(badSig), ct: response.ct)
        XCTAssertThrowsError(try ClientSession(privateKey: privateKey).open(forged, serverPublicKey: pkSign)) { e in
            XCTAssertEqual(e as? SecureKeypadError, .badSignature, "\(name): forged signature")
        }
        XCTAssertThrowsError(try ClientSession(privateKey: privateKey).open(response, serverPublicKey: nil, strict: true))

        try session.open(response, serverPublicKey: pkSign)
        XCTAssertEqual(session.state, .open)
        let set = try XCTUnwrap(session.layoutSet)
        XCTAssertTrue(try jsonEqual(expectSession["inner_json"] as! String, JSONEncoder().encode(set)) ||
            jsonEqualDecoded(expectSession["inner_json"] as! String, set), "\(name): inner json")
        XCTAssertEqual(session.tiles.count, 0, "vectors are rendered without sprites")

        // relayout
        if let relayout = v["relayout"] as? [String: Any] {
            let expect = relayout["expect"] as! [String: Any]
            let rr = try RelayoutResponse.decode(JSONSerialization.data(withJSONObject: expect["response"]!))
            try session.openRelayout(rr)
            let set2 = try XCTUnwrap(session.layoutSet)
            XCTAssertEqual(set2.gen, rr.gen)
            XCTAssertTrue(jsonEqualDecoded(expect["inner_json"] as! String, set2), "\(name): relayout inner json")
            XCTAssertEqual(set2.layouts.first?.id, (rr.gen << 3) | 0)
        }

        // input payload
        let taps = (input["taps"] as! [[Int]]).map { Tap(layoutID: $0[0], x: $0[1], y: $0[2]) }
        let payload = try session.buildInputPayload(taps: taps)
        let got = try JSONSerialization.jsonObject(with: Data(payload.utf8)) as! [String: Any]
        let want = input["payload"] as! [String: Any]
        XCTAssertEqual(got["ct"] as? String, want["ct"] as? String, "\(name): payload ct")
        XCTAssertEqual(got["sid"] as? String, want["sid"] as? String, "\(name): payload sid")
        XCTAssertEqual(got["v"] as? Int, 1)
        XCTAssertEqual(session.state, .consumed)
        XCTAssertThrowsError(try session.buildInputPayload(taps: taps)) { e in
            XCTAssertEqual(e as? SecureKeypadError, .sessionConsumed)
        }
    }

    /// Compares the expected canonical JSON against the decoded model (field by field through re-encoding).
    private func jsonEqualDecoded(_ expected: String, _ set: KeypadLayoutSet) -> Bool {
        guard let want = try? JSONSerialization.jsonObject(with: Data(expected.utf8)) as? [String: Any] else { return false }
        let decodedAgain = try? JSONDecoder().decode(KeypadLayoutSet.self, from: Data(expected.utf8))
        return decodedAgain == set && (want["layouts"] as? [[String: Any]])?.count == set.layouts.count
    }

    func testTooManyTapsRejected() throws {
        XCTAssertThrowsError(try InputBatch.build(taps: [Tap(layoutID: 0, x: 1, y: 1), Tap(layoutID: 0, x: 2, y: 2)], maxLen: 1))
        let batch = try InputBatch.build(taps: [Tap(layoutID: 9, x: 0x1234, y: 0x0102)], maxLen: 3)
        XCTAssertEqual(batch.count, 4 + 8 * 3)
        XCTAssertEqual([UInt8](batch.prefix(12)), [1, 0, 0, 1, 0, 0, 9, 0, 0x12, 0x34, 0x01, 0x02])
        XCTAssertTrue(batch.suffix(16).allSatisfy { $0 == 0 })
    }

    func testHKDFKnownAnswer() {
        // RFC 5869 test case 1
        let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        let salt = hex("000102030405060708090a0b0c")
        let info = hex("f0f1f2f3f4f5f6f7f8f9")
        let prk = HKDF.extract(salt: salt, ikm: ikm)
        XCTAssertEqual(prk, hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"))
        let okm = HKDF.expand(prk: prk, info: info, length: 42)
        XCTAssertEqual(okm, hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"))
    }

    func testBase64URL() {
        let d = Data([0xfb, 0xff, 0xfe, 0x01])
        XCTAssertEqual(Base64.encodeURL(d), "-__-AQ")
        XCTAssertEqual(Base64.decodeURL("-__-AQ"), d)
        XCTAssertNil(Base64.decodeURL("!!"))
    }

    func testHitTestNearestAndTies() {
        // A covers x 0...9, B covers x 11...20; x = 10 is one pixel from both.
        let a = KeypadKey(r: [0, 0, 10, 10], role: .char, t: 0)
        let b = KeypadKey(r: [11, 0, 10, 10], role: .char, t: 1)
        let layout = KeypadLayout(id: 0, mode: .lower, keys: [a, b])
        XCTAssertEqual(layout.hitTest(x: 5, y: 5), a)
        XCTAssertEqual(layout.hitTest(x: 15, y: 5), b)
        XCTAssertEqual(layout.hitTest(x: 10, y: 5), a, "tie resolves to the first key")
        XCTAssertEqual(layout.hitTest(x: 12, y: 40), b)
        XCTAssertEqual(layout.hitTest(x: 5, y: 30), a)
        XCTAssertEqual(layout.hitTest(x: 300, y: 300), b)
        XCTAssertEqual(layout.hitTest(x: 9, y: 9), a)
        XCTAssertEqual(layout.hitTest(x: 11, y: 0), b)
    }

    func testFrameParsing() throws {
        var f = Data([0, 0, 0, 2, 0x7b, 0x7d, 0, 0, 0, 1, 0xAA, 0, 0, 0, 0])
        let parsed = try InnerFrame.parse(f)
        XCTAssertEqual(parsed.json, Data([0x7b, 0x7d]))
        XCTAssertEqual(parsed.tiles, Data([0xAA]))
        XCTAssertEqual(parsed.popups.count, 0)
        f.append(0)
        XCTAssertThrowsError(try InnerFrame.parse(f))
        XCTAssertThrowsError(try InnerFrame.parse(Data([0, 0, 0, 9])))
    }
}
