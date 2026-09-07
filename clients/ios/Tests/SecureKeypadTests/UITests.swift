#if canImport(UIKit) && !os(watchOS)
import UIKit
import XCTest
@testable import SecureKeypad

/// UI-side logic that runs on the simulator: point → device pixel conversion, layout installation,
/// and tap reporting through the input view.
final class UITests: XCTestCase {
    func testDeviceTapConversionAndClamping() {
        let t = SecureKeypadInputView.deviceTap(from: CGPoint(x: 10.4, y: 20.6), scale: 3, width: 1170, height: 648)
        XCTAssertEqual(t.x, 31)
        XCTAssertEqual(t.y, 62)
        let clampedHigh = SecureKeypadInputView.deviceTap(from: CGPoint(x: 1000, y: 1000), scale: 3, width: 1170, height: 648)
        XCTAssertEqual(clampedHigh.x, 1169)
        XCTAssertEqual(clampedHigh.y, 647)
        let clampedLow = SecureKeypadInputView.deviceTap(from: CGPoint(x: -4, y: -4), scale: 2, width: 100, height: 50)
        XCTAssertEqual(clampedLow.x, 0)
        XCTAssertEqual(clampedLow.y, 0)
        let one = SecureKeypadInputView.deviceTap(from: CGPoint(x: 0.5, y: 0.5), scale: 1, width: 100, height: 50)
        XCTAssertEqual(one.x, 1)
        XCTAssertEqual(one.y, 1)
    }

    private func loadVector(_ name: String) throws -> [String: Any] {
        let url = try XCTUnwrap(Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "vectors"))
        return try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
    }

    func testInputViewInstallsLayoutAndReportsTaps() throws {
        let v = try loadVector("number-ios-390x3-blank-fixed")
        let inner = (v["expect_session"] as! [String: Any])["inner_json"] as! String
        let set = try KeypadLayoutSet.decode(Data(inner.utf8))
        let view = SecureKeypadInputView()
        view.contentScaleFactor = 3
        view.frame = CGRect(x: 0, y: 0, width: 390, height: 216)
        view.apply(layoutSet: set, tiles: Data(), popups: Data())
        view.layoutIfNeeded()
        XCTAssertEqual(view.intrinsicContentSize.height, 216, accuracy: 0.01)
        XCTAssertEqual(view.layoutSet?.layouts.count, 1)

        var reported: [Tap] = []
        var backspaces = 0
        view.onTap = { reported.append($0) }
        view.onBackspace = { backspaces += 1 }

        // simulate a tap on the first char key's centre by driving the same path the touch handler uses
        let layout = set.layouts[0]
        let first = layout.keys.first { $0.role == .char }!
        let centre = CGPoint(x: CGFloat(first.x + first.w / 2) / 3, y: CGFloat(first.y + first.h / 2) / 3)
        view.simulateTap(at: centre)
        XCTAssertEqual(reported.count, 1)
        XCTAssertEqual(reported.first?.layoutID, layout.id)
        XCTAssertEqual(layout.hitTest(x: reported.first!.x, y: reported.first!.y), first)

        let bs = layout.keys.first { $0.role == .backspace }!
        view.simulateTap(at: CGPoint(x: CGFloat(bs.x + 2) / 3, y: CGFloat(bs.y + 2) / 3))
        XCTAssertEqual(backspaces, 1)
        XCTAssertEqual(reported.count, 1, "backspace is never reported as a tap")

        // the blank cell is ignored
        let blank = layout.keys.first { $0.role == .blank }!
        view.simulateTap(at: CGPoint(x: CGFloat(blank.x + blank.w / 2) / 3, y: CGFloat(blank.y + blank.h / 2) / 3))
        XCTAssertEqual(reported.count, 1)
    }

    func testQwertyShiftAndModeSwitching() throws {
        let v = try loadVector("qwerty-ios-390x3-shuffle")
        let inner = (v["expect_session"] as! [String: Any])["inner_json"] as! String
        let set = try KeypadLayoutSet.decode(Data(inner.utf8))
        let view = SecureKeypadInputView()
        view.contentScaleFactor = 3
        view.frame = CGRect(x: 0, y: 0, width: 390, height: 216)
        view.apply(layoutSet: set, tiles: Data(), popups: Data())
        view.layoutIfNeeded()
        var reported: [Tap] = []
        view.onTap = { reported.append($0) }

        let lower = set.layout(for: .lower)!, upper = set.layout(for: .upper)!, sym1 = set.layout(for: .sym1)!
        let shift = lower.keys.first { $0.role == .shift }!
        let p = { (k: KeypadKey) in CGPoint(x: CGFloat(k.x + k.w / 2) / 3, y: CGFloat(k.y + k.h / 2) / 3) }
        view.simulateTap(at: p(shift))                       // one-shot shift → upper layer
        view.simulateTap(at: p(upper.keys[0]))               // first key of row 0
        XCTAssertEqual(reported.last?.layoutID, upper.id)
        view.simulateTap(at: p(lower.keys[1]))               // shift released → lower again
        XCTAssertEqual(reported.last?.layoutID, lower.id)
        let mode = lower.keys.first { $0.role == .modeSym1 }!
        view.simulateTap(at: p(mode))
        view.simulateTap(at: p(sym1.keys[0]))
        XCTAssertEqual(reported.last?.layoutID, sym1.id)
        XCTAssertEqual(reported.count, 3)
    }
}
#endif
