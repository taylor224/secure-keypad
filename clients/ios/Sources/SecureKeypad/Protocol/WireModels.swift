import Foundation

/// Keypad type requested from the server.
public enum KeypadType: String, Codable {
    case qwerty
    case number
}

/// Layer of a keypad (spec/LAYOUT.md). The raw values are the `mode` strings on the wire. Letter layers
/// (`lower` / `upper`) exist once per installed language; symbol layers are shared.
public enum KeypadMode: String, Codable {
    case lower, upper, sym1, sym2, number
}

/// Display names for the space bar when several keyboard languages are installed.
public let keypadLanguageNames: [String: String] = ["en": "English", "ko": "한국어"]

/// Role of a key. Only `char` and `space` taps are ever transmitted.
public enum KeyRole: String, Codable {
    case char
    case space
    case shift
    case backspace
    case modeAbc = "mode_abc"
    case modeSym1 = "mode_sym1"
    case modeSym2 = "mode_sym2"
    case done
    case blank
    /// Globe key: switches to the next installed language. Never transmitted.
    case lang

    /// Whether a tap on this key becomes an input record.
    public var isCharacter: Bool { self == .char || self == .space }
}

/// A key rectangle in device pixels relative to the keypad surface.
public struct KeypadKey: Codable, Equatable {
    public let r: [Int]
    public let role: KeyRole
    /// Sprite cell index; present for `char` keys only. Never depends on the character.
    public let t: Int?

    public var x: Int { r[0] }
    public var y: Int { r[1] }
    public var w: Int { r[2] }
    public var h: Int { r[3] }

    public init(r: [Int], role: KeyRole, t: Int?) {
        self.r = r
        self.role = role
        self.t = t
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let r = try c.decode([Int].self, forKey: .r)
        guard r.count == 4, r[2] > 0, r[3] > 0 else {
            throw DecodingError.dataCorruptedError(forKey: .r, in: c, debugDescription: "rect needs 4 positive ints")
        }
        self.r = r
        self.role = try c.decode(KeyRole.self, forKey: .role)
        self.t = try c.decodeIfPresent(Int.self, forKey: .t)
    }
}

/// One layer of the keypad with its server-assigned layout id (`(gen << 3) | slot`, opaque to the client).
public struct KeypadLayout: Codable, Equatable {
    public let id: Int
    public let mode: KeypadMode
    /// Language code of a letter layer ("en", "ko", …); nil on symbol and number layers.
    public let lang: String?
    public let keys: [KeypadKey]

    public init(id: Int, mode: KeypadMode, lang: String? = nil, keys: [KeypadKey]) {
        self.id = id
        self.mode = mode
        self.lang = lang
        self.keys = keys
    }

    /// spec/PROTOCOL.md §10: the key with the smallest squared distance to its rect; ties go to the
    /// key listed first. Reproduces exactly what the server will compute for the same coordinates.
    public func hitTest(x: Int, y: Int) -> KeypadKey? {
        var best: KeypadKey?
        var bestD = Int.max
        for k in keys {
            let dx = max(k.x - x, 0, x - (k.x + k.w - 1))
            let dy = max(k.y - y, 0, y - (k.y + k.h - 1))
            let d = dx * dx + dy * dy
            if best == nil || d < bestD {
                best = k
                bestD = d
            }
        }
        return best
    }
}

/// Sprite sheet geometry (8-bit grayscale PNG, `count` cells of `w × h` laid out in `cols` columns).
public struct SpriteInfo: Codable, Equatable {
    public let w: Int
    public let h: Int
    public let cols: Int
    public let count: Int
}

/// The decrypted inner JSON of a session or relayout response (spec/PROTOCOL.md §4.5).
public struct KeypadLayoutSet: Codable, Equatable {
    public let v: Int
    public let type: KeypadType
    public let style: String
    /// Surface size in device pixels.
    public let w: Int
    public let h: Int
    public let gen: Int
    public let maxLen: Int
    public let exp: Int
    /// Installed languages in switch order (empty for number pads; absent in older responses).
    public let langs: [String]?
    public let layouts: [KeypadLayout]
    public let tile: SpriteInfo
    public let popup: SpriteInfo

    /// Layer for a mode; for letter layers `lang` selects the language (nil: the first one listed).
    public func layout(for mode: KeypadMode, lang: String? = nil) -> KeypadLayout? {
        layouts.first { $0.mode == mode && (lang == nil || $0.lang == lang) }
    }

    /// Languages in switch order (never nil).
    public var languages: [String] { langs ?? [] }

    static func decode(_ data: Data) throws -> KeypadLayoutSet {
        let set = try JSONDecoder().decode(KeypadLayoutSet.self, from: data)
        guard set.v == 1 else { throw SecureKeypadError.unsupportedVersion(set.v) }
        guard set.w > 0, set.h > 0, set.maxLen > 0, !set.layouts.isEmpty else {
            throw SecureKeypadError.invalidResponse("layout set")
        }
        return set
    }
}

/// Client viewport description sent with session and relayout requests.
public struct Viewport: Equatable {
    public var w: Double
    public var dpr: Double
    public var platform: String
    public var style: String?

    public init(w: Double, dpr: Double, platform: String = "ios", style: String? = nil) {
        self.w = w
        self.dpr = dpr
        self.platform = platform
        self.style = style
    }

    var json: [String: Any] {
        var o: [String: Any] = ["dpr": jsonNumber(dpr), "platform": platform, "w": jsonNumber(w)]
        if let style = style { o["style"] = style }
        return o
    }
}

/// Emits integral doubles as integers so the wire JSON reads `390` rather than `390.0`.
func jsonNumber(_ v: Double) -> Any {
    if v == v.rounded(), abs(v) < 1e9 { return Int(v) }
    return v
}

/// Session creation response (spec/PROTOCOL.md §4.3).
public struct SessionResponse: Codable, Equatable {
    public let v: Int
    public let sid: String
    public let kid: String
    public let sp: String
    public let sig: String
    public let ct: String

    public init(v: Int, sid: String, kid: String, sp: String, sig: String, ct: String) {
        self.v = v
        self.sid = sid
        self.kid = kid
        self.sp = sp
        self.sig = sig
        self.ct = ct
    }

    public static func decode(_ data: Data) throws -> SessionResponse {
        do {
            return try JSONDecoder().decode(SessionResponse.self, from: data)
        } catch {
            throw SecureKeypadError.invalidResponse("session response")
        }
    }
}

/// Relayout response (spec/PROTOCOL.md §6).
public struct RelayoutResponse: Codable, Equatable {
    public let v: Int
    public let sid: String
    public let gen: Int
    public let ct: String

    public init(v: Int, sid: String, gen: Int, ct: String) {
        self.v = v
        self.sid = sid
        self.gen = gen
        self.ct = ct
    }

    public static func decode(_ data: Data) throws -> RelayoutResponse {
        do {
            return try JSONDecoder().decode(RelayoutResponse.self, from: data)
        } catch {
            throw SecureKeypadError.invalidResponse("relayout response")
        }
    }
}

/// A recorded character tap: which layout it was made on and where, in device pixels.
public struct Tap: Equatable {
    public var layoutID: Int
    public var x: Int
    public var y: Int

    public init(layoutID: Int, x: Int, y: Int) {
        self.layoutID = layoutID
        self.x = x
        self.y = y
    }
}
