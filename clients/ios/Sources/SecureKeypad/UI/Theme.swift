#if canImport(UIKit) && !os(watchOS)
import UIKit

/// Visual tokens for the client-drawn chrome. Glyphs come from the server's sprites; everything else is
/// native. Integrators may override colors; geometry always comes from the server.
public struct KeypadTheme: Equatable {
    /// Background behind the keys. `.clear` lets `UIInputView`'s keyboard blur show through.
    public var trayBackground: UIColor
    public var keyBackground: UIColor
    public var keyBackgroundPressed: UIColor
    public var specialKeyBackground: UIColor
    public var specialKeyBackgroundPressed: UIColor
    public var keyText: UIColor
    public var keyIcon: UIColor
    public var popupBackground: UIColor
    public var shadow: UIColor
    public var cornerRadius: CGFloat
    public var labelFont: UIFont
    public var smallLabelFont: UIFont

    public static func ios(dark: Bool) -> KeypadTheme {
        if dark {
            return KeypadTheme(
                trayBackground: .clear,
                keyBackground: UIColor(red: 0.42, green: 0.42, blue: 0.44, alpha: 1),
                keyBackgroundPressed: UIColor(red: 0.42, green: 0.42, blue: 0.44, alpha: 1),
                specialKeyBackground: UIColor(red: 0.27, green: 0.27, blue: 0.29, alpha: 1),
                specialKeyBackgroundPressed: UIColor(red: 0.42, green: 0.42, blue: 0.44, alpha: 1),
                keyText: .white,
                keyIcon: .white,
                popupBackground: UIColor(red: 0.42, green: 0.42, blue: 0.44, alpha: 1),
                shadow: UIColor.black.withAlphaComponent(0.6),
                cornerRadius: 5,
                labelFont: .systemFont(ofSize: 16),
                smallLabelFont: .systemFont(ofSize: 15)
            )
        }
        return KeypadTheme(
            trayBackground: .clear,
            keyBackground: .white,
            keyBackgroundPressed: .white,
            specialKeyBackground: UIColor(red: 0.68, green: 0.70, blue: 0.75, alpha: 1),
            specialKeyBackgroundPressed: .white,
            keyText: .black,
            keyIcon: .black,
            popupBackground: .white,
            shadow: UIColor.black.withAlphaComponent(0.35),
            cornerRadius: 5,
            labelFont: .systemFont(ofSize: 16),
            smallLabelFont: .systemFont(ofSize: 15)
        )
    }
}
#endif
