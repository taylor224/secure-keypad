#if canImport(UIKit) && canImport(SwiftUI) && !os(watchOS)
import SwiftUI
import UIKit

/// SwiftUI wrapper: a text field whose keyboard is the secure keypad.
///
/// ```swift
/// @StateObject var model = PinModel()   // owns a SecureKeypad
/// SecureKeypadField(keypad: model.keypad, placeholder: "PIN")
/// Button("Sign in") { let payload = try? model.keypad.submit() }
/// ```
@available(iOS 14.0, *)
public struct SecureKeypadField: UIViewRepresentable {
    public let keypad: SecureKeypad
    public var placeholder: String
    public var borderStyle: UITextField.BorderStyle

    public init(keypad: SecureKeypad, placeholder: String = "", borderStyle: UITextField.BorderStyle = .roundedRect) {
        self.keypad = keypad
        self.placeholder = placeholder
        self.borderStyle = borderStyle
    }

    public func makeUIView(context: Context) -> UITextField {
        let field = UITextField()
        field.placeholder = placeholder
        field.borderStyle = borderStyle
        field.setContentHuggingPriority(.defaultHigh, for: .vertical)
        keypad.attach(to: field)
        return field
    }

    public func updateUIView(_ uiView: UITextField, context: Context) {
        uiView.placeholder = placeholder
        uiView.borderStyle = borderStyle
    }
}
#endif
