// Example integration (not part of the package build). Shows a PIN field driven by SecureKeypad.
import SecureKeypad
import UIKit

final class DemoViewController: UIViewController {
    private let userField = UITextField()
    private let pinField = UITextField()
    private let button = UIButton(type: .system)
    private let status = UILabel()
    private var keypad: SecureKeypad!

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground
        userField.placeholder = "User id"
        userField.borderStyle = .roundedRect
        pinField.placeholder = "PIN"
        pinField.borderStyle = .roundedRect
        button.setTitle("Sign in", for: .normal)
        button.isEnabled = false
        button.addTarget(self, action: #selector(signIn), for: .touchUpInside)
        status.font = .preferredFont(forTextStyle: .footnote)
        status.textColor = .secondaryLabel
        status.numberOfLines = 0

        let stack = UIStackView(arrangedSubviews: [userField, pinField, button, status])
        stack.axis = .vertical
        stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor, constant: 24),
            stack.trailingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.trailingAnchor, constant: -24),
            stack.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 40),
        ])

        var config = SecureKeypad.Config(
            sessionURL: URL(string: "https://api.example.com/keypad/session")!,
            type: .number,
            serverPublicKey: "REPLACE_WITH_OUTPUT_OF_skp-keygen --pubkey")
        config.relayoutURL = URL(string: "https://api.example.com/keypad/relayout")
        config.maxLen = 6
        // for a QWERTY field: config.languages = ["ko", "en"]  (Korean first; the globe key switches to English)
        keypad = SecureKeypad(config: config)
        keypad.onChange = { [weak self] count in self?.button.isEnabled = count == 6 }
        keypad.onDone = { [weak self] in self?.signIn() }
        keypad.onStateChange = { [weak self] state in self?.status.text = "keypad: \(state)" }
        keypad.onError = { [weak self] error in self?.status.text = "keypad error: \(error)" }
        keypad.attach(to: pinField)
    }

    @objc private func signIn() {
        do {
            let payload = try keypad.submit()
            // POST {"userId": ..., "pin": payload} to your backend, which calls the server SDK's decrypt().
            status.text = "payload ready (\(payload.count) bytes); sending…"
            sendLogin(userId: userField.text ?? "", pinPayload: payload) { [weak self] ok in
                self?.status.text = ok ? "signed in" : "wrong PIN — try again"
                if !ok { self?.keypad.reset() }   // sessions are single use
            }
        } catch {
            status.text = "could not submit: \(error)"
            keypad.reset()
        }
    }

    private func sendLogin(userId: String, pinPayload: String, completion: @escaping (Bool) -> Void) {
        var req = URLRequest(url: URL(string: "https://api.example.com/login")!)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try? JSONSerialization.data(withJSONObject: ["userId": userId, "pin": pinPayload])
        URLSession.shared.dataTask(with: req) { _, response, _ in
            let ok = (response as? HTTPURLResponse)?.statusCode == 200
            DispatchQueue.main.async { completion(ok) }
        }.resume()
    }
}
