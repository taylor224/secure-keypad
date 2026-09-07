#if canImport(UIKit) && !os(watchOS)
import UIKit

/// Drives one secure keypad: session lifecycle, the input view, the attached text field, relayout, and
/// capture protection. Create one per input field. All members must be used from the main thread.
public final class SecureKeypad {
    public enum ThemeMode { case auto, light, dark }
    public enum CaptureAction { case warn, close, ignore }

    public enum State: Equatable {
        case idle
        case loading
        case ready
        case consumed
        case expired
        case failed
    }

    public struct Config {
        /// Integrator endpoint that forwards the body to the server SDK's `createSession`.
        public var sessionURL: URL
        /// Endpoint forwarding to `relayout`. Without it a size change starts a new session (input is lost).
        public var relayoutURL: URL?
        /// Base64 Ed25519 public key printed by `skp-keygen --pubkey`. Strongly recommended.
        public var serverPublicKey: String?
        /// Refuse to open sessions without a configured server key.
        public var strict = false
        public var type: KeypadType
        /// Requested maximum length; the server may lower it.
        public var maxLen: Int?
        public var theme: ThemeMode = .auto
        public var haptics = true
        public var sound = true
        public var captureAction: CaptureAction = .warn
        public var transport: SecureKeypadTransport = URLSessionTransport()
        /// Text shown on the cover while the screen is being captured.
        public var captureMessage = "Screen recording is active. The keypad is hidden."

        public init(sessionURL: URL, type: KeypadType, serverPublicKey: String? = nil) {
            self.sessionURL = sessionURL
            self.type = type
            self.serverPublicKey = serverPublicKey
        }
    }

    public let config: Config
    public private(set) var state: State = .idle {
        didSet { if state != oldValue { onStateChange?(state) } }
    }
    /// Number of characters entered so far (the only thing the client knows about the value).
    public var length: Int { taps.count }
    public var onChange: ((Int) -> Void)?
    public var onDone: (() -> Void)?
    public var onStateChange: ((State) -> Void)?
    /// The session expired before `submit()`; a fresh session is started automatically.
    public var onExpire: (() -> Void)?
    public var onError: ((Error) -> Void)?
    public let inputView: SecureKeypadInputView

    private var session: ClientSession?
    private var taps: [Tap] = []
    private weak var textField: UITextField?
    private var serverKey: Data?
    private var expiryTimer: Timer?
    private var relayoutWork: DispatchWorkItem?
    private var observers: [NSObjectProtocol] = []
    private var loadTask: Task<Void, Never>?
    private var generationCounter = 0

    public init(config: Config) {
        self.config = config
        self.inputView = SecureKeypadInputView()
        inputView.haptics = config.haptics
        inputView.sound = config.sound
        inputView.setThemeMode(config.theme)
        if let k = config.serverPublicKey {
            serverKey = Base64.decode(k)
            precondition(serverKey?.count == 32, "serverPublicKey must be the base64 of a 32-byte Ed25519 key")
        }
        inputView.onTap = { [weak self] tap in self?.record(tap) }
        inputView.onBackspace = { [weak self] in self?.backspace() }
        inputView.onDone = { [weak self] in self?.onDone?() }
        inputView.onWidthChange = { [weak self] w in self?.scheduleRelayout(width: w) }
        installObservers()
    }

    deinit {
        for o in observers { NotificationCenter.default.removeObserver(o) }
        expiryTimer?.invalidate()
        loadTask?.cancel()
        session?.wipe()
    }

    // MARK: attach

    /// Replaces the field's keyboard with the secure keypad and starts a session. The field's text only
    /// ever contains bullets; the value exists solely on the server.
    public func attach(to field: UITextField) {
        textField = field
        field.inputView = inputView
        field.isSecureTextEntry = true
        field.autocorrectionType = .no
        field.spellCheckingType = .no
        field.smartQuotesType = .no
        field.smartDashesType = .no
        field.smartInsertDeleteType = .no
        field.autocapitalizationType = .none
        if #available(iOS 12.0, *) { field.textContentType = .oneTimeCode }
        if config.type == .number {
            field.inputAccessoryView = makeAccessoryBar()
        }
        field.text = ""
        field.reloadInputViews()
        if session == nil { startSession() }
    }

    public func detach() {
        textField?.inputView = nil
        textField?.inputAccessoryView = nil
        textField?.reloadInputViews()
        textField = nil
    }

    private func makeAccessoryBar() -> UIView {
        let bar = UIToolbar(frame: CGRect(x: 0, y: 0, width: UIScreen.main.bounds.width, height: 44))
        bar.items = [
            UIBarButtonItem(barButtonSystemItem: .flexibleSpace, target: nil, action: nil),
            UIBarButtonItem(title: "Done", style: .done, target: self, action: #selector(accessoryDone)),
        ]
        bar.sizeToFit()
        return bar
    }

    @objc private func accessoryDone() { onDone?() }

    // MARK: session

    /// Discards the current session and input and starts a new one.
    public func reset() {
        session?.wipe()
        session = nil
        taps.removeAll()
        expiryTimer?.invalidate()
        inputView.clear()
        updateField()
        onChange?(0)
        startSession()
    }

    private func currentViewport() -> Viewport {
        let width = inputView.bounds.width > 0 ? inputView.bounds.width : UIScreen.main.bounds.width
        return Viewport(w: Double(width), dpr: Double(UIScreen.main.scale), platform: "ios", style: "ios")
    }

    private func startSession() {
        loadTask?.cancel()
        state = .loading
        let s = ClientSession()
        session = s
        let viewport = currentViewport()
        let cfg = config
        loadTask = Task { [weak self] in
            do {
                let body = try s.requestJSON(type: cfg.type, viewport: viewport, maxLen: cfg.maxLen)
                let data = try await cfg.transport.post(url: cfg.sessionURL, body: body)
                let response = try SessionResponse.decode(data)
                await MainActor.run { [weak self] in
                    guard let self = self, self.session === s else { return }
                    do {
                        try s.open(response, serverPublicKey: self.serverKey, strict: cfg.strict)
                        self.installLayout(s)
                    } catch {
                        self.fail(error)
                    }
                }
            } catch {
                await MainActor.run { [weak self] in
                    guard let self = self, self.session === s else { return }
                    self.fail(error)
                }
            }
        }
    }

    private func installLayout(_ s: ClientSession) {
        guard let set = s.layoutSet else { return }
        inputView.apply(layoutSet: set, tiles: s.tiles, popups: s.popups)
        state = .ready
        expiryTimer?.invalidate()
        let seconds = max(TimeInterval(set.exp) - 5, 1)
        expiryTimer = Timer.scheduledTimer(withTimeInterval: seconds, repeats: false) { [weak self] _ in
            self?.expire()
        }
    }

    private func fail(_ error: Error) {
        state = .failed
        onError?(error)
    }

    private func expire() {
        guard state == .ready else { return }
        state = .expired
        onExpire?()
        reset()
    }

    // MARK: input

    private func record(_ tap: Tap) {
        guard state == .ready, let set = session?.layoutSet else { return }
        guard taps.count < set.maxLen else { return }
        taps.append(tap)
        updateField()
        onChange?(taps.count)
    }

    private func backspace() {
        guard !taps.isEmpty else { return }
        taps.removeLast()
        updateField()
        onChange?(taps.count)
    }

    private func updateField() {
        textField?.text = String(repeating: "\u{2022}", count: taps.count)
    }

    /// Encrypts the recorded taps and returns the opaque payload JSON to send with your form. The session
    /// is consumed; call `reset()` for another attempt.
    public func submit() throws -> String {
        guard let s = session else { throw SecureKeypadError.sessionNotReady }
        switch state {
        case .ready: break
        case .consumed: throw SecureKeypadError.sessionConsumed
        case .expired: throw SecureKeypadError.expired
        default: throw SecureKeypadError.sessionNotReady
        }
        let payload = try s.buildInputPayload(taps: taps)
        for i in taps.indices { taps[i] = Tap(layoutID: 0, x: 0, y: 0) }
        taps.removeAll()
        expiryTimer?.invalidate()
        inputView.clear()
        state = .consumed
        return payload
    }

    // MARK: relayout

    private func scheduleRelayout(width: CGFloat) {
        relayoutWork?.cancel()
        let work = DispatchWorkItem { [weak self] in self?.relayout() }
        relayoutWork = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.15, execute: work)
    }

    private func relayout() {
        guard state == .ready, let s = session, let set = s.layoutSet else { return }
        let viewport = currentViewport()
        let wantedWidth = Int((viewport.w * viewport.dpr * 1000 + 500_000) / 1_000_000)
        if wantedWidth == set.w { return }
        guard let url = config.relayoutURL else {
            reset()
            return
        }
        let cfg = config
        Task { [weak self] in
            do {
                let body = try s.relayoutRequestJSON(viewport: viewport)
                let data = try await cfg.transport.post(url: url, body: body)
                let response = try RelayoutResponse.decode(data)
                await MainActor.run { [weak self] in
                    guard let self = self, self.session === s else { return }
                    do {
                        try s.openRelayout(response)
                        if let newSet = s.layoutSet {
                            self.inputView.apply(layoutSet: newSet, tiles: s.tiles, popups: s.popups)
                        }
                    } catch {
                        self.onError?(error)
                        self.reset()
                    }
                }
            } catch {
                await MainActor.run { [weak self] in
                    self?.onError?(error)
                }
            }
        }
    }

    // MARK: capture protection

    private func installObservers() {
        let nc = NotificationCenter.default
        observers.append(nc.addObserver(forName: UIScreen.capturedDidChangeNotification, object: nil, queue: .main) { [weak self] _ in
            self?.captureChanged()
        })
        observers.append(nc.addObserver(forName: UIApplication.userDidTakeScreenshotNotification, object: nil, queue: .main) { [weak self] _ in
            self?.screenshotTaken()
        })
        observers.append(nc.addObserver(forName: UIApplication.willResignActiveNotification, object: nil, queue: .main) { [weak self] _ in
            self?.inputView.setCovered(true, message: nil)
        })
        observers.append(nc.addObserver(forName: UIApplication.didBecomeActiveNotification, object: nil, queue: .main) { [weak self] _ in
            self?.captureChanged()
        })
        captureChanged()
    }

    private func captureChanged() {
        let captured = UIScreen.main.isCaptured
        switch config.captureAction {
        case .ignore:
            inputView.setCovered(false)
        case .warn:
            inputView.setCovered(captured, message: captured ? config.captureMessage : nil)
        case .close:
            inputView.setCovered(captured, message: captured ? config.captureMessage : nil)
            if captured {
                textField?.resignFirstResponder()
                if !taps.isEmpty { reset() }
            }
        }
    }

    private func screenshotTaken() {
        guard config.captureAction != .ignore else { return }
        inputView.setCovered(true, message: config.captureMessage)
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [weak self] in self?.captureChanged() }
        if config.captureAction == .close, !taps.isEmpty { reset() }
    }
}
#endif
