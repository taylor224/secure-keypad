#if canImport(UIKit) && !os(watchOS)
import UIKit

/// The keypad surface. A `UIInputView` with the system keyboard background, so that attaching it as a
/// text field's `inputView` gives the native slide-up animation and keyboard notifications.
///
/// It draws the chrome itself (key backgrounds, shadows, control icons) and blits the server's glyph
/// sprites for character keys. It never knows which character a key carries: it reports taps as
/// `(layout id, x, y)` in device pixels, exactly what the server hit-tests.
public final class SecureKeypadInputView: UIInputView, UIInputViewAudioFeedback {
    // MARK: configuration

    public var haptics = true
    public var sound = true
    public var enableInputClicksWhenVisible: Bool { sound }
    /// Height used before a layout set arrives (points).
    public var fallbackHeight: CGFloat = 216

    /// Called for every character/space tap, with the tap in device pixels on the layout it was made on.
    var onTap: ((Tap) -> Void)?
    var onBackspace: (() -> Void)?
    var onDone: (() -> Void)?
    /// Called when the view's width (in points) changed after layout, for relayout requests.
    var onWidthChange: ((CGFloat) -> Void)?

    // MARK: state

    public private(set) var layoutSet: KeypadLayoutSet?
    private var tiles: SpriteSheet?
    private var popups: SpriteSheet?
    private var theme: KeypadTheme = .ios(dark: false)
    private var themeMode: SecureKeypad.ThemeMode = .auto

    private enum ShiftState { case off, on, caps }
    private var shift: ShiftState = .off
    private var lastShiftTap: TimeInterval = 0
    private var mode: KeypadMode = .lower

    private var containers: [KeypadMode: UIView] = [:]
    private var keyViews: [KeypadMode: [KeyView]] = [:]
    private var activeTouch: UITouch?
    private var activeKey: KeyView?
    private var popup: PopupView?
    private var repeatTimer: Timer?
    private var lastWidth: CGFloat = 0
    private let impact = UIImpactFeedbackGenerator(style: .light)
    private let coverView = UIView()
    private let coverLabel = UILabel()

    /// Device pixels per point for this view (the screen scale).
    var pixelScale: CGFloat { max(contentScaleFactor, 1) }

    // MARK: init

    public init() {
        super.init(frame: CGRect(x: 0, y: 0, width: UIScreen.main.bounds.width, height: 216), inputViewStyle: .keyboard)
        allowsSelfSizing = true
        isMultipleTouchEnabled = false
        isAccessibilityElement = true
        accessibilityLabel = "Secure keypad"
        accessibilityHint = "Randomised keypad. Keys are not announced."
        contentScaleFactor = UIScreen.main.scale
        coverView.isHidden = true
        coverView.backgroundColor = UIColor.systemBackground
        coverLabel.textAlignment = .center
        coverLabel.numberOfLines = 0
        coverLabel.font = .preferredFont(forTextStyle: .footnote)
        coverLabel.textColor = .secondaryLabel
        coverView.addSubview(coverLabel)
        addSubview(coverView)
        applyTheme()
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { nil }

    public override var intrinsicContentSize: CGSize {
        let h = layoutSet.map { CGFloat($0.h) / pixelScale } ?? fallbackHeight
        return CGSize(width: UIView.noIntrinsicMetric, height: h)
    }

    // MARK: theme

    func setThemeMode(_ mode: SecureKeypad.ThemeMode) {
        themeMode = mode
        applyTheme()
    }

    private func applyTheme() {
        let dark: Bool
        switch themeMode {
        case .light: dark = false
        case .dark: dark = true
        case .auto: dark = traitCollection.userInterfaceStyle == .dark
        }
        theme = .ios(dark: dark)
        backgroundColor = theme.trayBackground
        for views in keyViews.values {
            for kv in views { kv.apply(theme: theme, tiles: tiles) }
        }
    }

    public override func traitCollectionDidChange(_ previous: UITraitCollection?) {
        super.traitCollectionDidChange(previous)
        if previous?.userInterfaceStyle != traitCollection.userInterfaceStyle { applyTheme() }
    }

    // MARK: layout set

    /// Installs a layout set and its sprites (session open or relayout). Keeps the current mode/shift.
    func apply(layoutSet set: KeypadLayoutSet, tiles tileData: Data, popups popupData: Data) {
        layoutSet = set
        tiles = SpriteSheet(png: tileData, info: set.tile)
        popups = SpriteSheet(png: popupData, info: set.popup)
        rebuild()
        invalidateIntrinsicContentSize()
        setNeedsLayout()
    }

    /// Drops the layout and shows the tray only (session consumed / reset).
    func clear() {
        layoutSet = nil
        tiles = nil
        popups = nil
        rebuild()
        invalidateIntrinsicContentSize()
    }

    private func rebuild() {
        dismissPopup()
        for c in containers.values { c.removeFromSuperview() }
        containers = [:]
        keyViews = [:]
        guard let set = layoutSet else { return }
        let scale = pixelScale
        for layout in set.layouts {
            let container = UIView(frame: bounds)
            container.isAccessibilityElement = false
            container.isUserInteractionEnabled = false
            var views: [KeyView] = []
            for key in layout.keys where key.role != .blank {
                let kv = KeyView(key: key, layoutID: layout.id)
                kv.frame = CGRect(x: CGFloat(key.x) / scale, y: CGFloat(key.y) / scale,
                                  width: CGFloat(key.w) / scale, height: CGFloat(key.h) / scale)
                kv.apply(theme: theme, tiles: tiles)
                container.addSubview(kv)
                views.append(kv)
            }
            containers[layout.mode] = container
            keyViews[layout.mode] = views
            insertSubview(container, belowSubview: coverView)
        }
        if set.type == .number {
            mode = .number
        } else if mode == .number || set.layout(for: mode) == nil {
            mode = .lower
        }
        showMode(mode)
    }

    private func showMode(_ m: KeypadMode) {
        mode = m
        for (k, c) in containers { c.isHidden = k != m }
        updateShiftKeys()
    }

    private func updateShiftKeys() {
        let on = shift != .off
        for kv in keyViews[.upper] ?? [] where kv.key.role == .shift { kv.setShift(on: on, caps: shift == .caps) }
        for kv in keyViews[.lower] ?? [] where kv.key.role == .shift { kv.setShift(on: on, caps: shift == .caps) }
    }

    public override func layoutSubviews() {
        super.layoutSubviews()
        for c in containers.values { c.frame = bounds }
        coverView.frame = bounds
        coverLabel.frame = bounds.insetBy(dx: 24, dy: 8)
        let w = bounds.width
        if w > 0, w != lastWidth {
            let first = lastWidth == 0
            lastWidth = w
            if !first { onWidthChange?(w) }
        }
    }

    // MARK: cover (capture / background)

    func setCovered(_ covered: Bool, message: String? = nil) {
        coverLabel.text = message
        coverView.isHidden = !covered
        bringSubviewToFront(coverView)
        if covered { dismissPopup() }
    }

    // MARK: touches

    /// Converts a point in this view to device pixels clamped to the surface, spec/PROTOCOL.md §7.
    static func deviceTap(from point: CGPoint, scale: CGFloat, width: Int, height: Int) -> (x: Int, y: Int) {
        let x = Int((point.x * scale).rounded())
        let y = Int((point.y * scale).rounded())
        return (min(max(x, 0), max(width - 1, 0)), min(max(y, 0), max(height - 1, 0)))
    }

    private func keyView(at point: CGPoint) -> (KeyView, Tap)? {
        guard coverView.isHidden, let set = layoutSet, let layout = set.layout(for: mode) else { return nil }
        let p = Self.deviceTap(from: point, scale: pixelScale, width: set.w, height: set.h)
        guard let key = layout.hitTest(x: p.x, y: p.y), key.role != .blank,
              let kv = keyViews[mode]?.first(where: { $0.key == key }) else { return nil }
        return (kv, Tap(layoutID: layout.id, x: p.x, y: p.y))
    }

    public override func touchesBegan(_ touches: Set<UITouch>, with event: UIEvent?) {
        guard activeTouch == nil, let t = touches.first else { return }
        activeTouch = t
        press(at: t.location(in: self))
    }

    public override func touchesMoved(_ touches: Set<UITouch>, with event: UIEvent?) {
        guard let t = activeTouch, touches.contains(t) else { return }
        let hit = keyView(at: t.location(in: self))
        if hit?.0 !== activeKey {
            stopRepeat()
            activeKey?.setPressed(false)
            dismissPopup()
            activeKey = hit?.0
            activeKey?.setPressed(true)
            if let (kv, _) = hit, kv.key.role == .char { showPopup(for: kv) }
        }
    }

    public override func touchesEnded(_ touches: Set<UITouch>, with event: UIEvent?) {
        guard let t = activeTouch, touches.contains(t) else { return }
        let hit = keyView(at: t.location(in: self))
        release(commit: hit)
    }

    public override func touchesCancelled(_ touches: Set<UITouch>, with event: UIEvent?) {
        guard let t = activeTouch, touches.contains(t) else { return }
        release(commit: nil)
    }

    /// Test hook: runs the press/release path for a point in view coordinates without a `UITouch`.
    func simulateTap(at point: CGPoint) {
        press(at: point)
        release(commit: keyView(at: point))
    }

    private func press(at point: CGPoint) {
        guard let (kv, _) = keyView(at: point) else { return }
        activeKey = kv
        didRepeat = false
        kv.setPressed(true)
        if haptics { impact.impactOccurred() }
        if sound { UIDevice.current.playInputClick() }
        switch kv.key.role {
        case .char: showPopup(for: kv)
        case .backspace: startRepeat()
        default: break
        }
    }

    private func release(commit hit: (KeyView, Tap)?) {
        let repeated = didRepeat
        didRepeat = false
        stopRepeat()
        activeKey?.setPressed(false)
        dismissPopup()
        activeKey = nil
        activeTouch = nil
        guard let (kv, tap) = hit else { return }
        switch kv.key.role {
        case .char, .space:
            onTap?(tap)
            if shift == .on {
                shift = .off
                showMode(.lower)
            }
        case .backspace:
            if !repeated { onBackspace?() }
        case .shift:
            let now = Date().timeIntervalSinceReferenceDate
            if now - lastShiftTap < 0.35 {
                shift = .caps
            } else {
                shift = shift == .off ? .on : .off
            }
            lastShiftTap = now
            showMode(shift == .off ? .lower : .upper)
        case .modeAbc:
            showMode(shift == .off ? .lower : .upper)
        case .modeSym1:
            showMode(.sym1)
        case .modeSym2:
            showMode(.sym2)
        case .done:
            onDone?()
        case .blank:
            break
        }
    }

    private func startRepeat() {
        stopRepeat()
        repeatTimer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: false) { [weak self] _ in
            guard let self = self else { return }
            self.onBackspace?()
            let t = Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { [weak self] _ in
                self?.onBackspace?()
                if self?.sound == true { UIDevice.current.playInputClick() }
            }
            t.tolerance = 0.01
            self.repeatTimer = t
            self.didRepeat = true
        }
    }

    /// True once a held backspace has auto-repeated, so the release does not delete one more.
    private var didRepeat = false

    private func stopRepeat() {
        repeatTimer?.invalidate()
        repeatTimer = nil
    }

    // MARK: popup

    private func showPopup(for kv: KeyView) {
        dismissPopup()
        guard let set = layoutSet, let t = kv.key.t, let sheet = popups else { return }
        let scale = pixelScale
        let cellW = CGFloat(set.popup.w) / scale, cellH = CGFloat(set.popup.h) / scale
        let p = PopupView(theme: theme)
        p.setGlyph(sheet: sheet, cell: t, color: theme.keyText, scale: scale, cellSize: CGSize(width: cellW, height: cellH))
        let keyFrame = kv.superview?.convert(kv.frame, to: self) ?? kv.frame
        var x = keyFrame.midX - cellW / 2
        x = min(max(x, 2), bounds.width - cellW - 2)
        let height = cellH + keyFrame.height + 2
        p.frame = CGRect(x: x, y: keyFrame.maxY - height, width: cellW, height: height)
        p.keyFrameInPopup = CGRect(x: keyFrame.minX - x, y: cellH + 2, width: keyFrame.width, height: keyFrame.height)
        p.setNeedsDisplay()
        insertSubview(p, belowSubview: coverView)
        popup = p
    }

    private func dismissPopup() {
        popup?.removeFromSuperview()
        popup = nil
    }
}

// MARK: - KeyView

/// One key's chrome. Character keys show a tinted sprite cell; control keys show SF Symbols or labels.
final class KeyView: UIView {
    let key: KeypadKey
    let layoutID: Int
    private let glyph = CALayer()
    private let icon = UIImageView()
    private let label = UILabel()
    private var theme: KeypadTheme = .ios(dark: false)
    private var pressed = false
    private var shiftOn = false
    private var caps = false

    init(key: KeypadKey, layoutID: Int) {
        self.key = key
        self.layoutID = layoutID
        super.init(frame: .zero)
        isAccessibilityElement = false
        isUserInteractionEnabled = false
        layer.shadowOffset = CGSize(width: 0, height: 1)
        layer.shadowOpacity = 1
        layer.shadowRadius = 0
        glyph.contentsGravity = .center
        glyph.isOpaque = false
        layer.addSublayer(glyph)
        icon.contentMode = .center
        icon.isHidden = true
        addSubview(icon)
        label.textAlignment = .center
        label.adjustsFontSizeToFitWidth = true
        label.minimumScaleFactor = 0.6
        label.isHidden = true
        addSubview(label)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { nil }

    var isSpecial: Bool {
        switch key.role {
        case .char, .space: return false
        default: return true
        }
    }

    func apply(theme: KeypadTheme, tiles: SpriteSheet?) {
        self.theme = theme
        layer.cornerRadius = theme.cornerRadius
        layer.shadowColor = theme.shadow.cgColor
        icon.tintColor = theme.keyIcon
        label.textColor = theme.keyText
        label.font = theme.smallLabelFont
        icon.isHidden = true
        label.isHidden = true
        glyph.contents = nil
        switch key.role {
        case .char:
            if let t = key.t, let sheet = tiles, let img = sheet.tintedImage(theme.keyText) {
                glyph.contents = img
                glyph.contentsRect = sheet.contentsRect(cell: t)
                glyph.contentsScale = UIScreen.main.scale
            }
        case .space:
            label.text = "space"
            label.isHidden = false
        case .shift:
            icon.image = UIImage(systemName: shiftOn ? (caps ? "capslock.fill" : "shift.fill") : "shift")
            icon.isHidden = false
        case .backspace:
            icon.image = UIImage(systemName: "delete.left")
            icon.isHidden = false
        case .modeAbc:
            label.text = "ABC"
            label.isHidden = false
        case .modeSym1:
            label.text = "123"
            label.isHidden = false
        case .modeSym2:
            label.text = "#+="
            label.isHidden = false
        case .done:
            label.text = "Done"
            label.isHidden = false
        case .blank:
            break
        }
        updateColors()
    }

    override func layoutSubviews() {
        super.layoutSubviews()
        glyph.frame = bounds
        icon.frame = bounds
        label.frame = bounds.insetBy(dx: 2, dy: 0)
    }

    func setPressed(_ p: Bool) {
        pressed = p
        updateColors()
    }

    func setShift(on: Bool, caps: Bool) {
        shiftOn = on
        self.caps = caps
        icon.image = UIImage(systemName: on ? (caps ? "capslock.fill" : "shift.fill") : "shift")
        updateColors()
    }

    private func updateColors() {
        let special = isSpecial && !(key.role == .shift && shiftOn)
        if special {
            backgroundColor = pressed ? theme.specialKeyBackgroundPressed : theme.specialKeyBackground
        } else {
            backgroundColor = pressed ? theme.keyBackgroundPressed : theme.keyBackground
        }
    }
}

// MARK: - PopupView

/// iOS-style key popup: a bubble above the key holding the enlarged glyph, joined to the key area.
final class PopupView: UIView {
    private let theme: KeypadTheme
    private let glyph = CALayer()
    var keyFrameInPopup = CGRect.zero
    private var cellSize = CGSize.zero

    init(theme: KeypadTheme) {
        self.theme = theme
        super.init(frame: .zero)
        isOpaque = false
        backgroundColor = .clear
        isUserInteractionEnabled = false
        isAccessibilityElement = false
        glyph.contentsGravity = .center
        layer.addSublayer(glyph)
        layer.shadowColor = UIColor.black.cgColor
        layer.shadowOpacity = 0.25
        layer.shadowOffset = CGSize(width: 0, height: 1)
        layer.shadowRadius = 3
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { nil }

    func setGlyph(sheet: SpriteSheet, cell: Int, color: UIColor, scale: CGFloat, cellSize: CGSize) {
        self.cellSize = cellSize
        glyph.contents = sheet.tintedImage(color)
        glyph.contentsRect = sheet.contentsRect(cell: cell)
        glyph.contentsScale = scale
    }

    override func layoutSubviews() {
        super.layoutSubviews()
        glyph.frame = CGRect(x: 0, y: 0, width: bounds.width, height: cellSize.height)
    }

    override func draw(_ rect: CGRect) {
        let bubble = UIBezierPath(roundedRect: CGRect(x: 0, y: 0, width: bounds.width, height: cellSize.height + 6),
                                  cornerRadius: 9)
        let stem = UIBezierPath(roundedRect: keyFrameInPopup.insetBy(dx: 0, dy: -4), cornerRadius: theme.cornerRadius)
        bubble.append(stem)
        theme.popupBackground.setFill()
        bubble.fill()
    }
}
#endif
