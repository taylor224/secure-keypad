package dev.securekeypad.ui

import android.content.Context
import android.content.res.Configuration
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Path
import android.graphics.Rect
import android.graphics.RectF
import android.media.AudioManager
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.util.AttributeSet
import android.view.HapticFeedbackConstants
import android.view.MotionEvent
import android.view.View
import android.view.accessibility.AccessibilityNodeInfo
import dev.securekeypad.protocol.HitTest
import dev.securekeypad.protocol.KeyInfo
import dev.securekeypad.protocol.LANGUAGE_NAMES
import dev.securekeypad.protocol.KeypadLayout
import dev.securekeypad.protocol.KeypadType
import dev.securekeypad.protocol.LayoutInfo
import dev.securekeypad.protocol.Role
import dev.securekeypad.protocol.SessionPayload
import dev.securekeypad.protocol.Tap
import java.nio.ByteBuffer

/**
 * Draws the keypad chrome natively and blits the server's glyph sprites. It never holds a character: only
 * rectangles, roles, sprite cell indices and the taps the user made.
 *
 * The view reports `w = widthPx / density, dpr = density`, so the server's device-pixel rects map 1:1 onto
 * the view's own pixels and nothing is ever scaled.
 */
class SecureKeypadView @JvmOverloads constructor(context: Context, attrs: AttributeSet? = null) : View(context, attrs) {

    /** Called with the current input length after every change. */
    var onChange: ((Int) -> Unit)? = null
    /** The Done key was pressed. */
    var onDone: (() -> Unit)? = null
    /** The view's size no longer matches the session's surface; the controller should request a relayout. */
    var onRelayoutNeeded: ((widthPx: Int) -> Unit)? = null
    /** The user switched keyboard language (code from the layout's `langs`). */
    var onLanguageChange: ((String) -> Unit)? = null
    /** Space-bar labels per language code; falls back to [LANGUAGE_NAMES], then the code. */
    var languageNames: Map<String, String> = emptyMap()

    var theme: KeypadTheme = KeypadTheme.LIGHT
        set(value) {
            field = value
            invalidate()
        }
    var haptics: Boolean = true
    var sound: Boolean = true
    var showPopup: Boolean = true
    var doneLabel: String = "Done"

    private var layout: KeypadLayout? = null
    private var tiles: Bitmap? = null
    private var popups: Bitmap? = null
    private var maxLen: Int = 0
    private val records = ArrayList<Tap>()

    private enum class Shift { OFF, ONCE, CAPS }
    private var shift = Shift.OFF
    private var lastShiftTap = 0L
    private var symMode = 0 // 0 abc, 1 sym1, 2 sym2
    /** Current language code; kept across sessions while the server keeps offering it. */
    var language: String? = null
        private set

    private var pressed: KeyInfo? = null
    private var downX = 0
    private var downY = 0
    private var activePointer = -1
    private val handler = Handler(Looper.getMainLooper())
    private val repeatRunnable = object : Runnable {
        override fun run() {
            if (pressed?.role == Role.BACKSPACE) {
                backspace()
                handler.postDelayed(this, 100)
            }
        }
    }

    private val density = resources.displayMetrics.density
    private val fillPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val tilePaint = Paint(Paint.ANTI_ALIAS_FLAG or Paint.FILTER_BITMAP_FLAG)
    private val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { textAlign = Paint.Align.CENTER }
    private val iconPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeJoin = Paint.Join.ROUND
        strokeCap = Paint.Cap.ROUND
    }
    private val rectF = RectF()
    private val src = Rect()
    private val dst = Rect()
    private val path = Path()

    init {
        isFocusable = false
        isClickable = true
        filterTouchesWhenObscured = true
        contentDescription = "Secure keypad"
        importantForAccessibility = IMPORTANT_FOR_ACCESSIBILITY_YES
        applyAutoTheme()
    }

    // ---- session data -------------------------------------------------------------------------------

    /** Installs a fresh session payload (generation 0). Records are cleared. */
    fun setSession(payload: SessionPayload) {
        recycle()
        layout = payload.layout
        maxLen = payload.layout.maxLen
        tiles = decodeMask(payload.tilesPng)
        popups = decodeMask(payload.popupsPng)
        records.clear()
        shift = Shift.OFF
        symMode = 0
        pressed = null
        pickLanguage(payload.layout)
        requestLayout()
        invalidate()
        onChange?.invoke(0)
    }

    private fun pickLanguage(l: KeypadLayout) {
        val current = language
        language = if (current != null && l.langs.contains(current)) current else l.langs.firstOrNull()
    }

    /** Switches to one of the installed languages; returns false when the layout does not offer it. */
    fun setLanguage(code: String): Boolean {
        val l = layout ?: return false
        if (!l.langs.contains(code)) return false
        language = code
        symMode = 0
        shift = Shift.OFF
        invalidate()
        return true
    }

    private fun spaceLabel(l: KeypadLayout): String? {
        val code = language ?: return null
        if (l.langs.size < 2) return null
        return languageNames[code] ?: LANGUAGE_NAMES[code] ?: code.uppercase()
    }

    /** Installs a relayout payload (new generation). Records keep their original layout ids. */
    fun applyRelayout(payload: SessionPayload) {
        val t = decodeMask(payload.tilesPng)
        val p = decodeMask(payload.popupsPng)
        tiles?.recycle()
        popups?.recycle()
        tiles = t
        popups = p
        layout = payload.layout
        pressed = null
        pickLanguage(payload.layout)
        requestLayout()
        invalidate()
    }

    /** Drops the session and every recorded tap. */
    fun clear() {
        recycle()
        layout = null
        records.clear()
        pressed = null
        shift = Shift.OFF
        symMode = 0
        invalidate()
        onChange?.invoke(0)
    }

    fun hasSession(): Boolean = layout != null
    val length: Int get() = records.size
    val currentGen: Int get() = layout?.gen ?: -1
    val surfaceWidth: Int get() = layout?.w ?: 0

    /** Takes the recorded taps (the caller builds the payload) and clears them. */
    fun takeRecords(): List<Tap> {
        val out = ArrayList(records)
        records.clear()
        onChange?.invoke(0)
        return out
    }

    fun clearInput() {
        records.clear()
        invalidate()
        onChange?.invoke(0)
    }

    private fun recycle() {
        tiles?.recycle()
        popups?.recycle()
        tiles = null
        popups = null
    }

    /** Grayscale coverage PNG → ALPHA_8 mask (luminance becomes alpha) so it can be drawn tinted. */
    private fun decodeMask(png: ByteArray): Bitmap? {
        if (png.isEmpty()) return null
        val opts = BitmapFactory.Options().apply { inPreferredConfig = Bitmap.Config.ARGB_8888 }
        val rgb = BitmapFactory.decodeByteArray(png, 0, png.size, opts) ?: return null
        val w = rgb.width
        val h = rgb.height
        val px = IntArray(w * h)
        rgb.getPixels(px, 0, w, 0, 0, w, h)
        rgb.recycle()
        val buf = ByteBuffer.allocate(w * h)
        for (v in px) buf.put((v and 0xff).toByte()) // blue channel == gray level
        buf.rewind()
        val mask = Bitmap.createBitmap(w, h, Bitmap.Config.ALPHA_8)
        mask.copyPixelsFromBuffer(buf)
        return mask
    }

    fun applyAutoTheme() {
        val night = (resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES
        theme = if (night) KeypadTheme.DARK else KeypadTheme.LIGHT
    }

    // ---- layout ---------------------------------------------------------------------------------------

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        val width = MeasureSpec.getSize(widthMeasureSpec)
        val fallback = (214 * density).toInt()
        val h = layout?.h ?: fallback
        setMeasuredDimension(width, resolveSize(h, heightMeasureSpec))
    }

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        val l = layout ?: return
        if (w > 0 && l.w != w) onRelayoutNeeded?.invoke(w)
    }

    /** Which layer is shown right now. */
    private fun currentLayer(): LayoutInfo? {
        val l = layout ?: return null
        if (l.type == KeypadType.NUMBER) return l.layer(KeypadLayout.MODE_NUMBER)
        return when (symMode) {
            1 -> l.layer(KeypadLayout.MODE_SYM1)
            2 -> l.layer(KeypadLayout.MODE_SYM2)
            else -> {
                val mode = if (shift == Shift.OFF) KeypadLayout.MODE_LOWER else KeypadLayout.MODE_UPPER
                l.layer(mode, language) ?: l.layer(mode)
            }
        }
    }

    // ---- drawing --------------------------------------------------------------------------------------

    override fun onDraw(canvas: Canvas) {
        canvas.drawColor(theme.keypadBackground)
        val l = layout ?: return
        val layer = currentLayer() ?: return
        val radius = theme.cornerRadiusDp * density
        for (k in layer.keys) {
            if (k.role == Role.BLANK) continue
            val isPressed = pressed === k
            fillPaint.color = when (k.role) {
                Role.CHAR, Role.SPACE -> if (isPressed) theme.keyBackgroundPressed else theme.keyBackground
                Role.DONE -> if (isPressed) theme.specialBackgroundPressed else theme.doneBackground
                Role.SHIFT -> if (isPressed || shift != Shift.OFF) theme.specialBackgroundPressed else theme.specialBackground
                else -> if (isPressed) theme.specialBackgroundPressed else theme.specialBackground
            }
            rectF.set(k.rect.x.toFloat(), k.rect.y.toFloat(), k.rect.right.toFloat(), k.rect.bottom.toFloat())
            canvas.drawRoundRect(rectF, radius, radius, fillPaint)
            when (k.role) {
                Role.CHAR -> drawCell(canvas, tiles, l.tile.w, l.tile.h, l.tile.cols, k.tile, k.rect, theme.keyText)
                Role.SPACE -> spaceLabel(l)?.let { drawLabel(canvas, k, it, theme.keyText) }
                Role.SHIFT -> drawShift(canvas, k, shift == Shift.CAPS)
                Role.BACKSPACE -> drawBackspace(canvas, k)
                Role.LANG -> drawGlobe(canvas, k)
                Role.MODE_ABC -> drawLabel(canvas, k, "ABC", theme.keyText)
                Role.MODE_SYM1 -> drawLabel(canvas, k, "?123", theme.keyText)
                Role.MODE_SYM2 -> drawLabel(canvas, k, "=\\<", theme.keyText)
                Role.DONE -> drawLabel(canvas, k, doneLabel, theme.doneText)
                else -> {}
            }
        }
        val p = pressed
        if (showPopup && p != null && p.role == Role.CHAR) drawPopup(canvas, l, p)
    }

    private fun drawCell(canvas: Canvas, sprite: Bitmap?, cw: Int, ch: Int, cols: Int, index: Int, rect: dev.securekeypad.protocol.KeyRect, color: Int) {
        if (sprite == null || index < 0 || cols <= 0) return
        val cx = (index % cols) * cw
        val cy = (index / cols) * ch
        if (cx + cw > sprite.width || cy + ch > sprite.height) return
        src.set(cx, cy, cx + cw, cy + ch)
        val left = rect.x + (rect.w - cw) / 2
        val top = rect.y + (rect.h - ch) / 2
        dst.set(left, top, left + cw, top + ch)
        tilePaint.color = color
        canvas.drawBitmap(sprite, src, dst, tilePaint)
    }

    private fun drawPopup(canvas: Canvas, l: KeypadLayout, k: KeyInfo) {
        val pw = l.popup.w
        val ph = l.popup.h
        val cx = k.rect.x + k.rect.w / 2
        var left = cx - pw / 2
        left = left.coerceIn(0, maxOf(0, width - pw))
        val bottom = k.rect.y - (4 * density).toInt()
        val top = bottom - ph
        rectF.set(left.toFloat(), top.toFloat(), (left + pw).toFloat(), bottom.toFloat())
        fillPaint.color = theme.popupBackground
        fillPaint.setShadowLayer(6 * density, 0f, 2 * density, 0x55000000)
        val r = theme.cornerRadiusDp * density
        canvas.drawRoundRect(rectF, r, r, fillPaint)
        fillPaint.clearShadowLayer()
        drawCell(canvas, popups, pw, ph, l.popup.cols, k.tile, dev.securekeypad.protocol.KeyRect(left, top, pw, ph), theme.keyText)
    }

    private fun drawLabel(canvas: Canvas, k: KeyInfo, text: String, color: Int) {
        textPaint.color = color
        textPaint.textSize = minOf(k.rect.h * 0.34f, 16f * density)
        val y = k.rect.y + k.rect.h / 2f - (textPaint.descent() + textPaint.ascent()) / 2f
        canvas.drawText(text, k.rect.x + k.rect.w / 2f, y, textPaint)
    }

    private fun drawShift(canvas: Canvas, k: KeyInfo, caps: Boolean) {
        val s = minOf(k.rect.w, k.rect.h) * 0.42f
        val cx = k.rect.x + k.rect.w / 2f
        val cy = k.rect.y + k.rect.h / 2f
        path.reset()
        path.moveTo(cx, cy - s / 2)
        path.lineTo(cx + s / 2, cy)
        path.lineTo(cx + s / 4, cy)
        path.lineTo(cx + s / 4, cy + s / 2)
        path.lineTo(cx - s / 4, cy + s / 2)
        path.lineTo(cx - s / 4, cy)
        path.lineTo(cx - s / 2, cy)
        path.close()
        iconPaint.color = theme.keyIcon
        iconPaint.strokeWidth = 1.6f * density
        iconPaint.style = if (caps || shift == Shift.ONCE) Paint.Style.FILL_AND_STROKE else Paint.Style.STROKE
        canvas.drawPath(path, iconPaint)
        if (caps) {
            iconPaint.style = Paint.Style.STROKE
            canvas.drawLine(cx - s / 4, cy + s / 2 + 3 * density, cx + s / 4, cy + s / 2 + 3 * density, iconPaint)
        }
    }

    /** Globe icon of the language key: a circle with a meridian and two parallels. */
    private fun drawGlobe(canvas: Canvas, k: KeyInfo) {
        val r = minOf(k.rect.w, k.rect.h) * 0.24f
        val cx = k.rect.x + k.rect.w / 2f
        val cy = k.rect.y + k.rect.h / 2f
        iconPaint.color = theme.keyIcon
        iconPaint.strokeWidth = 1.5f * density
        iconPaint.style = Paint.Style.STROKE
        canvas.drawCircle(cx, cy, r, iconPaint)
        canvas.drawLine(cx - r, cy, cx + r, cy, iconPaint)
        canvas.drawLine(cx, cy - r, cx, cy + r, iconPaint)
        rectF.set(cx - r * 0.42f, cy - r, cx + r * 0.42f, cy + r)
        canvas.drawOval(rectF, iconPaint)
        val lat = r * 0.5f
        val half = kotlin.math.sqrt(r * r - lat * lat)
        path.reset()
        path.moveTo(cx - half, cy - lat)
        path.quadTo(cx, cy - lat - r * 0.16f, cx + half, cy - lat)
        path.moveTo(cx - half, cy + lat)
        path.quadTo(cx, cy + lat + r * 0.16f, cx + half, cy + lat)
        canvas.drawPath(path, iconPaint)
    }

    private fun drawBackspace(canvas: Canvas, k: KeyInfo) {
        val w = minOf(k.rect.w, k.rect.h) * 0.55f
        val h = w * 0.62f
        val cx = k.rect.x + k.rect.w / 2f
        val cy = k.rect.y + k.rect.h / 2f
        path.reset()
        path.moveTo(cx - w / 2, cy)
        path.lineTo(cx - w / 2 + h / 2, cy - h / 2)
        path.lineTo(cx + w / 2, cy - h / 2)
        path.lineTo(cx + w / 2, cy + h / 2)
        path.lineTo(cx - w / 2 + h / 2, cy + h / 2)
        path.close()
        iconPaint.color = theme.keyIcon
        iconPaint.strokeWidth = 1.6f * density
        iconPaint.style = Paint.Style.STROKE
        canvas.drawPath(path, iconPaint)
        val xc = cx + h / 6
        val r = h * 0.22f
        canvas.drawLine(xc - r, cy - r, xc + r, cy + r, iconPaint)
        canvas.drawLine(xc - r, cy + r, xc + r, cy - r, iconPaint)
    }

    // ---- input ----------------------------------------------------------------------------------------

    override fun onTouchEvent(event: MotionEvent): Boolean {
        val layer = currentLayer() ?: return true
        when (event.actionMasked) {
            MotionEvent.ACTION_DOWN -> {
                activePointer = event.getPointerId(0)
                downX = event.x.toInt()
                downY = event.y.toInt()
                val k = HitTest.nearest(layer.keys, downX, downY)
                if (k == null || k.role == Role.BLANK) return true
                pressed = k
                feedback()
                if (k.role == Role.BACKSPACE) {
                    backspace()
                    handler.postDelayed(repeatRunnable, 500)
                }
                invalidate()
            }
            MotionEvent.ACTION_MOVE -> {
                if (pressed != null && pressed?.role != Role.BACKSPACE) {
                    val idx = event.findPointerIndex(activePointer)
                    if (idx >= 0) {
                        val k = HitTest.nearest(layer.keys, event.getX(idx).toInt(), event.getY(idx).toInt())
                        if (k !== pressed) {
                            pressed = null // slid off: cancel
                            invalidate()
                        }
                    }
                }
            }
            MotionEvent.ACTION_UP -> {
                val k = pressed
                pressed = null
                handler.removeCallbacks(repeatRunnable)
                if (k != null && k.role != Role.BACKSPACE) commit(layer, k)
                invalidate()
            }
            MotionEvent.ACTION_CANCEL -> {
                pressed = null
                handler.removeCallbacks(repeatRunnable)
                invalidate()
            }
        }
        return true
    }

    private fun commit(layer: LayoutInfo, k: KeyInfo) {
        if (k.role != Role.SHIFT) lastShiftTap = 0L // caps lock needs two consecutive shift taps
        when (k.role) {
            Role.CHAR, Role.SPACE -> {
                if (records.size >= maxLen) return
                records.add(Tap(layer.id, downX, downY))
                if (shift == Shift.ONCE) shift = Shift.OFF
                onChange?.invoke(records.size)
            }
            Role.SHIFT -> {
                val now = SystemClock.uptimeMillis()
                shift = when {
                    shift == Shift.OFF && now - lastShiftTap < 300 -> Shift.CAPS
                    shift == Shift.OFF -> Shift.ONCE
                    shift == Shift.ONCE && now - lastShiftTap < 300 -> Shift.CAPS
                    else -> Shift.OFF
                }
                lastShiftTap = now
            }
            Role.MODE_ABC -> { symMode = 0; shift = Shift.OFF }
            Role.MODE_SYM1 -> symMode = 1
            Role.MODE_SYM2 -> symMode = 2
            Role.LANG -> {
                val langs = layout?.langs ?: emptyList()
                if (langs.size >= 2) {
                    val next = langs[(langs.indexOf(language) + 1) % langs.size]
                    language = next
                    symMode = 0
                    shift = Shift.OFF
                    onLanguageChange?.invoke(next)
                }
            }
            Role.DONE -> onDone?.invoke()
            else -> {}
        }
    }

    private fun backspace() {
        if (records.isEmpty()) return
        records.removeAt(records.size - 1)
        onChange?.invoke(records.size)
    }

    private fun feedback() {
        if (haptics) performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP)
        if (sound) {
            (context.getSystemService(Context.AUDIO_SERVICE) as? AudioManager)?.playSoundEffect(AudioManager.FX_KEYPRESS_STANDARD)
        }
    }

    // ---- accessibility: one opaque node, no key labels -----------------------------------------------

    override fun onInitializeAccessibilityNodeInfo(info: AccessibilityNodeInfo) {
        super.onInitializeAccessibilityNodeInfo(info)
        info.className = View::class.java.name
        info.contentDescription = "Secure keypad"
    }

    override fun onDetachedFromWindow() {
        handler.removeCallbacks(repeatRunnable)
        super.onDetachedFromWindow()
    }
}
