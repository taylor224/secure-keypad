package dev.securekeypad.ui

import android.app.Activity
import android.app.Application
import android.content.Context
import android.content.ContextWrapper
import android.os.Build
import android.os.Bundle
import android.text.InputFilter
import android.text.InputType
import android.view.ActionMode
import android.view.Gravity
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.view.WindowInsets
import android.view.WindowManager
import android.widget.EditText
import android.widget.FrameLayout
import dev.securekeypad.protocol.B64
import dev.securekeypad.protocol.ClientSession
import dev.securekeypad.protocol.KeypadType
import dev.securekeypad.protocol.OpenedSession
import dev.securekeypad.protocol.SecureKeypadException
import dev.securekeypad.protocol.Viewport
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Controller: fetches sessions, shows the keypad panel at the bottom of the activity, keeps the attached
 * `EditText` masked, and turns the user's taps into one opaque payload for your backend.
 *
 * ```
 * val keypad = SecureKeypad(activity, SecureKeypad.Config(sessionUrl = "https://…/keypad/session",
 *     relayoutUrl = "https://…/keypad/relayout", serverPublicKey = "BASE64", type = KeypadType.NUMBER, maxLen = 6))
 * keypad.attach(pinField)
 * val payload = keypad.submit()   // suspend; send with your form
 * ```
 */
class SecureKeypad(context: Context, val config: Config) {

    data class Config(
        val sessionUrl: String,
        val relayoutUrl: String? = null,
        /** Base64 Ed25519 public key printed by `skp-keygen --pubkey`. Strongly recommended. */
        val serverPublicKey: String? = null,
        val type: KeypadType = KeypadType.QWERTY,
        val maxLen: Int? = null,
        val theme: ThemeMode = ThemeMode.AUTO,
        val haptics: Boolean = true,
        val sound: Boolean = true,
        val showPopup: Boolean = true,
        val doneLabel: String = "Done",
        /** Shift the activity content up when the focused field would be covered by the panel. */
        val adjustPan: Boolean = true,
        /** Extra request headers (auth). */
        val headers: Map<String, String> = emptyMap(),
        val transport: Transport = HttpUrlConnectionTransport(),
    )

    /** Input length changed. */
    var onChange: ((Int) -> Unit)? = null
    /** The Done key was pressed. */
    var onDone: (() -> Unit)? = null
    /** Session fetch/relayout failed or the session expired; a new session is fetched automatically. */
    var onError: ((SecureKeypadException) -> Unit)? = null

    private val activity: Activity = findActivity(context) ?: throw IllegalArgumentException("SecureKeypad needs an Activity context")
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val serverKey: ByteArray? = config.serverPublicKey?.let { B64.decode(it) }
    val view: SecureKeypadView = SecureKeypadView(activity)
    private val panel: FrameLayout = FrameLayout(activity)
    private var editText: EditText? = null
    private var session: Deferred<OpenedSession>? = null
    private var expiryJob: Job? = null
    private var relayoutJob: Job? = null
    private var shown = false
    private var hadSecureFlag = false
    private var internalUpdate = false
    private var contentShift = 0f
    private val density = activity.resources.displayMetrics.density

    private val lifecycle = object : Application.ActivityLifecycleCallbacks {
        override fun onActivityPaused(a: Activity) { if (a === activity) hide() }
        override fun onActivityDestroyed(a: Activity) { if (a === activity) detach() }
        override fun onActivityCreated(a: Activity, b: Bundle?) {}
        override fun onActivityStarted(a: Activity) {}
        override fun onActivityResumed(a: Activity) {}
        override fun onActivityStopped(a: Activity) {}
        override fun onActivitySaveInstanceState(a: Activity, b: Bundle) {}
    }

    init {
        view.haptics = config.haptics
        view.sound = config.sound
        view.showPopup = config.showPopup
        view.doneLabel = config.doneLabel
        when (config.theme) {
            ThemeMode.LIGHT -> view.theme = KeypadTheme.LIGHT
            ThemeMode.DARK -> view.theme = KeypadTheme.DARK
            ThemeMode.AUTO -> view.applyAutoTheme()
        }
        view.onChange = { n -> updateMask(n); onChange?.invoke(n) }
        view.onDone = { hide(); onDone?.invoke() }
        view.onRelayoutNeeded = { w -> requestRelayout(w) }
        panel.addView(view, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        panel.setBackgroundColor(view.theme.keypadBackground)
        panel.isClickable = true // swallow touches so they do not reach the content below
        panel.setOnApplyWindowInsetsListener { v, insets ->
            v.setPadding(0, 0, 0, navBarInset(insets))
            insets
        }
        activity.application.registerActivityLifecycleCallbacks(lifecycle)
    }

    // ---- public API -------------------------------------------------------------------------------------

    /** Routes the field's input through the secure keypad. The field never receives characters. */
    fun attach(field: EditText) {
        editText = field
        field.showSoftInputOnFocus = false
        field.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        field.isLongClickable = false
        field.setTextIsSelectable(false)
        field.customSelectionActionModeCallback = NoActionMode
        field.customInsertionActionModeCallback = NoActionMode
        field.filters = arrayOf(InputFilter { source, _, _, _, _, _ -> if (internalUpdate) null else "" })
        field.setOnFocusChangeListener { _, hasFocus -> if (hasFocus) show() else hide() }
        field.setOnClickListener { show() }
        updateMask(view.length)
        prefetch()
    }

    /** Starts fetching a session so the keypad opens instantly. Safe to call repeatedly. */
    fun prefetch() {
        if (session == null) session = fetchSession()
    }

    fun show() {
        if (shown) return
        val decor = activity.window.decorView as ViewGroup
        if (panel.parent == null) {
            val lp = FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.BOTTOM)
            decor.addView(panel, lp)
        }
        panel.visibility = View.VISIBLE
        shown = true
        hadSecureFlag = (activity.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE) != 0
        activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        prefetch()
        panel.post { adjustPan() }
    }

    fun hide() {
        if (!shown) return
        shown = false
        panel.visibility = View.GONE
        if (!hadSecureFlag) activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        restorePan()
    }

    val isShown: Boolean get() = shown
    val length: Int get() = view.length

    /**
     * Produces the encrypted payload for the taps made so far and consumes the session. Send the returned
     * JSON string with your form; the server SDK's `decrypt` turns it into the typed value. After this call
     * the keypad holds a fresh session (prefetched) and zero input.
     */
    suspend fun submit(): String {
        val s = (session ?: fetchSession().also { session = it }).await()
        val taps = view.takeRecords()
        val payload = s.buildInput(s.initial.layout.maxLen, taps)
        session = null
        expiryJob?.cancel()
        hide()
        view.clear()
        prefetch()
        return payload
    }

    /** Drops the current session and input and fetches a new one. */
    fun reset() {
        session?.cancel()
        session = null
        expiryJob?.cancel()
        view.clear()
        updateMask(0)
        prefetch()
    }

    /** Removes the panel and listeners. */
    fun detach() {
        hide()
        scope.cancel()
        (panel.parent as? ViewGroup)?.removeView(panel)
        view.clear()
        editText?.let {
            it.onFocusChangeListener = null
            it.setOnClickListener(null)
        }
        editText = null
        activity.application.unregisterActivityLifecycleCallbacks(lifecycle)
    }

    // ---- internals --------------------------------------------------------------------------------------

    private fun viewport(widthPx: Int): Viewport = Viewport(w = widthPx / density.toDouble(), dpr = density.toDouble())

    private fun panelWidth(): Int = if (panel.width > 0) panel.width else activity.resources.displayMetrics.widthPixels

    private fun fetchSession(): Deferred<OpenedSession> = scope.async {
        val client = ClientSession.create()
        try {
            val req = client.requestJson(config.type, viewport(panelWidth()), config.maxLen)
            val resp = withContext(Dispatchers.IO) { config.transport.post(config.sessionUrl, req, config.headers) }
            val opened = client.open(resp, serverKey)
            view.setSession(opened.initial)
            scheduleExpiry(opened.initial.layout.expSeconds)
            opened
        } catch (e: SecureKeypadException) {
            client.wipe()
            onError?.invoke(e)
            throw e
        } catch (e: Exception) {
            client.wipe()
            val wrapped = SecureKeypadException.network(e.message ?: e.javaClass.simpleName)
            onError?.invoke(wrapped)
            throw wrapped
        }
    }

    private fun scheduleExpiry(seconds: Int) {
        expiryJob?.cancel()
        expiryJob = scope.launch {
            delay(maxOf(1, seconds - 5) * 1000L)
            onError?.invoke(SecureKeypadException.expired())
            reset()
        }
    }

    private fun requestRelayout(widthPx: Int) {
        val url = config.relayoutUrl ?: run { reset(); return }
        val s = session ?: return
        relayoutJob?.cancel()
        relayoutJob = scope.launch {
            try {
                val opened = s.await()
                if (opened.isConsumed) return@launch
                val req = opened.relayoutRequestJson(viewport(widthPx))
                val resp = withContext(Dispatchers.IO) { config.transport.post(url, req, config.headers) }
                val payload = opened.openRelayout(resp)
                if (payload.layout.w == view.width || view.width == 0) view.applyRelayout(payload) else requestRelayout(view.width)
            } catch (e: SecureKeypadException) {
                onError?.invoke(e)
                reset()
            } catch (e: Exception) {
                onError?.invoke(SecureKeypadException.network(e.message ?: e.javaClass.simpleName))
                reset()
            }
        }
    }

    private fun updateMask(n: Int) {
        val f = editText ?: return
        internalUpdate = true
        try {
            f.setText("•".repeat(n))
            f.setSelection(f.text.length)
        } finally {
            internalUpdate = false
        }
    }

    private fun navBarInset(insets: WindowInsets): Int =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) insets.getInsets(WindowInsets.Type.navigationBars()).bottom
        else @Suppress("DEPRECATION") insets.systemWindowInsetBottom

    private fun adjustPan() {
        if (!config.adjustPan) return
        val f = editText ?: return
        val content = activity.findViewById<View>(android.R.id.content) ?: return
        val loc = IntArray(2)
        f.getLocationOnScreen(loc)
        val fieldBottom = loc[1] + f.height + (16 * density).toInt()
        val pl = IntArray(2)
        panel.getLocationOnScreen(pl)
        val overlap = fieldBottom - pl[1]
        if (overlap > 0) {
            contentShift = overlap.toFloat()
            content.translationY = -contentShift
        }
    }

    private fun restorePan() {
        if (contentShift == 0f) return
        activity.findViewById<View>(android.R.id.content)?.translationY = 0f
        contentShift = 0f
    }

    private object NoActionMode : ActionMode.Callback {
        override fun onCreateActionMode(mode: ActionMode?, menu: Menu?) = false
        override fun onPrepareActionMode(mode: ActionMode?, menu: Menu?) = false
        override fun onActionItemClicked(mode: ActionMode?, item: MenuItem?) = false
        override fun onDestroyActionMode(mode: ActionMode?) {}
    }

    private companion object {
        fun findActivity(context: Context): Activity? {
            var c: Context? = context
            while (c != null) {
                if (c is Activity) return c
                c = (c as? ContextWrapper)?.baseContext
            }
            return null
        }
    }
}
