package dev.securekeypad.demo

import android.app.Activity
import android.os.Bundle
import android.util.TypedValue
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import dev.securekeypad.protocol.KeypadType
import dev.securekeypad.ui.SecureKeypad
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Minimal integration: a PIN field on a number pad and a password field on a QWERTY pad. Point
 * [SERVER] at any of the example servers in `examples/` (they expose /keypad/session and /keypad/relayout).
 */
class DemoActivity : Activity() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private lateinit var pinKeypad: SecureKeypad
    private lateinit var passwordKeypad: SecureKeypad

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val pad = dp(20)
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
        }
        val title = TextView(this).apply {
            text = "secure-keypad demo"
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 22f)
        }
        val pin = EditText(this).apply { hint = "PIN (6 digits)" }
        val password = EditText(this).apply { hint = "Password" }
        val status = TextView(this).apply { text = "Server: $SERVER" }
        val submit = Button(this).apply { text = "Submit" }
        column.addView(title)
        column.addView(pin, wrap())
        column.addView(password, wrap())
        column.addView(submit, wrap())
        column.addView(status, wrap())
        setContentView(ScrollView(this).apply { addView(column) })

        pinKeypad = SecureKeypad(this, SecureKeypad.Config(
            sessionUrl = "$SERVER/keypad/session", relayoutUrl = "$SERVER/keypad/relayout",
            serverPublicKey = SERVER_PUBLIC_KEY, type = KeypadType.NUMBER, maxLen = 6))
        passwordKeypad = SecureKeypad(this, SecureKeypad.Config(
            sessionUrl = "$SERVER/keypad/session", relayoutUrl = "$SERVER/keypad/relayout",
            serverPublicKey = SERVER_PUBLIC_KEY, type = KeypadType.QWERTY, maxLen = 32,
            languages = listOf("ko", "en")))   // Korean first, globe key switches to English; omit for the server default (en, ko)
        pinKeypad.onError = { status.text = "PIN keypad: ${it.code}" }
        passwordKeypad.onError = { status.text = "Password keypad: ${it.code}" }
        pinKeypad.attach(pin)
        passwordKeypad.attach(password)

        submit.setOnClickListener {
            scope.launch {
                try {
                    val p1 = pinKeypad.submit()
                    val p2 = passwordKeypad.submit()
                    status.text = "PIN payload ${p1.length} chars, password payload ${p2.length} chars — POST them to your login endpoint"
                } catch (e: Exception) {
                    status.text = "submit failed: ${e.message}"
                }
            }
        }
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private fun dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()
    private fun wrap() = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dp(12) }

    companion object {
        /** 10.0.2.2 reaches the host machine from the Android emulator. */
        const val SERVER = "http://10.0.2.2:3000"
        /** Replace with the value printed by `skp-keygen --pubkey master.key`; null disables pinning (dev only). */
        val SERVER_PUBLIC_KEY: String? = null
    }
}
