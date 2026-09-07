package dev.securekeypad.ui

import android.graphics.Color

/** Material-style keypad colors. Only colors are customisable; geometry comes from the server. */
data class KeypadTheme(
    val keypadBackground: Int,
    val keyBackground: Int,
    val keyBackgroundPressed: Int,
    val specialBackground: Int,
    val specialBackgroundPressed: Int,
    val keyText: Int,
    val keyIcon: Int,
    val popupBackground: Int,
    val doneBackground: Int,
    val doneText: Int,
    val cornerRadiusDp: Float = 8f,
) {
    companion object {
        val LIGHT = KeypadTheme(
            keypadBackground = Color.parseColor("#ECEFF1"),
            keyBackground = Color.WHITE,
            keyBackgroundPressed = Color.parseColor("#CFD8DC"),
            specialBackground = Color.parseColor("#CFD8DC"),
            specialBackgroundPressed = Color.parseColor("#B0BEC5"),
            keyText = Color.parseColor("#1F2328"),
            keyIcon = Color.parseColor("#37474F"),
            popupBackground = Color.WHITE,
            doneBackground = Color.parseColor("#1F5FBF"),
            doneText = Color.WHITE,
        )
        val DARK = KeypadTheme(
            keypadBackground = Color.parseColor("#1F2226"),
            keyBackground = Color.parseColor("#3C4247"),
            keyBackgroundPressed = Color.parseColor("#5A6168"),
            specialBackground = Color.parseColor("#2B3034"),
            specialBackgroundPressed = Color.parseColor("#454B51"),
            keyText = Color.parseColor("#F1F3F4"),
            keyIcon = Color.parseColor("#DDE1E4"),
            popupBackground = Color.parseColor("#4A5158"),
            doneBackground = Color.parseColor("#8AB4F8"),
            doneText = Color.parseColor("#0E1B33"),
        )
    }
}

enum class ThemeMode { AUTO, LIGHT, DARK }
