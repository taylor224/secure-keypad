package dev.securekeypad.protocol

import org.json.JSONArray
import org.json.JSONObject

enum class KeypadType(val wire: String) { QWERTY("qwerty"), NUMBER("number") }

enum class Role(val wire: String) {
    CHAR("char"), SPACE("space"), SHIFT("shift"), BACKSPACE("backspace"), MODE_ABC("mode_abc"),
    MODE_SYM1("mode_sym1"), MODE_SYM2("mode_sym2"), DONE("done"), BLANK("blank"), LANG("lang");

    companion object {
        fun fromWire(s: String): Role = entries.firstOrNull { it.wire == s } ?: throw SecureKeypadException.protocol("role $s")
    }
}

/** Key rectangle in device pixels relative to the keypad surface. */
data class KeyRect(val x: Int, val y: Int, val w: Int, val h: Int) {
    val right: Int get() = x + w
    val bottom: Int get() = y + h
    fun contains(px: Int, py: Int): Boolean = px >= x && px < right && py >= y && py < bottom
}

/** One key. [tile] is the sprite cell for character keys, -1 otherwise. The client never learns a character. */
data class KeyInfo(val rect: KeyRect, val role: Role, val tile: Int)

/**
 * A layer. [id] = (gen << 3) | slot is assigned by the server and echoed with every tap; [mode] is one of
 * lower / upper / sym1 / sym2 / number and [lang] names the language of a letter layer ("en", "ko", …).
 */
data class LayoutInfo(val id: Int, val mode: String, val lang: String?, val keys: List<KeyInfo>) {
    val gen: Int get() = id shr 3
}

/** Space-bar labels when several keyboard languages are installed. */
val LANGUAGE_NAMES: Map<String, String> = mapOf("en" to "English", "ko" to "한국어")

data class SpriteInfo(val w: Int, val h: Int, val cols: Int, val count: Int)

data class KeypadLayout(
    val version: Int,
    val type: KeypadType,
    val style: String,
    val w: Int,
    val h: Int,
    val gen: Int,
    val maxLen: Int,
    val expSeconds: Int,
    /** Installed languages in switch order (empty for number pads). */
    val langs: List<String>,
    val layouts: List<LayoutInfo>,
    val tile: SpriteInfo,
    val popup: SpriteInfo,
) {
    /** Layer for a mode; for letter layers [lang] selects the language (null: the first one listed). */
    fun layer(mode: String, lang: String? = null): LayoutInfo? =
        layouts.firstOrNull { it.mode == mode && (lang == null || it.lang == lang) }

    companion object {
        const val MODE_LOWER = "lower"
        const val MODE_UPPER = "upper"
        const val MODE_SYM1 = "sym1"
        const val MODE_SYM2 = "sym2"
        const val MODE_NUMBER = "number"

        fun parse(json: String): KeypadLayout = try {
            val o = JSONObject(json)
            val v = o.getInt("v")
            if (v != 1) throw SecureKeypadException.protocol("inner version $v")
            val typeWire = o.getString("type")
            val type = KeypadType.entries.firstOrNull { it.wire == typeWire } ?: throw SecureKeypadException.protocol("type")
            val layouts = ArrayList<LayoutInfo>()
            val la = o.getJSONArray("layouts")
            for (i in 0 until la.length()) layouts.add(parseLayer(la.getJSONObject(i)))
            val langs = ArrayList<String>()
            val lg = o.optJSONArray("langs")
            if (lg != null) for (i in 0 until lg.length()) langs.add(lg.getString(i))
            KeypadLayout(
                version = v,
                type = type,
                style = o.getString("style"),
                w = o.getInt("w"),
                h = o.getInt("h"),
                gen = o.getInt("gen"),
                maxLen = o.getInt("maxLen"),
                expSeconds = o.getInt("exp"),
                langs = langs,
                layouts = layouts,
                tile = parseSprite(o.getJSONObject("tile")),
                popup = parseSprite(o.getJSONObject("popup")),
            )
        } catch (e: org.json.JSONException) {
            throw SecureKeypadException.protocol("inner json: ${e.message}")
        }

        private fun parseSprite(o: JSONObject) = SpriteInfo(o.getInt("w"), o.getInt("h"), o.getInt("cols"), o.getInt("count"))

        private fun parseLayer(o: JSONObject): LayoutInfo {
            val keys = ArrayList<KeyInfo>()
            val ka: JSONArray = o.getJSONArray("keys")
            for (i in 0 until ka.length()) {
                val k = ka.getJSONObject(i)
                val r = k.getJSONArray("r")
                if (r.length() != 4) throw SecureKeypadException.protocol("rect")
                val role = Role.fromWire(k.getString("role"))
                val tile = if (k.has("t")) k.getInt("t") else -1
                if ((role == Role.CHAR) != (tile >= 0)) throw SecureKeypadException.protocol("tile/role mismatch")
                keys.add(KeyInfo(KeyRect(r.getInt(0), r.getInt(1), r.getInt(2), r.getInt(3)), role, tile))
            }
            return LayoutInfo(o.getInt("id"), o.getString("mode"), if (o.has("lang")) o.getString("lang") else null, keys)
        }
    }
}

/** Decrypted content of a session or relayout response. Sprites are 8-bit grayscale PNG coverage masks. */
class SessionPayload(val layout: KeypadLayout, val tilesPng: ByteArray, val popupsPng: ByteArray)

/** A character tap as recorded by the client: which layer was shown and where the finger landed (device px). */
data class Tap(val layoutId: Int, val x: Int, val y: Int)

/** spec/PROTOCOL.md §10: the key with the smallest squared distance to the point, first wins on ties. */
object HitTest {
    fun nearest(keys: List<KeyInfo>, x: Int, y: Int): KeyInfo? {
        var best: KeyInfo? = null
        var bestD = Long.MAX_VALUE
        for (k in keys) {
            val r = k.rect
            val dx = maxOf(r.x - x, 0, x - (r.right - 1)).toLong()
            val dy = maxOf(r.y - y, 0, y - (r.bottom - 1)).toLong()
            val d = dx * dx + dy * dy
            if (d < bestD) {
                best = k
                bestD = d
            }
        }
        return best
    }
}
