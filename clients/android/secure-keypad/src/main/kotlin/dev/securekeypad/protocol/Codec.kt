package dev.securekeypad.protocol

/**
 * Base64 without java.util.Base64 (API 26+) or android.util.Base64 (not usable in JVM unit tests).
 * Standard alphabet with padding (RFC 4648 §4) and URL-safe without padding (§5), strict decoding.
 */
object B64 {
    private const val STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    private const val URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

    fun encode(data: ByteArray): String = encode(data, STD, pad = true)
    fun encodeUrl(data: ByteArray): String = encode(data, URL, pad = false)
    fun decode(text: String): ByteArray = decode(text, STD, padded = true)
    fun decodeUrl(text: String): ByteArray = decode(text, URL, padded = false)

    private fun encode(data: ByteArray, alphabet: String, pad: Boolean): String {
        val sb = StringBuilder((data.size + 2) / 3 * 4)
        var i = 0
        while (i < data.size) {
            val b0 = data[i].toInt() and 0xff
            val b1 = if (i + 1 < data.size) data[i + 1].toInt() and 0xff else -1
            val b2 = if (i + 2 < data.size) data[i + 2].toInt() and 0xff else -1
            sb.append(alphabet[b0 shr 2])
            sb.append(alphabet[((b0 and 3) shl 4) or (if (b1 < 0) 0 else b1 shr 4)])
            if (b1 < 0) {
                if (pad) sb.append("==")
            } else {
                sb.append(alphabet[((b1 and 15) shl 2) or (if (b2 < 0) 0 else b2 shr 6)])
                if (b2 < 0) {
                    if (pad) sb.append('=')
                } else {
                    sb.append(alphabet[b2 and 63])
                }
            }
            i += 3
        }
        return sb.toString()
    }

    private fun decode(text: String, alphabet: String, padded: Boolean): ByteArray {
        var s = text
        if (padded) {
            if (s.length % 4 != 0) throw SecureKeypadException.protocol("base64 length")
            s = s.trimEnd('=')
            if (text.length - s.length > 2) throw SecureKeypadException.protocol("base64 padding")
        } else if (s.contains('=')) {
            throw SecureKeypadException.protocol("base64url must not be padded")
        }
        val rem = s.length % 4
        if (rem == 1) throw SecureKeypadException.protocol("base64 length")
        val out = ByteArray(s.length * 3 / 4)
        var acc = 0
        var bits = 0
        var o = 0
        for (c in s) {
            val v = alphabet.indexOf(c)
            if (v < 0) throw SecureKeypadException.protocol("base64 alphabet")
            acc = (acc shl 6) or v
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out[o++] = ((acc shr bits) and 0xff).toByte()
            }
        }
        if (bits >= 6 || (acc and ((1 shl bits) - 1)) != 0) throw SecureKeypadException.protocol("base64 trailing bits")
        return if (o == out.size) out else out.copyOf(o)
    }
}

/** Big-endian helpers. */
internal object BE {
    fun u16(b: ByteArray, off: Int): Int = ((b[off].toInt() and 0xff) shl 8) or (b[off + 1].toInt() and 0xff)
    fun u32(b: ByteArray, off: Int): Long =
        ((b[off].toLong() and 0xff) shl 24) or ((b[off + 1].toLong() and 0xff) shl 16) or
            ((b[off + 2].toLong() and 0xff) shl 8) or (b[off + 3].toLong() and 0xff)

    fun putU16(b: ByteArray, off: Int, v: Int) {
        b[off] = (v shr 8).toByte()
        b[off + 1] = v.toByte()
    }

    fun putU64(b: ByteArray, off: Int, v: Long) {
        for (i in 0 until 8) b[off + i] = (v shr (56 - 8 * i)).toByte()
    }
}
