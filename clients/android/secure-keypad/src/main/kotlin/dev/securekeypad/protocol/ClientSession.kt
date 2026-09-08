package dev.securekeypad.protocol

import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject

/** What the client reports about its surface (spec §4.1). Width in logical units, dpr = density. */
data class Viewport(val w: Double, val dpr: Double, val platform: String = "android", val style: String? = null) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("w", w)
        put("dpr", dpr)
        put("platform", platform)
        if (style != null) put("style", style)
    }
}

private const val LABEL_SALT = "skp/v1"
private const val AAD_SESSION = "skp/v1/session"
private const val AAD_RELAYOUT = "skp/v1/relayout"
private const val AAD_INPUT = "skp/v1/input"
private const val SIG_LABEL = "skp/v1/session"

/**
 * Client side of one session establishment: holds the ephemeral X25519 key until the response is opened.
 * Pure JVM; no Android types.
 */
class ClientSession private constructor(private var privateKey: ByteArray?, val publicKey: ByteArray) {

    companion object {
        fun create(): ClientSession {
            val (sk, pk) = Crypto.x25519KeyPair()
            return ClientSession(sk, pk)
        }

        /** Test hook: build from a known private key. */
        fun fromPrivateKey(sk: ByteArray): ClientSession = ClientSession(sk.copyOf(), Crypto.x25519Public(sk))
    }

    /**
     * The session creation request (spec §4.1). [languages] asks for keyboard languages in switch order
     * (the server may override it; the default is en + ko).
     */
    fun requestJson(type: KeypadType, viewport: Viewport, maxLen: Int? = null, languages: List<String>? = null): String {
        val o = JSONObject()
        o.put("v", 1)
        o.put("kp", B64.encode(publicKey))
        o.put("type", type.wire)
        o.put("viewport", viewport.toJson())
        val opts = JSONObject()
        if (maxLen != null) opts.put("maxLen", maxLen)
        if (!languages.isNullOrEmpty() && type == KeypadType.QWERTY) opts.put("langs", JSONArray(languages))
        if (opts.length() > 0) o.put("opts", opts)
        return o.toString()
    }

    /**
     * Verifies (when [serverPublicKey] is given), derives the session keys, decrypts the inner frame and
     * wipes the ephemeral private key. Can be called once.
     */
    fun open(responseJson: String, serverPublicKey: ByteArray?): OpenedSession {
        val sk = privateKey ?: throw SecureKeypadException.state("session already opened")
        val o = try {
            JSONObject(responseJson)
        } catch (e: JSONException) {
            throw SecureKeypadException.protocol("response json")
        }
        if (o.optInt("v", 0) != 1) throw SecureKeypadException.protocol("response version")
        val kid = o.optString("kid", "")
        if (kid.length != 8) throw SecureKeypadException.protocol("kid")
        val sid = B64.decodeUrl(o.getString("sid"))
        val sp = B64.decode(o.getString("sp"))
        val sig = B64.decode(o.getString("sig"))
        val ct = B64.decode(o.getString("ct"))
        if (sid.size != 16 || sp.size != 32 || sig.size != 64) throw SecureKeypadException.protocol("field sizes")
        if (serverPublicKey != null) {
            val msg = SIG_LABEL.toByteArray(Charsets.US_ASCII) + kid.toByteArray(Charsets.US_ASCII) + sid +
                publicKey + sp + Crypto.sha256(ct)
            if (!Crypto.ed25519Verify(serverPublicKey, msg, sig)) throw SecureKeypadException.signature()
        }
        val ss = Crypto.x25519(sk, sp)
        val prk = Crypto.hkdfExtract(LABEL_SALT.toByteArray(Charsets.US_ASCII) + sid, ss)
        val kS2c = Crypto.hkdfExpand(prk, "s2c".toByteArray(Charsets.US_ASCII) + publicKey + sp, 32)
        val kC2s = Crypto.hkdfExpand(prk, "c2s".toByteArray(Charsets.US_ASCII) + publicKey + sp, 32)
        Crypto.wipe(sk, ss, prk)
        privateKey = null
        val plain = try {
            Crypto.aeadDecrypt(kS2c, Crypto.nonce(0), AAD_SESSION.toByteArray(Charsets.US_ASCII) + sid, ct)
        } catch (e: SecureKeypadException) {
            Crypto.wipe(kS2c, kC2s)
            throw e
        }
        val payload = Frame.parse(plain)
        plain.fill(0)
        return OpenedSession(sid, kid, kS2c, kC2s, payload)
    }

    fun wipe() {
        privateKey?.fill(0)
        privateKey = null
    }
}

/** Inner frame: u32 len | json | u32 len | tiles png | u32 len | popups png (big-endian). */
internal object Frame {
    fun parse(buf: ByteArray): SessionPayload {
        var pos = 0
        val parts = ArrayList<ByteArray>(3)
        repeat(3) {
            if (pos + 4 > buf.size) throw SecureKeypadException.protocol("frame")
            val n = BE.u32(buf, pos)
            pos += 4
            if (n < 0 || pos + n > buf.size) throw SecureKeypadException.protocol("frame length")
            parts.add(buf.copyOfRange(pos, pos + n.toInt()))
            pos += n.toInt()
        }
        if (pos != buf.size) throw SecureKeypadException.protocol("frame trailing bytes")
        val layout = KeypadLayout.parse(String(parts[0], Charsets.UTF_8))
        return SessionPayload(layout, parts[1], parts[2])
    }
}

/**
 * An established session: keys, counters, and the input batch builder. [consume] wipes the keys.
 */
class OpenedSession internal constructor(
    val sid: ByteArray,
    val kid: String,
    private var kS2c: ByteArray?,
    private var kC2s: ByteArray?,
    val initial: SessionPayload,
) {
    /** Next server→client counter (0 was the session response). */
    var s2cCounter: Long = 1
        private set

    val sidUrl: String get() = B64.encodeUrl(sid)
    val isConsumed: Boolean get() = kC2s == null

    /** Test hook. */
    fun keysForTest(): Pair<ByteArray, ByteArray> = Pair(kS2c!!.copyOf(), kC2s!!.copyOf())

    fun relayoutRequestJson(viewport: Viewport): String =
        JSONObject().put("v", 1).put("sid", sidUrl).put("viewport", viewport.toJson()).toString()

    /** Opens a relayout response with the next s2c counter (spec §6). */
    fun openRelayout(responseJson: String): SessionPayload {
        val key = kS2c ?: throw SecureKeypadException.state("session consumed")
        val o = try {
            JSONObject(responseJson)
        } catch (e: JSONException) {
            throw SecureKeypadException.protocol("relayout json")
        }
        if (o.optInt("v", 0) != 1) throw SecureKeypadException.protocol("relayout version")
        if (!B64.decodeUrl(o.getString("sid")).contentEquals(sid)) throw SecureKeypadException.protocol("relayout sid")
        val ct = B64.decode(o.getString("ct"))
        val plain = Crypto.aeadDecrypt(key, Crypto.nonce(s2cCounter), AAD_RELAYOUT.toByteArray(Charsets.US_ASCII) + sid, ct)
        s2cCounter++
        val payload = Frame.parse(plain)
        plain.fill(0)
        if (payload.layout.gen != o.optInt("gen", -1)) throw SecureKeypadException.protocol("relayout gen")
        return payload
    }

    /**
     * Builds the encrypted input payload (spec §7) and consumes the session: both keys are wiped, so the
     * result can be produced exactly once.
     */
    fun buildInput(maxLen: Int, taps: List<Tap>): String {
        val key = kC2s ?: throw SecureKeypadException.state("session consumed")
        if (taps.size > maxLen) throw SecureKeypadException.state("too many taps")
        val batch = ByteArray(4 + 8 * maxLen)
        batch[0] = 1
        batch[1] = 0
        BE.putU16(batch, 2, taps.size)
        for ((i, t) in taps.withIndex()) {
            val off = 4 + 8 * i
            BE.putU16(batch, off, i)
            batch[off + 2] = t.layoutId.toByte()
            batch[off + 3] = 0
            BE.putU16(batch, off + 4, t.x)
            BE.putU16(batch, off + 6, t.y)
        }
        val ct = Crypto.aeadEncrypt(key, Crypto.nonce(0), AAD_INPUT.toByteArray(Charsets.US_ASCII) + sid, batch)
        batch.fill(0)
        consume()
        return JSONObject().put("v", 1).put("sid", sidUrl).put("ct", B64.encode(ct)).toString()
    }

    fun consume() {
        Crypto.wipe(kS2c, kC2s)
        kS2c = null
        kC2s = null
    }
}
