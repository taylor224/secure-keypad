package dev.securekeypad

import dev.securekeypad.protocol.B64
import dev.securekeypad.protocol.ClientSession
import dev.securekeypad.protocol.HitTest
import dev.securekeypad.protocol.KeyInfo
import dev.securekeypad.protocol.KeyRect
import dev.securekeypad.protocol.KeypadLayout
import dev.securekeypad.protocol.Role
import dev.securekeypad.protocol.SecureKeypadException
import dev.securekeypad.protocol.Tap
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File

/** Replays every JSON vector in spec/vectors: the client side must reproduce every byte the reference produced. */
class VectorsTest {

    private fun vectorsDir(): File {
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        while (dir != null) {
            val candidate = File(dir, "spec/vectors")
            if (candidate.isDirectory) return candidate
            dir = dir.parentFile
        }
        throw IllegalStateException("spec/vectors not found above ${System.getProperty("user.dir")}")
    }

    private fun hex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
    private fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

    private fun vectors(): List<JSONObject> {
        val files = vectorsDir().listFiles { f -> f.name.endsWith(".json") }!!.sortedBy { it.name }
        assertTrue("no vectors found", files.isNotEmpty())
        return files.map { JSONObject(it.readText()) }
    }

    private fun taps(arr: org.json.JSONArray): List<Tap> = (0 until arr.length()).map {
        val t = arr.getJSONArray(it)
        Tap(t.getInt(0), t.getInt(1), t.getInt(2))
    }

    @Test
    fun everyVectorRoundTrips() {
        var n = 0
        for (v in vectors()) {
            n++
            val name = v.getString("name")
            val client = ClientSession.fromPrivateKey(hex(v.getString("client_sk")))
            assertEquals("$name kp", v.getJSONObject("request").getString("kp"), B64.encode(client.publicKey))
            val expect = v.getJSONObject("expect_session")
            val pk = hex(v.getJSONObject("expect_master").getString("pk_sign"))
            val opened = client.open(expect.getJSONObject("response").toString(), pk)
            val (s2c, c2s) = opened.keysForTest()
            assertEquals("$name k_s2c", expect.getString("k_s2c"), hex(s2c))
            assertEquals("$name k_c2s", expect.getString("k_c2s"), hex(c2s))
            assertEquals("$name kid", expect.getJSONObject("response").getString("kid"), opened.kid)
            val innerExpected = JSONObject(expect.getString("inner_json"))
            val innerGot = JSONObject(reserialize(opened.initial.layout))
            assertTrue("$name inner json differs", jsonEquals(innerExpected, innerGot))
            assertEquals("$name empty sprites in vectors", 0, opened.initial.tilesPng.size)
            var maxLen = opened.initial.layout.maxLen
            if (v.has("relayout")) {
                val rl = v.getJSONObject("relayout")
                val payload = opened.openRelayout(rl.getJSONObject("expect").getJSONObject("response").toString())
                val rlExpected = JSONObject(rl.getJSONObject("expect").getString("inner_json"))
                assertTrue("$name relayout inner json differs", jsonEquals(rlExpected, JSONObject(reserialize(payload.layout))))
                assertEquals(1, payload.layout.gen)
                assertEquals(2L, opened.s2cCounter)
                maxLen = payload.layout.maxLen
            }
            val input = v.getJSONObject("input")
            val payload = JSONObject(opened.buildInput(maxLen, taps(input.getJSONArray("taps"))))
            val expectedPayload = input.getJSONObject("payload")
            assertEquals("$name payload ct", expectedPayload.getString("ct"), payload.getString("ct"))
            assertEquals("$name payload sid", expectedPayload.getString("sid"), payload.getString("sid"))
            assertEquals(1, payload.getInt("v"))
            assertTrue(opened.isConsumed)
            try {
                opened.buildInput(maxLen, emptyList())
                fail("second buildInput must fail")
            } catch (e: SecureKeypadException) {
                assertEquals("STATE", e.code)
            }
        }
        assertEquals(11, n)
    }

    @Test
    fun languageLayersAndLangKeyAreParsed() {
        val v = vectors().first { it.getString("name") == "qwerty-ios-390x3-ko-en-shuffle" }
        val client = ClientSession.fromPrivateKey(hex(v.getString("client_sk")))
        val opened = client.open(v.getJSONObject("expect_session").getJSONObject("response").toString(), null)
        val layout = opened.initial.layout
        assertEquals(listOf("ko", "en"), layout.langs)
        assertEquals(listOf("ko", "ko", "en", "en", null, null), layout.layouts.map { it.lang })
        assertEquals(listOf("lower", "upper", "lower", "upper", "sym1", "sym2"), layout.layouts.map { it.mode })
        assertEquals(2, layout.layer("lower", "en")!!.id)
        assertEquals(0, layout.layer("lower")!!.id)
        for (l in layout.layouts) assertEquals("one lang key per layer", 1, l.keys.count { it.role == Role.LANG })
        // the request carries the languages the client asked for
        val request = v.getJSONObject("request")
        val vp = request.getJSONObject("viewport")
        val json = JSONObject(client.requestJson(dev.securekeypad.protocol.KeypadType.QWERTY,
            dev.securekeypad.protocol.Viewport(vp.getDouble("w"), vp.getDouble("dpr"), vp.getString("platform")),
            request.getJSONObject("opts").getInt("maxLen"), listOf("ko", "en")))
        assertEquals(request.getJSONObject("opts").getJSONArray("langs").toString(), json.getJSONObject("opts").getJSONArray("langs").toString())
        // English-only vectors have no lang key and no languages beyond en
        val en = vectors().first { it.getString("name") == "qwerty-ios-390x3-shuffle" }
        val l2 = ClientSession.fromPrivateKey(hex(en.getString("client_sk")))
            .open(en.getJSONObject("expect_session").getJSONObject("response").toString(), null).initial.layout
        assertEquals(listOf("en"), l2.langs)
        assertTrue(l2.layouts.none { l -> l.keys.any { it.role == Role.LANG } })
    }

    /** Structural JSON equality (org.json on Android has no `similar`). */
    private fun jsonEquals(a: Any?, b: Any?): Boolean = when {
        a is JSONObject && b is JSONObject -> {
            val ka = a.keys().asSequence().toSet()
            val kb = b.keys().asSequence().toSet()
            ka == kb && ka.all { jsonEquals(a.get(it), b.get(it)) }
        }
        a is org.json.JSONArray && b is org.json.JSONArray ->
            a.length() == b.length() && (0 until a.length()).all { jsonEquals(a.get(it), b.get(it)) }
        a is Number && b is Number -> a.toDouble() == b.toDouble()
        else -> a == b
    }

    /** Re-serialises the parsed layout in canonical field order so it can be compared with the vector. */
    private fun reserialize(l: KeypadLayout): String {
        val o = JSONObject()
        o.put("v", l.version)
        o.put("type", l.type.wire)
        o.put("style", l.style)
        o.put("w", l.w)
        o.put("h", l.h)
        o.put("gen", l.gen)
        o.put("maxLen", l.maxLen)
        o.put("exp", l.expSeconds)
        o.put("langs", org.json.JSONArray(l.langs))
        val layouts = org.json.JSONArray()
        for (layer in l.layouts) {
            val lo = JSONObject().put("id", layer.id).put("mode", layer.mode)
            if (layer.lang != null) lo.put("lang", layer.lang)
            val keys = org.json.JSONArray()
            for (k in layer.keys) {
                val ko = JSONObject()
                ko.put("r", org.json.JSONArray(listOf(k.rect.x, k.rect.y, k.rect.w, k.rect.h)))
                ko.put("role", k.role.wire)
                if (k.role == Role.CHAR) ko.put("t", k.tile)
                keys.put(ko)
            }
            lo.put("keys", keys)
            layouts.put(lo)
        }
        o.put("layouts", layouts)
        o.put("tile", JSONObject().put("w", l.tile.w).put("h", l.tile.h).put("cols", l.tile.cols).put("count", l.tile.count))
        o.put("popup", JSONObject().put("w", l.popup.w).put("h", l.popup.h).put("cols", l.popup.cols).put("count", l.popup.count))
        return o.toString()
    }

    @Test
    fun tamperedSignatureIsRejected() {
        val v = vectors().first()
        val client = ClientSession.fromPrivateKey(hex(v.getString("client_sk")))
        val resp = v.getJSONObject("expect_session").getJSONObject("response")
        val pk = hex(v.getJSONObject("expect_master").getString("pk_sign"))
        val forged = JSONObject(resp.toString()).put("sig", B64.encode(ByteArray(64)))
        try {
            client.open(forged.toString(), pk)
            fail("forged signature accepted")
        } catch (e: SecureKeypadException) {
            assertEquals("BAD_SIGNATURE", e.code)
        }
        // wrong pinned key
        val client2 = ClientSession.fromPrivateKey(hex(v.getString("client_sk")))
        try {
            client2.open(resp.toString(), ByteArray(32) { 7 })
            fail("wrong key accepted")
        } catch (e: SecureKeypadException) {
            assertEquals("BAD_SIGNATURE", e.code)
        }
        // unpinned: accepted, but a flipped ciphertext bit fails authentication
        val client3 = ClientSession.fromPrivateKey(hex(v.getString("client_sk")))
        val ct = B64.decode(resp.getString("ct"))
        ct[5] = (ct[5].toInt() xor 1).toByte()
        try {
            client3.open(JSONObject(resp.toString()).put("ct", B64.encode(ct)).toString(), null)
            fail("tampered ciphertext accepted")
        } catch (e: SecureKeypadException) {
            assertEquals("BAD_MAC", e.code)
        }
    }

    @Test
    fun gapTapsHitTheNearestKey() {
        val v = vectors().first { it.getString("name") == "qwerty-web-ios-style-375x2-gaps" }
        val client = ClientSession.fromPrivateKey(hex(v.getString("client_sk")))
        val opened = client.open(v.getJSONObject("expect_session").getJSONObject("response").toString(), null)
        // the vector's taps sit 25 px above the key centres, inside the row gap
        for (t in taps(v.getJSONObject("input").getJSONArray("taps"))) {
            val layer = opened.initial.layout.layouts.first { it.id == t.layoutId }
            val hit = HitTest.nearest(layer.keys, t.x, t.y)!!
            val centred = HitTest.nearest(layer.keys, t.x, t.y + 25)!!
            assertSame(centred, hit)
            assertEquals(Role.CHAR, hit.role)
        }
    }

    @Test
    fun hitTestSpecCases() {
        val a = KeyInfo(KeyRect(0, 0, 10, 10), Role.CHAR, 0)
        val b = KeyInfo(KeyRect(13, 0, 10, 10), Role.CHAR, 1) // gap covers x = 10, 11, 12
        val keys = listOf(a, b)
        assertSame(a, HitTest.nearest(keys, 5, 5))
        assertSame(b, HitTest.nearest(keys, 13, 0))
        assertSame(a, HitTest.nearest(keys, 10, 3)) // gap, nearer to a (1 vs 3)
        assertSame(b, HitTest.nearest(keys, 12, 3)) // gap, nearer to b (3 vs 1)
        assertSame(a, HitTest.nearest(keys, 11, 3)) // tie (2 vs 2) → first listed
        assertSame(a, HitTest.nearest(keys, 3, 40)) // below both, nearer to a
        assertEquals(null, HitTest.nearest(emptyList(), 1, 1))
    }

    @Test
    fun base64Codec() {
        val data = ByteArray(40) { (it * 7).toByte() }
        assertEquals(data.toList(), B64.decode(B64.encode(data)).toList())
        assertEquals(data.toList(), B64.decodeUrl(B64.encodeUrl(data)).toList())
        assertEquals("AAAAAAAAAAAAAAAAAAAAAA", B64.encodeUrl(ByteArray(16)))
        assertEquals("AQID", B64.encode(byteArrayOf(1, 2, 3)))
        assertEquals("AQI=", B64.encode(byteArrayOf(1, 2)))
        for (bad in listOf("AQI", "AQ=", "A===", "@@@@")) {
            try {
                B64.decode(bad)
                fail("accepted $bad")
            } catch (e: SecureKeypadException) {
                assertEquals("PROTOCOL", e.code)
            }
        }
    }

    @Test
    fun batchIsPaddedToMaxLen() {
        val v = vectors().first { it.getString("name").startsWith("number-ios") }
        val client = ClientSession.fromPrivateKey(hex(v.getString("client_sk")))
        val opened = client.open(v.getJSONObject("expect_session").getJSONObject("response").toString(), null)
        val maxLen = opened.initial.layout.maxLen
        val payload = JSONObject(opened.buildInput(maxLen, listOf(Tap(32, 5, 5))))
        val ct = B64.decode(payload.getString("ct"))
        assertEquals(4 + 8 * maxLen + 16, ct.size)
        assertNotNull(payload.getString("sid"))
    }
}
