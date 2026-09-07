package dev.securekeypad.protocol

import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.math.ec.rfc7748.X25519
import org.bouncycastle.math.ec.rfc8032.Ed25519
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * The primitive set of spec/PROTOCOL.md §2, on top of BouncyCastle's lightweight API (no provider
 * registration, works on every Android API level) plus JCA HMAC-SHA256 / SHA-256.
 */
internal object Crypto {
    private val random = SecureRandom()

    fun randomBytes(n: Int): ByteArray = ByteArray(n).also { random.nextBytes(it) }

    /** Returns (privateKey, publicKey). */
    fun x25519KeyPair(): Pair<ByteArray, ByteArray> {
        val sk = ByteArray(32)
        X25519.generatePrivateKey(random, sk)
        return sk to x25519Public(sk)
    }

    fun x25519Public(sk: ByteArray): ByteArray {
        require(sk.size == 32)
        val pk = ByteArray(32)
        X25519.generatePublicKey(sk, 0, pk, 0)
        return pk
    }

    /** Shared secret; rejects the all-zero result produced by low-order points. */
    fun x25519(sk: ByteArray, pk: ByteArray): ByteArray {
        if (sk.size != 32 || pk.size != 32) throw SecureKeypadException.crypto("x25519 key size")
        val ss = ByteArray(32)
        if (!X25519.calculateAgreement(sk, 0, pk, 0, ss, 0)) {
            ss.fill(0)
            throw SecureKeypadException.crypto("x25519 low-order point")
        }
        return ss
    }

    fun ed25519Verify(pk: ByteArray, message: ByteArray, sig: ByteArray): Boolean {
        if (pk.size != 32 || sig.size != 64) return false
        return try {
            Ed25519.verify(sig, 0, pk, 0, message, 0, message.size)
        } catch (e: RuntimeException) {
            false
        }
    }

    fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    private fun hmac(key: ByteArray, vararg parts: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        for (p in parts) mac.update(p)
        return mac.doFinal()
    }

    fun hkdfExtract(salt: ByteArray, ikm: ByteArray): ByteArray = hmac(salt, ikm)

    fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        val out = ByteArray(length)
        var t = ByteArray(0)
        var pos = 0
        var counter = 1
        while (pos < length) {
            t = hmac(prk, t, info, byteArrayOf(counter.toByte()))
            val n = minOf(32, length - pos)
            System.arraycopy(t, 0, out, pos, n)
            pos += n
            counter++
        }
        t.fill(0)
        return out
    }

    /** NONCE(ctr) = 0x00000000 || u64be(ctr). */
    fun nonce(counter: Long): ByteArray = ByteArray(12).also { BE.putU64(it, 4, counter) }

    fun aeadEncrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = ChaCha20Poly1305()
        cipher.init(true, AEADParameters(KeyParameter(key), 128, nonce, aad))
        val out = ByteArray(cipher.getOutputSize(plaintext.size))
        var len = cipher.processBytes(plaintext, 0, plaintext.size, out, 0)
        len += cipher.doFinal(out, len)
        return if (len == out.size) out else out.copyOf(len)
    }

    fun aeadDecrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray {
        if (ciphertext.size < 16) throw SecureKeypadException.badMac()
        val cipher = ChaCha20Poly1305()
        cipher.init(false, AEADParameters(KeyParameter(key), 128, nonce, aad))
        val out = ByteArray(cipher.getOutputSize(ciphertext.size))
        return try {
            var len = cipher.processBytes(ciphertext, 0, ciphertext.size, out, 0)
            len += cipher.doFinal(out, len)
            if (len == out.size) out else out.copyOf(len).also { out.fill(0) }
        } catch (e: InvalidCipherTextException) {
            out.fill(0)
            throw SecureKeypadException.badMac()
        }
    }

    fun wipe(vararg arrays: ByteArray?) {
        for (a in arrays) a?.fill(0)
    }
}
