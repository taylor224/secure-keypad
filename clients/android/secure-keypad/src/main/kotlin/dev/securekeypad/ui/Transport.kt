package dev.securekeypad.ui

import dev.securekeypad.protocol.SecureKeypadException
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

/** Blocking JSON POST. Implement to route through your own HTTP stack (OkHttp, certificate pinning, auth). */
fun interface Transport {
    @Throws(SecureKeypadException::class)
    fun post(url: String, jsonBody: String, headers: Map<String, String>): String
}

/** Default transport on `HttpURLConnection`; no third-party dependency. */
class HttpUrlConnectionTransport(
    private val connectTimeoutMs: Int = 10_000,
    private val readTimeoutMs: Int = 15_000,
) : Transport {
    override fun post(url: String, jsonBody: String, headers: Map<String, String>): String {
        val conn = try {
            URL(url).openConnection() as HttpURLConnection
        } catch (e: IOException) {
            throw SecureKeypadException.network("open: ${e.message}")
        }
        try {
            conn.requestMethod = "POST"
            conn.connectTimeout = connectTimeoutMs
            conn.readTimeout = readTimeoutMs
            conn.doOutput = true
            conn.useCaches = false
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8")
            conn.setRequestProperty("Accept", "application/json")
            conn.setRequestProperty("Cache-Control", "no-store")
            for ((k, v) in headers) conn.setRequestProperty(k, v)
            conn.outputStream.use { it.write(jsonBody.toByteArray(Charsets.UTF_8)) }
            val code = conn.responseCode
            if (code !in 200..299) throw SecureKeypadException.network("http $code")
            return conn.inputStream.use { String(it.readBytes(), Charsets.UTF_8) }
        } catch (e: IOException) {
            throw SecureKeypadException.network(e.message ?: "io")
        } finally {
            conn.disconnect()
        }
    }
}
