package dev.securekeypad.protocol

/** Every failure surfaces as this exception. Codes are stable strings; messages never contain secrets. */
class SecureKeypadException(val code: String, message: String) : Exception("$code: $message") {
    companion object {
        fun protocol(detail: String) = SecureKeypadException("PROTOCOL", detail)
        fun crypto(detail: String) = SecureKeypadException("CRYPTO", detail)
        fun signature() = SecureKeypadException("BAD_SIGNATURE", "server signature does not verify")
        fun badMac() = SecureKeypadException("BAD_MAC", "authentication failed")
        fun state(detail: String) = SecureKeypadException("STATE", detail)
        fun network(detail: String) = SecureKeypadException("NETWORK", detail)
        fun expired() = SecureKeypadException("EXPIRED", "session expired")
    }
}
