package bridge.shizbridge.app.core

/**
 * One-time pairing codes: 12 characters of Crockford base32 (60 bits),
 * alphabet excludes I, L, O, U to avoid transcription errors.
 */
object CodeGen {
    const val ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    const val LENGTH = 12
    const val TTL_MS = 5 * 60 * 1000L
    const val MAX_ATTEMPTS = 3
    const val LOCKOUT_MS = 10 * 60 * 1000L

    fun generate(): String = buildString(LENGTH) {
        repeat(LENGTH) { append(ALPHABET[Crypto.randomInt(ALPHABET.length)]) }
    }

    /** Accepts lowercase and Crockford-confusable input (I/L→1, O→0). */
    fun normalize(raw: String): String = raw.uppercase(java.util.Locale.US)
        .replace("I", "1").replace("L", "1").replace("O", "0")
}
