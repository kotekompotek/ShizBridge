package bridge.shizbridge.app.core

import com.google.gson.Gson
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Cross-language vectors — must match agent/internal/cryptox/testdata/vectors.json
 * asserted by the Go test suite (and RFC 5869 for HKDF).
 */
class CryptoVectorsTest {

    private class Vectors {
        lateinit var hkdf: Hkdf
        lateinit var proof: Proof
        lateinit var record: Rec

        class Hkdf {
            lateinit var ikm_hex: String
            lateinit var salt_hex: String
            lateinit var info: String
            var length: Int = 0
            lateinit var okm_hex: String
        }

        class Proof {
            lateinit var key_hex: String
            lateinit var code: String
            lateinit var proof_hex: String
        }

        class Rec {
            lateinit var key_hex: String
            var dir: Int = 0
            var nonce_ctr: Int = 0
            lateinit var plaintext_hex: String
            lateinit var cipher_hex: String
        }
    }

    private fun vectors(): Vectors {
        val json = checkNotNull(javaClass.classLoader?.getResourceAsStream("vectors.json")) {
            "vectors.json missing from test resources"
        }.use { it.readBytes().decodeToString() }
        return Gson().fromJson(json, Vectors::class.java)
    }

    @Test
    fun hkdfMatchesGoReference() {
        val v = vectors().hkdf
        val okm = Crypto.hkdfSha256(
            unhex(v.ikm_hex), unhex(v.salt_hex), v.info.toByteArray(Charsets.UTF_8), v.length,
        )
        assertEquals(v.okm_hex, hex(okm))
    }

    @Test
    fun codeProofMatchesGoReference() {
        val v = vectors().proof
        val proof = Crypto.codeProof(unhex(v.key_hex), v.code)
        assertEquals(v.proof_hex, hex(proof))
    }

    @Test
    fun recordCipherMatchesGoReference() {
        val v = vectors().record
        val s = Crypto.RecordCipher(unhex(v.key_hex), v.dir.toByte())
        // Position the counter at nonce_ctr (nonce depends only on the counter).
        repeat(v.nonce_ctr) { s.seal(ByteArray(0)) }
        assertEquals(v.cipher_hex, hex(s.seal(unhex(v.plaintext_hex))))
    }

    @Test
    fun recordOpenRoundTrip() {
        val key = Crypto.randomBytes(32)
        val sealer = Crypto.RecordCipher(key, Crypto.DIR_C2S)
        val opener = Crypto.RecordCipher(key, Crypto.DIR_C2S)
        val msg = "hello shizbridge".toByteArray()
        repeat(3) {
            val ct = sealer.seal(msg)
            assertTrue(ct.size == msg.size + 16)
            assertEquals(String(msg), String(opener.open(ct)))
        }
    }

    @Test
    fun recordDirectionSeparatesNonces() {
        val key = Crypto.randomBytes(32)
        val c2s = Crypto.RecordCipher(key, Crypto.DIR_C2S)
        val s2c = Crypto.RecordCipher(key, Crypto.DIR_S2C)
        val msg = "same message".toByteArray()
        // Same counter, different direction → different ciphertext (GCM nonce differs)
        assertTrue(hex(c2s.seal(msg)) != hex(s2c.seal(msg)))
    }

    @Test
    fun hkdfRfc5869Case1() {
        val okm = Crypto.hkdfSha256(
            ByteArray(22) { 0x0b.toByte() },
            byteArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12),
            byteArrayOf(0xf0.toByte(), 0xf1.toByte(), 0xf2.toByte(), 0xf3.toByte(), 0xf4.toByte(), 0xf5.toByte(), 0xf6.toByte(), 0xf7.toByte(), 0xf8.toByte(), 0xf9.toByte()),
            42,
        )
        assertEquals(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            hex(okm),
        )
    }

    private fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

    private fun unhex(s: String): ByteArray {
        val clean = s.trim()
        val out = ByteArray(clean.length / 2)
        for (i in out.indices) {
            out[i] = clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
        return out
    }
}
