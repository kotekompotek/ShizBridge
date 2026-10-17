package bridge.shizbridge.app.core

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PublicKey
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** HKDF/HMAC/ECDH/record-layer primitives — mirrors agent/internal/cryptox. */
object Crypto {

    private val random = SecureRandom()

    // ---- HKDF-SHA256 (RFC 5869) ----

    fun hkdfSha256(ikm: ByteArray, salt: ByteArray?, info: ByteArray, length: Int): ByteArray {
        require(length in 1..255 * 32) { "hkdf: invalid length $length" }
        val effSalt = salt ?: ByteArray(32)
        val prk = hmacSha256(effSalt, ikm)
        val out = ByteArray(length)
        var t = ByteArray(0)
        var pos = 0
        var counter = 1
        while (pos < length) {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            mac.update(t)
            mac.update(info)
            mac.update(byteArrayOf(counter.toByte()))
            t = mac.doFinal()
            val take = minOf(t.size, length - pos)
            t.copyInto(out, pos, 0, take)
            pos += take
            counter++
        }
        return out
    }

    fun hmacSha256(key: ByteArray, msg: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(msg)
    }

    fun codeProof(sessionKey: ByteArray, code: String): ByteArray =
        hmacSha256(sessionKey, (Proto.PROOF_LABEL + code).toByteArray(Charsets.UTF_8))

    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)

    // ---- record layer: AES-256-GCM, nonce = dir || be_u64(counter) || 0x000000 ----

    const val DIR_C2S: Byte = 0x01
    const val DIR_S2C: Byte = 0x02

    class RecordCipher(key: ByteArray, private val dir: Byte) {
        private val key = key.copyOf()
        private var ctr = 0L

        private fun nonce(): ByteArray {
            val n = ByteArray(12)
            n[0] = dir
            var v = ctr++
            for (i in 7 downTo 0) {
                n[1 + i] = (v and 0xff).toByte()
                v = v ushr 8
            }
            return n
        }

        private fun cipher(mode: Int, nonce: ByteArray): Cipher {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            return c
        }

        fun seal(plain: ByteArray): ByteArray = cipher(Cipher.ENCRYPT_MODE, nonce()).doFinal(plain)

        fun open(cipherText: ByteArray): ByteArray = cipher(Cipher.DECRYPT_MODE, nonce()).doFinal(cipherText)
    }

    // ---- ECDH P-256 ----

    fun generateEcKeyPair(): KeyPair {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        return kpg.generateKeyPair()
    }

    fun ecdh(priv: java.security.PrivateKey, peerPub: PublicKey): ByteArray {
        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(priv)
        ka.doPhase(peerPub, true) // Android's KeyAgreement has no doFinal(Key)
        return ka.generateSecret()
    }

    /** Uncompressed point encoding 0x04 || X || Y (fixed field size). */
    fun publicKeyRaw(pub: PublicKey): ByteArray {
        val ec = pub as ECPublicKey
        val fieldSize = (ec.params.curve.field.fieldSize + 7) / 8
        val x = ec.w.affineX.toByteArray()
        val y = ec.w.affineY.toByteArray()
        val out = ByteArray(1 + fieldSize * 2)
        out[0] = 0x04
        putFixed(x, out, 1, fieldSize)
        putFixed(y, out, 1 + fieldSize, fieldSize)
        return out
    }

    private fun putFixed(src: ByteArray, dst: ByteArray, off: Int, size: Int) {
        var s = src
        if (s.size > size) {
            // strip leading zero bytes (BigInteger sign)
            val trim = s.size - size
            s = s.copyOfRange(trim, s.size)
        }
        s.copyInto(dst, off + (size - s.size))
    }

    fun parsePublicKeyRaw(raw: ByteArray): PublicKey {
        require(raw.size >= 65 && raw[0] == 0x04.toByte()) { "bad public point" }
        val spec = p256Params()
        val fieldSize = (spec.curve.field.fieldSize + 7) / 8
        val xs = raw.copyOfRange(1, 1 + fieldSize)
        val ys = raw.copyOfRange(1 + fieldSize, 1 + fieldSize * 2)
        val point = ECPoint(BigInteger(1, xs), BigInteger(1, ys))
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, spec))
    }

    private var cachedParams: ECParameterSpec? = null

    fun p256Params(): ECParameterSpec {
        cachedParams?.let { return it }
        val ap = AlgorithmParameters.getInstance("EC")
        ap.init(ECGenParameterSpec("secp256r1"))
        val spec = ap.getParameterSpec(ECParameterSpec::class.java)
        cachedParams = spec
        return spec
    }

    // ---- encoding helpers ----

    fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

    fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

    fun b64(b: ByteArray): String = Base64.getEncoder().encodeToString(b)

    fun b64Decode(s: String): ByteArray = Base64.getDecoder().decode(s)

    fun randomBytes(n: Int): ByteArray = ByteArray(n).also { random.nextBytes(it) }

    fun randomInt(bound: Int): Int = random.nextInt(bound)
}
