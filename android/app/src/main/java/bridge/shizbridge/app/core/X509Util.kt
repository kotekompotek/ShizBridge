package bridge.shizbridge.app.core

import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

data class ServerIdentity(
    val certificate: X509Certificate,
    val certDer: ByteArray,
    val privateKey: PrivateKey,
)

/**
 * Minimal X.509 v3 writer for self-signed ECDSA P-256 / SHA-256 certificates.
 * Android has no public API for creating certificates, so the DER is assembled
 * here by hand (structure mirrors what openssl/x509.go emits for the Go agent).
 */
object X509Util {

    fun generateSelfSigned(cn: String): ServerIdentity {
        val kp = Crypto.generateEcKeyPair()
        val tbs = derSeq(
            derCtx(0, derInt(BigInteger.valueOf(2))),          // version v3
            derInt(randomSerial()),                            // serialNumber
            algId(),                                           // signature AlgorithmIdentifier
            name(cn),                                          // issuer
            derSeq(utc(Date()), utc(Date(System.currentTimeMillis() + 10L * 365 * 24 * 3600 * 1000))),
            name(cn),                                          // subject
            kp.public.encoded,                                 // subjectPublicKeyInfo (JCA emits correct SPKI)
        )
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(kp.private)
        signer.update(tbs)
        val sig = signer.sign()
        val certDer = derSeq(tbs, algId(), derBitString(sig))
        val cert = parseCert(certDer)
        return ServerIdentity(cert, certDer, kp.private)
    }

    fun parseCert(der: ByteArray): X509Certificate {
        val cf = CertificateFactory.getInstance("X.509")
        return cf.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
    }

    /** SPKI-SHA256, lowercase hex — same as the Go agent's pin format. */
    fun spkiSha256(cert: X509Certificate): String = Crypto.hex(Crypto.sha256(cert.publicKey.encoded))

    fun spkiSha256FromDer(certDer: ByteArray): String = spkiSha256(parseCert(certDer))

    private fun randomSerial(): BigInteger {
        var s = BigInteger(128, java.security.SecureRandom())
        if (s.signum() == 0) s = BigInteger.ONE
        return s
    }

    // ---- DER primitives ----

    private fun algId(): ByteArray = derSeq(derOid(1, 2, 840, 10045, 4, 3, 2)) // ecdsa-with-SHA256

    private fun name(cn: String): ByteArray {
        val atv = derSeq(derOid(2, 5, 4, 3), derUtf8(cn)) // commonName
        return derSeq(derSet(atv))
    }

    private fun utc(d: Date): ByteArray {
        val fmt = SimpleDateFormat("yyMMddHHmmss'Z'", Locale.US)
        fmt.timeZone = TimeZone.getTimeZone("UTC")
        return der(0x17, fmt.format(d).toByteArray(Charsets.US_ASCII))
    }

    internal fun der(tag: Int, content: ByteArray): ByteArray {
        val len = derLen(content.size)
        val out = ByteArray(1 + len.size + content.size)
        out[0] = tag.toByte()
        len.copyInto(out, 1)
        content.copyInto(out, 1 + len.size)
        return out
    }

    private fun derLen(n: Int): ByteArray = when {
        n < 0x80 -> byteArrayOf(n.toByte())
        n < 0x100 -> byteArrayOf(0x81.toByte(), n.toByte())
        n < 0x10000 -> byteArrayOf(0x82.toByte(), (n ushr 8).toByte(), n.toByte())
        else -> byteArrayOf(
            0x83.toByte(), (n ushr 16).toByte(), (n ushr 8).toByte(), n.toByte(),
        )
    }

    internal fun derSeq(vararg parts: ByteArray): ByteArray = der(0x30, concat(*parts))
    internal fun derSet(vararg parts: ByteArray): ByteArray = der(0x31, concat(*parts))
    internal fun derCtx(n: Int, content: ByteArray): ByteArray = der(0xa0 or n, content)

    internal fun derInt(v: BigInteger): ByteArray = der(0x02, v.toByteArray())

    internal fun derBitString(b: ByteArray): ByteArray = der(0x03, byteArrayOf(0) + b)

    internal fun derUtf8(s: String): ByteArray = der(0x0c, s.toByteArray(Charsets.UTF_8))

    internal fun derOctet(b: ByteArray): ByteArray = der(0x04, b)

    internal fun derOid(vararg arcs: Int): ByteArray {
        require(arcs.size >= 2)
        val body = ArrayList<Byte>(8)
        body.add((arcs[0] * 40 + arcs[1]).toByte())
        for (i in 2 until arcs.size) {
            var v = arcs[i]
            require(v >= 0)
            val tmp = ArrayList<Byte>(4)
            tmp.add((v and 0x7f).toByte())
            v = v ushr 7
            while (v > 0) {
                tmp.add((0x80 or (v and 0x7f)).toByte())
                v = v ushr 7
            }
            for (i2 in tmp.size - 1 downTo 0) body.add(tmp[i2])
        }
        return der(0x06, body.toByteArray())
    }

    private fun concat(vararg parts: ByteArray): ByteArray {
        val total = parts.sumOf { it.size }
        val out = ByteArray(total)
        var off = 0
        for (p in parts) {
            p.copyInto(out, off)
            off += p.size
        }
        return out
    }
}
