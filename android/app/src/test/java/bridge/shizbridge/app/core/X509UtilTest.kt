package bridge.shizbridge.app.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.Signature

class X509UtilTest {

    @Test
    fun generatesParsableSelfSignedCert() {
        val id = X509Util.generateSelfSigned("ShizBridge test")
        // Parser inside generateSelfSigned already accepted it; re-parse to be sure.
        val cert = X509Util.parseCert(id.certDer)
        assertEquals("ShizBridge test", cert.subjectX500Principal.name.removePrefix("CN="))
        assertTrue(cert.notAfter.time > System.currentTimeMillis())
        assertTrue(cert.notBefore.time <= System.currentTimeMillis() + 60_000)
    }

    @Test
    fun certificateSignatureVerifies() {
        val id = X509Util.generateSelfSigned("sig-test")
        id.certificate.verify(id.certificate.publicKey) // throws on failure
    }

    @Test
    fun spkiFingerprintFormatMatchesGo() {
        val id = X509Util.generateSelfSigned("fp-test")
        val fp = X509Util.spkiSha256(id.certificate)
        assertEquals(64, fp.length)
        assertTrue(fp.all { it in "0123456789abcdef" })
        // Same value when derived from DER
        assertEquals(fp, X509Util.spkiSha256FromDer(id.certDer))
    }

    @Test
    fun identityRoundTripsThroughPkcs8() {
        val id = X509Util.generateSelfSigned("roundtrip")
        val key = java.security.KeyFactory.getInstance("EC")
            .generatePrivate(java.security.spec.PKCS8EncodedKeySpec(id.privateKey.encoded))
        val cert = X509Util.parseCert(id.certDer)
        // Key still matches the certificate
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(key)
        sig.update("payload".toByteArray())
        val der = sig.sign()
        sig.initVerify(cert.publicKey)
        sig.update("payload".toByteArray())
        assertTrue(sig.verify(der))
    }

    @Test
    fun ecdhRoundTrip() {
        val a = Crypto.generateEcKeyPair()
        val b = Crypto.generateEcKeyPair()
        val s1 = Crypto.ecdh(a.private, Crypto.parsePublicKeyRaw(Crypto.publicKeyRaw(b.public)))
        val s2 = Crypto.ecdh(b.private, Crypto.parsePublicKeyRaw(Crypto.publicKeyRaw(a.public)))
        assertTrue(s1.contentEquals(s2))
    }

    @Test
    fun publicKeyRawEncodingIsUncompressed() {
        val kp = Crypto.generateEcKeyPair()
        val raw = Crypto.publicKeyRaw(kp.public)
        assertEquals(65, raw.size)
        assertEquals(0x04, raw[0].toInt())
    }
}
