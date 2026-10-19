package bridge.shizbridge.app.core

import android.content.Context
import java.io.EOFException
import java.io.InputStream
import java.io.PushbackInputStream
import java.net.Socket
import java.security.KeyFactory
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLException
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509KeyManager
import javax.net.ssl.X509TrustManager

/**
 * Phone-side server: one TLS port serves pairing (SBPR), the control
 * channel (SBCTL) and the raw ADB relay. Mirrors the Go reference
 * implementation in agent/internal/cryptox.
 */
class BridgeEngine(context: Context) {

    interface Listener {
        fun onLog(line: String)
        fun onStateChanged()
        fun onCodeChanged()
        fun onAllowlistChanged()
        fun onStatsChanged()
    }

    data class PairCode(val code: String, val expiresAt: Long)

    private val appContext = context.applicationContext
    val prefs = Prefs(context)

    @Volatile
    var running = false
        private set

    @Volatile
    var currentCode: PairCode? = null
        private set

    var serverIdentity: ServerIdentity? = null
        private set

    val activeRelays = AtomicInteger(0)
    val acceptedSessions = AtomicInteger(0)

    private val listeners = CopyOnWriteArrayList<Listener>()
    private val logRing = ArrayDeque<String>()
    private val timeFmt = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US)
    private val pool = Executors.newCachedThreadPool { r ->
        Thread(r, "bridge-io").apply { isDaemon = true }
    }
    private val trustCapture = CapturingTrustManager()
    private var sslContext: SSLContext? = null
    private var serverSocket: SSLServerSocket? = null
    private var acceptThread: Thread? = null

    // ---- listeners ----

    fun addListener(l: Listener) { listeners.addIfAbsent(l) }
    fun removeListener(l: Listener) { listeners.remove(l) }

    private fun log(line: String) {
        val stamped = synchronized(this) {
            val s = "${timeFmt.format(java.util.Date())} $line"
            logRing.addLast(s)
            while (logRing.size > 200) logRing.removeFirst()
            s
        }
        listeners.forEach { it.onLog(stamped) }
    }

    fun recentLogs(): List<String> = synchronized(this) { logRing.toList() }
    private fun emitState() = listeners.forEach { it.onStateChanged() }
    private fun emitCode() = listeners.forEach { it.onCodeChanged() }
    private fun emitAllow() = listeners.forEach { it.onAllowlistChanged() }
    private fun emitStats() = listeners.forEach { it.onStatsChanged() }

    // ---- lifecycle ----

    @Synchronized
    fun start(): Boolean {
        if (running) return true
        return try {
            val ident = loadOrCreateIdentity()
            serverIdentity = ident
            val ctx = SSLContext.getInstance("TLS")
            ctx.init(arrayOf(IdentityKeyManager(ident)), arrayOf(trustCapture), SecureRandom())
            sslContext = ctx
            val ss = ctx.serverSocketFactory.createServerSocket(prefs.listenPort) as SSLServerSocket
            ss.needClientAuth = true
            ss.enabledProtocols = ss.supportedProtocols.filter {
                it == "TLSv1.3" || it == "TLSv1.2"
            }.toTypedArray()
            serverSocket = ss
            currentCode = PairCode(CodeGen.generate(), System.currentTimeMillis() + CodeGen.TTL_MS)
            running = true
            acceptThread = Thread({ acceptLoop() }, "bridge-accept").apply {
                isDaemon = true
                start()
            }
            log("server listening on :${prefs.listenPort} (TLS, client cert required)")
            log("server identity ${X509Util.spkiSha256(ident.certificate).take(16)}…")
            emitState()
            emitCode()
            true
        } catch (e: Exception) {
            log("start failed: ${e.message}")
            stop()
            false
        }
    }

    @Synchronized
    fun stop() {
        val was = running
        running = false
        try { serverSocket?.close() } catch (_: Exception) {}
        serverSocket = null
        acceptThread = null
        if (was) {
            log("server stopped")
            emitState()
        }
        currentCode = null
        emitCode()
    }

    fun newCode() {
        currentCode = PairCode(CodeGen.generate(), System.currentTimeMillis() + CodeGen.TTL_MS)
        prefs.clearLockout()
        log("new pairing code generated")
        emitCode()
    }

    fun revoke(spki: String) {
        prefs.revoke(spki)
        log("revoked client ${spki.take(16)}…")
        emitAllow()
    }

    fun revokeAll() {
        prefs.revokeAll()
        log("all paired computers revoked")
        emitAllow()
    }

    fun allowlist(): Map<String, AllowEntry> = prefs.allowlist()

    fun info(): CtlInfoResp = CtlInfoResp(
        op = "info",
        app = Proto.APP_NAME,
        proto = Proto.VERSION,
        ver = Proto.APP_VERSION,
        adbdPort = 0,
        adbdUp = false,
        clients = activeRelays.get(),
        shizuku = ShizukuBridge.protocolState(appContext),
    )

    // ---- identity ----

    private fun loadOrCreateIdentity(): ServerIdentity {
        val der = prefs.serverCertDer
        val key = prefs.serverKeyPkcs8
        if (der != null && key != null) {
            try {
                val cert = X509Util.parseCert(der)
                val priv = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(key))
                return ServerIdentity(cert, der, priv)
            } catch (_: Exception) {
                log("stored identity unreadable, regenerating")
            }
        }
        val fresh = X509Util.generateSelfSigned("ShizBridge phone")
        prefs.serverCertDer = fresh.certDer
        prefs.serverKeyPkcs8 = fresh.privateKey.encoded
        return fresh
    }

    // ---- accept ----

    private fun acceptLoop() {
        val ss = serverSocket ?: return
        while (running) {
            val raw = try {
                ss.accept()
            } catch (e: Exception) {
                if (running) log("accept error: ${e.message}")
                return
            }
            pool.execute { handleConnection(raw) }
        }
    }

    private fun handleConnection(raw: Socket) {
        var ssl: SSLSocket? = null
        try {
            // SSLServerSocket.accept() already returns a fully configured
            // SSLSocket (inherits needClientAuth/enabledProtocols). Wrapping it
            // again via createSocket() would stack a second nested TLS layer:
            // the client handshakes with the inner one, the outer one then
            // chokes on decrypted app bytes ("Unable to parse TLS packet").
            val tls = raw as? SSLSocket
                ?: sslContext!!.socketFactory
                    .createSocket(raw, raw.inetAddress.hostAddress, raw.port, true) as SSLSocket
            ssl = tls
            tls.soTimeout = 15_000
            tls.enabledProtocols = protocolsOf(tls)
            tls.startHandshake()
            val peerChain = trustCapture.clientChain.get()
            trustCapture.clientChain.remove()
            val inp = PushbackInputStream(ssl.inputStream, 8)
            val head = readHead(inp, 4)
            val asText = String(head, Charsets.US_ASCII)
            when {
                asText == Proto.PAIR_MAGIC -> handlePairing(ssl, inp)
                head[0] == 'S'.code.toByte() && head[1] == 'B'.code.toByte() &&
                    head[2] == 'C'.code.toByte() && head[3] == 'T'.code.toByte() -> {
                    val l = inp.read()
                    if (l != 'L'.code) throw ProtocolException("bad control magic")
                    if (!allowlisted(peerChain)) {
                        log("control rejected: unknown client")
                        return
                    }
                    handleControl(ssl, inp)
                }
                else -> {
                    inp.unread(head)
                    if (!allowlisted(peerChain)) {
                        log("relay rejected: unknown client cert")
                        return
                    }
                    handleAdb(ssl, inp)
                }
            }
        } catch (e: SSLException) {
            log("TLS handshake failed: ${e.message}")
        } catch (e: java.net.SocketTimeoutException) {
            // idle probe or slow client — nothing to report
        } catch (e: EOFException) {
            // peer vanished before sending anything
        } catch (e: Exception) {
            log("session error: ${e.message}")
        } finally {
            try { ssl?.close() } catch (_: Exception) {}
            try { raw.close() } catch (_: Exception) {}
        }
    }

    private class ProtocolException(msg: String) : Exception(msg)

    private fun protocolsOf(s: SSLSocket): Array<String> =
        s.supportedProtocols.filter { it == "TLSv1.3" || it == "TLSv1.2" }.toTypedArray()

    private fun readHead(inp: InputStream, n: Int): ByteArray {
        val b = ByteArray(n)
        var off = 0
        while (off < n) {
            val r = inp.read(b, off, n - off)
            if (r < 0) throw EOFException("closed during dispatch")
            off += r
        }
        return b
    }

    private fun allowlisted(chain: Array<X509Certificate>?): Boolean {
        if (chain.isNullOrEmpty()) return false
        val spki = X509Util.spkiSha256(chain[0])
        return prefs.allowlist().containsKey(spki)
    }

    // ---- pairing ----

    private fun handlePairing(ssl: SSLSocket, inp: InputStream) {
        val out = ssl.outputStream
        val code = currentCode?.takeIf { System.currentTimeMillis() < it.expiresAt }
        var attempts = prefs.pairingAttempts
        var sealer: Crypto.RecordCipher? = null

        fun sendResult(ok: Boolean, fp: String? = null, reason: String? = null) {
            val plain = Proto.toJson(PairResult("pair_result", ok, fp, reason))
            Proto.writeFrame(out, sealer!!.seal(plain))
        }

        val hello = Proto.parse<PairHello>(Proto.readFrame(inp))
        if (hello.t != "pair_hello" || hello.v != Proto.VERSION) {
            log("pairing: bad hello")
            return
        }
        val clientEph = Crypto.b64Decode(hello.ephPub)
        val cnonce = Crypto.b64Decode(hello.nonce)
        require(cnonce.size == 16) { "bad client nonce" }

        val serverEph = Crypto.generateEcKeyPair()
        val snonce = Crypto.randomBytes(16)
        val shared = Crypto.ecdh(serverEph.private, Crypto.parsePublicKeyRaw(clientEph))
        val salt = cnonce + snonce
        val key = Crypto.hkdfSha256(shared, salt, Proto.HKDF_INFO.toByteArray(), 32)

        val reply = PairHello(
            t = "pair_hello",
            v = Proto.VERSION,
            ephPub = Crypto.b64(Crypto.publicKeyRaw(serverEph.public)),
            nonce = Crypto.b64(snonce),
            srvCert = Crypto.b64(serverIdentity!!.certDer),
        )
        Proto.writeFrame(out, Proto.toJson(reply))

        sealer = Crypto.RecordCipher(key, Crypto.DIR_S2C)
        val opener = Crypto.RecordCipher(key, Crypto.DIR_C2S)

        if (System.currentTimeMillis() < prefs.lockoutUntil) {
            sendResult(false, reason = "locked")
            log("pairing refused: locked out")
            return
        }

        val auth = Proto.parse<PairAuth>(opener.open(Proto.readFrame(inp)))
        if (auth.t != "pair_auth") {
            log("pairing: bad auth message")
            return
        }

        prefs.pairingAttempts = ++attempts
        val proof = try { Crypto.b64Decode(auth.proof) } catch (_: Exception) { ByteArray(0) }
        val verified = code != null && Crypto.constantTimeEquals(proof, Crypto.codeProof(key, code.code))

        if (!verified) {
            when {
                code == null -> {
                    sendResult(false, reason = "expired")
                    log("pairing attempt #$attempts failed: code expired")
                }
                attempts >= CodeGen.MAX_ATTEMPTS -> {
                    prefs.lockoutUntil = System.currentTimeMillis() + CodeGen.LOCKOUT_MS
                    sendResult(false, reason = "locked")
                    log("pairing locked for ${CodeGen.LOCKOUT_MS / 60000} min after $attempts failed attempts")
                }
                else -> {
                    sendResult(false, reason = "bad_code")
                    log("pairing attempt #$attempts/${CodeGen.MAX_ATTEMPTS} failed")
                }
            }
            emitCode()
            return
        }

        val clientCert = try {
            X509Util.parseCert(Crypto.b64Decode(auth.cliCert))
        } catch (e: Exception) {
            sendResult(false, reason = "bad_cert")
            log("pairing: invalid client certificate")
            return
        }
        val spki = X509Util.spkiSha256(clientCert)
        val label = auth.label.ifBlank { "unknown" }
        prefs.enroll(spki, label)
        prefs.clearLockout()
        prefs.pairingAttempts = 0
        currentCode = null // single-use
        sendResult(true, fp = X509Util.spkiSha256(serverIdentity!!.certificate))
        log("paired: $label (${spki.take(16)}…)")
        emitAllow()
        emitCode()
    }

    // ---- control channel ----

    private fun handleControl(ssl: SSLSocket, inp: InputStream) {
        ssl.soTimeout = 60_000
        val out = ssl.outputStream
        log("control channel opened")
        while (running && !ssl.isClosed) {
            val req = Proto.parse<com.google.gson.JsonObject>(Proto.readFrame(inp))
            val op = req.get("op")?.asString
            when (op) {
                "ping" -> Proto.writeFrame(out, Proto.toJson(CtlPong("pong", System.currentTimeMillis())))
                "info" -> Proto.writeFrame(out, Proto.toJson(info()))
                else -> log("control: unknown op $op")
            }
        }
    }

    // ---- adb device session (in-app mini-adbd) ----

    private fun handleAdb(ssl: SSLSocket, inp: InputStream) {
        if (ShizukuBridge.state(appContext) != ShizukuBridge.State.RUNNING) {
            log("adb session rejected: Shizuku is not running")
            return
        }
        val svc = ShizukuBridge.ensureService(appContext, onLog = ::log)
        if (svc == null) {
            log("adb session rejected: Shizuku UserService unavailable")
            return
        }
        ssl.soTimeout = 0 // interactive shells may sit idle for hours
        activeRelays.incrementAndGet()
        emitStats()
        log("adb session opened (${activeRelays.get()} active)")
        try {
            AdbDeviceSession(ssl, inp, svc, ::log).run()
        } catch (e: EOFException) {
            // client closed the connection — normal end of session
        } catch (e: Exception) {
            log("adb session error: ${e.message}")
        } finally {
            activeRelays.decrementAndGet()
            emitStats()
            log("adb session closed (${activeRelays.get()} active)")
        }
    }

    // ---- TLS helpers ----

    private class CapturingTrustManager : X509TrustManager {
        val clientChain = ThreadLocal<Array<X509Certificate>>()
        override fun checkClientTrusted(chain: Array<out X509Certificate>, authType: String) {
            clientChain.set(arrayOf(*chain))
        }
        override fun checkServerTrusted(chain: Array<out X509Certificate>, authType: String) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    private class IdentityKeyManager(private val id: ServerIdentity) : X509KeyManager {
        private val alias = "shizbridge"
        override fun chooseServerAlias(
            keyType: String, issuers: Array<out java.security.Principal>?, socket: java.net.Socket?,
        ) = alias
        override fun chooseClientAlias(
            keyType: Array<out String>, issuers: Array<out java.security.Principal>?,
            socket: java.net.Socket?,
        ) = alias
        override fun getCertificateChain(alias: String?): Array<X509Certificate>? =
            if (alias == this.alias) arrayOf(id.certificate) else null
        override fun getPrivateKey(alias: String?) =
            if (alias == this.alias) id.privateKey else null
        override fun getClientAliases(keyType: String, issuers: Array<out java.security.Principal>?) =
            arrayOf(alias)
        override fun getServerAliases(keyType: String, issuers: Array<out java.security.Principal>?) =
            arrayOf(alias)
    }
}

/** Process-wide engine shared by the UI and the foreground service. */
object BridgeHolder {
    @Volatile
    private var instance: BridgeEngine? = null

    fun get(context: Context): BridgeEngine =
        instance ?: synchronized(this) {
            instance ?: BridgeEngine(context.applicationContext).also { instance = it }
        }
}
