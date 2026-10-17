package bridge.shizbridge.app.core

import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import java.io.InputStream
import java.io.OutputStream

/** Wire protocol constants and frame codec — mirrors agent/internal/proto. */
object Proto {
    const val VERSION = 1
    const val DEFAULT_PORT = 8787
    const val MAX_FRAME = 65536
    const val PAIR_MAGIC = "SBPR"
    const val CONTROL_MAGIC = "SBCTL"
    const val HKDF_INFO = "ShizBridge pairing v1"
    const val PROOF_LABEL = "ShizBridge code proof"
    const val APP_NAME = "ShizBridge"
    const val APP_VERSION = "0.1.0"

    val gson: Gson = Gson()

    fun writeFrame(out: OutputStream, payload: ByteArray) {
        require(payload.size <= MAX_FRAME) { "frame too large" }
        val hdr = byteArrayOf(
            (payload.size ushr 24).toByte(),
            (payload.size ushr 16).toByte(),
            (payload.size ushr 8).toByte(),
            payload.size.toByte(),
        )
        out.write(hdr)
        out.write(payload)
        out.flush()
    }

    fun readFrame(inp: InputStream): ByteArray {
        val hdr = readFully(inp, 4)
        val n = ((hdr[0].toInt() and 0xff) shl 24) or
            ((hdr[1].toInt() and 0xff) shl 16) or
            ((hdr[2].toInt() and 0xff) shl 8) or
            (hdr[3].toInt() and 0xff)
        require(n in 0..MAX_FRAME) { "bad frame length $n" }
        return readFully(inp, n)
    }

    fun readFully(inp: InputStream, n: Int): ByteArray {
        val buf = ByteArray(n)
        var off = 0
        while (off < n) {
            val r = inp.read(buf, off, n - off)
            if (r < 0) throw java.io.EOFException("stream closed after $off/$n bytes")
            off += r
        }
        return buf
    }

    inline fun <reified T> parse(json: String): T = gson.fromJson(json, T::class.java)
    inline fun <reified T> parse(bytes: ByteArray): T = parse(String(bytes, Charsets.UTF_8))
    fun toJson(v: Any): ByteArray = gson.toJson(v).toByteArray(Charsets.UTF_8)
}

// ---- pairing messages ----

data class PairHello(
    val t: String,
    val v: Int,
    @SerializedName("eph_pub") val ephPub: String,
    val nonce: String,
    @SerializedName("srv_cert") val srvCert: String? = null,
)

data class PairAuth(
    val t: String,
    val proof: String,
    @SerializedName("cli_cert") val cliCert: String,
    val label: String,
)

data class PairResult(
    val t: String,
    val ok: Boolean,
    val fp: String? = null,
    val reason: String? = null,
)

// ---- control channel ----

data class CtlPing(val op: String)
data class CtlPong(val op: String, val ts: Long)
data class CtlInfoReq(val op: String)

data class CtlInfoResp(
    val op: String,
    val app: String,
    val proto: Int,
    val ver: String,
    @SerializedName("adbd_port") val adbdPort: Int,
    @SerializedName("adbd_up") val adbdUp: Boolean,
    val clients: Int,
    val shizuku: String,
)
