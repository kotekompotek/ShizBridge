package bridge.shizbridge.app.core

import java.io.File
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.net.Socket

/**
 * Finds the phone's local adbd TCP port:
 * 1. parse /proc/self/net/tcp{,6} for LISTEN sockets on loopback/wildcard
 *    owned by root/shell,
 * 2. probe each candidate with a real ADB CNXN exchange (port >= 1024,
 *    excluding our own server port).
 */
object AdbdDetector {

    const val ADB_CNXN = 0x434e584e
    private const val ADB_VERSION = 0x01000001 // skips per-message checksums
    private const val ADB_MAXDATA = 0x100000

    fun candidates(excludePort: Int): List<Int> {
        val ports = LinkedHashSet<Int>()
        for (path in listOf("/proc/self/net/tcp", "/proc/self/net/tcp6")) {
            try {
                parseProcNetTcp(File(path).readText(), excludePort).forEach { ports.add(it) }
            } catch (_: Exception) {
                // unreadable (SELinux/rooted restrictions) — manual entry stays available
            }
        }
        return ports.sortedDescending()
    }

    internal fun parseProcNetTcp(content: String, excludePort: Int): List<Int> {
        val out = ArrayList<Int>()
        for (line in content.lineSequence().drop(1)) {
            val f = line.trim().split(Regex("\\s+"))
            if (f.size < 10) continue
            val local = f[1]
            val st = f[3]
            val uid = f[7].toIntOrNull() ?: continue
            if (st != "0A") continue // TCP_LISTEN
            if (uid != 0 && uid != 2000) continue // root or shell (adbd)
            val colon = local.indexOf(':')
            if (colon < 0) continue
            val addr = local.substring(0, colon)
            if (!isLoopbackOrAny(addr)) continue
            val port = local.substring(colon + 1).toIntOrNull(16) ?: continue
            if (port in 1024..65535 && port != excludePort) out.add(port)
        }
        return out
    }

    /** Hex-encoded IPv4 little-endian / IPv6 as written by the kernel. */
    private fun isLoopbackOrAny(addrHex: String): Boolean {
        return when (addrHex.length) {
            8 -> addrHex == "00000000" || addrHex == "0100007F" // 0.0.0.0 / 127.0.0.1
            32 -> addrHex.all { it == '0' } || addrHex == "00000000000000000000000001000000" // :: / ::1
            else -> false
        }
    }

    /** Returns the adbd port or 0 if none of the candidates answers CNXN. */
    fun detect(excludePort: Int, timeoutMs: Int = 700): Int {
        for (port in candidates(excludePort)) {
            if (probeCnxn(port, timeoutMs)) return port
        }
        return 0
    }

    internal fun probeCnxn(port: Int, timeoutMs: Int): Boolean = try {
        Socket().use { s ->
            s.soTimeout = timeoutMs
            s.connect(InetSocketAddress("127.0.0.1", port), timeoutMs)
            s.getOutputStream().write(cnxnPacket())
            s.getOutputStream().flush()
            val hdr = ByteArray(24)
            var off = 0
            while (off < 24) {
                val r = s.getInputStream().read(hdr, off, 24 - off)
                if (r < 0) return false
                off += r
            }
            val bb = ByteBuffer.wrap(hdr).order(ByteOrder.LITTLE_ENDIAN)
            val cmd = bb.int
            val magic = bb.int
            cmd == ADB_CNXN && magic == ADB_CNXN.inv()
        }
    } catch (_: Exception) {
        false
    }

    internal fun cnxnPacket(): ByteArray {
        val payload = "host::".toByteArray(StandardCharsets.US_ASCII)
        val bb = ByteBuffer.allocate(24 + payload.size).order(ByteOrder.LITTLE_ENDIAN)
        bb.putInt(payload.size)
        bb.putInt(ADB_CNXN)
        bb.putInt(ADB_VERSION)
        bb.putInt(ADB_MAXDATA)
        bb.putInt(0) // checksum skipped at version >= 0x01000001
        bb.putInt(ADB_CNXN.inv())
        bb.put(payload)
        return bb.array()
    }
}
