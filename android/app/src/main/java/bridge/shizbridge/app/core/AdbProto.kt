package bridge.shizbridge.app.core

import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * ADB wire format: 24-byte little-endian header + payload.
 * magic = command xor 0xffffffff. Version >= 0x01000001 skips checksums.
 */
object AdbProto {

    const val A_CNXN = 0x4e584e43
    const val A_AUTH = 0x48545541
    const val A_OPEN = 0x4e45504f
    const val A_OKAY = 0x59414b4f
    const val A_CLSE = 0x45534c43
    const val A_WRTE = 0x45545257

    const val VERSION = 0x01000001
    const val MAXDATA = 256 * 1024
    const val HEADER = 24

    data class Message(val command: Int, val arg0: Int, val arg1: Int, val payload: ByteArray) {
        override fun equals(other: Any?): Boolean =
            other is Message && command == other.command && arg0 == other.arg0 &&
                arg1 == other.arg1 && payload.contentEquals(other.payload)

        override fun hashCode(): Int =
            (command * 31 + arg0) * 31 + arg1 * 31 + payload.contentHashCode()
    }

    /**
     * Standard ADB header: command, arg0, arg1, data_length, data_check,
     * command_magic. (The wire order is command-first — NOT length-first;
     * a length-first header parses the peer's command as a 1GB payload.)
     */
    fun encode(command: Int, arg0: Int, arg1: Int, payload: ByteArray = EMPTY): ByteArray {
        val bb = ByteBuffer.allocate(HEADER + payload.size).order(ByteOrder.LITTLE_ENDIAN)
        bb.putInt(command)
        bb.putInt(arg0)
        bb.putInt(arg1)
        bb.putInt(payload.size)
        bb.putInt(0) // checksum skipped at VERSION
        bb.putInt(command.inv())
        bb.put(payload)
        return bb.array()
    }

    fun write(out: OutputStream, command: Int, arg0: Int, arg1: Int, payload: ByteArray = EMPTY) {
        out.write(encode(command, arg0, arg1, payload))
        out.flush()
    }

    /** Reads one message; throws EOFException when the peer closed cleanly. */
    fun read(inp: InputStream): Message {
        val head = readFully(inp, HEADER)
        val bb = ByteBuffer.wrap(head).order(ByteOrder.LITTLE_ENDIAN)
        val command = bb.int
        val arg0 = bb.int
        val arg1 = bb.int
        val len = bb.int
        bb.int // checksum — unused at VERSION
        val magic = bb.int
        if (magic != command.inv()) {
            throw IllegalStateException(
                "bad magic 0x${Integer.toHexString(magic)} for command 0x${Integer.toHexString(command)}",
            )
        }
        if (len < 0 || len > MAXDATA) {
            throw IllegalStateException("bad payload length $len")
        }
        val payload = if (len == 0) EMPTY else readFully(inp, len)
        return Message(command, arg0, arg1, payload)
    }

    internal fun readFully(inp: InputStream, n: Int): ByteArray {
        val buf = ByteArray(n)
        var off = 0
        while (off < n) {
            val r = inp.read(buf, off, n - off)
            if (r < 0) throw EOFException("stream closed after $off/$n bytes")
            off += r
        }
        return buf
    }

    val EMPTY = ByteArray(0)
}
