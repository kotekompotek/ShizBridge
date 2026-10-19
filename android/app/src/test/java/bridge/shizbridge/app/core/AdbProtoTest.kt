package bridge.shizbridge.app.core

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class AdbProtoTest {

    @Test
    fun cnxnRoundtrip() {
        val payload = "device:shizbridge:".toByteArray(Charsets.US_ASCII)
        val bytes = AdbProto.encode(AdbProto.A_CNXN, AdbProto.VERSION, AdbProto.MAXDATA, payload)
        assertEquals(AdbProto.HEADER + payload.size, bytes.size)
        val msg = AdbProto.read(ByteArrayInputStream(bytes))
        assertEquals(AdbProto.A_CNXN, msg.command)
        assertEquals(AdbProto.VERSION, msg.arg0)
        assertEquals(AdbProto.MAXDATA, msg.arg1)
        assertArrayEquals(payload, msg.payload)
    }

    @Test
    fun openWithServiceRoundtrip() {
        val payload = "shell:ls -l /sdcard".toByteArray(Charsets.US_ASCII) + 0
        val msg = AdbProto.read(
            ByteArrayInputStream(AdbProto.encode(AdbProto.A_OPEN, 1, 0, payload)),
        )
        assertEquals(AdbProto.A_OPEN, msg.command)
        assertEquals(1, msg.arg0)
        assertEquals(0, msg.arg1)
        assertArrayEquals(payload, msg.payload)
        assertEquals(
            "shell:ls -l /sdcard",
            String(msg.payload, Charsets.UTF_8).trimEnd('\u0000'),
        )
    }

    @Test
    fun okayAndClseRoundtrip() {
        val okay = AdbProto.read(
            ByteArrayInputStream(AdbProto.encode(AdbProto.A_OKAY, 100, 1)),
        )
        assertEquals(AdbProto.A_OKAY, okay.command)
        assertEquals(100, okay.arg0)
        assertEquals(1, okay.arg1)
        assertEquals(0, okay.payload.size)

        val clse = AdbProto.read(
            ByteArrayInputStream(AdbProto.encode(AdbProto.A_CLSE, 0, 1)),
        )
        assertEquals(AdbProto.A_CLSE, clse.command)
        assertEquals(0, clse.arg0)
    }

    @Test
    fun wrteLargePayloadRoundtrip() {
        val payload = ByteArray(64 * 1024) { (it % 251).toByte() }
        val out = ByteArrayOutputStream()
        AdbProto.write(out, AdbProto.A_WRTE, 3, 7, payload)
        val msg = AdbProto.read(ByteArrayInputStream(out.toByteArray()))
        assertEquals(AdbProto.A_WRTE, msg.command)
        assertEquals(3, msg.arg0)
        assertEquals(7, msg.arg1)
        assertArrayEquals(payload, msg.payload)
    }

    @Test
    fun magicIsValidated() {
        val bytes = AdbProto.encode(AdbProto.A_CNXN, AdbProto.VERSION, AdbProto.MAXDATA, AdbProto.EMPTY)
        bytes[20] = 0 // corrupt the low byte of magic
        assertThrows(IllegalStateException::class.java) {
            AdbProto.read(ByteArrayInputStream(bytes))
        }
    }

    @Test
    fun oversizedPayloadRejected() {
        val bytes = AdbProto.encode(AdbProto.A_WRTE, 1, 1, AdbProto.EMPTY)
        // data_length at offset 12 (LE int) — claim 1MB, larger than MAXDATA
        bytes[12] = 0
        bytes[13] = 0
        bytes[14] = 0x10
        bytes[15] = 0
        assertThrows(IllegalStateException::class.java) {
            AdbProto.read(ByteArrayInputStream(bytes))
        }
    }

    @Test
    fun headerFollowsStandardAdbLayout() {
        // The wire format is command-first: command, arg0, arg1, length, check, magic.
        // (A length-first header parses the peer's command as a huge payload.)
        val bytes = AdbProto.encode(AdbProto.A_CNXN, AdbProto.VERSION, AdbProto.MAXDATA, byteArrayOf(1, 2, 3))
        val bb = java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        assertEquals(AdbProto.A_CNXN, bb.int) // command at offset 0
        assertEquals(AdbProto.VERSION, bb.int)
        assertEquals(AdbProto.MAXDATA, bb.int)
        assertEquals(3, bb.int) // data_length at offset 12
        assertEquals(0, bb.int)
        assertEquals(AdbProto.A_CNXN.inv(), bb.int)
        // first four bytes on the wire spell the command little-endian: 43 4E 58 4E
        assertEquals('C'.code.toByte(), bytes[0])
        assertEquals('N'.code.toByte(), bytes[1])
        assertEquals('X'.code.toByte(), bytes[2])
        assertEquals('N'.code.toByte(), bytes[3])
    }

    @Test
    fun eofOnEmptyStream() {
        assertThrows(EOFException::class.java) {
            AdbProto.read(ByteArrayInputStream(ByteArray(0)))
        }
    }

    @Test
    fun commandConstantsMatchAscii() {
        // Standard ADB: the numeric constant is the ASCII name byte-reversed,
        // so a little-endian write spells the name forward on the wire.
        assertEquals(0x4e584e43, AdbProto.A_CNXN) // wire "CNXN"
        assertEquals(0x4e45504f, AdbProto.A_OPEN) // wire "OPEN"
        assertEquals(0x59414b4f, AdbProto.A_OKAY) // wire "OKAY"
        assertEquals(0x45534c43, AdbProto.A_CLSE) // wire "CLSE"
        assertEquals(0x45545257, AdbProto.A_WRTE) // wire "WRTE"
        assertEquals(0x48545541, AdbProto.A_AUTH) // wire "AUTH"
    }

    @Test
    fun syncMessageFormat() {
        val line = "40755,0,1700000000,files"
        val bytes = AdbDeviceSession.syncMsg(0x5453494c, line.toByteArray()) // LIST
        assertEquals(8 + line.length, bytes.size)
        // id "LIST" little-endian
        assertEquals('L'.code, bytes[0].toInt())
        assertEquals('I'.code, bytes[1].toInt())
        assertEquals('S'.code, bytes[2].toInt())
        assertEquals('T'.code, bytes[3].toInt())
        // length LE
        assertEquals(line.length, bytes[4].toInt())
        assertEquals(0, bytes[5].toInt())
        assertEquals(0, bytes[6].toInt())
        assertEquals(0, bytes[7].toInt())
        assertEquals(line, String(bytes, 8, line.length, Charsets.UTF_8))
    }

    @Test
    fun versionIsLegacyNoChecksums() {
        assertEquals(0x01000001, AdbProto.VERSION)
        val bytes = AdbProto.encode(AdbProto.A_CNXN, AdbProto.VERSION, AdbProto.MAXDATA, AdbProto.EMPTY)
        // checksum field (offset 16) must be zero at VERSION
        assertEquals(0, bytes[16].toInt())
        assertEquals(0, bytes[17].toInt())
        assertEquals(0, bytes[18].toInt())
        assertEquals(0, bytes[19].toInt())
    }
}
