package bridge.shizbridge.app.core

import bridge.shizbridge.app.shizuku.IShizBridgeUserService
import bridge.shizbridge.app.shizuku.IShizProcess
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLSocket
import android.os.ParcelFileDescriptor

/**
 * In-app mini-adbd: terminates the ADB wire protocol on the TLS socket and
 * executes every request through the Shizuku UserService (shell uid).
 *
 * Flow control follows ADB's credit model: each side starts with one credit,
 * receiving OPEN grants one, OKAY/CLSE never consume, every received OKAY
 * grants one. An incoming WRTE is OKAYed only after its payload has been
 * consumed, which keeps at most one chunk in flight per stream.
 *
 * Supported services: shell: / shell / exec: / exec-out: / sync: / reboot:.
 * Everything else (tcp:, localabstract:, root:, …) is refused with CLSE.
 */
class AdbDeviceSession(
    private val socket: SSLSocket,
    private val input: InputStream,
    private val service: IShizBridgeUserService,
    private val log: (String) -> Unit,
) {

    private val out = socket.outputStream
    private val writeLock = Any()
    private val streams = ConcurrentHashMap<Int, Stream>()
    private var nextLocalId = 1

    @Volatile
    private var maxData = AdbProto.MAXDATA

    fun run() {
        val hello = AdbProto.read(input)
        if (hello.command != AdbProto.A_CNXN) {
            throw IOException("expected CNXN, got 0x${Integer.toHexString(hello.command)}")
        }
        val clientMax = hello.arg1
        if (clientMax in 1 until AdbProto.MAXDATA) maxData = clientMax
        // type:serial:banner — no features key, so clients stay on the legacy
        // shell/sync protocol (no shell_v2, no AUTH on our side either).
        AdbProto.write(
            out, AdbProto.A_CNXN, AdbProto.VERSION, AdbProto.MAXDATA,
            "device:shizbridge:".toByteArray(Charsets.US_ASCII),
        )
        log("adb: session established (maxdata=$maxData)")
        while (true) {
            val msg = AdbProto.read(input)
            when (msg.command) {
                AdbProto.A_OPEN -> handleOpen(msg)
                AdbProto.A_OKAY -> streams[msg.arg1]?.credit?.release()
                AdbProto.A_WRTE -> handleWrte(msg)
                AdbProto.A_CLSE -> handleClose(msg)
                AdbProto.A_CNXN -> Unit
                else -> throw IOException("unexpected command 0x${Integer.toHexString(msg.command)}")
            }
        }
    }

    // ---- protocol plumbing ----

    private fun send(command: Int, arg0: Int, arg1: Int, payload: ByteArray = AdbProto.EMPTY) {
        synchronized(writeLock) {
            AdbProto.write(out, command, arg0, arg1, payload)
        }
    }

    private fun handleWrte(msg: AdbProto.Message) {
        val stream = streams[msg.arg1]
        if (stream == null) {
            send(AdbProto.A_CLSE, 0, msg.arg0)
            return
        }
        if (stream.closed) {
            stream.closeLocal()
            return
        }
        stream.inbound.put(msg.payload) // OKAYed by the consumer once drained
    }

    private fun handleClose(msg: AdbProto.Message) {
        val stream = streams.remove(msg.arg1)
        if (stream == null) {
            send(AdbProto.A_CLSE, 0, msg.arg0)
            return
        }
        if (!stream.closeSent) {
            stream.closeSent = true
            send(AdbProto.A_CLSE, stream.localId, stream.clientId)
        }
        stream.closed = true
        stream.cleanup()
    }

    private fun handleOpen(msg: AdbProto.Message) {
        val name = String(msg.payload, Charsets.UTF_8).trimEnd('\u0000')
        val clientId = msg.arg0
        log("adb: OPEN '$name' (cid=$clientId)")
        val stream = Stream(nextLocalId++, clientId)
        when {
            name == "sync:" -> accept(stream) { runSync(stream) }
            name == "shell:" || name == "shell" || name == "shell," ->
                startProcess(stream, arrayOf("/system/bin/sh"))
            name.startsWith("shell:") ->
                startProcess(stream, arrayOf("/system/bin/sh", "-c", name.substring(6)))
            name.startsWith("shell,") ->
                startProcess(stream, arrayOf("/system/bin/sh", "-c", name.substring(6).replace(',', ' ')))
            name.startsWith("exec:") ->
                startProcess(stream, name.substring(5).split(',').toTypedArray())
            name.startsWith("exec-out:") ->
                startProcess(stream, name.substring(9).split(',').toTypedArray())
            name == "reboot:" -> startProcess(stream, arrayOf("/system/bin/reboot"))
            else -> {
                log("adb: unsupported service '$name'")
                send(AdbProto.A_CLSE, 0, clientId)
            }
        }
    }

    private fun accept(stream: Stream, body: () -> Unit) {
        streams[stream.localId] = stream
        stream.okay()
        stream.start(body)
    }

    private fun startProcess(stream: Stream, argv: Array<String>) {
        accept(stream) {
            val proc = try {
                service.exec(argv, null)
            } catch (e: Exception) {
                log("adb: exec '${argv.firstOrNull()}' failed: ${e.message}")
                stream.closeLocal()
                stream.cleanup()
                return@accept
            }
            stream.process = proc
            stream.onCleanup = { runCatching { proc.destroy() } }

            // stdin: consume inbound WRTE payloads, then OKAY (backpressure)
            Thread({
                try {
                    while (true) {
                        val data = stream.requestInbound()
                        var off = 0
                        while (off < data.size) {
                            val n = minOf(STDIN_CHUNK, data.size - off)
                            proc.writeStdin(data.copyOfRange(off, off + n))
                            off += n
                        }
                        stream.okay()
                    }
                } catch (_: Exception) {
                    runCatching { proc.closeStdin() }
                }
            }, "adb-stdin-${stream.localId}").apply { isDaemon = true; start() }

            // stdout: pump → WRTE (credit-gated) → CLSE at EOF
            try {
                val stdout = proc.acquireStdout()
                ParcelFileDescriptor.AutoCloseInputStream(stdout).use { src ->
                    val buf = ByteArray(maxData)
                    while (true) {
                        val n = src.read(buf)
                        if (n < 0) break
                        if (n > 0) stream.sendData(if (n == buf.size) buf else buf.copyOf(n))
                    }
                }
            } catch (_: Exception) {
                // client vanished or process died — CLSE below
            }
            runCatching { proc.waitFor() }
            stream.closeLocal()
        }
    }

    // ---- sync service ----

    private fun runSync(stream: Stream) {
        val input = SyncInput(stream)
        try {
            while (true) {
                val id = input.readInt()
                val len = input.readInt()
                require(len in 0..SYNC_MAX_PAYLOAD) { "sync length $len" }
                val payload = if (len > 0) input.read(len) else AdbProto.EMPTY
                when (id) {
                    SYNC_STAT -> handleStat(stream, payload)
                    SYNC_LIST -> handleList(stream, payload)
                    SYNC_RECV -> handleRecv(stream, payload)
                    SYNC_SEND -> handleSend(stream, input, payload)
                    SYNC_QUIT -> {
                        stream.closeLocal()
                        stream.cleanup()
                        return
                    }
                    else -> stream.writeSync(syncMsg(SYNC_FAIL, "unknown command".toByteArray()))
                }
            }
        } catch (_: Exception) {
            // stream or session closed mid-sync
        }
    }

    private fun handleStat(stream: Stream, payload: ByteArray) {
        val path = String(payload, Charsets.UTF_8)
        val line = try {
            service.statLine(path)
        } catch (e: Exception) {
            "0000,0,0,"
        }
        stream.writeSync(syncMsg(SYNC_STAT, line.toByteArray(Charsets.UTF_8)))
    }

    private fun handleList(stream: Stream, payload: ByteArray) {
        val path = String(payload, Charsets.UTF_8)
        try {
            for (entry in service.listDir(path)) {
                stream.writeSync(syncMsg(SYNC_LIST, entry.toByteArray(Charsets.UTF_8)))
            }
            stream.writeSync(syncMsg(SYNC_DONE, AdbProto.EMPTY))
        } catch (e: Exception) {
            stream.writeSync(syncMsg(SYNC_FAIL, (e.message ?: "list failed").toByteArray()))
        }
    }

    private fun handleRecv(stream: Stream, payload: ByteArray) {
        val path = String(payload, Charsets.UTF_8)
        val pfd = try {
            service.openRead(path)
        } catch (e: Exception) {
            stream.writeSync(syncMsg(SYNC_FAIL, (e.message ?: "open failed").toByteArray()))
            return
        }
        try {
            ParcelFileDescriptor.AutoCloseInputStream(pfd).use { src ->
                val buf = ByteArray(SYNC_MAX_PAYLOAD)
                while (true) {
                    val n = src.read(buf)
                    if (n < 0) break
                    if (n > 0) {
                        stream.writeSync(syncMsg(SYNC_DATA, if (n == buf.size) buf else buf.copyOf(n)))
                    }
                }
            }
            stream.writeSync(syncMsg(SYNC_DONE, AdbProto.EMPTY))
        } catch (e: Exception) {
            stream.writeSync(syncMsg(SYNC_FAIL, (e.message ?: "read failed").toByteArray()))
        } finally {
            runCatching { pfd.close() }
        }
    }

    private fun handleSend(stream: Stream, input: SyncInput, payload: ByteArray) {
        val spec = String(payload, Charsets.UTF_8)
        val comma = spec.lastIndexOf(',')
        if (comma < 0) {
            stream.writeSync(syncMsg(SYNC_FAIL, "bad SEND spec".toByteArray()))
            return
        }
        val path = spec.substring(0, comma)
        val mode = spec.substring(comma + 1).toIntOrNull() ?: 0b110_100_100 // 0644
        val pfd = try {
            service.openWrite(path, mode)
        } catch (e: Exception) {
            stream.writeSync(syncMsg(SYNC_FAIL, (e.message ?: "create failed").toByteArray()))
            return
        }
        var sink: FileOutputStream? = null
        try {
            val fileSink = FileOutputStream(pfd.fileDescriptor)
            sink = fileSink
            stream.writeSync(syncMsg(SYNC_OKAY, AdbProto.EMPTY))
            while (true) {
                val id = input.readInt()
                val len = input.readInt()
                when (id) {
                    SYNC_DATA -> fileSink.write(input.read(len))
                    SYNC_DONE -> {
                        fileSink.flush()
                        fileSink.close()
                        sink = null
                        pfd.close()
                        val doneMode = if (len >= 8) input.read(8).let {
                            ByteBuffer.wrap(it, 4, 4).order(ByteOrder.LITTLE_ENDIAN).int
                        } else 0
                        val effective = if (doneMode != 0) doneMode else mode
                        runCatching { service.chmod(path, effective and 0xFFF) }
                            .onFailure { log("adb: chmod '$path' failed: ${it.message}") }
                        stream.writeSync(syncMsg(SYNC_OKAY, AdbProto.EMPTY))
                        return
                    }
                    else -> {
                        stream.writeSync(syncMsg(SYNC_FAIL, "unexpected sync id".toByteArray()))
                        return
                    }
                }
            }
        } catch (e: Exception) {
            runCatching { stream.writeSync(syncMsg(SYNC_FAIL, (e.message ?: "write failed").toByteArray())) }
            log("adb: push '$path' failed: ${e.message}")
        } finally {
            runCatching { sink?.close() }
            runCatching { pfd.close() }
        }
    }

    // ---- stream ----

    private inner class Stream(val localId: Int, val clientId: Int) {
        /** One credit comes from the OPEN that created the stream. */
        val credit = Semaphore(1)
        val inbound = LinkedBlockingQueue<ByteArray>()
        val cleaned = AtomicBoolean(false)

        @Volatile var closed = false
        @Volatile var closeSent = false
        @Volatile var process: IShizProcess? = null
        @Volatile var onCleanup: (() -> Unit)? = null

        fun start(body: () -> Unit) {
            Thread({
                try {
                    body()
                } catch (_: Exception) {
                    closeLocal()
                    cleanup()
                }
            }, "adb-stream-$localId").apply { isDaemon = true; start() }
        }

        fun okay() = send(AdbProto.A_OKAY, localId, clientId)

        fun sendData(data: ByteArray) {
            var off = 0
            while (off < data.size) {
                val n = minOf(maxData, data.size - off)
                credit.acquire()
                send(AdbProto.A_WRTE, localId, clientId, if (n == data.size) data else data.copyOfRange(off, off + n))
                off += n
            }
        }

        fun writeSync(bytes: ByteArray) = sendData(bytes)

        fun requestInbound(): ByteArray {
            while (true) {
                val data = inbound.poll(200, TimeUnit.MILLISECONDS)
                if (data != null) return data
                if (closed) throw IOException("stream $localId closed")
            }
        }

        fun closeLocal() {
            if (closeSent) return
            closeSent = true
            runCatching { send(AdbProto.A_CLSE, localId, clientId) }
        }

        fun cleanup() {
            if (!cleaned.compareAndSet(false, true)) return
            closed = true
            runCatching { onCleanup?.invoke() }
            // unblock any credit/poll waiters so threads can notice `closed`
            credit.release(Int.MAX_VALUE / 2)
        }
    }

    /** Byte-level reader over a sync stream's WRTE payloads. */
    private inner class SyncInput(private val stream: Stream) {
        private var buf = ByteArray(512)
        private var len = 0
        private var pos = 0

        fun read(n: Int): ByteArray {
            val outBytes = ByteArray(n)
            var got = 0
            while (got < n) {
                if (pos == len) {
                    val next = stream.requestInbound()
                    stream.okay()
                    if (len + next.size > buf.size) {
                        buf = buf.copyOf(maxOf(buf.size * 2, len + next.size))
                    }
                    System.arraycopy(next, 0, buf, len, next.size)
                    len += next.size
                }
                val take = minOf(n - got, len - pos)
                System.arraycopy(buf, pos, outBytes, got, take)
                pos += take
                got += take
            }
            return outBytes
        }

        fun readInt(): Int = ByteBuffer.wrap(read(4)).order(ByteOrder.LITTLE_ENDIAN).int
    }

    companion object {
        private const val STDIN_CHUNK = 64 * 1024
        private const val SYNC_MAX_PAYLOAD = 65536

        private fun fourcc(s: String): Int =
            s[0].code or (s[1].code shl 8) or (s[2].code shl 16) or (s[3].code shl 24)

        private val SYNC_STAT = fourcc("STAT")
        private val SYNC_LIST = fourcc("LIST")
        private val SYNC_SEND = fourcc("SEND")
        private val SYNC_RECV = fourcc("RECV")
        private val SYNC_DATA = fourcc("DATA")
        private val SYNC_DONE = fourcc("DONE")
        private val SYNC_FAIL = fourcc("FAIL")
        private val SYNC_OKAY = fourcc("OKAY")
        private val SYNC_QUIT = fourcc("QUIT")

        fun syncMsg(id: Int, payload: ByteArray): ByteArray {
            val bb = ByteBuffer.allocate(8 + payload.size).order(ByteOrder.LITTLE_ENDIAN)
            bb.putInt(id)
            bb.putInt(payload.size)
            bb.put(payload)
            return bb.array()
        }
    }
}
