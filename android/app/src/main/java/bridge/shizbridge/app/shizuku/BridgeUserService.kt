package bridge.shizbridge.app.shizuku

import android.content.Context
import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import androidx.annotation.Keep
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Runs as shell (uid 2000) inside the Shizuku-managed process. Implements
 * exactly what the in-app mini-adbd needs; every call is one binder hop.
 */
@Keep
class BridgeUserService(@Suppress("UNUSED_PARAMETER") context: Context) : IShizBridgeUserService.Stub() {

    private val processes = ConcurrentHashMap<Int, ShizProcess>()
    private val nextPid = java.util.concurrent.atomic.AtomicInteger(1)
    private val destroyed = AtomicBoolean(false)

    override fun exec(argv: Array<out String>?, cwd: String?): IShizProcess {
        check(!destroyed.get()) { "user service destroyed" }
        val args = argv?.map { it }.orEmpty()
        require(args.isNotEmpty()) { "empty argv" }
        val pb = ProcessBuilder(args)
        if (!cwd.isNullOrEmpty()) pb.directory(File(cwd))
        pb.redirectErrorStream(true)
        val process = try {
            pb.start()
        } catch (e: Exception) {
            throw IOException("exec ${args.firstOrNull()}: ${e.message}", e)
        }
        val (stdoutRead, stdoutWrite) = ParcelFileDescriptor.createPipe()
        val shiz = ShizProcess(nextPid.getAndIncrement(), process, stdoutRead, stdoutWrite, process.outputStream)
        processes[shiz.id] = shiz
        shiz.startPump()
        return shiz
    }

    override fun statLine(path: String): String {
        val st = try {
            Os.stat(path)
        } catch (e: ErrnoException) {
            if (e.errno == OsConstants.ENOENT) return "0000,0,0,"
            throw IOException("stat $path: ${e.message}")
        }
        return syncEntry(st.st_mode, st.st_size, st.st_mtime, null)
    }

    override fun listDir(path: String): Array<String> {
        val children = File(path).listFiles() ?: throw IOException("list $path: not a directory")
        return children.map { child ->
            val st = try {
                Os.stat(child.absolutePath)
            } catch (e: ErrnoException) {
                throw IOException("stat ${child.absolutePath}: ${e.message}")
            }
            syncEntry(st.st_mode, st.st_size, st.st_mtime, child.name)
        }.toTypedArray()
    }

    override fun openRead(path: String): ParcelFileDescriptor =
        ParcelFileDescriptor.open(File(path), ParcelFileDescriptor.MODE_READ_ONLY)

    override fun openWrite(path: String, mode: Int): ParcelFileDescriptor =
        ParcelFileDescriptor.open(
            File(path),
            ParcelFileDescriptor.MODE_CREATE or
                ParcelFileDescriptor.MODE_WRITE_ONLY or
                ParcelFileDescriptor.MODE_TRUNCATE,
        )

    override fun chmod(path: String, mode: Int) {
        Os.chmod(path, mode)
    }

    override fun destroy() {
        if (!destroyed.compareAndSet(false, true)) return
        processes.values.forEach { it.destroyQuietly() }
        processes.clear()
        android.os.Process.killProcess(android.os.Process.myPid())
    }

    private fun syncEntry(mode: Int, size: Long, mtime: Long, name: String?): String {
        val base = String.format(java.util.Locale.US, "%04o,%d,%d,", mode, size, mtime)
        return if (name == null) base else base + name
    }

    private inner class ShizProcess(
        val id: Int,
        private val process: java.lang.Process,
        private val stdoutRead: ParcelFileDescriptor,
        private val stdoutWrite: ParcelFileDescriptor,
        private val stdinSink: java.io.OutputStream,
    ) : IShizProcess.Stub() {

        private val exitCode = java.util.concurrent.atomic.AtomicInteger(-1)
        private val exited = AtomicBoolean(false)
        private val stdoutTaken = AtomicBoolean(false)
        private val stdinClosed = AtomicBoolean(false)

        fun startPump() {
            // stdout: process → pipe write end; close the write end at EOF so
            // the client sees the stream finish.
            Thread({
                try {
                    process.inputStream.use { src ->
                        FileOutputStream(stdoutWrite.fileDescriptor).use { dst ->
                            src.copyTo(dst, 64 * 1024)
                            dst.flush()
                        }
                    }
                } catch (_: Exception) {
                    // process died or client vanished — pipe close below signals EOF
                } finally {
                    try { stdoutWrite.close() } catch (_: Exception) {}
                }
            }, "shiz-pump-$id").apply { isDaemon = true; start() }

            // reaper: reap the child so it never zombifies, cache the exit code
            Thread({
                val code = try {
                    process.waitFor()
                } catch (_: Exception) {
                    -1
                }
                exitCode.set(code)
                exited.set(true)
                closeStdinQuietly()
                processes.remove(id)
            }, "shiz-reaper-$id").apply { isDaemon = true; start() }
        }

        override fun acquireStdout(): ParcelFileDescriptor {
            check(stdoutTaken.compareAndSet(false, true)) { "stdout already taken" }
            return stdoutRead
        }

        override fun writeStdin(data: ByteArray?) {
            val bytes = data ?: return
            check(!stdinClosed.get()) { "stdin closed" }
            synchronized(stdinSink) {
                stdinSink.write(bytes)
                stdinSink.flush()
            }
        }

        override fun closeStdin() {
            closeStdinQuietly()
        }

        override fun waitFor(): Int {
            while (!exited.get()) {
                try {
                    Thread.sleep(20)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    return -1
                }
            }
            return exitCode.get()
        }

        override fun destroy() {
            destroyQuietly()
        }

        fun destroyQuietly() {
            try { process.destroy() } catch (_: Exception) {}
            try {
                if (!process.waitFor(300, java.util.concurrent.TimeUnit.MILLISECONDS)) {
                    process.destroyForcibly()
                }
            } catch (_: Exception) {}
            closeStdinQuietly()
            try { stdoutRead.close() } catch (_: Exception) {}
            try { stdoutWrite.close() } catch (_: Exception) {}
            processes.remove(id)
        }

        private fun closeStdinQuietly() {
            if (stdinClosed.compareAndSet(false, true)) {
                try { stdinSink.flush() } catch (_: Exception) {}
                try { stdinSink.close() } catch (_: Exception) {}
            }
        }
    }
}
