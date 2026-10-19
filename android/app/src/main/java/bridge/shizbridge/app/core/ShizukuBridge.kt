package bridge.shizbridge.app.core

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.IBinder
import bridge.shizbridge.app.BuildConfig
import bridge.shizbridge.app.shizuku.BridgeUserService
import bridge.shizbridge.app.shizuku.IShizBridgeUserService
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.locks.ReentrantLock
import rikka.shizuku.Shizuku

/** Shizuku-backed helpers: service state, permission, UserService binding. */
object ShizukuBridge {

    const val SHIZUKU_PKG = "moe.shizuku.privileged.api"
    const val PERMISSION_REQUEST_CODE = 0x5342 // 'SB'
    private const val BIND_TIMEOUT_MS = 8_000L

    enum class State { NOT_INSTALLED, NOT_RUNNING, PERMISSION_REQUIRED, RUNNING }

    @Volatile
    private var service: IShizBridgeUserService? = null

    /**
     * Binder transactions to a wedged Shizuku server can block forever, so all
     * Shizuku calls run on this watchdog pool with hard timeouts — a hang must
     * never freeze every incoming ADB session behind the bind lock.
     */
    private val binderPool: ExecutorService = Executors.newCachedThreadPool { r ->
        Thread(r, "shizuku-binder").apply { isDaemon = true }
    }
    private val bindLock = ReentrantLock()

    fun isInstalled(context: Context): Boolean = try {
        context.packageManager.getPackageInfo(SHIZUKU_PKG, 0)
        true
    } catch (_: Exception) {
        false
    }

    fun state(context: Context): State = when {
        !isInstalled(context) -> State.NOT_INSTALLED
        !Shizuku.pingBinder() -> State.NOT_RUNNING
        Shizuku.checkSelfPermission() != PackageManager.PERMISSION_GRANTED ->
            State.PERMISSION_REQUIRED
        else -> State.RUNNING
    }

    /** Protocol-compatible summary: running | stopped | unsupported. */
    fun protocolState(context: Context): String = when (state(context)) {
        State.NOT_INSTALLED -> "unsupported"
        State.NOT_RUNNING -> "stopped"
        else -> "running"
    }

    fun openShizukuApp(context: Context): Boolean {
        val intent = context.packageManager.getLaunchIntentForPackage(SHIZUKU_PKG) ?: return false
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(intent)
        return true
    }

    fun requestPermission() {
        Shizuku.requestPermission(PERMISSION_REQUEST_CODE)
    }

    /**
     * Returns the bound BridgeUserService, binding it on first use. Blocks up
     * to [timeoutMs] on the handshake; the returned binder stays valid for the
     * app's lifetime (death drops the cache, next call rebinds).
     *
     * [onLog] receives diagnostic lines (bind blocked/timed out, with the stuck
     * thread's stack) so a wedged Shizuku server is visible in the app log
     * instead of manifesting as silently hanging ADB sessions.
     */
    fun ensureService(
        context: Context,
        timeoutMs: Long = BIND_TIMEOUT_MS,
        onLog: ((String) -> Unit)? = null,
    ): IShizBridgeUserService? {
        service?.let { if (it.asBinder().isBinderAlive) return it }
        // Never queue behind a possibly-stuck bind: if the lock isn't free
        // within the budget, fail fast and let the caller log/report it.
        if (!bindLock.tryLock(timeoutMs + 2_000, TimeUnit.MILLISECONDS)) {
            onLog?.invoke("shizuku: previous bind attempt still stuck — skipping")
            return null
        }
        try {
            service?.let { if (it.asBinder().isBinderAlive) return it }
            if (!pingBounded()) return null
            if (permissionDeniedBounded()) return null

            val appContext = context.applicationContext
            val args = Shizuku.UserServiceArgs(
                ComponentName(appContext.packageName, BridgeUserService::class.java.name),
            )
                .daemon(false)
                .processNameSuffix("bridge")
                .debuggable(BuildConfig.DEBUG)
                .version(BuildConfig.VERSION_CODE)

            val latch = CountDownLatch(1)
            var bound: IShizBridgeUserService? = null
            val conn = object : ServiceConnection {
                override fun onServiceConnected(name: ComponentName, binder: IBinder) {
                    bound = IShizBridgeUserService.Stub.asInterface(binder)
                    latch.countDown()
                }

                override fun onServiceDisconnected(name: ComponentName) {
                    service = null
                }
            }

            var worker: Thread? = null
            val bindCall = binderPool.submit {
                worker = Thread.currentThread()
                runCatching { Shizuku.bindUserService(args, conn) }
            }
            try {
                bindCall.get(timeoutMs, TimeUnit.MILLISECONDS)
            } catch (e: TimeoutException) {
                onLog?.invoke(
                    "shizuku: bindUserService blocked >${timeoutMs}ms at\n" +
                        "   " + (worker?.stackTrace?.take(8)?.joinToString("\n   ") ?: "not started"),
                )
                // The bind may still complete later — clean up if it does.
                binderPool.submit {
                    runCatching { latch.await(30, TimeUnit.SECONDS) }
                    runCatching { Shizuku.unbindUserService(args, conn, true) }
                }
                return null
            } catch (e: Exception) {
                onLog?.invoke("shizuku: bindUserService failed: $e")
                return null
            }

            if (!latch.await(timeoutMs, TimeUnit.MILLISECONDS)) {
                onLog?.invoke("shizuku: UserService did not connect within ${timeoutMs}ms")
                // unbind is a binder call too — never block on it
                binderPool.submit { runCatching { Shizuku.unbindUserService(args, conn, true) } }
                return null
            }
            val svc = bound ?: return null
            runCatching {
                svc.asBinder().linkToDeath({ service = null }, 0)
            }
            service = svc
            return svc
        } finally {
            bindLock.unlock()
        }
    }

    private fun pingBounded(): Boolean = try {
        binderPool.submit<Boolean> { Shizuku.pingBinder() }.get(3, TimeUnit.SECONDS)
    } catch (e: Exception) {
        false
    }

    private fun permissionDeniedBounded(): Boolean = try {
        binderPool.submit<Boolean> {
            Shizuku.checkSelfPermission() != PackageManager.PERMISSION_GRANTED
        }.get(3, TimeUnit.SECONDS)
    } catch (e: Exception) {
        true // treat a blocked check as "no permission" — caller reports it
    }
}
