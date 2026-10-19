package bridge.shizbridge.app.ui

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.RecyclerView
import bridge.shizbridge.app.BridgeService
import bridge.shizbridge.app.R
import bridge.shizbridge.app.core.AllowEntry
import bridge.shizbridge.app.core.BridgeEngine
import bridge.shizbridge.app.core.BridgeHolder
import bridge.shizbridge.app.core.ShizukuBridge
import com.google.android.material.button.MaterialButton
import java.net.NetworkInterface
import rikka.shizuku.Shizuku

class MainActivity : AppCompatActivity(), BridgeEngine.Listener {

    private lateinit var engine: BridgeEngine
    private lateinit var statusTitle: TextView
    private lateinit var statusAddr: TextView
    private lateinit var btnStartStop: MaterialButton
    private lateinit var codeText: TextView
    private lateinit var codeExpiry: TextView
    private lateinit var btnRegen: MaterialButton
    private lateinit var btnCopy: MaterialButton
    private lateinit var shizukuStatus: TextView
    private lateinit var btnConnectShizuku: MaterialButton
    private lateinit var btnRevokeAll: MaterialButton
    private lateinit var devicesEmpty: TextView
    private lateinit var deviceList: RecyclerView
    private lateinit var logText: TextView

    private val mainHandler = Handler(Looper.getMainLooper())
    private val logBuffer = ArrayDeque<String>()
    private lateinit var deviceAdapter: DeviceAdapter

    private var shizukuConnectPending = false

    private companion object {
        /** One auto permission prompt per process; the button can still retry. */
        var permissionAutoRequested = false
    }

    private val shizukuBinderListener = Shizuku.OnBinderReceivedListener {
        if (shizukuConnectPending) {
            shizukuConnectPending = false
            mainHandler.post { onShizukuReady() }
        } else {
            mainHandler.post { refreshShizuku() }
        }
    }

    private val shizukuPermissionListener =
        Shizuku.OnRequestPermissionResultListener { requestCode, _ ->
            if (requestCode == ShizukuBridge.PERMISSION_REQUEST_CODE) {
                mainHandler.post {
                    if (ShizukuBridge.state(this) == ShizukuBridge.State.RUNNING) {
                        bindUserService() // granted — connect without any further taps
                    } else {
                        Toast.makeText(this, R.string.toast_shizuku_denied, Toast.LENGTH_LONG).show()
                        refreshShizuku()
                    }
                }
            }
        }

    private val notifPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            if (!granted) {
                Toast.makeText(this, R.string.permission_rationale, Toast.LENGTH_LONG).show()
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        engine = BridgeHolder.get(this)

        statusTitle = findViewById(R.id.statusTitle)
        statusAddr = findViewById(R.id.statusAddr)
        btnStartStop = findViewById(R.id.btnStartStop)
        codeText = findViewById(R.id.codeText)
        codeExpiry = findViewById(R.id.codeExpiry)
        btnRegen = findViewById(R.id.btnRegen)
        btnCopy = findViewById(R.id.btnCopy)
        shizukuStatus = findViewById(R.id.shizukuStatus)
        btnConnectShizuku = findViewById(R.id.btnConnectShizuku)
        btnRevokeAll = findViewById(R.id.btnRevokeAll)
        devicesEmpty = findViewById(R.id.devicesEmpty)
        deviceList = findViewById(R.id.deviceList)
        logText = findViewById(R.id.logText)

        deviceAdapter = DeviceAdapter(emptyList()) { spki -> engine.revoke(spki) }
        deviceList.adapter = deviceAdapter

        btnStartStop.setOnClickListener {
            if (engine.running) {
                BridgeService.stop(this)
            } else {
                requestNotifIfNeeded()
                BridgeService.start(this)
            }
        }
        btnRegen.setOnClickListener { engine.newCode() }
        btnCopy.setOnClickListener { copyCode() }
        btnConnectShizuku.setOnClickListener { connectShizuku() }
        btnRevokeAll.setOnClickListener { confirmRevokeAll() }

        refreshAll()

        Shizuku.addBinderReceivedListenerSticky(shizukuBinderListener)
        Shizuku.addRequestPermissionResultListener(shizukuPermissionListener)
        autoConnectShizuku()
    }

    override fun onDestroy() {
        Shizuku.removeBinderReceivedListener(shizukuBinderListener)
        Shizuku.removeRequestPermissionResultListener(shizukuPermissionListener)
        super.onDestroy()
    }

    override fun onStart() {
        super.onStart()
        engine.addListener(this)
        pullRecentLogs()
        refreshAll()
        mainHandler.post(ticker)
    }

    override fun onStop() {
        engine.removeListener(this)
        mainHandler.removeCallbacks(ticker)
        super.onStop()
    }

    private val ticker = object : Runnable {
        override fun run() {
            refreshCodeExpiry()
            mainHandler.postDelayed(this, 1000)
        }
    }

    // ---- BridgeEngine.Listener (may be called from IO threads) ----

    override fun onLog(line: String) = onMain { appendLog(line) }
    override fun onStateChanged() = onMain { refreshStatus() }
    override fun onCodeChanged() = onMain { refreshCode(); refreshCodeExpiry() }
    override fun onAllowlistChanged() = onMain { refreshDevices() }
    override fun onStatsChanged() = onMain { refreshStatus() }

    private fun onMain(block: () -> Unit) {
        if (Looper.myLooper() == Looper.getMainLooper()) block()
        else mainHandler.post(block)
    }

    // ---- refresh ----

    private fun refreshAll() {
        refreshStatus()
        refreshCode()
        refreshCodeExpiry()
        refreshDevices()
        refreshShizuku()
    }

    private fun refreshShizuku() {
        shizukuStatus.setText(
            when (ShizukuBridge.state(this)) {
                ShizukuBridge.State.NOT_INSTALLED -> R.string.shizuku_status_not_installed
                ShizukuBridge.State.NOT_RUNNING -> R.string.shizuku_status_stopped
                ShizukuBridge.State.PERMISSION_REQUIRED -> R.string.shizuku_status_permission
                ShizukuBridge.State.RUNNING -> R.string.shizuku_status_ready
            },
        )
    }

    private fun refreshStatus() {
        statusTitle.setText(if (engine.running) R.string.status_running else R.string.status_stopped)
        val lines = mutableListOf<String>()
        if (engine.running) {
            lines.add("listen :${engine.prefs.listenPort} · active relays: ${engine.activeRelays.get()}")
        }
        val ips = localIpv4s()
        lines.add(if (ips.isEmpty()) "no network interfaces" else "phone: ${ips.joinToString(", ")}")
        lines.add("PC: shizbridge pair <code> --server <phone-ip>:${engine.prefs.listenPort}")
        statusAddr.text = lines.joinToString("\n")
        btnStartStop.setText(if (engine.running) R.string.btn_stop else R.string.btn_start)
    }

    private fun refreshCode() {
        val code = engine.currentCode?.code
        codeText.text = code?.chunked(4)?.joinToString(" ") ?: "—"
    }

    private fun refreshCodeExpiry() {
        val code = engine.currentCode
        if (code == null) {
            codeExpiry.text = ""
            return
        }
        val left = code.expiresAt - System.currentTimeMillis()
        codeExpiry.text = if (left <= 0) {
            getString(R.string.code_expired)
        } else {
            val s = left / 1000
            "expires in %d:%02d".format(s / 60, s % 60)
        }
    }

    private fun refreshDevices() {
        val items = engine.allowlist().toList()
        deviceAdapter.items = items
        deviceAdapter.notifyDataSetChanged()
        devicesEmpty.visibility = if (items.isEmpty()) View.VISIBLE else View.GONE
    }

    private fun pullRecentLogs() {
        logBuffer.clear()
        engine.recentLogs().forEach { logBuffer.addLast(it) }
        renderLog()
    }

    private fun appendLog(line: String) {
        logBuffer.addLast(line)
        while (logBuffer.size > 80) logBuffer.removeFirst()
        renderLog()
    }

    private fun renderLog() {
        logText.text = logBuffer.joinToString("\n")
    }

    // ---- actions ----

    private fun requestNotifIfNeeded() {
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    private fun copyCode() {
        val code = engine.currentCode?.code ?: return
        val clipboard = getSystemService(ClipboardManager::class.java)
        clipboard.setPrimaryClip(ClipData.newPlainText("ShizBridge", code))
        Toast.makeText(this, R.string.toast_copied, Toast.LENGTH_SHORT).show()
    }

    private fun connectShizuku() {
        when (ShizukuBridge.state(this)) {
            ShizukuBridge.State.NOT_INSTALLED -> {
                Toast.makeText(this, R.string.toast_shizuku_not_installed, Toast.LENGTH_LONG).show()
                refreshShizuku()
            }
            ShizukuBridge.State.NOT_RUNNING -> {
                shizukuConnectPending = true
                if (ShizukuBridge.openShizukuApp(this)) {
                    Toast.makeText(this, R.string.toast_shizuku_opening, Toast.LENGTH_LONG).show()
                    shizukuStatus.setText(R.string.shizuku_status_stopped)
                } else {
                    shizukuConnectPending = false
                    Toast.makeText(this, R.string.toast_shizuku_not_installed, Toast.LENGTH_LONG).show()
                }
            }
            ShizukuBridge.State.PERMISSION_REQUIRED -> ShizukuBridge.requestPermission()
            ShizukuBridge.State.RUNNING -> bindUserService()
        }
    }

    private fun onShizukuReady() {
        when (ShizukuBridge.state(this)) {
            ShizukuBridge.State.PERMISSION_REQUIRED -> ShizukuBridge.requestPermission()
            ShizukuBridge.State.RUNNING -> bindUserService()
            else -> refreshShizuku()
        }
    }

    /** Walks the whole Shizuku flow with no user taps: launch → permission → bind. */
    private fun autoConnectShizuku() {
        when (ShizukuBridge.state(this)) {
            ShizukuBridge.State.NOT_INSTALLED -> refreshShizuku()
            ShizukuBridge.State.NOT_RUNNING -> {
                if (!shizukuConnectPending) {
                    shizukuConnectPending = true
                    if (ShizukuBridge.openShizukuApp(this)) {
                        Toast.makeText(this, R.string.toast_shizuku_opening, Toast.LENGTH_LONG).show()
                        shizukuStatus.setText(R.string.shizuku_status_stopped)
                    } else {
                        shizukuConnectPending = false
                        refreshShizuku()
                    }
                }
            }
            ShizukuBridge.State.PERMISSION_REQUIRED -> {
                if (!permissionAutoRequested) {
                    permissionAutoRequested = true
                    ShizukuBridge.requestPermission()
                } else {
                    refreshShizuku()
                }
            }
            ShizukuBridge.State.RUNNING -> bindUserService()
        }
    }

    private fun bindUserService() {
        if (shizukuConnectPending) return
        shizukuConnectPending = true
        shizukuStatus.setText(R.string.shizuku_status_binding)
        Thread {
            val svc = ShizukuBridge.ensureService(applicationContext)
            mainHandler.post {
                shizukuConnectPending = false
                if (svc != null) {
                    shizukuStatus.setText(R.string.shizuku_status_bound)
                } else {
                    Toast.makeText(this, R.string.toast_shizuku_bind_failed, Toast.LENGTH_LONG).show()
                    refreshShizuku()
                }
            }
        }.start()
    }

    private fun confirmRevokeAll() {
        AlertDialog.Builder(this)
            .setTitle(R.string.btn_revoke_all)
            .setMessage(R.string.revoke_all_confirm)
            .setPositiveButton(R.string.btn_revoke) { _, _ -> engine.revokeAll() }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun localIpv4s(): List<String> = try {
        val out = mutableListOf<String>()
        NetworkInterface.getNetworkInterfaces()?.asSequence()?.forEach { nif ->
            if (nif.isUp && !nif.isLoopback) {
                nif.inetAddresses?.asSequence()?.forEach { addr ->
                    if (addr is java.net.Inet4Address && !addr.isLoopbackAddress) {
                        out.add(addr.hostAddress ?: return@forEach)
                    }
                }
            }
        }
        out
    } catch (_: Exception) {
        emptyList()
    }
}

private class DeviceAdapter(
    var items: List<Pair<String, AllowEntry>>,
    private val onRevoke: (String) -> Unit,
) : RecyclerView.Adapter<DeviceAdapter.VH>() {

    class VH(view: View) : RecyclerView.ViewHolder(view) {
        val label: TextView = view.findViewById(R.id.deviceLabel)
        val fp: TextView = view.findViewById(R.id.deviceFp)
        val btn: MaterialButton = view.findViewById(R.id.btnRevoke)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_device, parent, false)
        return VH(view)
    }

    override fun onBindViewHolder(holder: VH, position: Int) {
        val (spki, entry) = items[position]
        holder.label.text = entry.label
        holder.fp.text = spki.take(24) + "…"
        holder.btn.setOnClickListener { onRevoke(spki) }
    }

    override fun getItemCount(): Int = items.size
}
