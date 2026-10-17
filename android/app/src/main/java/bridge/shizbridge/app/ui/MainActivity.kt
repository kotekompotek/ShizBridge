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
import android.view.inputmethod.EditorInfo
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
import com.google.android.material.button.MaterialButton
import com.google.android.material.textfield.TextInputEditText
import java.net.NetworkInterface

class MainActivity : AppCompatActivity(), BridgeEngine.Listener {

    private lateinit var engine: BridgeEngine
    private lateinit var statusTitle: TextView
    private lateinit var statusAddr: TextView
    private lateinit var btnStartStop: MaterialButton
    private lateinit var codeText: TextView
    private lateinit var codeExpiry: TextView
    private lateinit var btnRegen: MaterialButton
    private lateinit var btnCopy: MaterialButton
    private lateinit var portInput: TextInputEditText
    private lateinit var portHint: TextView
    private lateinit var btnDetect: MaterialButton
    private lateinit var btnRevokeAll: MaterialButton
    private lateinit var devicesEmpty: TextView
    private lateinit var deviceList: RecyclerView
    private lateinit var logText: TextView

    private val mainHandler = Handler(Looper.getMainLooper())
    private val logBuffer = ArrayDeque<String>()
    private lateinit var deviceAdapter: DeviceAdapter

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
        portInput = findViewById(R.id.portInput)
        portHint = findViewById(R.id.portHint)
        btnDetect = findViewById(R.id.btnDetect)
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
        btnDetect.setOnClickListener { detectPort() }
        btnRevokeAll.setOnClickListener { confirmRevokeAll() }

        portInput.setOnFocusChangeListener { _, hasFocus -> if (!hasFocus) savePort() }
        portInput.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_DONE) {
                savePort()
                portInput.clearFocus()
                true
            } else {
                false
            }
        }

        refreshAll()
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
        portInput.setText(if (engine.prefs.adbdPort > 0) engine.prefs.adbdPort.toString() else "")
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

    private fun detectPort() {
        btnDetect.isEnabled = false
        Thread {
            val port = engine.detectAdbd()
            runOnUiThread {
                btnDetect.isEnabled = true
                if (port > 0) {
                    portInput.setText(port.toString())
                    Toast.makeText(this, getString(R.string.toast_detected, port), Toast.LENGTH_SHORT).show()
                    portHint.text = getString(R.string.toast_detected, port)
                } else {
                    Toast.makeText(this, R.string.toast_notfound, Toast.LENGTH_LONG).show()
                    portHint.setText(R.string.adbd_hint)
                }
            }
        }.start()
    }

    private fun savePort() {
        val p = portInput.text?.toString()?.trim()?.toIntOrNull() ?: return
        if (p in 1..65535) {
            engine.setAdbdPort(p)
            Toast.makeText(this, getString(R.string.toast_port_saved, p), Toast.LENGTH_SHORT).show()
            portHint.text = getString(R.string.toast_port_saved, p)
        }
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
