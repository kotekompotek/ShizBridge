package bridge.shizbridge.app.core

import android.content.Context
import android.content.SharedPreferences
import com.google.gson.reflect.TypeToken

data class AllowEntry(val label: String, val addedAt: Long)

/** Persistent app state: server identity, allowlist, pairing lockout, ports. */
class Prefs(context: Context) {

    private val sp: SharedPreferences =
        context.applicationContext.getSharedPreferences("shizbridge", Context.MODE_PRIVATE)

    companion object {
        private const val K_CERT = "server_cert_der"
        private const val K_KEY = "server_key_pkcs8"
        private const val K_PORT = "listen_port"
        private const val K_ALLOW = "allowlist"
        private const val K_ATTEMPTS = "pair_attempts"
        private const val K_LOCKOUT = "pair_lockout_until"
    }

    // ---- server identity ----

    var serverCertDer: ByteArray?
        get() = sp.getString(K_CERT, null)?.let { Crypto.b64Decode(it) }
        set(value) = sp.edit().putString(K_CERT, value?.let { Crypto.b64(it) }).apply()

    var serverKeyPkcs8: ByteArray?
        get() = sp.getString(K_KEY, null)?.let { Crypto.b64Decode(it) }
        set(value) = sp.edit().putString(K_KEY, value?.let { Crypto.b64(it) }).apply()

    // ---- ports ----

    val listenPort: Int
        get() = sp.getInt(K_PORT, Proto.DEFAULT_PORT)

    // ---- pairing lockout ----

    var pairingAttempts: Int
        get() = sp.getInt(K_ATTEMPTS, 0)
        set(value) = sp.edit().putInt(K_ATTEMPTS, value).apply()

    var lockoutUntil: Long
        get() = sp.getLong(K_LOCKOUT, 0L)
        set(value) = sp.edit().putLong(K_LOCKOUT, value).apply()

    fun clearLockout() {
        sp.edit().remove(K_ATTEMPTS).remove(K_LOCKOUT).apply()
    }

    // ---- allowlist ----

    @Suppress("UNCHECKED_CAST")
    fun allowlist(): LinkedHashMap<String, AllowEntry> {
        val json = sp.getString(K_ALLOW, null) ?: return LinkedHashMap()
        val type = object : TypeToken<LinkedHashMap<String, AllowEntry>>() {}.type
        return Proto.gson.fromJson<LinkedHashMap<String, AllowEntry>>(json, type) ?: LinkedHashMap()
    }

    fun saveAllowlist(map: Map<String, AllowEntry>) {
        sp.edit().putString(K_ALLOW, Proto.gson.toJson(map)).apply()
    }

    fun enroll(spki: String, label: String) {
        val map = allowlist()
        map[spki] = AllowEntry(label, System.currentTimeMillis())
        saveAllowlist(map)
    }

    fun revoke(spki: String) {
        val map = allowlist()
        map.remove(spki)
        saveAllowlist(map)
    }

    fun revokeAll() {
        saveAllowlist(LinkedHashMap())
    }
}
