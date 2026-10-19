# ShizBridge

**Full ADB over the internet — through your own phone.**

Android's *Wireless debugging* refuses to work across networks ("both
devices must be on the same LAN"), and ADB has no built-in way through
NATs. ShizBridge fixes that with two small pieces you own end-to-end:

* an **Android app** that runs a hardened TLS server on the phone and
  serves ADB itself through **Shizuku** (shell privileges, no adbd, no
  Wireless debugging),
* a **Go agent** on your PC that pairs with it, then exposes a local
  ADB port (`127.0.0.1:5555`) tunneled straight to the app.

Put Tailscale (or any VPN) on both devices and `adb connect` works from
anywhere — home ↔ office, LAN ↔ LTE, anywhere in your tailnet.

```
   PC (Windows/macOS/Linux)                    Phone (Android 8+)
┌──────────────────────────┐               ┌──────────────────────────┐
│  adb / sdkmgr            │               │        ShizBridge app    │
│        │                 │               │  ┌────────────────────┐  │
│        ▼                 │    TLS 1.3    │  │  TLS server :8787  │  │
│ 127.0.0.1:5555 ──────────┼──── ╌╌ ╌╌ ────┼─▶│  pairing │ mini-adbd│  │
│        │                 │  (mTLS+pinned)│  └────┬────────────────┘  │
│  shizbridge up (agent)   │               │       │ binder            │
└──────────────────────────┘               │       ▼                   │
                                           │  Shizuku UserService      │
                                           │  (shell uid, sh / sync)   │
                                           └──────────────────────────┘
```

## Why it's not just "port forward ADB"

| Threat | Countermeasure |
|---|---|
| Anyone scanning your tailnet | mTLS — client certificate must be in the phone's allowlist |
| MITM during pairing | ECDH P-256 + one-time code proof, independent of the transport |
| Code brute-forcing | 60-bit Crockford code, 3 attempts → 10-minute lockout, 5-min TTL |
| Stolen PC | revoke the computer in the app UI → next connection is refused |
| Plain ADB on the wire | everything after TCP accept is TLS 1.3 (1.2 fallback) |

Trust is **pin-based**: both sides keep self-signed ECDSA P-256
certificates and pin each other's `SPKI-SHA256`. No CA, no accounts, no
cloud — the pairing code is the root of trust.

## Quick start

### Phone

1. Install [Shizuku](https://shizuku.rikka.app/) and start it (wireless
   debugging / root / pairing with a PC — follow its own guide).
2. Install `app-debug.apk` (or build: `cd android && ./gradlew assembleDebug`).
3. Open ShizBridge → **Connect Shizuku** (grant the permission) →
   **Start server** → copy the 12-character code.

No *Wireless debugging* toggle is needed — ShizBridge executes ADB
requests itself through Shizuku.

### PC

```bash
# one-time pairing (code from the phone; <phone-ip> is e.g. its Tailscale IP)
shizbridge pair MJGP2X4KQ7TA --server 100.77.77.26:8787

# start the local ADB forward (keeps running, auto-runs adb connect)
shizbridge up

# now just use adb as usual — over the internet
adb devices          # → 127.0.0.1:5555    device
adb install app.apk
adb shell
```

Works: `adb shell`, `install`, `push`/`pull`, `reboot`, and anything
else built on those. Doesn't (yet): `scrcpy`, `adb forward/reverse`,
`logcat -T`-style multi-stream tricks — there is no socket forwarding
through the tunnel.

Other commands: `shizbridge status [--json]`, `shizbridge revoke`,
`shizbridge selftest`.

## Repository layout

```
agent/                  Go CLI — pairing, pinned TLS client, local ADB forward
  internal/proto        frame codec + message types
  internal/cryptox      HKDF, record layer, X.509, pairing handshake + reference server
  internal/tlsclient    SPKI-pinned mTLS dialer
  internal/fwd          local listener → per-connection TLS tunnel → relay
  internal/ctl          control channel (ping/info)
  cmd/shizbridge        CLI entry point
android/                Kotlin app (Views, no Compose; minSdk 26, targetSdk 34)
  .../core/BridgeEngine the single-port TLS server: dispatch → pairing/control/ADB session
  .../core/X509Util     from-scratch DER writer for self-signed certs (no BC dep)
  .../core/AdbProto     ADB wire codec (24-byte LE header, credit-based flow)
  .../core/AdbDeviceSession  in-app mini-adbd: shell/exec/sync over Shizuku
  .../shizuku           UserService (AIDL) running as shell uid via Shizuku
  .../ui/MainActivity   pairing code, allowlist, Shizuku status, live log
docs/PROTOCOL.md        wire protocol v1 — the contract between Go and Kotlin
```

## Protocol (short version)

One TCP port, TLS-first. The first bytes after the handshake pick the
mode: `SBPR` → pairing handshake (ECDH + code proof + encrypted frames),
`SBCTL` → JSON control channel, anything else → ADB device session
(served by the app's own mini-adbd via Shizuku).
Full spec: [`docs/PROTOCOL.md`](docs/PROTOCOL.md).

Both implementations assert the **same test vectors**
(`agent/internal/cryptox/testdata/vectors.json`, mirrored into the
Android unit tests): RFC 5869 HKDF, the code-proof HMAC and the
AES-GCM record layer — so Go and Kotlin provably speak the same crypto.

## Status

v0.3.0 — crypto/protocol layer is unit-tested on both sides (Go +
Kotlin), `shizbridge selftest` validates the full pairing handshake
offline, and the phone serves real ADB sessions (`shell`, `install`,
`push`/`pull`) through a Shizuku UserService — no adbd, no Wireless
debugging. Live device soak-testing is in progress; see
[`ROADMAP.md`](ROADMAP.md) for what's next (PTY shells, `shell_v2`,
QR pairing).

## License

[MIT](LICENSE)
