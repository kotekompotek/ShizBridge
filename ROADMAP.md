# Roadmap

## MVP (current)

- [x] Protocol spec (`docs/PROTOCOL.md`) + cross-language test vectors
- [x] Go agent: pairing, pinned mTLS, local forward, control channel, `selftest`
- [x] Android app: TLS server, pairing with lockout, allowlist, relay,
      foreground service, adbd auto-detection (`/proc` + CNXN probe)
- [ ] Live end-to-end test PC ↔ phone over Tailscale

## Next

- [ ] Shizuku-based adbd management (read wireless-debugging port directly,
      `adb tcpip 5555`, show Shizuku state in `info`)
- [ ] QR code for pairing (encode `code@host:port`, skip typing)
- [ ] Keepalive/reconnect in the agent (`up --watch`), per-device connect
      history in the app
- [ ] Multi-user profiles: separate allowlists per phone profile/work profile
- [ ] Release pipeline: signed release APK + tagged Go binaries (goreleaser)
- [ ] scrcpy-through-tunnel soak test (video = best stress test for the relay)

## Ideas / backlog

- One-tap "connect this PC" via LAN mDNS discovery of the agent
- Optional: no-tailscale mode using a public relay you host yourself
- Windows service mode for the agent (run at boot)
