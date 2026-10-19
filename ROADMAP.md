# Roadmap

## v0.3.0 (current)

- [x] Protocol spec (`docs/PROTOCOL.md`) + cross-language test vectors
- [x] Go agent: pairing, pinned mTLS, local forward, control channel, `selftest`
- [x] Android app: TLS server, pairing with lockout, allowlist, foreground service
- [x] In-app mini-adbd served through a Shizuku UserService (shell/exec/sync/reboot);
      no adbd, no Wireless debugging, no port scanning
- [ ] Live end-to-end test PC ↔ phone over Tailscale (adb shell/install/push/pull)

## Next

- [ ] PTY for interactive shells + CRLF translation (adbd parity)
- [ ] `shell_v2` + exit codes (`adb shell` returning real status)
- [ ] QR code for pairing (encode `code@host:port`, skip typing)
- [ ] Keepalive/reconnect in the agent (`up --watch`), per-device connect
      history in the app
- [ ] Multi-user profiles: separate allowlists per phone profile/work profile
- [ ] Release pipeline: signed release APK + tagged Go binaries (goreleaser)

## Ideas / backlog

- Socket forwarding (`tcp:` service) — would unlock scrcpy and `adb forward`
- One-tap "connect this PC" via LAN mDNS discovery of the agent
- Optional: no-tailscale mode using a public relay you host yourself
- Windows service mode for the agent (run at boot)
