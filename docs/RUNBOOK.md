# ShizBridge Runbook — подключение, живые ресурсы, диагностика

Инструкция для оператора/агента: как подключаться к телефону через ADB по
интернету и где лежит уже инициированное подключение. Рабочая машина — Windows,
репозиторий — `C:\Users\palpa\Documents\ShizBridge` (GitHub `kotekompotek/ShizBridge`,
ветка `main`).

## 1. Схема

```
adb (tcp:5037, ПК)  →  127.0.0.1:5555          ← слушает shizbridge up (fwd)
                       fwd: pin-TLS дайл        →  телефон :8787 (ShizBridge app)
                       телефон терминирует ADB-протокол в Shizuku UserService (uid 2000)
```

Всё шифруется пинованным TLS (сертификат телефона + клиентский сертификат ПК),
пароль/подпись ADB не используется. Поддерживается `shell:`, `exec:`, `exec-out:`,
`sync:`, `reboot:`; `tcp:`/`localabstract:`/`forward` — не поддерживаются (см. ROADMAP).

## 2. Где лежит уже инициированное подключение

| Что | Где | Как проверить |
|---|---|---|
| ADB-транспорт | внутри adb-сервера `tcp:5037`, запись `127.0.0.1:5555` | `adb devices` → строка `127.0.0.1:5555  device` |
| Туннель (fwd) | процесс `shizbridge.exe up` (отдельный, detached), слушает `127.0.0.1:5555` | `Get-CimInstance Win32_Process -Filter "Name='shizbridge.exe'"` |
| Pairing/identity ПК | `%AppData%\shizbridge\`: `config.json` (server_host/port/pin), `client.crt`, `client.key` | `shizbridge status --json` |
| Лог туннеля | `C:\Users\palpa\Documents\telegainator\up.err` (stderr: `[conn]/[u#]/[d#]/[err]/[warn]`), `up.log` (stdout) | `Get-Content ...\up.err -Tail 30` |
| Сервер на телефоне | приложение ShizBridge, порт `:8787`, всегда брать IP с экрана приложения | экран приложения / `status --json` |
| APK для установки | `android\app\build\outputs\apk\debug\app-debug.apk` | отправляется пользователю в Telegram |

Актуальные значения на 19.10.2026:

- телефон (Tailscale, стабилен): `100.123.144.126:8787`; LAN-IP телефона
  меняется — для `pair`/`up` использовать Tailscale-адрес или IP с экрана приложения;
- пин (отпечаток сертификата телефона, = `server_pin` в config.json):
  `5eb0e11ddb61760e35e4748c713a5f6ea6b29620679e1d134eb5025eae7fb8dc`;
- adb: `C:\Program Files\platform-tools\adb.exe` (36.0.0);
- CLI: `C:\Users\palpa\Documents\ShizBridge\agent\shizbridge.exe`
  (команды: `pair`, `up`, `status`, `selftest`; флаги перед позиционными).

**Главное для другого агента:** подключение уже живое — если `adb devices`
показывает `127.0.0.1:5555  device`, НИЧЕГО перезапускать не нужно, просто
работай: `adb shell …`. Переподключение нужно только при упавших компонентах
(сек. 5).

## 3. Полное подключение с нуля (или восстановление)

1. **Телефон**: открыть ShizBridge → «Start server» (экран покажет `:8787` и IP).
   Shizuku подключается автоматически: при первом открытии система спросит
   доступ — Approve; дальше статус сам доходит до «UserService bound».
2. **Проверка с ПК**: `shizbridge status --json` → `phone: reachable`,
   `shizuku: running`, `local: listening` (или `not listening` — тогда шаг 4).
3. **Если pairing отсутствует** (переустановка приложения, новый ПК):
   на телефоне «New code» (код живёт 5 минут, одноразовый), затем
   `shizbridge pair --server 100.123.144.126:8787 <КОДБЕЗПРОБЕЛОВ>`.
   Успешный вывод содержит `phone pin` — он должен совпасть с пином выше.
4. **Туннель**: `shizbridge up` — запускать ТОЛЬКО detached (см. правила §4).
   В логе: `[ok] local listener on 127.0.0.1:5555 -> … (tls, pinned)`.
5. **ADB**: `adb connect 127.0.0.1:5555` → `adb devices` → `device` →
   `adb shell id` → `uid=2000(shell)`.

## 4. Правила (по нажженным зависаниям)

- **Никогда `adb kill-server`** — на этой машине зависает навечно.
  Безопасно: `adb disconnect 127.0.0.1:5555` / `adb connect`; если сервер
  реально нужно убить — только `Stop-Process -Name adb` (прямое убийство процесса).
- **Любой adb — через редирект в файл**:
  `cmd /c "adb <…> > C:\Users\palpa\Documents\telegainator\tmp.txt 2>&1"`.
  Холодный старт демона наследует pipe и может держать его часами.
- **Долгие процессы только detached** (`shizbridge up`, `gradlew`, `nodaemon`
  серверы) — не из foreground bash:
  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
    CommandLine = 'cmd.exe /c ""C:\path\shizbridge.exe" up > "up.log" 2> "up.err""'
  }
  ```
- **Логи читать только снизу**: `Get-Content <log> -Tail 30`; `-Wait` запрещён.
- Всем bash-командам явный `-Timeout` (30–120 с).
- `gradlew` — только с `JAVA_HOME=C:\Program Files\Android\Android Studio\jbr`
  и редиректом в `gradle_build.log`; сборка 1–12 мин (холодный демон).

## 5. Диагностика отказов

| Симптом | Причина | Действие |
|---|---|---|
| `adb connect` → `failed`, транспорт `offline` | упал туннель / телефонный сервер / Shizuku | `shizbridge status --json`; лог `up.err` -Tail 30; поднять телефонный сервер |
| `phone: unreachable` / `actively refused` | приложение на телефоне не запущено (стоп/переустановка) | открыть ShizBridge → Start server |
| `[err] … pausing accepts for 2m` | circuit-breaker: 5 «тихих» сессий подряд (телефон закрыл без ответа) | не перезапускать агента в цикле! Ждать ≤2 мин; чинить телефон: приложение открыто, «UserService bound», версия с wire-фиксом |
| `[u#N] …315B` + `[d#N] 0B` | телефон принял CNXN и молча закрыл | обычно старый APK (без фикса байтового порядка констант ADB) или не связан Shizuku |
| `pair … error: pairing rejected: bad_code` | код истёк (5 мин), уже использован, или перепутаны `0/O` | «New code» на экране телефона, повторить |
| паринг «пропал» после установки APK | переустановка чистит allowlist телефона | заново `pair` (шаг 3); identity телефона при этом сохраняется, пин не меняется |
| `emulator-5554 offline/device` в `adb devices` | мусорный транспорт эмулятора | игнорировать, к ShizBridge отношения не имеет |
| нужен чистый статус | — | `shizbridge status --json`: `phone/shizuku/local` |

Быстрый чеклист живости:

```
shizbridge status --json      → phone reachable, shizuku running, local listening
adb devices                   → 127.0.0.1:5555 device
adb shell id                  → uid=2000(shell) …
Get-Content <telegainator>\up.err -Tail 5   → нет [err]/[warn]
```

## 6. Тестовые/диагностические инструменты

- `agent/cmd/adbprobe` — мини-ADB-клиент: `set PLAIN=1 && go run ./cmd/adbprobe 127.0.0.1:5555`
  (через туннель, обычный TCP) или `go run ./cmd/adbprobe 100.123.144.126:8787`
  (напрямую в pin-TLS). Показывает рукопожатие CNXN/OPEN/WRTE — быстро
  отличает «сломан туннель» от «сломан телефон».
- `agent/cmd/probe` — пробник паринга (одноразовый код → пин).
- `shizbridge selftest` — локальная проверка крипто/протокола без телефона.
- Юнит-тесты протокола: `android/…/test/…/AdbProtoTest.kt`
  (запуск: `gradlew :app:testDebugUnitTest`, включая проверку эталонного
  wire-порядка `43 4E 58 4E`).

## 7. Ключевые файлы в репозитории

- `agent/internal/fwd/fwd.go` — туннель, peek-логирование, circuit-breaker;
- `agent/cmd/shizbridge/main.go` — CLI (`pair/up/status/selftest`);
- `android/…/core/AdbProto.kt` — wire-формат ADB (константы команд в
  стандартном байтовом порядке!);
- `android/…/core/AdbDeviceSession.kt` — мини-adbd на телефоне;
- `android/…/core/ShizukuBridge.kt` — bounded-биндинг UserService;
- `android/…/ui/MainActivity.kt` — авто-подключение Shizuku;
- `docs/PROTOCOL.md` — протокол PC↔телефон; `AGENT_HANDOFF.md` — хронология
  работ и инцидентов.
