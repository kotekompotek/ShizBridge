# ShizBridge — разбор зависаний opencode (2026-10-19)

## Что случилось

Агент (MyCode) вёл диагностику тоннеля ShizBridge через bash и «висел» на часы:

| Команда | Длительность | Причина |
|---|---|---|
| `Get-Content up.log, up.err ...` | 6ч 36м | follow/large log либо ожидание, пока stderr-писатель (реконнект-шторм) не замолкает |
| `adb connect 127.0.0.1:5555; ... Get-Content fwd log` | 3ч 49м | adb connect к мёртвой mini-adbd; потом чтение лога, который писался каждые ~450 мс |
| `Start-Process adb ... nodaemon` | 19–54 мин | фоновый демон унаследовал stdio; opencode ждал закрытия пайпа |
| `shizbridge pair` / `shizbridge up` из foreground bash | 1ч 15м+ | вечный демон в process tree PowerShell |
| gradle build | 12–56 мин | kotlin/gradle daemon; нормально, но тоже не отдавать bash |

## Корневая причина шторма в логах

На телефоне **Shizuku UserService мёртв**, хотя `status` показывает `shizuku=running`:

- TLS handshake проходит (пины, серт — ок),
- агент шлёт ADB `CNXN` (315 B),
- телефон закрывает сессию **0 байт в ответ**,
- adb/скрипты бесконечно переподключаются → ~6000+ conns, `up.err` 1.4–3.6 МБ.

`adbd_port=0, adbd_up=false` — **deprecated**, это нормально (v0.3.0 сам терминирует ADB).

## Что исправлено на PC

1. Убиты зависшие `shizbridge` / штормовые процессы.
2. В `agent/internal/fwd/fwd.go` добавлен **circuit-breaker**:
   - 5 подряд «TLS ok, но phone 0B» → пауза accept 2 минуты,
   - один warn вместо 3 строк × N conns в лог,
   - verbose peek-логи только первые 3 «здоровых» conns.
3. Пересобран `agent/shizbridge.exe` (`selftest` pass, `go test` pass).
4. Демон запущен **вне job object** (Win32_Process.Create + cmd /c redirect), PID в `telegainator`.

## Что нужно сделать на телефоне (вручную)

PC удалённо починить mini-adbd не может:

1. Открыть приложение **ShizBridge** на телефоне.
2. **Connect Shizuku** (перевыдать permission, если Shizuku перезапускался).
3. Убедиться, что **Shizuku running** (notification / приложение Shizuku).
4. **Start server** в ShizBridge.
5. На PC: `adb connect 127.0.0.1:5555` → должно быть `device`, не `offline`.

## Правила для агента (обязательно)

- **Никогда** не запускать из foreground bash вечные процессы:
  `shizbridge up`, `adb nodaemon server`, `gradlew`, `python -m ... run`.
  Демон — только detached:
  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
    CommandLine = 'cmd.exe /c ""C:\path\shizbridge.exe" up > "up.log" 2> "up.err""'
  }
  ```
- **Никогда** `Get-Content -Wait` / follow по `up.err` / `adb5038.err`.
  Только срез: `Get-Content up.err -Tail 30`.
- Любому bash с потенциально долгим io — явный `-Timeout` (30–120 с).
- `shizbridge status --json` — безопасная команда для проверки тоннеля.
- Circuit-breaker в агенте сам долбит «тихий» телефон; если в логе
  `pausing accepts for 2m` — чинить телефон, а не перезапускать в цикле.
- gradle/kotlin daemon живут сами; после build не ждать их смерти.

## Текущее состояние

- `shizbridge.exe up` — detached, listener 127.0.0.1:5555.
- Телефон reachable, Shizuku protocol-state running, **ADB-сессии всё ещё 0B** —
  нужен ручной re-grant Shizuku + Start server на телефоне.
- После починки телефона breaker снимет паузу сам (через PauseFor) или после
  первого успешного с down>0.
