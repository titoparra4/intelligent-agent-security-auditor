# Spyware and covert-behavior indicators (MODULE 04)

**Principle:** capabilities are not verdicts. Agents legitimately read files and use the network.
The module separates *capabilities* (inventoried) from *indicators* (reported for review) and never
labels code as spyware automatically.

| Indicator (EXF-003) | Examples detected | Default severity |
|---|---|---|
| clipboard | `pyperclip.paste`, `pbpaste`, `Get-Clipboard` | MEDIUM |
| camera / microphone | `cv2.VideoCapture`, `getUserMedia`, `sounddevice.rec`, `pyaudio` | HIGH |
| keystrokes | `pynput.keyboard`, `keyboard.hook`, `SetWindowsHookEx` | HIGH |
| screenshots | `ImageGrab.grab`, `mss`, `pyautogui.screenshot` | MEDIUM |
| credential stores | `~/.ssh`, `~/.aws/credentials`, `.netrc`, keychain access | HIGH |
| browser data | Chrome/Firefox/Safari profile paths, `browser_cookie3` | HIGH |
| host fingerprinting | user + platform info sent over HTTP, env dumps | MEDIUM |

| Hidden behavior (EXF-004) | Examples |
|---|---|
| persistence | crontab, LaunchAgents/Daemons, systemd units, registry Run keys, shell profiles |
| obfuscated execution | `exec`/`eval` of `b64decode`/`decompress`/`unhexlify`/`marshal.loads` output |
| detached processes | `Popen(..., start_new_session=True)` and similar |

Undeclared telemetry (EXF-005): analytics/tracing SDK imports not listed under `telemetry:` in the
manifest (Sentry, PostHog, Mixpanel, Segment, Datadog, LangSmith, Langfuse, OpenTelemetry, …).

## Triage guidance

1. Is the capability required by the agent's declared purpose? If yes, declare it (manifest +
   user disclosure) and scope it. If no, remove it.
2. Is the code path reachable from a tool or at install time? Install-time hooks are reported by
   SUP-003 and never executed.
3. Indicators flagged `requires_specialized_review` (EXF-004) should go to a code-level review.

## Dynamic analysis

Only inside the verified sandbox (MODULE 11): no network, no real data, audit-hook guards that
block and log network, process creation and writes. Blocked operations are reported in the
scenario result ("sandbox blocked: …").
