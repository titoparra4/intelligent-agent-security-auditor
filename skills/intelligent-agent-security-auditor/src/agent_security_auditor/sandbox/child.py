"""Child process entry point for one dynamic scenario (runs ONLY inside the sandbox).

Defense in depth inside the child, on top of the pre-flight isolation check:

* a ``sys.addaudithook`` hook (cannot be removed once installed) blocks non-loopback socket
  connections, DNS resolution of non-local names, subprocess / os.system / exec / spawn and
  file writes outside the scenario's temporary directory;
* bytecode writing is disabled;
* the parent applies CPU / memory / file-size / open-file limits and a wall-clock timeout.

Protocol: JSON request on stdin, one JSON line prefixed with ``ASA-RESULT:`` on stdout.
"""

from __future__ import annotations

import importlib.util
import ipaddress
import json
import os
import sys
import traceback

BLOCKED_EVENTS = ("subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.fork", "os.forkpty",
                  "ctypes.dlopen", "os.startfile", "pty.spawn")
_blocked: list[str] = []


def _is_local(host: object) -> bool:
    h = str(host).strip("[]")
    if h in ("localhost", "", "None"):
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def _install_guard(workdir: str) -> None:
    work = os.path.realpath(workdir)

    def hook(event: str, args: tuple) -> None:
        if event == "socket.connect":
            addr = args[1]
            host = addr[0] if isinstance(addr, tuple) else addr
            if isinstance(host, str) and not _is_local(host):
                _blocked.append(f"network connect to {host}")
                raise PermissionError(f"sandbox: network access to {host} blocked")
        elif event == "socket.getaddrinfo":
            if not _is_local(args[0]):
                _blocked.append(f"dns lookup {args[0]}")
                raise PermissionError("sandbox: DNS resolution blocked")
        elif event in BLOCKED_EVENTS or event.startswith("os.exec") or event.startswith("os.spawn"):
            _blocked.append(event)
            raise PermissionError(f"sandbox: {event} blocked")
        elif event == "open":
            path, mode = args[0], args[1]
            writing = isinstance(mode, str) and any(c in mode for c in "wax+")
            if not writing and isinstance(args[2], int):
                writing = bool(args[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND))
            if writing and isinstance(path, (str, bytes)):
                p = os.path.realpath(path if isinstance(path, str) else path.decode(errors="replace"))
                if not p.startswith(work + os.sep) and p != work:
                    _blocked.append(f"write {p}")
                    raise PermissionError("sandbox: write outside scenario directory blocked")

    sys.addaudithook(hook)


def main() -> int:
    sys.dont_write_bytecode = True
    request = json.loads(sys.stdin.read())
    pkg_root = request["package_root"]
    if pkg_root not in sys.path:
        sys.path.insert(0, pkg_root)
    from agent_security_auditor.sandbox.env import SandboxEnv  # noqa: E402 (after sys.path setup)

    # resolve the harness location before the guard; its code only runs (exec_module) once the guard is active
    spec = importlib.util.spec_from_file_location("asa_harness", request["harness"])
    if spec is None or spec.loader is None:
        print("ASA-RESULT:" + json.dumps({"status": "ERROR", "error": "harness not loadable"}))
        return 0
    module = importlib.util.module_from_spec(spec)
    _install_guard(request["workdir"])
    env = SandboxEnv(request["fixture"], user=request.get("user", "user-a"), max_tool_calls=request.get("max_tool_calls", 50))
    status, error = "COMPLETED", None
    try:
        spec.loader.exec_module(module)
        run = getattr(module, "run", None)
        if not callable(run):
            raise AttributeError("harness must define run(task, env)")
        run(env.task, env)
    except Exception as exc:  # the agent under test may fail in any way; record it
        status = "AGENT_ERROR"
        error = f"{type(exc).__name__}: {exc}"[:500]
        env.errors.append(traceback.format_exc(limit=3)[-1500:])
    out = env.export()
    out.update({"status": status, "error": error, "blocked_operations": _blocked})
    sys.stdout.write("ASA-RESULT:" + json.dumps(out, default=str) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
