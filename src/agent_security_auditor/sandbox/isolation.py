"""Pre-flight isolation verification for CONTROLLED DYNAMIC mode.

Dynamic tests only start when every check passes. There is no fallback to the real
environment: a failed check aborts the run.

Network check: a UDP ``connect()`` to a documentation-only address (RFC 5737 / RFC 3849)
consults the routing table without sending any packet. If a route exists, the host has
network access and is NOT considered isolated (run inside e.g. ``docker run --network none``).
"""

from __future__ import annotations

import os
import re
import socket
from dataclasses import dataclass, field
from pathlib import Path

CREDENTIAL_ENV = re.compile(
    r"(?i)^(AWS_|AZURE_|GOOGLE_APPLICATION_CREDENTIALS|GCP_|GITHUB_TOKEN|GH_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|"
    r"HF_TOKEN|SLACK_|STRIPE_|DATABASE_URL|.*_API_KEY$|.*_SECRET$|.*_TOKEN$|.*_PASSWORD$)"
)
PROBE_V4 = ("192.0.2.1", 9)      # TEST-NET-1, never routed on the internet
PROBE_V6 = ("2001:db8::1", 9)    # documentation prefix


@dataclass
class IsolationReport:
    ok: bool
    checks: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"isolated": self.ok, "checks": self.checks}


def _route_exists(family: int, addr: tuple) -> bool:
    try:
        s = socket.socket(family, socket.SOCK_DGRAM)
    except OSError:
        return False
    try:
        s.connect(addr)  # UDP connect: no packet is sent
        return True
    except OSError:
        return False
    finally:
        s.close()


def verify_isolation(env: dict[str, str] | None = None) -> IsolationReport:
    env = dict(os.environ if env is None else env)
    checks: list[dict[str, str]] = []

    def add(name: str, ok: bool, detail: str) -> None:
        checks.append({"check": name, "status": "PASS" if ok else "FAIL", "detail": detail})

    v4 = _route_exists(socket.AF_INET, PROBE_V4)
    v6 = _route_exists(socket.AF_INET6, PROBE_V6) if socket.has_ipv6 else False
    add("no_external_network_route", not (v4 or v6),
        "no route to external networks" if not (v4 or v6) else
        f"external route available (ipv4={v4}, ipv6={v6}); run inside a network-less container")
    creds = sorted(k for k in env if CREDENTIAL_ENV.match(k))
    add("no_credentials_in_environment", not creds,
        "no credential-like environment variables" if not creds else f"credential-like variables present: {', '.join(creds)}")
    proxies = sorted(k for k in env if k.lower() in ("http_proxy", "https_proxy", "all_proxy"))
    add("no_proxy_configuration", not proxies, "no proxy variables" if not proxies else f"proxy variables: {', '.join(proxies)}")
    dock = Path("/var/run/docker.sock").exists()
    add("no_container_runtime_socket", not dock, "docker socket not present" if not dock else "/var/run/docker.sock is reachable")
    return IsolationReport(all(c["status"] == "PASS" for c in checks), checks)
