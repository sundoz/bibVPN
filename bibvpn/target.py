"""Check whether a site is a good Reality `sni` (the site the node impersonates).

A good target:
* speaks TLS 1.3 and HTTP/2 (Reality requires TLS 1.3; h2 keeps the fingerprint normal);
* presents a certificate valid for that exact name;
* is not blocked in Russia and is not a "too famous" name (Xray itself warns about
  apple/microsoft/etc., and many nodes sharing one SNI get correlated);
* ideally is hosted close to the node (same country / ASN), so that a node in, say,
  Finland claiming to be a Finnish site is plausible, and RTT stays similar.

Run it *from the node* (or from a machine near it) for meaningful latency numbers.
"""

import socket
import ssl
import time
from dataclasses import dataclass, field

# Names Xray flags as increasing block risk, plus other overused defaults from guides.
OVERUSED = (
    "apple.com", "icloud.com", "microsoft.com", "bing.com", "google.com", "yahoo.com",
    "amazon.com", "cloudflare.com", "discord.com", "github.com", "speedtest.net",
)


@dataclass
class TargetReport:
    host: str
    ok: bool = True
    tls_version: str = ""
    alpn: str = ""
    rtt_ms: float = 0.0
    problems: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def check_target(host: str, timeout: float = 8.0, port: int = 443, ca_file: str | None = None) -> TargetReport:
    report = TargetReport(host=host)

    if any(host == d or host.endswith("." + d) for d in OVERUSED):
        report.warnings.append("overused target: pick a less famous site hosted near the node")

    ctx = ssl.create_default_context(cafile=ca_file)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    try:
        start = time.monotonic()
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                report.rtt_ms = (time.monotonic() - start) * 1000
                report.tls_version = tls.version() or ""
                report.alpn = tls.selected_alpn_protocol() or ""
    except ssl.SSLCertVerificationError as e:
        report.problems.append(f"certificate is not valid for {host}: {e.verify_message}")
    except ssl.SSLError as e:
        report.problems.append(f"TLS 1.3 handshake failed: {e.reason or e}")
    except OSError as e:
        report.problems.append(f"cannot connect to {host}:{port}: {e}")

    if report.tls_version and report.alpn != "h2":
        report.problems.append("server does not negotiate HTTP/2 (h2)")

    report.ok = not report.problems
    return report
