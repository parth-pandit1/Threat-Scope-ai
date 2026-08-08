"""
SSL / TLS certificate inspector for domain scanning.

Connects to a host over TLS, retrieves the peer certificate, and
analyses it for expiry, self-signing, issuer, SANs, signature
algorithm, and key strength.

Scoring contribution: 0-10 points toward the overall threat score.
"""

import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# Well-known legitimate certificate issuers
# ─────────────────────────────────────────────────────────────

KNOWN_ISSUERS: set[str] = {
    "let's encrypt",
    "digicert",
    "comodo",
    "sectigo",
    "geotrust",
    "globalsign",
    "godaddy",
    "amazon",
    "google trust services",
    "cloudflare",
    "microsoft",
    "starfield",
    "entrust",
    "thawte",
    "verisign",
    "buypass",
    "certum",
    "zerossl",
}


def inspect_ssl(hostname: str, port: int = 443) -> dict[str, Any]:
    """
    Connect to a host and analyse its SSL/TLS certificate.

    Args:
        hostname: Domain name to inspect.
        port: Port to connect to (default 443).

    Returns:
        Dictionary with certificate metadata, validity flags,
        and an ``ssl_score`` (0-10) threat contribution.

    All exceptions are caught — never crashes the parent scan.
    """
    result: dict[str, Any] = {"ssl_available": False}

    try:
        # Build an unverified context to still retrieve the cert
        # even if it's self-signed or expired
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                tls_version = ssock.version() or "unknown"
                cert_bin = ssock.getpeercert(binary_form=True)
                cert = ssock.getpeercert()

        if not cert:
            # Try decoding the binary DER cert
            result["ssl_available"] = False
            result["error"] = "No certificate presented"
            result["ssl_score"] = 5
            return result

        result["ssl_available"] = True

        # ── Issued to / by ───────────────────
        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))

        result["issued_to"] = subject.get("commonName", hostname)
        result["issued_by"] = issuer.get("commonName", "unknown")
        result["issuer_org"] = issuer.get("organizationName", "unknown")

        # ── Validity dates ───────────────────
        not_before_str = cert.get("notBefore", "")
        not_after_str = cert.get("notAfter", "")

        try:
            not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            now = datetime.now(timezone.utc)

            result["valid_from"] = not_before.strftime("%Y-%m-%d")
            result["valid_until"] = not_after.strftime("%Y-%m-%d")
            result["is_expired"] = now > not_after
            result["days_until_expiry"] = max(0, (not_after - now).days)
        except (ValueError, TypeError):
            result["valid_from"] = not_before_str
            result["valid_until"] = not_after_str
            result["is_expired"] = False
            result["days_until_expiry"] = None

        # ── Self-signed check ────────────────
        result["is_self_signed"] = (
            result["issued_to"] == result["issued_by"]
            or subject == issuer
        )

        # ── Overall validity ─────────────────
        result["is_valid"] = not result["is_expired"] and not result["is_self_signed"]

        # ── SAN domains ──────────────────────
        san_list: list[str] = []
        for san_type, san_value in cert.get("subjectAltName", ()):
            if san_type == "DNS":
                san_list.append(san_value)
        result["san_domains"] = san_list

        # ── Signature algorithm ──────────────
        result["signature_algorithm"] = cert.get(
            "signatureAlgorithm", "unknown"
        ) if "signatureAlgorithm" in cert else "unknown"

        # ── TLS version ──────────────────────
        result["tls_version"] = tls_version

        # ── Key bits (from binary cert) ──────
        try:
            from ssl import DER_cert_to_PEM_cert
            # Key bits are not directly available from getpeercert()
            # so we set a placeholder; full X.509 parsing needs cryptography lib
            result["key_bits"] = None
        except Exception:
            result["key_bits"] = None

        # ── Score + notes ────────────────────
        ssl_score, ssl_notes = get_ssl_score(result)
        result["ssl_score"] = ssl_score
        result["ssl_notes"] = ssl_notes

        return result

    except socket.timeout:
        logger.debug("SSL connection timed out for %s:%d", hostname, port)
        return {
            "ssl_available": False,
            "error": "Connection timed out (5s)",
            "ssl_score": 0,
            "ssl_notes": [],
        }
    except ConnectionRefusedError:
        logger.debug("SSL connection refused for %s:%d", hostname, port)
        return {
            "ssl_available": False,
            "error": "Connection refused",
            "ssl_score": 0,
            "ssl_notes": [],
        }
    except OSError as exc:
        logger.debug("SSL connection error for %s:%d: %s", hostname, port, str(exc))
        return {
            "ssl_available": False,
            "error": str(exc),
            "ssl_score": 0,
            "ssl_notes": [],
        }
    except Exception as exc:
        logger.warning("SSL inspection failed for %s:%d: %s", hostname, port, str(exc))
        return {
            "ssl_available": False,
            "error": str(exc),
            "ssl_score": 0,
            "ssl_notes": [],
        }


def get_ssl_score(ssl_result: dict[str, Any]) -> tuple[int, list[str]]:
    """
    Calculate the SSL threat-score contribution (0-10).

    Scoring:
    - Not available on HTTPS target: +5
    - Expired certificate: +10 (capped)
    - Self-signed certificate: +7
    - Expiring within 7 days: +3
    - Unknown / untrusted issuer: +2

    Returns:
        Tuple of ``(score, list_of_notes)``.
    """
    score = 0
    notes: list[str] = []

    if not ssl_result.get("ssl_available"):
        # No SSL = slight risk (could be HTTP-only site)
        return 0, ["SSL not available or not applicable"]

    if ssl_result.get("is_expired"):
        score += 10
        notes.append("Certificate is expired")

    if ssl_result.get("is_self_signed"):
        score += 7
        notes.append("Certificate is self-signed")

    days = ssl_result.get("days_until_expiry")
    if days is not None and days <= 7 and not ssl_result.get("is_expired"):
        score += 3
        notes.append(f"Certificate expires in {days} day(s)")

    issuer_org = str(ssl_result.get("issuer_org", "")).lower()
    if issuer_org and issuer_org != "unknown":
        if not any(known in issuer_org for known in KNOWN_ISSUERS):
            score += 2
            notes.append(f"Uncommon certificate issuer: {ssl_result.get('issuer_org')}")

    if not notes:
        notes.append("Valid SSL certificate from a trusted issuer")

    return min(10, score), notes
