"""The certificate an address presents to a TLS client, read from the handshake.

Shared by origin discovery (is a candidate origin the brand's own server?) and
IP attribution (is an address dedicated to the target?): both dial without SNI
to see the certificate a server falls back to when it is not asked for a name.
Nothing here decides whether a dial is allowed; the caller applies its own
guards, rate limit and host health first.
"""

from __future__ import annotations

import socket
import ssl
from typing import Optional


def tls_handshake_cert(host_or_ip: str, sni: Optional[str], port: int, timeout: float) -> Optional[dict]:
    """TLS-dial host_or_ip:port, return {serial, cn, sans}. sni None sends no SNI.

    Raises the socket / TLS error, so a caller can say why the dial failed.
    """
    ctx_ssl = ssl.create_default_context()
    ctx_ssl.check_hostname = False
    ctx_ssl.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host_or_ip, port), timeout=timeout) as sock:
        with ctx_ssl.wrap_socket(sock, server_hostname=sni) as ssock:
            der = ssock.getpeercert(binary_form=True)
            cert = ssock.getpeercert()
    # getpeercert() returns {} with CERT_NONE, so parse the DER for the fields.
    return parse_cert_der(der, cert)


def parse_cert_der(der: bytes, decoded: dict) -> Optional[dict]:
    serial = None
    cn = None
    sans: set[str] = set()
    # decoded is usually {} under CERT_NONE; fall back to a DER parse via cryptography
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        c = x509.load_der_x509_certificate(der, default_backend())
        serial = str(c.serial_number)
        try:
            cn = c.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        except Exception:
            cn = None
        try:
            ext = c.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = {n.lower() for n in ext.value.get_values_for_type(x509.DNSName)}
        except Exception:
            sans = set()
    except Exception:
        if decoded:
            serial = decoded.get("serialNumber")
            for tup in decoded.get("subject", ()):
                for k, v in tup:
                    if k == "commonName":
                        cn = v
            sans = {v.lower() for (k, v) in decoded.get("subjectAltName", ()) if k == "DNS"}
    if serial is None and cn is None and not sans:
        return None
    return {"serial": serial, "cn": cn, "sans": sans}


def cert_names(cert: Optional[dict]) -> list[str]:
    """The certificate's CN and SANs, lower-cased and sorted: one stable value per cert."""
    if not cert:
        return []
    names = {cert.get("cn") or ""} | set(cert.get("sans") or ())
    return sorted({str(n).strip().lower().rstrip(".") for n in names} - {""})


def cert_covers(cert: dict, domain: str) -> bool:
    for name in cert_names(cert):
        if name.startswith("*."):
            name = name[2:]
        if name and (name == domain or name.endswith("." + domain)):
            return True
    return False


def tls_failure_reason(exc: BaseException, port: int) -> str:
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(exc, ConnectionRefusedError):
        return f"port {port} closed"
    if isinstance(exc, ssl.SSLError):
        return "TLS error"
    return "connection failed"
