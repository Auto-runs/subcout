"""Active TLS certificate grabbing.

Connecting directly to a live host on 443 and reading its certificate often
reveals *other* hostnames: certs are routinely issued for several names at once
(Subject Alternative Names). Those SANs frequently include sibling subdomains
that never appeared in any passive dataset - so this is a cheap, high-signal way
to expand coverage from hosts you have already confirmed.

We extract:
  - dNSName entries from the SAN extension, and
  - the CN from the subject (legacy, but still seen),
then keep the ones in scope.

This is active (a real TLS handshake to the target) - authorized targets only.
"""
from __future__ import annotations

import asyncio
import logging
import ssl

from subscout.config import Config
from subscout.models import Subdomain
from subscout.utils import in_scope, normalize_domain

logger = logging.getLogger("subscout")


def extract_cert_names(cert: dict) -> set[str]:
    """Pull every hostname out of a parsed peer certificate dict.

    Accepts the structure returned by ``ssl.SSLSocket.getpeercert()``:
    ``subjectAltName`` is a tuple of ``(type, value)`` pairs; ``subject`` is a
    nested tuple of RDNs. Wildcards are de-wildcarded to their apex.
    """
    names: set[str] = set()

    for typ, value in cert.get("subjectAltName", ()) or ():
        if typ.lower() == "dns" and value:
            names.add(value)

    for rdn in cert.get("subject", ()) or ():
        for key, value in rdn:
            if key == "commonName" and value:
                names.add(value)

    cleaned: set[str] = set()
    for n in names:
        n = n.strip().lower().lstrip("*.")
        n = normalize_domain(n)
        if n:
            cleaned.add(n)
    return cleaned


class TLSGrabber:
    def __init__(self, config: Config) -> None:
        self.config = config
        self._sem = asyncio.Semaphore(config.http_concurrency)
        # We only want the cert, so disable verification (self-signed/expired
        # certs are common and still carry useful SANs).
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self._ctx = ctx

    async def _grab_one(self, host: str) -> set[str]:
        async with self._sem:
            try:
                fut = asyncio.open_connection(
                    host, self.config.tls_port, ssl=self._ctx,
                    server_hostname=host,
                )
                reader, writer = await asyncio.wait_for(fut, timeout=self.config.timeout)
            except Exception as exc:  # noqa: BLE001 - many hosts won't speak TLS
                logger.debug("tls %s failed: %s", host, exc)
                return set()
            try:
                ssl_obj = writer.get_extra_info("ssl_object")
                cert = ssl_obj.getpeercert() if ssl_obj else None
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:  # noqa: BLE001
                    pass
            return extract_cert_names(cert) if cert else set()

    async def grab_all(
        self, subdomains: list[Subdomain], scope_root: str
    ) -> list[Subdomain]:
        """Grab certs from resolved hosts; return new in-scope names found."""
        targets = [s.name for s in subdomains if s.resolved]
        if not targets:
            return []
        logger.info("tls: grabbing certificates from %d host(s)", len(targets))

        results = await asyncio.gather(*(self._grab_one(h) for h in targets))
        found: dict[str, Subdomain] = {}
        for names in results:
            for name in names:
                if in_scope(name, scope_root):
                    found.setdefault(name, Subdomain(name=name, sources={"tls-san"}))
        logger.info("tls: %d in-scope name(s) from certificates", len(found))
        return list(found.values())
