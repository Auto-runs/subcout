"""Resume / checkpointing for long scans.

Large active scans (millions of brute candidates, recursive enumeration, ASN
sweeps) can run for a long time. If one is interrupted, you don't want to start
from scratch. A checkpoint file records every confirmed live host as it is
found (append-only JSONL). On a re-run with the same ``--resume FILE``, those
hosts are pre-loaded so they are neither lost nor re-emitted, and already-known
names are not re-resolved.

The format is plain JSONL (one ``Subdomain.to_dict()`` per line), so the same
file doubles as a usable result artifact and can be tailed live.
"""
from __future__ import annotations

import json
import logging
from typing import TextIO

from subscout.models import Subdomain

logger = logging.getLogger("subscout")


class Checkpoint:
    """Append-only JSONL checkpoint of confirmed live subdomains."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._fh: TextIO | None = None

    # ---- loading -------------------------------------------------------

    def load(self) -> dict[str, Subdomain]:
        """Read previously-saved hosts. Returns {name: Subdomain}. Last wins."""
        out: dict[str, Subdomain] = {}
        try:
            with open(self.path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    name = rec.get("name")
                    if not name:
                        continue
                    out[name] = self._from_dict(rec)
        except FileNotFoundError:
            return {}
        except OSError as exc:
            logger.warning("checkpoint: could not read %s: %s", self.path, exc)
            return {}
        if out:
            logger.info("checkpoint: resumed %d host(s) from %s", len(out), self.path)
        return out

    @staticmethod
    def _from_dict(rec: dict) -> Subdomain:
        sub = Subdomain(name=rec["name"], sources=set(rec.get("sources") or []))
        sub.resolved = bool(rec.get("resolved"))
        sub.a_records = list(rec.get("a_records") or [])
        sub.aaaa_records = list(rec.get("aaaa_records") or [])
        sub.cname = rec.get("cname")
        sub.takeover = bool(rec.get("takeover"))
        sub.takeover_service = rec.get("takeover_service")
        return sub

    # ---- appending -----------------------------------------------------

    def _ensure_open(self) -> TextIO | None:
        if self._fh is None:
            try:
                self._fh = open(self.path, "a", encoding="utf-8")
            except OSError as exc:
                logger.error("checkpoint: cannot write %s: %s", self.path, exc)
                self._fh = None
        return self._fh

    def append(self, sub: Subdomain) -> None:
        fh = self._ensure_open()
        if fh is None:
            return
        try:
            fh.write(json.dumps(sub.to_dict(), separators=(",", ":")) + "\n")
            fh.flush()
        except OSError as exc:
            logger.debug("checkpoint: append failed: %s", exc)

    def close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            finally:
                self._fh = None
