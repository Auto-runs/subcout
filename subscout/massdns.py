"""Optional massdns acceleration for mass DNS resolution.

Pure-Python asyncio resolution is fine for thousands of names, but active
brute-force / permutation over *millions* of candidates is bottlenecked by the
interpreter. `massdns <https://github.com/blechschmidt/massdns>`_ is a native
stub resolver that can push 100k+ queries/sec.

This module is an **optional accelerator**: if the ``massdns`` binary is on
``PATH`` (or pointed at via config), large batches are resolved through it;
otherwise everything falls back to the built-in async resolver transparently.
We never hard-depend on it, so subscout still works out of the box.

Output parsing uses massdns' simple text format (``-o S``), which is stable
across versions:

    www.example.com. A 93.184.216.34
    blog.example.com. CNAME ghost.example.io.
"""
from __future__ import annotations

import asyncio
import logging
import os
import shutil
import tempfile

logger = logging.getLogger("subscout")


def find_massdns(explicit: str | None = None) -> str | None:
    """Return a usable massdns binary path, or None if unavailable."""
    if explicit:
        if os.path.isfile(explicit) and os.access(explicit, os.X_OK):
            return explicit
        found = shutil.which(explicit)
        if found:
            return found
        logger.warning("massdns: configured path %r not executable", explicit)
        return None
    return shutil.which("massdns")


def _parse_simple(output: str) -> dict[str, tuple[list[str], str | None]]:
    """Parse massdns ``-o S`` output into {name: (a_records, cname)}."""
    records: dict[str, tuple[list[str], str | None]] = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        name = parts[0].rstrip(".").lower()
        rtype = parts[1].upper()
        value = parts[2].rstrip(".")
        a_records, cname = records.get(name, ([], None))
        if rtype == "A":
            if value not in a_records:
                a_records = a_records + [value]
        elif rtype == "CNAME":
            cname = value.lower()
        else:
            continue
        records[name] = (a_records, cname)
    return records


class MassDNS:
    """Thin async wrapper around the massdns binary."""

    def __init__(
        self,
        binary: str,
        resolvers: list[str],
        *,
        concurrency: int = 1000,
        timeout: float = 600.0,
    ) -> None:
        self.binary = binary
        self.resolvers = [r for r in resolvers if r]
        self.concurrency = max(100, concurrency)
        self.timeout = timeout

    async def resolve(self, names: list[str]) -> dict[str, tuple[list[str], str | None]]:
        """Resolve A/CNAME for *names*. Returns {name: (a_records, cname)}.

        Raises RuntimeError on failure so the caller can fall back cleanly.
        """
        if not names:
            return {}
        if not self.resolvers:
            raise RuntimeError("massdns: no resolvers available")

        names_fd, names_path = tempfile.mkstemp(prefix="subscout-names-", suffix=".txt")
        res_fd, res_path = tempfile.mkstemp(prefix="subscout-resolvers-", suffix=".txt")
        try:
            with os.fdopen(names_fd, "w", encoding="utf-8") as fh:
                fh.write("\n".join(names) + "\n")
            with os.fdopen(res_fd, "w", encoding="utf-8") as fh:
                fh.write("\n".join(self.resolvers) + "\n")

            cmd = [
                self.binary,
                "-r", res_path,
                "-t", "A",
                "-o", "S",
                "-q",
                "-s", str(self.concurrency),
                names_path,
            ]
            logger.info("massdns: resolving %d name(s) via %s", len(names), self.binary)
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=self.timeout
                )
            except asyncio.TimeoutError as exc:
                proc.kill()
                raise RuntimeError("massdns: timed out") from exc

            if proc.returncode != 0:
                msg = stderr.decode("utf-8", "replace").strip()
                raise RuntimeError(f"massdns: exit {proc.returncode}: {msg}")

            return _parse_simple(stdout.decode("utf-8", "replace"))
        finally:
            for path in (names_path, res_path):
                try:
                    os.unlink(path)
                except OSError:
                    pass
