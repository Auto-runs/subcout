"""Data models used across subscout."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Subdomain:
    """A discovered subdomain and everything we learn about it."""

    name: str
    sources: set[str] = field(default_factory=set)

    # Filled in by the resolver
    resolved: bool = False
    a_records: list[str] = field(default_factory=list)
    aaaa_records: list[str] = field(default_factory=list)
    cname: Optional[str] = None

    # Filled in by the HTTP prober
    http_status: Optional[int] = None
    http_url: Optional[str] = None
    title: Optional[str] = None
    server: Optional[str] = None
    content_length: Optional[int] = None
    cdn: Optional[str] = None
    technologies: list[str] = field(default_factory=list)

    # Filled in by the takeover detector
    takeover: bool = False
    takeover_service: Optional[str] = None

    def merge(self, other: "Subdomain") -> None:
        """Merge another record for the same name into this one."""
        self.sources |= other.sources

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "sources": sorted(self.sources),
            "resolved": self.resolved,
            "a_records": self.a_records,
            "aaaa_records": self.aaaa_records,
            "cname": self.cname,
            "http_status": self.http_status,
            "http_url": self.http_url,
            "title": self.title,
            "server": self.server,
            "content_length": self.content_length,
            "cdn": self.cdn,
            "technologies": self.technologies,
            "takeover": self.takeover,
            "takeover_service": self.takeover_service,
        }
