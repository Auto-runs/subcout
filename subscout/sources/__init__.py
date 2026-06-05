"""Source plugins package.

Importing this package imports every plugin module, which triggers their
`@register` decorators so they appear in the registry.
"""
from __future__ import annotations

from subscout.sources.base import (  # noqa: F401
    Source,
    all_sources,
    get_sources,
    register,
)

# Import side effects register each source. Keep alphabetical.
from subscout.sources import (  # noqa: F401,E402
    alienvault,
    anubis,
    bufferover,
    censys,
    certspotter,
    chaos,
    commoncrawl,
    crtsh,
    digitorus,
    dnsdumpster,
    fullhunt,
    hackertarget,
    leakix,
    rapiddns,
    riddler,
    securitytrails,
    urlscan,
    virustotal,
    wayback,
)

# Load the declarative (data-driven) source catalog. Coded sources above take
# precedence on name clashes; everything else is registered from JSON.
from subscout.sources.declarative import load_declarative_sources  # noqa: E402

load_declarative_sources()
