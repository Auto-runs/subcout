"""Lightweight technology fingerprinting from HTTP responses.

Given the response headers and a slice of the body, infer:
  - the CDN / WAF in front (Cloudflare, Akamai, Fastly, CloudFront, ...), and
  - notable technologies (server, framework, CMS, language).

This is intentionally signature-based and dependency-free - it won't rival a
full Wappalyzer ruleset, but it flags the high-value tells that matter during
recon (what's behind a host, is it a CDN edge, what stack to probe next).

The core ``fingerprint()`` function is pure (headers dict + body string in,
results out), which keeps it trivial to unit-test offline.
"""
from __future__ import annotations

# CDN / WAF detection. Each entry: label -> (header-substring checks, body checks).
# Header checks match against "name: value" lowercased.
_CDN_SIGNATURES: dict[str, dict] = {
    "Cloudflare": {"headers": ["server: cloudflare", "cf-ray:", "cf-cache-status:"]},
    "Akamai": {"headers": ["x-akamai", "akamaighost", "x-akamai-transformed:"]},
    "Fastly": {"headers": ["x-served-by: cache", "x-fastly", "fastly-"]},
    "Amazon CloudFront": {"headers": ["x-amz-cf-id:", "via: ", "x-cache: hit from cloudfront"]},
    "Sucuri": {"headers": ["x-sucuri-id:", "x-sucuri-cache:", "server: sucuri"]},
    "Imperva/Incapsula": {"headers": ["x-iinfo:", "x-cdn: incapsula"]},
    "Microsoft Azure": {"headers": ["x-azure-ref:", "x-msedge-ref:"]},
    "Google": {"headers": ["server: gws", "via: 1.1 google"]},
    "Vercel": {"headers": ["server: vercel", "x-vercel-id:"]},
    "Netlify": {"headers": ["server: netlify", "x-nf-request-id:"]},
}

# Technology / framework / CMS detection.
_TECH_SIGNATURES: dict[str, dict] = {
    "nginx": {"headers": ["server: nginx"]},
    "Apache": {"headers": ["server: apache"]},
    "Microsoft-IIS": {"headers": ["server: microsoft-iis", "server: iis"]},
    "LiteSpeed": {"headers": ["server: litespeed"]},
    "OpenResty": {"headers": ["server: openresty"]},
    "WordPress": {"headers": ["x-pingback:", "link: <https://wp."],
                  "body": ["/wp-content/", "/wp-includes/", 'name="generator" content="wordpress']},
    "Drupal": {"headers": ["x-generator: drupal", "x-drupal-cache:"],
               "body": ["drupal.settings", "/sites/all/"]},
    "Joomla": {"body": ["/media/jui/", "joomla!"]},
    "Django": {"headers": ["x-frame-options: sameorigin"],
               "body": ["csrfmiddlewaretoken"]},
    "Laravel": {"headers": ["set-cookie: laravel_session"]},
    "Express": {"headers": ["x-powered-by: express"]},
    "ASP.NET": {"headers": ["x-powered-by: asp.net", "x-aspnet-version:"]},
    "PHP": {"headers": ["x-powered-by: php", "set-cookie: phpsessid"]},
    "React": {"body": ['id="root"', "react", "__next_data__"]},
    "Next.js": {"headers": ["x-powered-by: next.js"], "body": ["__next_data__", "/_next/static/"]},
    "Shopify": {"headers": ["x-shopify-stage:", "x-shopid:"], "body": ["cdn.shopify.com"]},
}


def _header_blob(headers: dict) -> str:
    """Flatten headers into one lowercased "name: value\\n" blob for matching."""
    parts = []
    for k, v in (headers or {}).items():
        parts.append(f"{k}: {v}")
    return "\n".join(parts).lower()


def _match(signatures: dict, header_blob: str, body: str) -> list[str]:
    out: list[str] = []
    body_l = (body or "").lower()
    for label, sig in signatures.items():
        hit = False
        for needle in sig.get("headers", []):
            if needle in header_blob:
                hit = True
                break
        if not hit:
            for needle in sig.get("body", []):
                if needle in body_l:
                    hit = True
                    break
        if hit:
            out.append(label)
    return out


def fingerprint(headers: dict, body: str = "") -> tuple[str | None, list[str]]:
    """Return ``(cdn, technologies)`` inferred from a response.

    *cdn* is the first CDN/WAF matched (or None); *technologies* is the sorted
    list of tech/framework/CMS labels matched.
    """
    blob = _header_blob(headers)
    cdns = _match(_CDN_SIGNATURES, blob, body)
    techs = _match(_TECH_SIGNATURES, blob, body)
    cdn = cdns[0] if cdns else None
    return cdn, sorted(set(techs))
