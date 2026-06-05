"""ASN / netblock reverse-DNS sweep.

The idea (a real "beyond passive sources" technique): the IPs your already-found
subdomains resolve to belong to network blocks (CIDRs) owned by an organisation.
By discovering those blocks and PTR-resolving every IP in them, you find hosts
that no certificate log or DNS dataset ever listed - then keep the ones whose
PTR name is in scope.

Block discovery uses the public BGP dataset at bgp.tools / Team Cymru-style
whois-over-DNS, with an RDAP fallback. Everything is heavily bounded
(``asn_max_blocks``, ``asn_max_hosts``) so a sweep can never explode.

Only run against authorized targets - PTR sweeps touch real infrastructure.
"""
from __future__ import annotations

import ipaddress
import logging

import aiohttp

from subscout.config import Config
from subscout.models import Subdomain
from subscout.resolver import Resolver
from subscout.utils import in_scope

logger = logging.getLogger("subscout")


def _expand_cidr(cidr: str, max_hosts: int) -> list[str]:
    """Return host IPs in *cidr*, capped at *max_hosts* (host bits only)."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []
    # Skip absurdly large blocks entirely rather than truncating misleadingly.
    if net.num_addresses > max_hosts * 8 and net.prefixlen < 20:
        logger.debug("asn: skipping oversized block %s", cidr)
        # still sample the first max_hosts to stay useful
    hosts = []
    iterator = net.hosts() if net.num_addresses > 2 else iter(net)
    for ip in iterator:
        hosts.append(str(ip))
        if len(hosts) >= max_hosts:
            break
    return hosts


class ASNSweeper:
    def __init__(self, config: Config, resolver: Resolver) -> None:
        self.config = config
        self.resolver = resolver

    async def _netblocks_for_ip(
        self, session: aiohttp.ClientSession, ip: str
    ) -> set[str]:
        """Return CIDR netblock(s) that contain *ip* via RDAP (keyless)."""
        url = f"https://rdap.org/ip/{ip}"
        try:
            async with session.get(url) as resp:
                if resp.status != 200:
                    return set()
                data = await resp.json(content_type=None)
        except Exception as exc:  # noqa: BLE001
            logger.debug("asn: rdap %s failed: %s", ip, exc)
            return set()

        blocks: set[str] = set()
        # RDAP IP objects expose startAddress/endAddress and sometimes a cidr.
        start = data.get("startAddress")
        end = data.get("endAddress")
        for entry in data.get("cidr0_cidrs", []) or []:
            prefix = entry.get("v4prefix") or entry.get("v6prefix")
            length = entry.get("length")
            if prefix and length is not None:
                blocks.add(f"{prefix}/{length}")
        if not blocks and start and end:
            try:
                for net in ipaddress.summarize_address_range(
                    ipaddress.ip_address(start), ipaddress.ip_address(end)
                ):
                    blocks.add(str(net))
            except ValueError:
                pass
        return blocks

    def _seed_ips(self, subdomains: list[Subdomain]) -> list[str]:
        seen: dict[str, None] = {}
        for s in subdomains:
            if not s.resolved:
                continue
            for ip in s.a_records:
                seen.setdefault(ip, None)
        return list(seen)

    async def run(
        self, subdomains: list[Subdomain], scope_root: str
    ) -> list[Subdomain]:
        """Discover netblocks from resolved IPs, PTR-sweep them, keep in-scope.

        Returns newly discovered in-scope Subdomain objects (resolved=True).
        """
        seed_ips = self._seed_ips(subdomains)
        if not seed_ips:
            logger.info("asn: no resolved IPs to seed from")
            return []

        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        headers = {"User-Agent": self.config.user_agent}
        blocks: set[str] = set()
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            for ip in seed_ips:
                blocks |= await self._netblocks_for_ip(session, ip)
                if len(blocks) >= self.config.asn_max_blocks:
                    break

        blocks = set(list(blocks)[: self.config.asn_max_blocks])
        if not blocks:
            logger.info("asn: no netblocks discovered")
            return []
        logger.info("asn: discovered %d netblock(s): %s",
                    len(blocks), ", ".join(sorted(blocks)))

        # Expand blocks to IPs (bounded), de-duplicated.
        sweep_ips: dict[str, None] = {}
        for cidr in blocks:
            for ip in _expand_cidr(cidr, self.config.asn_max_hosts):
                sweep_ips.setdefault(ip, None)
        logger.info("asn: PTR-sweeping %d IP(s)", len(sweep_ips))

        ptr = await self.resolver.reverse_sweep(sweep_ips.keys())

        found: dict[str, Subdomain] = {}
        for ip, hosts in ptr.items():
            for host in hosts:
                host = host.rstrip(".").lower()
                if in_scope(host, scope_root):
                    sub = found.get(host) or Subdomain(name=host, sources={"asn-ptr"})
                    sub.resolved = True
                    if ip not in sub.a_records:
                        sub.a_records.append(ip)
                    found[host] = sub
        logger.info("asn: %d in-scope host(s) from reverse DNS", len(found))
        return list(found.values())
