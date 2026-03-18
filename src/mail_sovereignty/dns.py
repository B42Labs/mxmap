import asyncio
import ipaddress
import logging
import re

import dns.asyncresolver
import dns.exception
import dns.resolver
import dns.reversename

logger = logging.getLogger(__name__)

_resolvers = None

_RETRYABLE = (dns.exception.Timeout, dns.resolver.NoAnswer, dns.resolver.NoNameservers)


def make_resolvers() -> list[dns.asyncresolver.Resolver]:
    """Create a list of async resolvers pointing to different DNS servers."""
    resolvers = []
    for nameservers in [None, ["8.8.8.8", "8.8.4.4"], ["1.1.1.1", "1.0.0.1"]]:
        r = dns.asyncresolver.Resolver()
        if nameservers:
            r.nameservers = nameservers
        r.timeout = 10
        r.lifetime = 15
        resolvers.append(r)
    return resolvers


def get_resolvers() -> list[dns.asyncresolver.Resolver]:
    global _resolvers
    if _resolvers is None:
        _resolvers = make_resolvers()
    return _resolvers


async def lookup_mx(domain: str) -> list[str]:
    """Return list of MX exchange hostnames."""
    resolvers = get_resolvers()
    for i, resolver in enumerate(resolvers):
        try:
            answers = await resolver.resolve(domain, "MX")
            return sorted(str(r.exchange).rstrip(".").lower() for r in answers)
        except dns.resolver.NXDOMAIN:
            return []
        except _RETRYABLE as e:
            logger.debug(
                "MX %s: %s on resolver %d, retrying", domain, type(e).__name__, i
            )
            await asyncio.sleep(0.5)
            continue
        except Exception:
            continue
    logger.info("MX %s: all resolvers failed", domain)
    return []


_VERIFICATION_PREFIXES: dict[str, str] = {
    "ms=": "microsoft",
    "google-site-verification=": "google",
}


async def lookup_txt(domain: str) -> tuple[str, dict[str, str]]:
    """Return (SPF record, verification tokens) from TXT records."""
    resolvers = get_resolvers()
    for i, resolver in enumerate(resolvers):
        try:
            answers = await resolver.resolve(domain, "TXT")
            spf_records: list[str] = []
            verifications: dict[str, str] = {}
            for r in answers:
                txt = b"".join(r.strings).decode("utf-8", errors="ignore")
                txt_lower = txt.lower()
                if txt_lower.startswith("v=spf1"):
                    spf_records.append(txt)
                else:
                    for prefix, provider in _VERIFICATION_PREFIXES.items():
                        if txt_lower.startswith(prefix):
                            verifications[provider] = txt[len(prefix) :]
                            break
            spf = sorted(spf_records)[0] if spf_records else ""
            return spf, verifications
        except dns.resolver.NXDOMAIN:
            return "", {}
        except _RETRYABLE as e:
            logger.debug(
                "TXT %s: %s on resolver %d, retrying", domain, type(e).__name__, i
            )
            await asyncio.sleep(0.5)
            continue
        except Exception:
            continue
    logger.info("TXT %s: all resolvers failed", domain)
    return "", {}


async def lookup_spf(domain: str) -> str:
    """Return the SPF TXT record if found. Convenience wrapper."""
    spf, _ = await lookup_txt(domain)
    return spf


_SPF_INCLUDE_RE = re.compile(r"\binclude:(\S+)", re.IGNORECASE)
_SPF_REDIRECT_RE = re.compile(r"\bredirect=(\S+)", re.IGNORECASE)


async def resolve_spf_includes(spf_record: str, max_lookups: int = 10) -> str:
    """Recursively resolve include: and redirect= directives in an SPF record.

    Returns the original SPF text concatenated with all resolved SPF texts.
    Uses BFS to follow nested includes. Tracks visited domains for loop
    detection and enforces a lookup limit.
    """
    if not spf_record:
        return ""

    initial_domains = _SPF_INCLUDE_RE.findall(spf_record) + _SPF_REDIRECT_RE.findall(
        spf_record
    )
    if not initial_domains:
        return spf_record

    visited: set[str] = set()
    parts = [spf_record]
    queue = list(initial_domains)
    lookups = 0

    while queue and lookups < max_lookups:
        domain = queue.pop(0).lower().rstrip(".")
        if domain in visited:
            continue
        visited.add(domain)
        lookups += 1
        resolved = await lookup_spf(domain)
        if resolved:
            parts.append(resolved)
            nested = _SPF_INCLUDE_RE.findall(resolved) + _SPF_REDIRECT_RE.findall(
                resolved
            )
            queue.extend(nested)

    return " ".join(parts)


async def lookup_cname_chain(hostname: str, max_hops: int = 10) -> list[str]:
    """Follow CNAME chain for hostname. Return list of targets (empty if no CNAME)."""
    resolvers = get_resolvers()
    chain = []
    current = hostname

    for _ in range(max_hops):
        resolved = False
        for i, resolver in enumerate(resolvers):
            try:
                answers = await resolver.resolve(current, "CNAME")
                target = str(list(answers)[0].target).rstrip(".").lower()
                chain.append(target)
                current = target
                resolved = True
                break
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                break
            except _RETRYABLE as e:
                logger.debug(
                    "CNAME %s: %s on resolver %d, retrying",
                    current,
                    type(e).__name__,
                    i,
                )
                await asyncio.sleep(0.5)
                continue
            except Exception:
                continue
        if not resolved:
            break

    return chain


async def resolve_mx_cnames(mx_hosts: list[str]) -> dict[str, str]:
    """For each MX host, follow CNAME chain. Return mapping of host -> final target (only for hosts with CNAMEs)."""
    result = {}
    for host in mx_hosts:
        chain = await lookup_cname_chain(host)
        if chain:
            result[host] = chain[-1]
    return result


async def lookup_dkim(domain: str) -> dict[str, str]:
    """Check DKIM CNAME records for common selectors. Returns {selector: target}."""
    selectors = ["selector1", "selector2", "google"]
    chains = await asyncio.gather(
        *(lookup_cname_chain(f"{s}._domainkey.{domain}", max_hops=2) for s in selectors)
    )
    return {s: chain[-1] for s, chain in zip(selectors, chains) if chain}


async def lookup_a(hostname: str) -> list[str]:
    """Resolve hostname to IPv4 addresses via A record query."""
    resolvers = get_resolvers()
    for i, resolver in enumerate(resolvers):
        try:
            answers = await resolver.resolve(hostname, "A")
            return [str(r) for r in answers]
        except dns.resolver.NXDOMAIN:
            return []
        except _RETRYABLE as e:
            logger.debug(
                "A %s: %s on resolver %d, retrying", hostname, type(e).__name__, i
            )
            await asyncio.sleep(0.5)
            continue
        except Exception:
            continue
    logger.info("A %s: all resolvers failed", hostname)
    return []


async def lookup_asn_cymru(ip: str) -> int | None:
    """Query Team Cymru DNS for ASN number of an IP address."""
    reversed_ip = ".".join(reversed(ip.split(".")))
    query = f"{reversed_ip}.origin.asn.cymru.com"
    resolvers = get_resolvers()
    for i, resolver in enumerate(resolvers):
        try:
            answers = await resolver.resolve(query, "TXT")
            for r in answers:
                txt = b"".join(r.strings).decode("utf-8", errors="ignore")
                # Format: "3303 | 193.135.252.0/24 | CH | ripencc | ..."
                asn_str = txt.split("|")[0].strip()
                return int(asn_str)
        except dns.resolver.NXDOMAIN:
            return None
        except _RETRYABLE as e:
            logger.debug("ASN %s: %s on resolver %d, retrying", ip, type(e).__name__, i)
            await asyncio.sleep(0.5)
            continue
        except Exception:
            continue
    logger.info("ASN %s: all resolvers failed", ip)
    return None


async def lookup_srv(name: str) -> list[tuple[str, int]]:
    """Return list of (target, port) from SRV records."""
    resolvers = get_resolvers()
    for i, resolver in enumerate(resolvers):
        try:
            answers = await resolver.resolve(name, "SRV")
            return [(str(r.target).rstrip(".").lower(), r.port) for r in answers]
        except dns.resolver.NXDOMAIN:
            return []
        except _RETRYABLE as e:
            logger.debug(
                "SRV %s: %s on resolver %d, retrying", name, type(e).__name__, i
            )
            await asyncio.sleep(0.5)
            continue
        except Exception:
            continue
    logger.info("SRV %s: all resolvers failed", name)
    return []


async def lookup_autodiscover(domain: str) -> dict[str, str]:
    """Check autodiscover DNS records. Returns dict of record_type -> target."""
    cname_coro = lookup_cname_chain(f"autodiscover.{domain}", max_hops=1)
    srv_coro = lookup_srv(f"_autodiscover._tcp.{domain}")

    cname_result, srv_result = await asyncio.gather(cname_coro, srv_coro)

    result: dict[str, str] = {}
    if cname_result:
        result["autodiscover_cname"] = cname_result[-1]
    if srv_result:
        result["autodiscover_srv"] = srv_result[0][0]
    return result


async def resolve_mx_asns(mx_hosts: list[str]) -> set[int]:
    """Resolve all MX hosts to IPs, look up ASNs, return set of unique ASNs."""
    asns = set()
    for host in mx_hosts:
        ips = await lookup_a(host)
        for ip in ips:
            asn = await lookup_asn_cymru(ip)
            if asn is not None:
                asns.add(asn)
    return asns


async def resolve_mx_ips(mx_hosts: list[str]) -> dict[str, list[str]]:
    """Resolve each MX host to IPv4 addresses. Returns {host: [ip, ...]}."""
    result: dict[str, list[str]] = {}
    for host in mx_hosts:
        ips = await lookup_a(host)
        if ips:
            result[host] = ips
    return result


async def lookup_ptr(ip: str) -> str | None:
    """Reverse DNS lookup for an IP address. Returns PTR hostname or None."""
    try:
        rev_name = dns.reversename.from_address(ip)
    except Exception:
        return None
    resolvers = get_resolvers()
    for i, resolver in enumerate(resolvers):
        try:
            answers = await resolver.resolve(rev_name, "PTR")
            for r in answers:
                return str(r.target).rstrip(".").lower()
            return None
        except dns.resolver.NXDOMAIN:
            return None
        except _RETRYABLE as e:
            logger.debug("PTR %s: %s on resolver %d, retrying", ip, type(e).__name__, i)
            await asyncio.sleep(0.5)
            continue
        except Exception:
            continue
    logger.info("PTR %s: all resolvers failed", ip)
    return None


async def resolve_mx_ptrs(mx_ips: dict[str, list[str]]) -> dict[str, str]:
    """Takes pre-resolved IPs, returns {ip: ptr_hostname}."""
    result: dict[str, str] = {}
    for ips in mx_ips.values():
        for ip in ips:
            if ip not in result:
                ptr = await lookup_ptr(ip)
                if ptr:
                    result[ip] = ptr
    return result


async def resolve_asns_from_ips(mx_ips: dict[str, list[str]]) -> set[int]:
    """Takes pre-resolved IPs, returns ASN set."""
    asns: set[int] = set()
    for ips in mx_ips.values():
        for ip in ips:
            asn = await lookup_asn_cymru(ip)
            if asn is not None:
                asns.add(asn)
    return asns


_SPF_IP4_RE = re.compile(r"\bip4:(\S+)", re.IGNORECASE)


def _spf_representative_ips(spf_text: str) -> list[str]:
    """Extract one representative IP per unique /24 from ip4: directives."""
    seen_prefixes: set[str] = set()
    result: list[str] = []
    for raw in _SPF_IP4_RE.findall(spf_text):
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        if net.prefixlen >= 24:
            # Small network: just take the first host
            for host in net.hosts():
                prefix = str(ipaddress.ip_network(f"{host}/24", strict=False))
                if prefix not in seen_prefixes:
                    seen_prefixes.add(prefix)
                    result.append(str(host))
                break
        else:
            # Large network: iterate /24 subnets
            for subnet in net.subnets(new_prefix=24):
                prefix = str(subnet)
                if prefix not in seen_prefixes:
                    seen_prefixes.add(prefix)
                    # First host of each /24
                    result.append(str(next(subnet.hosts())))
    return result


async def resolve_spf_asns(spf_text: str) -> set[int]:
    """Resolve ip4: blocks in SPF text to ASN numbers."""
    ips = _spf_representative_ips(spf_text)
    asns: set[int] = set()
    for ip in ips:
        asn = await lookup_asn_cymru(ip)
        if asn is not None:
            asns.add(asn)
    return asns
