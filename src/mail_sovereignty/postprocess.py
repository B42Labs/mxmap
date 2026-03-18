import asyncio
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from mail_sovereignty import geoip
from mail_sovereignty.classify import (
    DomesticConfig,
    classify,
    classify_from_smtp_banner,
    detect_gateway,
)
from mail_sovereignty.constants import (
    EMAIL_RE,
    SKIP_DOMAINS,
    TYPO3_RE,
)
from mail_sovereignty.dns import (
    lookup_autodiscover,
    lookup_dkim,
    lookup_mx,
    lookup_txt,
    resolve_asns_from_ips,
    resolve_mx_cnames,
    resolve_mx_ips,
    resolve_mx_ptrs,
    resolve_spf_asns,
    resolve_spf_includes,
)
from mail_sovereignty.smtp import fetch_smtp_banner


def decrypt_typo3(encoded: str, offset: int = 2) -> str:
    """Decrypt TYPO3 linkTo_UnCryptMailto Caesar cipher.

    TYPO3 encrypts mailto: links with a Caesar shift on three ASCII ranges:
      0x2B-0x3A (+,-./0123456789:)  -- covers . : and digits
      0x40-0x5A (@A-Z)             -- covers @ and uppercase
      0x61-0x7A (a-z)             -- covers lowercase
    Default encryption offset is -2, so decryption is +2 with wrap.
    """
    ranges = [(0x2B, 0x3A), (0x40, 0x5A), (0x61, 0x7A)]
    result = []
    for c in encoded:
        code = ord(c)
        decrypted = False
        for start, end in ranges:
            if start <= code <= end:
                n = code + offset
                if n > end:
                    n = start + (n - end - 1)
                result.append(chr(n))
                decrypted = True
                break
        if not decrypted:
            result.append(c)
    return "".join(result)


def extract_email_domains(html: str, skip_domains: set[str] | None = None) -> set[str]:
    """Extract email domains from HTML, including TYPO3-obfuscated emails."""
    _skip = skip_domains if skip_domains is not None else SKIP_DOMAINS
    domains = set()

    for email in EMAIL_RE.findall(html):
        domain = email.split("@")[1].lower()
        if domain not in _skip:
            domains.add(domain)

    for email in __import__("re").findall(r'mailto:([^">\s?]+)', html):
        if "@" in email:
            domain = email.split("@")[1].lower()
            if domain not in _skip:
                domains.add(domain)

    for encoded in TYPO3_RE.findall(html):
        decoded = decrypt_typo3(encoded)
        decoded = decoded.replace("mailto:", "")
        if "@" in decoded:
            domain = decoded.split("@")[1].lower()
            if domain not in _skip:
                domains.add(domain)

    return domains


def build_urls(domain: str, subpages: list[str] | None = None) -> list[str]:
    """Build candidate URLs to scrape, trying www. prefix first."""
    _subpages = (
        subpages if subpages is not None else ["/kontakt", "/contact", "/impressum"]
    )
    domain = domain.strip()
    if domain.startswith(("http://", "https://")):
        parsed = urlparse(domain)
        domain = parsed.hostname or domain
    if domain.startswith("www."):
        bare = domain[4:]
    else:
        bare = domain

    bases = [f"https://www.{bare}", f"https://{bare}"]
    urls = []
    for base in bases:
        urls.append(base + "/")
        for path in _subpages:
            urls.append(base + path)
    return urls


async def scrape_email_domains(
    client: httpx.AsyncClient,
    domain: str,
    subpages: list[str] | None = None,
    skip_domains: set[str] | None = None,
) -> set[str]:
    """Scrape a municipality website for email domains."""
    if not domain:
        return set()

    all_domains = set()
    urls = build_urls(domain, subpages=subpages)

    for url in urls:
        try:
            r = await client.get(url, follow_redirects=True, timeout=15)
            if r.status_code != 200:
                continue
            domains = extract_email_domains(r.text, skip_domains=skip_domains)
            all_domains |= domains
            if all_domains:
                return all_domains
        except Exception:
            continue

    return all_domains


async def _enrich_domain(
    domain: str,
    mx: list[str],
    domestic: DomesticConfig | None,
) -> dict[str, Any]:
    """Perform DNS enrichment and classification for a domain with known MX records."""
    spf, txt_verifications = await lookup_txt(domain)
    spf_resolved = await resolve_spf_includes(spf) if spf else ""
    mx_cnames = await resolve_mx_cnames(mx) if mx else {}
    mx_ips = await resolve_mx_ips(mx) if mx else {}
    mx_asns = await resolve_asns_from_ips(mx_ips) if mx_ips else set()
    mx_ptrs = await resolve_mx_ptrs(mx_ips) if mx_ips else {}
    mx_geoip_countries = geoip.countries_for_mx_ips(mx_ips) if mx_ips else set()
    autodiscover = await lookup_autodiscover(domain)
    dkim = await lookup_dkim(domain)
    spf_asns = await resolve_spf_asns(spf_resolved or spf) if spf else set()
    provider, reason = classify(
        mx,
        spf,
        mx_cnames=mx_cnames,
        mx_asns=mx_asns or None,
        resolved_spf=spf_resolved or None,
        autodiscover=autodiscover or None,
        mx_ptrs=mx_ptrs or None,
        mx_geoip_countries=mx_geoip_countries or None,
        spf_asns=spf_asns or None,
        domestic=domestic,
        dkim=dkim or None,
        txt_verifications=txt_verifications or None,
    )
    gateway = detect_gateway(mx) if mx else None
    result: dict[str, Any] = {
        "mx": mx,
        "spf": spf,
        "provider": provider,
        "reason": reason,
    }
    if spf_resolved and spf_resolved != spf:
        result["spf_resolved"] = spf_resolved
    if gateway:
        result["gateway"] = gateway
    if mx_cnames:
        result["mx_cnames"] = mx_cnames
    if mx_asns:
        result["mx_asns"] = sorted(mx_asns)
    if mx_ptrs:
        result["mx_ptrs"] = mx_ptrs
    if mx_geoip_countries:
        result["mx_geoip_countries"] = sorted(mx_geoip_countries)
    if spf_asns:
        result["spf_asns"] = sorted(spf_asns)
    if autodiscover:
        result["autodiscover"] = autodiscover
    if dkim:
        result["dkim"] = dkim
    if txt_verifications:
        result["txt_verifications"] = txt_verifications
    if mx_ips:
        result["mx_ips"] = {host: sorted(ips) for host, ips in mx_ips.items()}
    return result


async def process_unknown(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    m: dict[str, Any],
    country_config=None,
) -> dict[str, Any]:
    """Try to resolve an unknown municipality by scraping its website."""
    _subpages = (
        list(country_config.subpages) if country_config else None
    )  # pragma: no cover
    _skip_domains = (
        country_config.skip_domains_merged if country_config else None
    )  # pragma: no cover

    async with semaphore:
        bfs = m["bfs"]
        name = m["name"]
        domain = m.get("domain", "")

        if not domain:
            print(f"  SKIP     {bfs:>5} {name:<30} (no domain)")
            return m

        email_domains = await scrape_email_domains(
            client, domain, subpages=_subpages, skip_domains=_skip_domains
        )

        domestic = country_config.domestic_config if country_config else None
        for email_domain in sorted(email_domains):
            mx = await lookup_mx(email_domain)
            if mx:
                enrichment = await _enrich_domain(email_domain, mx, domestic)
                print(
                    f"  RESOLVED {bfs:>5} {name:<30} "
                    f"email_domain={email_domain} -> {enrichment['provider']}"
                )
                m.update(enrichment)
                m["domain"] = email_domain
                return m

        print(
            f"  UNKNOWN  {bfs:>5} {name:<30} "
            f"(scraped email domains: {email_domains or 'none'})"
        )
        return m


async def run(data_path: Path, country_config=None) -> None:
    with open(data_path, encoding="utf-8") as f:
        data = json.load(f)

    muni = data["municipalities"]

    # Resolve config values
    manual_overrides = country_config.manual_overrides if country_config else {}
    _concurrency_pp = country_config.concurrency_postprocess if country_config else 10
    _concurrency_smtp = country_config.concurrency_smtp if country_config else 5
    _user_agent = (
        country_config.user_agent
        if country_config
        else "mxmap/1.0 (https://github.com/B42Labs/mxmap)"
    )
    _ehlo_hostname = country_config.ehlo_hostname if country_config else "mxmap.ch"
    geoip_db = getattr(country_config, "geoip_db", "") if country_config else ""
    if geoip_db:
        geoip.init(geoip_db)

    # Step 1: Apply manual overrides
    print("Applying manual overrides...")
    dns_relookup = []  # (bfs, domain) pairs needing MX/SPF re-lookup
    for bfs, override in manual_overrides.items():
        if bfs not in muni and "name" in override:
            muni[bfs] = {
                "bfs": bfs,
                "name": override["name"],
                "canton": override.get("canton", ""),
                "domain": "",
                "mx": [],
                "spf": "",
                "provider": "unknown",
            }
            print(f"  {bfs:>5} {override['name']:<30} (added missing municipality)")
        if bfs not in muni:
            continue
        if bfs in muni:
            if "domain" in override:
                muni[bfs]["domain"] = override["domain"]
            if "provider" in override:
                muni[bfs]["provider"] = override["provider"]
            if "gateway" in override:
                muni[bfs]["gateway"] = override["gateway"]
            if "mx" in override:
                muni[bfs]["mx"] = override["mx"]
            if "spf" in override:
                muni[bfs]["spf"] = override["spf"]
            if override.get("provider") == "merged":
                muni[bfs]["mx"] = []
                muni[bfs]["spf"] = ""
            # Domain-only override: need to re-lookup MX/SPF from DNS
            if (
                "domain" in override
                and override["domain"]
                and "mx" not in override
                and "provider" not in override
            ):
                dns_relookup.append((bfs, override["domain"]))
            else:
                print(
                    f"  {bfs:>5} {muni[bfs]['name']:<30} -> {override.get('provider', '?')}"
                )

    domestic = country_config.domestic_config if country_config else None

    if dns_relookup:

        async def _relookup(bfs, domain):
            mx = await lookup_mx(domain)
            enrichment = await _enrich_domain(domain, mx, domestic)
            return bfs, enrichment

        results = await asyncio.gather(*[_relookup(b, d) for b, d in dns_relookup])
        for bfs, enrichment in results:
            muni[bfs].update(enrichment)
            print(
                f"  {bfs:>5} {muni[bfs]['name']:<30} -> {enrichment['provider']} (DNS re-lookup)"
            )

    # Step 2: Retry DNS for unknowns that have a domain
    dns_retry_candidates = [
        m for m in muni.values() if m["provider"] == "unknown" and m.get("domain")
    ]
    if dns_retry_candidates:
        print(f"\nRetrying DNS for {len(dns_retry_candidates)} unknown domains...")
        for m in dns_retry_candidates:
            mx = await lookup_mx(m["domain"])
            if mx:
                enrichment = await _enrich_domain(m["domain"], mx, domestic)
                m.update(enrichment)
                print(
                    f"  RECOVERED {m['bfs']:>5} {m['name']:<30} -> {enrichment['provider']}"
                )

    # Step 2.5: SMTP banner check for independent/unknown with MX records
    smtp_candidates = [
        m
        for m in muni.values()
        if m["provider"] in ("independent", "unknown") and m.get("mx")
    ]
    if smtp_candidates:
        # Deduplicate: map each unique MX host -> list of BFS numbers
        mx_host_to_bfs: dict[str, list[str]] = {}
        for m in smtp_candidates:
            primary_mx = m["mx"][0]
            mx_host_to_bfs.setdefault(primary_mx, []).append(m["bfs"])

        print(
            f"\nSMTP banner check: {len(smtp_candidates)} entries, "
            f"{len(mx_host_to_bfs)} unique MX hosts..."
        )
        smtp_semaphore = asyncio.Semaphore(_concurrency_smtp)

        async def _fetch_banner(mx_host: str) -> tuple[str, dict[str, str]]:
            async with smtp_semaphore:
                res = await fetch_smtp_banner(mx_host, ehlo_hostname=_ehlo_hostname)
                return mx_host, res

        banner_results = await asyncio.gather(
            *[_fetch_banner(host) for host in mx_host_to_bfs]
        )

        smtp_reclassified = 0
        for mx_host, result in banner_results:
            banner = result.get("banner", "")
            ehlo = result.get("ehlo", "")
            if not banner:
                continue
            provider = classify_from_smtp_banner(banner, ehlo)
            for bfs in mx_host_to_bfs[mx_host]:
                muni[bfs]["smtp_banner"] = banner
                if provider and muni[bfs]["provider"] in ("independent", "unknown"):
                    old = muni[bfs]["provider"]
                    muni[bfs]["provider"] = provider
                    smtp_reclassified += 1
                    print(
                        f"  SMTP     {bfs:>5} {muni[bfs]['name']:<30} "
                        f"{old} -> {provider} ({mx_host})"
                    )

        print(f"  SMTP reclassified: {smtp_reclassified}")

    # Step 3: Scrape remaining unknowns
    unknowns = [m for m in muni.values() if m["provider"] == "unknown"]
    print(f"\n{len(unknowns)} unknown municipalities to investigate\n")

    if unknowns:
        semaphore = asyncio.Semaphore(_concurrency_pp)
        async with httpx.AsyncClient(
            headers={"User-Agent": _user_agent},
            follow_redirects=True,
        ) as client:
            tasks = [
                process_unknown(client, semaphore, m, country_config=country_config)
                for m in unknowns
            ]
            results = await asyncio.gather(*tasks)

        resolved = 0
        for m in results:
            muni[m["bfs"]] = m
            if m["provider"] != "unknown":
                resolved += 1
        print(f"\nResolved {resolved}/{len(unknowns)} via scraping")

    # Step 4: Enrich spf_asns for entries that have SPF but no spf_asns
    missing_spf_asns = [
        m
        for m in muni.values()
        if (m.get("spf") or m.get("spf_resolved")) and not m.get("spf_asns")
    ]
    if missing_spf_asns:
        print(f"\nEnriching SPF ASNs for {len(missing_spf_asns)} entries...")
        for m in missing_spf_asns:
            asns = await resolve_spf_asns(m.get("spf_resolved") or m.get("spf", ""))
            if asns:
                m["spf_asns"] = sorted(asns)
        print(
            f"  Enriched {sum(1 for m in missing_spf_asns if m.get('spf_asns'))} entries"
        )

    # Step 5: Re-classify with SPF ASN data
    domestic_label = domestic.label if domestic else ""
    reclass_candidates = [
        m
        for m in muni.values()
        if m["provider"] in ("independent", domestic_label, "unknown")
        and m.get("spf_asns")
    ]
    if reclass_candidates:
        print(
            f"\nRe-classifying {len(reclass_candidates)} entries with SPF ASN data..."
        )
        reclassified = 0
        for m in reclass_candidates:
            new_provider, new_reason = classify(
                m["mx"],
                m.get("spf"),
                mx_cnames=m.get("mx_cnames"),
                mx_asns=set(m["mx_asns"]) if m.get("mx_asns") else None,
                resolved_spf=m.get("spf_resolved"),
                autodiscover=m.get("autodiscover"),
                mx_ptrs=m.get("mx_ptrs"),
                mx_geoip_countries=(
                    set(m["mx_geoip_countries"])
                    if m.get("mx_geoip_countries")
                    else None
                ),
                spf_asns=set(m["spf_asns"]),
                domestic=domestic,
                dkim=m.get("dkim"),
                txt_verifications=m.get("txt_verifications"),
            )
            if new_provider != m["provider"]:
                print(
                    f"  SPF-ASN  {m['bfs']:>5} {m['name']:<30} {m['provider']} -> {new_provider}"
                )
                m["provider"] = new_provider
                m["reason"] = new_reason
                reclassified += 1
        print(f"  SPF-ASN reclassified: {reclassified}")

    # Recompute counts
    counts = {}
    for m in muni.values():
        counts[m["provider"]] = counts.get(m["provider"], 0) + 1
    data["counts"] = dict(sorted(counts.items()))
    data["total"] = len(muni)
    data["municipalities"] = dict(sorted(muni.items(), key=lambda kv: int(kv[0])))

    remaining = counts.get("unknown", 0)
    print(f"\nFinal counts: {json.dumps(counts)}")

    if remaining > 0:
        print(f"\nStill unknown ({remaining}, for manual review):")
        for m in sorted(muni.values(), key=lambda x: int(x["bfs"])):
            if m["provider"] == "unknown":
                print(
                    f"  {m['bfs']:>5}  {m['name']:<30} {m['canton']:<20} domain={m['domain']}"
                )

    with open(data_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, separators=(",", ":"))

    print(f"\nUpdated {data_path}")
