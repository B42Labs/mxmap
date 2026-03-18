import asyncio
import json
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from mail_sovereignty import geoip
from mail_sovereignty.classify import classify, detect_gateway
from mail_sovereignty.constants import SPARQL_URL
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


def url_to_domain(url: str | None) -> str | None:
    """Extract the base domain from a URL."""
    if not url:
        return None
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = parsed.hostname or ""
    if host.startswith("www."):
        host = host[4:]
    return host if host else None


def guess_domains(
    name: str, tld: str = ".ch", prefixes: list[str] | None = None
) -> list[str]:
    """Generate a small set of plausible domain guesses for a municipality."""
    _prefixes = prefixes if prefixes is not None else ["gemeinde-", "commune-de-"]
    raw = name.lower().strip()
    raw = re.sub(r"\s*\(.*?\)\s*", "", raw)

    # German umlaut transliteration
    de = raw.replace("\u00fc", "ue").replace("\u00e4", "ae").replace("\u00f6", "oe")
    # French accent removal
    fr = raw
    for a, b in [
        ("\u00e9", "e"),
        ("\u00e8", "e"),
        ("\u00ea", "e"),
        ("\u00eb", "e"),
        ("\u00e0", "a"),
        ("\u00e2", "a"),
        ("\u00f4", "o"),
        ("\u00ee", "i"),
        ("\u00f9", "u"),
        ("\u00fb", "u"),
        ("\u00e7", "c"),
        ("\u00ef", "i"),
    ]:
        fr = fr.replace(a, b)

    def slugify(s):
        s = re.sub(r"['\u2019`]", "", s)
        s = re.sub(r"[^a-z0-9]+", "-", s)
        return s.strip("-")

    slugs = {slugify(de), slugify(fr), slugify(raw)} - {""}
    candidates = set()
    for slug in slugs:
        candidates.add(f"{slug}{tld}")
        for prefix in _prefixes:
            candidates.add(f"{prefix}{slug}{tld}")
    return sorted(candidates)


def _load_cache(cache_path: Path | None) -> dict[str, dict[str, str]] | None:
    """Load municipalities from a cache file if it exists."""
    if cache_path and cache_path.exists():
        with open(cache_path, encoding="utf-8") as f:
            cached = json.load(f)
        print(
            f"  Loaded {len(cached['municipalities'])} municipalities from cache ({cache_path})"
        )
        print(f"  Cache date: {cached['fetched']}")
        return cached["municipalities"]
    return None


def _save_cache(
    cache_path: Path | None, municipalities: dict[str, dict[str, str]]
) -> None:
    """Save municipalities to a cache file."""
    if not cache_path:
        return
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "fetched": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total": len(municipalities),
        "municipalities": municipalities,
    }
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    print(f"  Cached {len(municipalities)} municipalities to {cache_path}")


async def fetch_wikidata(
    country_config=None,
    *,
    max_retries: int = 4,
    base_delay: float = 5.0,
    cache_path: Path | None = None,
    use_cache: bool = True,
) -> dict[str, dict[str, str]]:
    """Query Wikidata for municipalities with retry and exponential backoff.

    If *use_cache* is True and a cache file exists at *cache_path*, the cached
    data is returned without hitting Wikidata.  After a successful fetch the
    result is written to *cache_path* for future runs.
    """
    if country_config:
        sparql_query = country_config.sparql_query
        sparql_url = country_config.sparql_url
        label = country_config.country_code.upper()
    else:
        sparql_query = ""
        sparql_url = SPARQL_URL
        label = "Unknown"

    if use_cache:
        cached = _load_cache(cache_path)
        if cached is not None:
            return cached

    print(f"Querying Wikidata for {label} municipalities...")
    headers = {
        "Accept": "application/sparql-results+json",
        "User-Agent": "B42Labs/mxmap (https://github.com/B42Labs/mxmap)",
    }
    last_exception: Exception | None = None
    async with httpx.AsyncClient(timeout=120) as client:
        for attempt in range(max_retries + 1):
            try:
                r = await client.post(
                    sparql_url,
                    data={"query": sparql_query},
                    headers=headers,
                )
                r.raise_for_status()
                data = r.json()
                break
            except httpx.HTTPStatusError as exc:
                last_exception = exc
                if exc.response.status_code in (429, 403) and attempt < max_retries:
                    delay = base_delay * (2**attempt)
                    print(
                        f"  Rate limited ({exc.response.status_code}), "
                        f"retrying in {delay:.0f}s (attempt {attempt + 1}/{max_retries})..."
                    )
                    await asyncio.sleep(delay)
                    continue
                raise
            except httpx.TimeoutException as exc:
                last_exception = exc
                if attempt < max_retries:
                    delay = base_delay * (2**attempt)
                    print(
                        f"  Request timed out, "
                        f"retrying in {delay:.0f}s (attempt {attempt + 1}/{max_retries})..."
                    )
                    await asyncio.sleep(delay)
                    continue
                raise
            except httpx.RequestError as exc:
                last_exception = exc
                if attempt < max_retries:
                    delay = base_delay * (2**attempt)
                    print(
                        f"  Connection error ({type(exc).__name__}), "
                        f"retrying in {delay:.0f}s (attempt {attempt + 1}/{max_retries})..."
                    )
                    await asyncio.sleep(delay)
                    continue
                raise
        else:
            raise RuntimeError(
                "Wikidata query failed after all retries"
            ) from last_exception

    municipalities = {}
    for row in data["results"]["bindings"]:
        bfs = row["bfs"]["value"]
        name = row.get("itemLabel", {}).get("value", f"BFS-{bfs}")
        website = row.get("website", {}).get("value", "")
        canton = row.get("cantonLabel", {}).get("value", "")

        if bfs not in municipalities:
            municipalities[bfs] = {
                "bfs": bfs,
                "name": name,
                "website": website,
                "canton": canton,
            }
        elif not municipalities[bfs]["website"] and website:
            municipalities[bfs]["website"] = website

    print(
        f"  Found {len(municipalities)} municipalities, "
        f"{sum(1 for m in municipalities.values() if m['website'])} with websites"
    )
    _save_cache(cache_path, municipalities)
    return municipalities


async def scan_municipality(
    m: dict[str, str], semaphore: asyncio.Semaphore, country_config=None
) -> dict[str, Any]:
    """Scan a single municipality for email provider info."""
    async with semaphore:
        domain = url_to_domain(m.get("website", ""))
        mx, spf = [], ""

        txt_verifications: dict[str, str] = {}
        if domain:
            mx = await lookup_mx(domain)
            if mx:
                spf, txt_verifications = await lookup_txt(domain)

        if not mx:
            tld = country_config.tld if country_config else ".ch"
            prefixes = list(country_config.domain_prefixes) if country_config else None
            for guess in guess_domains(m["name"], tld=tld, prefixes=prefixes):
                if guess == domain:
                    continue
                mx = await lookup_mx(guess)
                if mx:
                    domain = guess
                    spf, txt_verifications = await lookup_txt(guess)
                    break

        spf_resolved = await resolve_spf_includes(spf) if spf else ""
        mx_cnames = await resolve_mx_cnames(mx) if mx else {}
        mx_ips = await resolve_mx_ips(mx) if mx else {}
        mx_asns = await resolve_asns_from_ips(mx_ips) if mx_ips else set()
        mx_ptrs = await resolve_mx_ptrs(mx_ips) if mx_ips else {}
        mx_geoip_countries = geoip.countries_for_mx_ips(mx_ips) if mx_ips else set()
        autodiscover = await lookup_autodiscover(domain) if domain else {}
        dkim = await lookup_dkim(domain) if domain else {}
        spf_asns = await resolve_spf_asns(spf_resolved or spf) if spf else set()

        domestic = country_config.domestic_config if country_config else None
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

        entry: dict[str, Any] = {
            "bfs": m["bfs"],
            "name": m["name"],
            "canton": m.get("canton", ""),
            "domain": domain or "",
            "mx": mx,
            "spf": spf,
            "provider": provider,
            "reason": reason,
        }
        if spf_resolved and spf_resolved != spf:
            entry["spf_resolved"] = spf_resolved
        if gateway:
            entry["gateway"] = gateway
        if mx_cnames:
            entry["mx_cnames"] = mx_cnames
        if mx_asns:
            entry["mx_asns"] = sorted(mx_asns)
        if mx_ptrs:
            entry["mx_ptrs"] = mx_ptrs
        if mx_geoip_countries:
            entry["mx_geoip_countries"] = sorted(mx_geoip_countries)
        if spf_asns:
            entry["spf_asns"] = sorted(spf_asns)
        if autodiscover:
            entry["autodiscover"] = autodiscover
        if dkim:
            entry["dkim"] = dkim
        if txt_verifications:
            entry["txt_verifications"] = txt_verifications
        return entry


def _format_counts(counts: dict[str, int]) -> str:
    """Format provider counts as a compact status line."""
    parts = []
    for provider in ["microsoft", "google", "aws"]:
        if counts.get(provider, 0):
            parts.append(f"{provider}={counts[provider]}")
    indep = counts.get("independent", 0)
    if indep:
        parts.append(f"indep={indep}")
    unknown = counts.get("unknown", 0)
    if unknown:
        parts.append(f"?={unknown}")
    return "  ".join(parts)


async def run(
    output_path: Path,
    country_config=None,
    municipality_filter: str | None = None,
    limit: int | None = None,
    use_cache: bool = True,
) -> None:
    country_code = country_config.country_code if country_config else "unknown"
    cache_path = Path("cache") / f"wikidata_{country_code}.json"
    concurrency = country_config.concurrency if country_config else 20
    geoip_db = getattr(country_config, "geoip_db", "") if country_config else ""
    if geoip_db:
        geoip.init(geoip_db)
    municipalities = await fetch_wikidata(
        country_config, cache_path=cache_path, use_cache=use_cache
    )

    if municipality_filter:
        municipalities = {
            k: v
            for k, v in municipalities.items()
            if municipality_filter.lower() in v["name"].lower()
        }
    if limit:
        municipalities = dict(list(municipalities.items())[:limit])

    total = len(municipalities)

    print(f"\nScanning {total} municipalities for MX/SPF records...")
    print("(This takes a few minutes with async lookups)\n")

    semaphore = asyncio.Semaphore(concurrency)
    tasks = [
        scan_municipality(m, semaphore, country_config) for m in municipalities.values()
    ]

    results = {}
    done = 0
    for coro in asyncio.as_completed(tasks):
        result = await coro
        results[result["bfs"]] = result
        done += 1
        if done % 50 == 0 or done == total:
            counts = {}
            for r in results.values():
                counts[r["provider"]] = counts.get(r["provider"], 0) + 1
            print(f"  [{done:4d}/{total}]  {_format_counts(counts)}")

    counts: dict[str, int] = {}
    detail_counts: dict[str, int] = {}
    for r in results.values():
        counts[r["provider"]] = counts.get(r["provider"], 0) + 1
        # Extract ISP name from reason for detail_counts
        reason = r.get("reason", "")
        if reason.endswith("(ASN match)"):
            isp_name = reason.rsplit(" (ASN match)", 1)[0]
            detail_counts[isp_name] = detail_counts.get(isp_name, 0) + 1

    print(f"\n{'=' * 50}")
    print(f"RESULTS: {len(results)} municipalities scanned")
    known = {
        "microsoft",
        "google",
        "aws",
        "independent",
        "unknown",
        "gateway",
        "public-it",
        "hosted-provider",
        "german-isp",
    }
    for provider in [
        "microsoft",
        "google",
        "aws",
        "public-it",
        "hosted-provider",
        "gateway",
        "independent",
        "unknown",
    ]:
        if counts.get(provider, 0):
            print(f"  {provider:<20}: {counts[provider]:>5}")
    for provider in sorted(counts):
        if provider not in known and counts[provider]:
            print(f"  {provider:<20}: {counts[provider]:>5}")
    print(f"{'=' * 50}")

    sorted_counts = dict(sorted(counts.items()))
    sorted_munis = dict(sorted(results.items(), key=lambda kv: int(kv[0])))

    # Build public-it ASN mapping for frontend split toggle
    domestic = country_config.domestic_config if country_config else None
    public_it_asns: dict[str, str] = {}
    if domestic and domestic.asn_categories:
        for asn, cat in domestic.asn_categories.items():
            if cat == "public-it":
                public_it_asns[str(asn)] = domestic.asns.get(asn, "")

    output: dict[str, Any] = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total": len(results),
        "counts": sorted_counts,
        "municipalities": sorted_munis,
    }
    if detail_counts:
        output["detail_counts"] = dict(sorted(detail_counts.items()))
    if public_it_asns:
        output["public_it_asns"] = public_it_asns

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=None, separators=(",", ":"))

    size_kb = len(json.dumps(output)) / 1024
    print(f"\nWritten {output_path} ({size_kb:.0f} KB)")
