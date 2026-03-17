from dataclasses import dataclass

from mail_sovereignty.constants import (
    AWS_KEYWORDS,
    FOREIGN_SENDER_KEYWORDS,
    GATEWAY_KEYWORDS,
    GOOGLE_KEYWORDS,
    HYPERSCALER_ASNS,
    MAILBOX_ASNS,
    MICROSOFT_KEYWORDS,
    PROVIDER_KEYWORDS,
    SMTP_BANNER_KEYWORDS,
)


@dataclass(frozen=True)
class DomesticConfig:
    asns: dict[int, str]  # curated ASN -> ISP name
    domains: list[str]  # known domestic domain suffixes
    country_tlds: list[str]  # e.g. [".de"]
    target_country: str  # ISO code for GeoIP, e.g. "DE"
    label: str  # e.g. "german-isp"


def classify_from_smtp_banner(banner: str, ehlo: str = "") -> str | None:
    """Classify provider from SMTP banner/EHLO. Returns provider or None."""
    if not banner and not ehlo:
        return None
    blob = f"{banner} {ehlo}".lower()
    for provider, keywords in SMTP_BANNER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            return provider
    return None


def classify_from_autodiscover(autodiscover: dict[str, str] | None) -> str | None:
    """Classify provider from autodiscover DNS records."""
    if not autodiscover:
        return None
    blob = " ".join(autodiscover.values()).lower()
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            return provider
    return None


def detect_gateway(mx_records: list[str]) -> str | None:
    """Return gateway provider name if MX matches a known gateway, else None."""
    mx_blob = " ".join(mx_records).lower()
    for gateway, keywords in GATEWAY_KEYWORDS.items():
        if any(k in mx_blob for k in keywords):
            return gateway
    return None


def _check_spf_for_provider(spf_blob: str) -> str | None:
    """Check an SPF blob for hyperscaler keywords, return provider or None."""
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if any(k in spf_blob for k in keywords):
            return provider
    return None


def _classify_from_spf_asns(spf_asns: set[int] | None) -> str | None:
    """Classify provider from ASNs resolved from SPF ip4: blocks."""
    if not spf_asns:
        return None
    for provider in ("microsoft", "google"):
        if any(MAILBOX_ASNS.get(a) == provider for a in spf_asns):
            return provider
    return None


def _check_domestic(
    mx_records: list[str],
    mx_asns: set[int] | None,
    mx_ptrs: dict[str, str] | None,
    mx_geoip_countries: set[str] | None,
    domestic: DomesticConfig,
) -> bool:
    """Check if MX setup points to a domestic ISP."""
    asns = mx_asns or set()
    all_hyperscaler = bool(asns) and asns.issubset(HYPERSCALER_ASNS)

    # Signal 1: ASN in curated domestic list (strongest — always trust)
    if asns & domestic.asns.keys():
        return True

    # Signal 2: GeoIP matches target country AND ASNs not all hyperscaler
    if mx_geoip_countries and domestic.target_country in mx_geoip_countries:
        if not all_hyperscaler:
            return True

    # Signals 3-5 are weaker heuristics; skip if all ASNs are hyperscaler
    # (custom domain on Azure/GCP/AWS should not be classified as domestic ISP)
    if all_hyperscaler:
        return False

    # Signal 3: PTR hostname matches domestic domains or country TLD
    if mx_ptrs:
        for ptr in mx_ptrs.values():
            ptr_lower = ptr.lower()
            if any(ptr_lower.endswith(d) for d in domestic.domains):
                return True
            if any(ptr_lower.endswith(tld) for tld in domestic.country_tlds):
                return True

    # Signal 4: MX hostname matches domestic domains
    mx_blob = " ".join(mx_records).lower()
    if any(d in mx_blob for d in domestic.domains):
        return True

    # Signal 5: MX hostname ends with country TLD
    for mx in mx_records:
        mx_lower = mx.lower()
        if any(mx_lower.endswith(tld) for tld in domestic.country_tlds):
            return True

    return False


def classify(
    mx_records: list[str],
    spf_record: str | None,
    mx_cnames: dict[str, str] | None = None,
    mx_asns: set[int] | None = None,
    resolved_spf: str | None = None,
    autodiscover: dict[str, str] | None = None,
    mx_ptrs: dict[str, str] | None = None,
    mx_geoip_countries: set[str] | None = None,
    spf_asns: set[int] | None = None,
    domestic: DomesticConfig | None = None,
) -> str:
    """Classify email provider based on MX, CNAME targets, and SPF.

    Detects hyperscalers (Microsoft, Google, AWS). Everything else with
    valid MX records is classified as 'independent'.

    MX records are checked first (they show where mail is actually delivered).
    CNAME targets of MX hosts are checked next (to detect hidden hyperscaler usage).
    If MX points to a known gateway, SPF (including resolved includes) is checked
    to identify the actual mailbox provider behind the gateway.
    SPF is only used as fallback when MX alone is inconclusive.
    """
    mx_blob = " ".join(mx_records).lower()

    if any(k in mx_blob for k in MICROSOFT_KEYWORDS):
        return "microsoft"
    if any(k in mx_blob for k in GOOGLE_KEYWORDS):
        return "google"
    if any(k in mx_blob for k in AWS_KEYWORDS):
        return "aws"

    if mx_records and mx_cnames:
        cname_blob = " ".join(mx_cnames.values()).lower()
        if any(k in cname_blob for k in MICROSOFT_KEYWORDS):
            return "microsoft"
        if any(k in cname_blob for k in GOOGLE_KEYWORDS):
            return "google"
        if any(k in cname_blob for k in AWS_KEYWORDS):
            return "aws"

    if mx_records and detect_gateway(mx_records):
        spf_blob = (spf_record or "").lower()
        provider = _check_spf_for_provider(spf_blob)
        if not provider and resolved_spf:
            provider = _check_spf_for_provider(resolved_spf.lower())
        if provider:
            return provider
        # No hyperscaler in SPF — check autodiscover for backend provider
        ad_provider = classify_from_autodiscover(autodiscover)
        if ad_provider:
            return ad_provider
        # Gateway relays to independent, fall through

    if mx_records:
        # Check autodiscover for hyperscaler backend behind independent MX
        ad_provider = classify_from_autodiscover(autodiscover)
        if ad_provider:
            return ad_provider
        # Check SPF ip4: ASNs for mailbox-hosting hyperscaler
        spf_asn_provider = _classify_from_spf_asns(spf_asns)
        if spf_asn_provider:
            return spf_asn_provider
        if domestic and _check_domestic(
            mx_records, mx_asns, mx_ptrs, mx_geoip_countries, domestic
        ):
            return domestic.label
        return "independent"

    spf_blob = (spf_record or "").lower()
    provider = _check_spf_for_provider(spf_blob)
    if not provider and resolved_spf:
        provider = _check_spf_for_provider(resolved_spf.lower())
    if provider:
        return provider

    return "unknown"


def classify_from_mx(mx_records: list[str]) -> str | None:
    """Classify provider from MX records alone."""
    if not mx_records:
        return None
    blob = " ".join(mx_records).lower()
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            return provider
    return "independent"


def classify_from_spf(spf_record: str | None) -> str | None:
    """Classify provider from SPF record alone."""
    if not spf_record:
        return None
    blob = spf_record.lower()
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            return provider
    return None


def spf_mentions_providers(spf_record: str | None) -> set[str]:
    """Return set of providers mentioned in SPF (main + foreign senders)."""
    if not spf_record:
        return set()
    blob = spf_record.lower()
    found = set()
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            found.add(provider)
    for provider, keywords in FOREIGN_SENDER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            found.add(provider)
    return found
