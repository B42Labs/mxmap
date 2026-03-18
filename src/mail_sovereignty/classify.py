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
    asn_categories: dict[
        int, str
    ]  # ASN -> category label ("public-it", "hosted-provider")
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


def classify_from_dkim(dkim: dict[str, str] | None) -> str | None:
    """Classify provider from DKIM CNAME targets."""
    if not dkim:
        return None
    blob = " ".join(dkim.values()).lower()
    if "onmicrosoft.com" in blob:
        return "microsoft"
    if "google" in blob or "googlemail" in blob:
        return "google"
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            return provider
    return None


def classify_from_txt_verifications(
    txt_verifications: dict[str, str] | None,
) -> str | None:
    """Classify provider from TXT verification tokens (ms=, google-site-verification=)."""
    if not txt_verifications:
        return None
    if "microsoft" in txt_verifications:
        return "microsoft"
    if "google" in txt_verifications:
        return "google"
    return None


def _check_domestic(
    mx_records: list[str],
    mx_asns: set[int] | None,
    mx_ptrs: dict[str, str] | None,
    mx_geoip_countries: set[str] | None,
    domestic: DomesticConfig,
) -> tuple[str, str] | None:
    """Check if MX setup points to a domestic ISP.

    Returns (category_label, isp_name) or None.
    category_label is from asn_categories if available, otherwise domestic.label.
    isp_name is the ISP name from the ASN mapping, or empty for weak signals.
    """
    asns = mx_asns or set()
    all_hyperscaler = bool(asns) and asns.issubset(HYPERSCALER_ASNS)

    # Signal 1: ASN in curated domestic list (strongest — always trust)
    # When multiple ASNs match, prefer public-it over hosted-provider.
    matched_asns = asns & domestic.asns.keys()
    if matched_asns:
        best_asn = min(
            matched_asns,
            key=lambda a: (
                0 if domestic.asn_categories.get(a) == "public-it" else 1,
                a,
            ),
        )
        isp_name = domestic.asns[best_asn]
        category = domestic.asn_categories.get(best_asn, domestic.label)
        return (category, isp_name)

    # Signal 2: GeoIP matches target country AND ASNs not all hyperscaler
    if mx_geoip_countries and domestic.target_country in mx_geoip_countries:
        if not all_hyperscaler:
            return (domestic.label, "")

    # Signals 3-5 are weaker heuristics; skip if all ASNs are hyperscaler
    # (custom domain on Azure/GCP/AWS should not be classified as domestic ISP)
    if all_hyperscaler:
        return None

    # Signal 3: PTR hostname matches domestic domains or country TLD
    if mx_ptrs:
        for ptr in mx_ptrs.values():
            ptr_lower = ptr.lower()
            if any(ptr_lower.endswith(d) for d in domestic.domains):
                return (domestic.label, "")
            if any(ptr_lower.endswith(tld) for tld in domestic.country_tlds):
                return (domestic.label, "")

    # Signal 4: MX hostname matches domestic domains
    mx_blob = " ".join(mx_records).lower()
    if any(d in mx_blob for d in domestic.domains):
        return (domestic.label, "")

    # Signal 5: MX hostname ends with country TLD
    for mx in mx_records:
        mx_lower = mx.lower()
        if any(mx_lower.endswith(tld) for tld in domestic.country_tlds):
            return (domestic.label, "")

    return None


def _check_spf_all(spf_record: str | None, resolved_spf: str | None) -> str | None:
    """Check raw + resolved SPF for hyperscaler keywords in one call."""
    spf_blob = (spf_record or "").lower()
    provider = _check_spf_for_provider(spf_blob)
    if not provider and resolved_spf:
        provider = _check_spf_for_provider(resolved_spf.lower())
    return provider


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
    dkim: dict[str, str] | None = None,
    txt_verifications: dict[str, str] | None = None,
) -> tuple[str, str]:
    """Classify email provider based on MX, CNAME targets, SPF, DKIM, and TXT.

    Returns (provider, reason) tuple.

    Detects hyperscalers (Microsoft, Google, AWS). Everything else with
    valid MX records is classified as 'independent'.

    MX records are checked first (they show where mail is actually delivered).
    CNAME targets of MX hosts are checked next (to detect hidden hyperscaler usage).
    If MX points to a known gateway, multiple signals (SPF, DKIM, autodiscover,
    TXT verification) are checked to identify the actual mailbox provider.
    SPF is only used as fallback when MX alone is inconclusive.
    """
    mx_blob = " ".join(mx_records).lower()

    if any(k in mx_blob for k in MICROSOFT_KEYWORDS):
        return ("microsoft", "MX matches Microsoft")
    if any(k in mx_blob for k in GOOGLE_KEYWORDS):
        return ("google", "MX matches Google")
    if any(k in mx_blob for k in AWS_KEYWORDS):
        return ("aws", "MX matches AWS")

    if mx_records and mx_cnames:
        cname_blob = " ".join(mx_cnames.values()).lower()
        if any(k in cname_blob for k in MICROSOFT_KEYWORDS):
            return ("microsoft", "MX CNAME resolves to Microsoft")
        if any(k in cname_blob for k in GOOGLE_KEYWORDS):
            return ("google", "MX CNAME resolves to Google")
        if any(k in cname_blob for k in AWS_KEYWORDS):
            return ("aws", "MX CNAME resolves to AWS")

    gateway = detect_gateway(mx_records) if mx_records else None
    if gateway:
        # Collect all signals
        spf_provider = _check_spf_all(spf_record, resolved_spf)
        ad_provider = classify_from_autodiscover(autodiscover)
        dkim_provider = classify_from_dkim(dkim)
        txt_provider = classify_from_txt_verifications(txt_verifications)

        if spf_provider:
            # Require confirmation from DKIM or autodiscover
            if spf_provider == dkim_provider or spf_provider == ad_provider:
                confirm = "DKIM" if spf_provider == dkim_provider else "autodiscover"
                return (
                    spf_provider,
                    f"MX is {gateway} gateway; SPF+{confirm} confirm {spf_provider}",
                )
            # No confirmation sources available — trust SPF alone (backward compat)
            if not ad_provider and not dkim_provider:
                return (
                    spf_provider,
                    f"MX is {gateway} gateway; SPF points to {spf_provider}",
                )
            # Contradiction — prefer DKIM > autodiscover
            if dkim_provider:
                return (
                    dkim_provider,
                    f"MX is {gateway} gateway; DKIM overrides SPF ({dkim_provider} vs {spf_provider})",
                )
            if ad_provider:
                return (
                    ad_provider,
                    f"MX is {gateway} gateway; autodiscover overrides SPF ({ad_provider} vs {spf_provider})",
                )

        # No SPF provider — try other signals
        if ad_provider:
            return (
                ad_provider,
                f"MX is {gateway} gateway; autodiscover points to {ad_provider}",
            )
        if dkim_provider:
            return (
                dkim_provider,
                f"MX is {gateway} gateway; DKIM signs via {dkim_provider}",
            )
        if txt_provider:
            return (
                txt_provider,
                f"MX is {gateway} gateway; TXT verification proves {txt_provider}",
            )
        # Gateway with unknown backend
        return ("gateway", f"MX is {gateway} gateway; backend unknown")

    if mx_records:
        # Check autodiscover for hyperscaler backend behind independent MX
        ad_provider = classify_from_autodiscover(autodiscover)
        if ad_provider:
            return (ad_provider, f"autodiscover points to {ad_provider}")
        # Check DKIM for hyperscaler backend
        dkim_provider = classify_from_dkim(dkim)
        if dkim_provider:
            return (dkim_provider, f"DKIM reveals {dkim_provider} backend")
        # Check SPF ip4: ASNs for mailbox-hosting hyperscaler
        spf_asn_provider = _classify_from_spf_asns(spf_asns)
        if spf_asn_provider:
            return (spf_asn_provider, f"SPF ip4 ASN matches {spf_asn_provider}")
        domestic_result = (
            _check_domestic(mx_records, mx_asns, mx_ptrs, mx_geoip_countries, domestic)
            if domestic
            else None
        )
        if domestic_result:
            category, isp_name = domestic_result
            if isp_name:
                return (category, f"{isp_name} (ASN match)")
            return (category, "domestic ISP signals")
        return ("independent", "MX is self-hosted")

    spf_provider = _check_spf_all(spf_record, resolved_spf)
    if spf_provider:
        return (spf_provider, f"no MX; SPF matches {spf_provider}")

    return ("unknown", "no MX records found")


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
