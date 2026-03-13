"""Optional GeoIP lookup module. Gracefully degrades if geoip2 is not installed."""

import logging

logger = logging.getLogger(__name__)

_reader = None


def init(db_path: str) -> bool:
    """Initialize GeoIP reader. Returns True on success, False otherwise."""
    global _reader
    if not db_path:
        return False
    try:
        import geoip2.database

        _reader = geoip2.database.Reader(db_path)
        return True
    except Exception as e:
        logger.debug("GeoIP init failed: %s", e)
        _reader = None
        return False


def country_for_ip(ip: str) -> str | None:
    """Return ISO country code for an IP, or None."""
    if _reader is None:
        return None
    try:
        response = _reader.country(ip)
        return response.country.iso_code
    except Exception:
        return None


def countries_for_mx_ips(mx_ips: dict[str, list[str]]) -> set[str]:
    """Batch lookup: return set of country codes for all MX IPs."""
    countries: set[str] = set()
    for ips in mx_ips.values():
        for ip in ips:
            code = country_for_ip(ip)
            if code:
                countries.add(code)
    return countries
