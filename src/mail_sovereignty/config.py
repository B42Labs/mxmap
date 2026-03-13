from pathlib import Path

from dynaconf import Dynaconf

from mail_sovereignty.classify import DomesticConfig


def build_domestic_config(settings: Dynaconf) -> DomesticConfig | None:
    """Build DomesticConfig from country settings. Returns None if not configured."""
    label = settings.get("map", {}).get("domestic_isp_label", "")
    if not label:
        return None

    raw_asns = settings.get("domestic_isp_asns", {})
    asns = {int(k): str(v) for k, v in raw_asns.items()}

    map_cfg = settings.get("map", {})
    domains = list(map_cfg.get("domestic_domains", []))
    country_tlds = list(map_cfg.get("country_tlds", []))
    target_country = settings.get("country_code", "").upper()

    return DomesticConfig(
        asns=asns,
        domains=domains,
        country_tlds=country_tlds,
        target_country=target_country,
        label=label,
    )


def load_country(code: str) -> Dynaconf:
    """Load country-specific configuration on top of global defaults."""
    settings = Dynaconf(
        settings_files=["config/settings.toml", f"config/{code}.toml"],
        environments=False,
    )

    # Load SPARQL query from external file
    sparql_path = Path(settings.sparql_query_file)
    settings.set("sparql_query", sparql_path.read_text())

    # Merge skip_domains with country-specific extras
    base_skip = set(settings.get("skip_domains", []))
    extra_skip = set(settings.get("skip_domains_extra", []))
    settings.set("skip_domains_merged", base_skip | extra_skip)

    # Convert manual_override_ids to a set
    override_ids = settings.get("manual_override_ids", [])
    settings.set("manual_override_ids_set", set(override_ids))

    # Normalize manual_overrides to plain dicts
    raw_overrides = settings.get("manual_overrides", {})
    manual_overrides = {}
    for bfs, override in raw_overrides.items():
        d = dict(override) if hasattr(override, "items") else override
        if "mx" in d:
            d["mx"] = list(d["mx"])
        manual_overrides[str(bfs)] = d
    settings.set("manual_overrides", manual_overrides)

    # Build domestic ISP config
    domestic = build_domestic_config(settings)
    settings.set("domestic_config", domestic)

    return settings
