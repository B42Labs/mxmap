from pathlib import Path

from dynaconf import Dynaconf


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

    return settings
