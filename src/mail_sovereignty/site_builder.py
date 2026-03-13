import shutil
from pathlib import Path

from jinja2 import Environment, FileSystemLoader


def build(country: str, config) -> None:
    """Render country-specific templates to sites/{country}/."""
    env = Environment(loader=FileSystemLoader(f"templates/{country}"))
    output_dir = Path("sites") / country
    output_dir.mkdir(parents=True, exist_ok=True)

    # Convert dynaconf objects to plain dicts for Jinja2
    map_cfg = dict(config.map)
    if "domestic_domains" in map_cfg:
        map_cfg["domestic_domains"] = list(map_cfg["domestic_domains"])
    if "country_tlds" in map_cfg:
        map_cfg["country_tlds"] = list(map_cfg["country_tlds"])

    site_cfg = dict(config.site)

    context = {
        "map": map_cfg,
        "site": site_cfg,
        "country_code": country,
        "domestic_isp_label": map_cfg.get("domestic_isp_label", "domestic-isp"),
    }

    for tpl_name in ["index.html", "datenschutz.html", "impressum.html"]:
        template = env.get_template(tpl_name)
        rendered = template.render(**context)
        (output_dir / tpl_name).write_text(rendered)

    # Copy TopoJSON file if configured as a local path
    topojson_url = map_cfg.get("topojson_url", "")
    if topojson_url and not topojson_url.startswith(("http://", "https://")):
        src = Path("config/geo") / topojson_url
        if src.exists():
            shutil.copy2(src, output_dir / topojson_url)
            print(f"Copied {src} -> {output_dir / topojson_url}")

    print(f"Built site for '{country}' in {output_dir}/")
