import argparse
import asyncio
import sys
from pathlib import Path


def _parse_args():  # pragma: no cover
    """Parse --country, --filter, --limit. Without --country: None (current behaviour)."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--country", default=None)
    parser.add_argument("--filter", default=None, help="Filter by municipality name")
    parser.add_argument("--limit", type=int, default=None, help="Limit municipalities")
    args, _ = parser.parse_known_args()
    config = None
    if args.country:
        from mail_sovereignty.config import load_country

        config = load_country(args.country)
    return args.country, config, getattr(args, "filter"), args.limit


def preprocess() -> None:
    country, config, municipality_filter, limit = _parse_args()
    from mail_sovereignty.preprocess import run

    if country:  # pragma: no cover
        output_dir = Path("sites") / country
        output_dir.mkdir(parents=True, exist_ok=True)
        asyncio.run(
            run(
                output_dir / "data.json",
                country_config=config,
                municipality_filter=municipality_filter,
                limit=limit,
            )
        )
    else:
        asyncio.run(run(Path("data.json")))


def postprocess() -> None:
    country, config, _, _ = _parse_args()
    from mail_sovereignty.postprocess import run

    if country:  # pragma: no cover
        data_path = Path("sites") / country / "data.json"
        asyncio.run(run(data_path, country_config=config))
    else:
        asyncio.run(run(Path("data.json")))


def validate() -> None:
    country, config, _, _ = _parse_args()
    from mail_sovereignty.validate import run

    if country:  # pragma: no cover
        data_path = Path("sites") / country / "data.json"
        output_dir = Path("sites") / country
        run(data_path, output_dir, quality_gate=True, country_config=config)
    else:
        run(Path("data.json"), Path("."), quality_gate=True)


def build_site() -> None:  # pragma: no cover
    country, config, _, _ = _parse_args()
    if not country:
        print("Error: --country is required for build-site")
        sys.exit(1)
    from mail_sovereignty.site_builder import build

    build(country, config)
