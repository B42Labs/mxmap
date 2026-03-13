import argparse
import asyncio
from pathlib import Path


def _parse_args():  # pragma: no cover
    """Parse --country (required), --filter, --limit, --no-cache."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--country", required=True, help="Country code (e.g. ch, de)")
    parser.add_argument("--filter", default=None, help="Filter by municipality name")
    parser.add_argument("--limit", type=int, default=None, help="Limit municipalities")
    parser.add_argument(
        "--no-cache",
        action="store_true",
        default=False,
        help="Bypass Wikidata cache and fetch fresh data",
    )
    args, _ = parser.parse_known_args()

    from mail_sovereignty.config import load_country

    config = load_country(args.country)
    return args.country, config, getattr(args, "filter"), args.limit, args.no_cache


def preprocess() -> None:
    country, config, municipality_filter, limit, no_cache = _parse_args()
    from mail_sovereignty.preprocess import run

    output_dir = Path("sites") / country
    output_dir.mkdir(parents=True, exist_ok=True)
    asyncio.run(
        run(
            output_dir / "data.json",
            country_config=config,
            municipality_filter=municipality_filter,
            limit=limit,
            use_cache=not no_cache,
        )
    )


def postprocess() -> None:
    country, config, _, _, _ = _parse_args()
    from mail_sovereignty.postprocess import run

    data_path = Path("sites") / country / "data.json"
    asyncio.run(run(data_path, country_config=config))


def validate() -> None:
    country, config, _, _, _ = _parse_args()
    from mail_sovereignty.validate import run

    data_path = Path("sites") / country / "data.json"
    output_dir = Path("sites") / country
    run(data_path, output_dir, quality_gate=True, country_config=config)


def build_site() -> None:  # pragma: no cover
    country, config, _, _, _ = _parse_args()
    from mail_sovereignty.site_builder import build

    build(country, config)
