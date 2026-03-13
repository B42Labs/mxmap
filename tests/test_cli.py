import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

from mail_sovereignty.cli import postprocess, preprocess, validate


class TestCli:
    def test_preprocess(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["prog", "--country", "ch"])
        with (
            patch("mail_sovereignty.config.load_country") as mock_load,
            patch(
                "mail_sovereignty.preprocess.run", new_callable=AsyncMock
            ) as mock_run,
        ):
            mock_load.return_value = type(
                "Config",
                (),
                {"country_code": "ch", "concurrency": 20},
            )()
            preprocess()
            mock_run.assert_called_once()

    def test_postprocess(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["prog", "--country", "ch"])
        with (
            patch("mail_sovereignty.config.load_country") as mock_load,
            patch(
                "mail_sovereignty.postprocess.run", new_callable=AsyncMock
            ) as mock_run,
        ):
            mock_load.return_value = type("Config", (), {"country_code": "ch"})()
            postprocess()
            mock_run.assert_called_once()

    def test_validate(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["prog", "--country", "ch"])
        with (
            patch("mail_sovereignty.config.load_country") as mock_load,
            patch("mail_sovereignty.validate.run") as mock_run,
        ):
            config = type("Config", (), {"country_code": "ch"})()
            mock_load.return_value = config
            validate()
            mock_run.assert_called_once_with(
                Path("sites/ch/data.json"),
                Path("sites/ch"),
                quality_gate=True,
                country_config=config,
            )
