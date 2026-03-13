from unittest.mock import MagicMock, patch

from mail_sovereignty import geoip


class TestInit:
    def setup_method(self):
        geoip._reader = None

    def test_empty_path_returns_false(self):
        assert geoip.init("") is False
        assert geoip._reader is None

    def test_missing_file_returns_false(self):
        assert geoip.init("/nonexistent/path.mmdb") is False
        assert geoip._reader is None

    def test_import_error_returns_false(self):
        with patch.dict("sys.modules", {"geoip2": None, "geoip2.database": None}):
            geoip._reader = None
            assert geoip.init("/some/path.mmdb") is False

    def test_success(self):
        import sys

        mock_reader = MagicMock()
        mock_db_module = MagicMock()
        mock_db_module.Reader.return_value = mock_reader
        mock_geoip2 = MagicMock()
        mock_geoip2.database = mock_db_module

        with patch.dict(
            sys.modules, {"geoip2": mock_geoip2, "geoip2.database": mock_db_module}
        ):
            assert geoip.init("/some/path.mmdb") is True
        assert geoip._reader is mock_reader


class TestCountryForIp:
    def setup_method(self):
        geoip._reader = None

    def test_without_init_returns_none(self):
        assert geoip.country_for_ip("1.2.3.4") is None

    def test_with_reader(self):
        mock_response = MagicMock()
        mock_response.country.iso_code = "DE"
        mock_reader = MagicMock()
        mock_reader.country.return_value = mock_response
        geoip._reader = mock_reader

        assert geoip.country_for_ip("1.2.3.4") == "DE"

    def test_exception_returns_none(self):
        mock_reader = MagicMock()
        mock_reader.country.side_effect = Exception("not found")
        geoip._reader = mock_reader

        assert geoip.country_for_ip("1.2.3.4") is None


class TestCountriesForMxIps:
    def setup_method(self):
        geoip._reader = None

    def test_without_init_returns_empty(self):
        result = geoip.countries_for_mx_ips({"mail.example.de": ["1.2.3.4"]})
        assert result == set()

    def test_with_reader(self):
        mock_response = MagicMock()
        mock_response.country.iso_code = "DE"
        mock_reader = MagicMock()
        mock_reader.country.return_value = mock_response
        geoip._reader = mock_reader

        result = geoip.countries_for_mx_ips(
            {
                "mail1.example.de": ["1.2.3.4"],
                "mail2.example.de": ["5.6.7.8"],
            }
        )
        assert result == {"DE"}

    def test_mixed_countries(self):
        def _country(ip):
            mock = MagicMock()
            mock.country.iso_code = "DE" if ip == "1.2.3.4" else "US"
            return mock

        mock_reader = MagicMock()
        mock_reader.country.side_effect = _country
        geoip._reader = mock_reader

        result = geoip.countries_for_mx_ips(
            {
                "mail1.example.de": ["1.2.3.4"],
                "mail2.example.com": ["5.6.7.8"],
            }
        )
        assert result == {"DE", "US"}
