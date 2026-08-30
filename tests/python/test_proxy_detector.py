"""Unit tests for phantomscan.proxy_detector smart proxy and auto-routing."""

import pytest
import asyncio
from unittest.mock import patch, MagicMock
from phantomscan.proxy_detector import (
    check_port_open,
    get_system_proxies,
    probe_target_via_proxy,
    async_probe_target_via_proxy,
    find_working_proxy,
    auto_resolve_route,
)


def test_check_port_open_success():
    with patch("socket.socket") as mock_sock:
        instance = MagicMock()
        instance.connect.return_value = None
        mock_sock.return_value = instance

        assert check_port_open("127.0.0.1", 8080) is True


def test_check_port_open_failure():
    with patch("socket.socket") as mock_sock:
        instance = MagicMock()
        instance.connect.side_effect = ConnectionRefusedError()
        mock_sock.return_value = instance

        assert check_port_open("127.0.0.1", 9999) is False


def test_get_system_proxies(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:8080")
    monkeypatch.setenv("HTTPS_PROXY", "127.0.0.1:8080")

    proxies = get_system_proxies()
    assert "http://127.0.0.1:8080" in proxies


def test_probe_target_via_proxy_success():
    with patch("urllib.request.build_opener") as mock_opener:
        mock_instance = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__.return_value = mock_resp
        mock_instance.open.return_value = mock_resp
        mock_opener.return_value = mock_instance

        assert probe_target_via_proxy("http://example.com", "http://127.0.0.1:8080") is True


def test_probe_target_via_proxy_failure():
    with patch("urllib.request.build_opener") as mock_opener:
        mock_instance = MagicMock()
        mock_instance.open.side_effect = Exception("Connection refused")
        mock_opener.return_value = mock_instance

        assert probe_target_via_proxy("http://example.com", "http://127.0.0.1:8080") is False


@pytest.mark.asyncio
async def test_find_working_proxy():
    with patch("phantomscan.proxy_detector.check_port_open", return_value=True), \
         patch("phantomscan.proxy_detector.async_probe_target_via_proxy", return_value=True):
        result = await find_working_proxy("http://testphp.vulnweb.com")
        assert result is not None
        proxy_url, desc = result
        assert "http://127.0.0.1" in proxy_url


@pytest.mark.asyncio
async def test_auto_resolve_route_explicit():
    proxy, desc = await auto_resolve_route("http://testphp.vulnweb.com", configured_proxy="http://127.0.0.1:8080")
    assert proxy == "http://127.0.0.1:8080"
    assert "Explicit proxy" in desc


@pytest.mark.asyncio
async def test_auto_resolve_route_deep_profile_auto_detect():
    with patch("phantomscan.proxy_detector.find_working_proxy", return_value=("http://127.0.0.1:8080", "Burp Suite on port 8080")):
        proxy, desc = await auto_resolve_route("http://testphp.vulnweb.com", profile="deep")
        assert proxy == "http://127.0.0.1:8080"
        assert "Auto-detected" in desc
