"""Unit and regression tests for Unified InjectionTarget and parameter preservation."""
from __future__ import annotations

import pytest
from phantomscan.injection_target import InjectionTarget, extract_injection_targets
from phantomscan.modules.sqli_detector import SQLiDetector
from phantomscan.modules.path_traversal import PathTraversalScanner
from phantomscan.http_client import HTTPResult, RobustHTTPClient


def test_extract_multi_param_query_preserves_siblings():
    observations = [
        {
            "name": "parameterized_urls",
            "value": [
                "http://testaspnet.vulnweb.com/ReadNews.aspx?id=3&NewsAd=ads/def.html",
            ],
        }
    ]
    targets = extract_injection_targets(observations, "http://testaspnet.vulnweb.com")
    
    assert len(targets) == 2
    
    t_id = next(t for t in targets if t.param_name == "id")
    assert t_id.url == "http://testaspnet.vulnweb.com/ReadNews.aspx"
    assert t_id.method == "GET"
    assert t_id.all_params == {"id": "3", "NewsAd": "ads/def.html"}
    assert t_id.original_value == "3"
    
    t_ad = next(t for t in targets if t.param_name == "NewsAd")
    assert t_ad.url == "http://testaspnet.vulnweb.com/ReadNews.aspx"
    assert t_ad.method == "GET"
    assert t_ad.all_params == {"id": "3", "NewsAd": "ads/def.html"}
    assert t_ad.original_value == "ads/def.html"


def test_extract_post_form_preserves_hidden_viewstate():
    observations = [
        {
            "name": "discovered_forms",
            "value": [
                {
                    "action": "http://testaspnet.vulnweb.com/Signup.aspx",
                    "method": "POST",
                    "fields": [
                        {"name": "__VIEWSTATE", "type": "hidden", "value": "secret_viewstate_token"},
                        {"name": "__EVENTVALIDATION", "type": "hidden", "value": "event_val_token"},
                        {"name": "tbUsername", "type": "text", "value": ""},
                        {"name": "tbPassword", "type": "password", "value": ""},
                    ],
                }
            ],
        }
    ]
    targets = extract_injection_targets(observations, "http://testaspnet.vulnweb.com")
    
    assert len(targets) >= 1
    t_user = next(t for t in targets if t.param_name == "tbUsername")
    assert t_user.url == "http://testaspnet.vulnweb.com/Signup.aspx"
    assert t_user.method == "POST"
    assert t_user.hidden_fields["__VIEWSTATE"] == "secret_viewstate_token"
    assert t_user.hidden_fields["__EVENTVALIDATION"] == "event_val_token"
    assert "tbUsername" in t_user.all_params


def test_endpoint_level_deduplication_allows_different_pages():
    observations = [
        {
            "name": "parameterized_urls",
            "value": [
                "http://testaspnet.vulnweb.com/Comments.aspx?id=1",
                "http://testaspnet.vulnweb.com/Comments.aspx?id=2",
                "http://testaspnet.vulnweb.com/ReadNews.aspx?id=1",
                "http://testaspnet.vulnweb.com/ReadNews.aspx?id=2",
            ],
        }
    ]
    targets = extract_injection_targets(observations, "http://testaspnet.vulnweb.com")
    
    # Should contain exactly one target for Comments.aspx (param id) and one for ReadNews.aspx (param id)
    assert len(targets) == 2
    urls = {t.url for t in targets}
    assert "http://testaspnet.vulnweb.com/Comments.aspx" in urls
    assert "http://testaspnet.vulnweb.com/ReadNews.aspx" in urls


def test_path_traversal_is_file_like_detects_value_patterns():
    t_ad = InjectionTarget(
        url="http://example.com/ReadNews.aspx",
        param_name="NewsAd",
        original_value="ads/def.html",
        all_params={"id": "3", "NewsAd": "ads/def.html"},
    )
    assert PathTraversalScanner._is_file_like(t_ad) is True

    t_id = InjectionTarget(
        url="http://example.com/ReadNews.aspx",
        param_name="id",
        original_value="3",
        all_params={"id": "3"},
    )
    assert PathTraversalScanner._is_file_like(t_id) is False
