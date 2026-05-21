# GhostOpcode — vhost_scan unit tests
# Run: pytest tests/test_vhost_scan.py -v

from __future__ import annotations

import pytest

from modules.vhost_scan import (
    build_hostname_list,
    is_different_from_baseline,
    _assess_risk,
    _response_is_cdn_dns_noise,
    _title_suggests_cdn_baseline,
)


class TestBuildHostnameList:
    def test_simple_word_becomes_subdomain(self) -> None:
        result = build_hostname_list(["api", "dev"], "example.com", [])
        assert "api.example.com" in result
        assert "dev.example.com" in result

    def test_fqdn_word_kept_as_is(self) -> None:
        result = build_hostname_list(["api.other.com"], "example.com", [])
        assert "api.other.com" in result

    def test_known_fqdns_excluded(self) -> None:
        """Already-known FQDNs must not appear in the candidate list."""
        known = ["api.example.com"]
        result = build_hostname_list(["api"], "example.com", known)
        assert "api.example.com" not in result

    def test_suffix_variations_generated_from_known_fqdns(self) -> None:
        known = ["www.example.com"]
        result = build_hostname_list([], "example.com", known)
        assert "www-dev.example.com" in result
        assert "www-staging.example.com" in result

    def test_no_short_hostnames(self) -> None:
        """Words shorter than 4 chars after building should be excluded."""
        result = build_hostname_list(["ab"], "example.com", [])
        # "ab.example.com" has len > 3, so it should appear
        # but "ab" alone should not appear
        for h in result:
            assert len(h) > 3

    def test_result_is_sorted(self) -> None:
        words = ["zzz", "aaa", "mmm"]
        result = build_hostname_list(words, "example.com", [])
        assert result == sorted(result)

    def test_empty_inputs(self) -> None:
        result = build_hostname_list([], "example.com", [])
        assert isinstance(result, list)


class TestIsDifferentFromBaseline:
    BASELINE = {"status": 200, "length": 10000, "title": "Default Page"}

    def test_same_response_not_different(self) -> None:
        resp = {"status": 200, "length": 10000, "title": "Default Page"}
        assert not is_different_from_baseline(resp, self.BASELINE)

    def test_different_status_is_different(self) -> None:
        resp = {"status": 403, "length": 10000, "title": "Default Page"}
        assert is_different_from_baseline(resp, self.BASELINE)

    def test_large_length_delta_is_different(self) -> None:
        resp = {"status": 200, "length": 500, "title": "Default Page"}
        assert is_different_from_baseline(resp, self.BASELINE)

    def test_small_length_delta_not_different(self) -> None:
        resp = {"status": 200, "length": 10050, "title": "Default Page"}
        assert not is_different_from_baseline(resp, self.BASELINE)

    def test_unique_title_is_different(self) -> None:
        resp = {"status": 200, "length": 10000, "title": "Admin Dashboard"}
        assert is_different_from_baseline(resp, self.BASELINE)

    def test_generic_error_title_not_different(self) -> None:
        """403 Forbidden and 404 Not Found titles are too generic to count."""
        resp = {"status": 200, "length": 10000, "title": "403 Forbidden"}
        assert not is_different_from_baseline(resp, self.BASELINE)

    def test_zero_baseline_length_skips_length_diff(self) -> None:
        baseline = {"status": 200, "length": 0, "title": ""}
        resp = {"status": 200, "length": 999, "title": ""}
        assert not is_different_from_baseline(resp, baseline)


class TestAssessRisk:
    def test_admin_token_is_critical(self) -> None:
        assert _assess_risk("admin.example.com", 200, "") == "CRITICAL"

    def test_vpn_in_title_is_critical(self) -> None:
        assert _assess_risk("host.example.com", 200, "VPN Login") == "CRITICAL"

    def test_dev_hostname_is_high(self) -> None:
        assert _assess_risk("dev.example.com", 200, "") == "HIGH"

    def test_200_uncategorized_is_medium(self) -> None:
        assert _assess_risk("blog.example.com", 200, "Blog") == "MEDIUM"

    def test_non_200_uncategorized_is_low(self) -> None:
        assert _assess_risk("random.example.com", 404, "") == "LOW"


class TestCdnFilters:
    def test_cloudflare_title_detected(self) -> None:
        assert _title_suggests_cdn_baseline("Cloudflare Error Page")

    def test_normal_title_not_cdn(self) -> None:
        assert not _title_suggests_cdn_baseline("Welcome to My App")

    def test_409_is_cdn_noise(self) -> None:
        assert _response_is_cdn_dns_noise(409, "")

    def test_nxdomain_title_is_cdn_noise(self) -> None:
        assert _response_is_cdn_dns_noise(200, "NXDOMAIN error")

    def test_normal_200_not_cdn_noise(self) -> None:
        assert not _response_is_cdn_dns_noise(200, "Admin Panel")
