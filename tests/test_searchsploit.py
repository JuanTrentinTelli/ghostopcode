# GhostOpcode — searchsploit utility tests
# Run: pytest tests/test_searchsploit.py -v

from __future__ import annotations

import threading
import time
from unittest.mock import patch

from utils.searchsploit import (
    clear,
    normalize_cve_id,
    search_cve,
    search_many,
    summarize,
)


class TestNormalizeCveId:
    def test_already_prefixed(self) -> None:
        assert normalize_cve_id("CVE-2021-44228") == "CVE-2021-44228"

    def test_adds_prefix(self) -> None:
        assert normalize_cve_id("2021-44228") == "CVE-2021-44228"

    def test_lowercased_prefix_uppercased(self) -> None:
        # Function uppercases input first, so "cve-..." becomes "CVE-..." → prefix already present
        assert normalize_cve_id("cve-2021-44228") == "CVE-2021-44228"

    def test_empty_returns_empty(self) -> None:
        assert normalize_cve_id("") == ""

    def test_whitespace_stripped(self) -> None:
        assert normalize_cve_id("  CVE-2021-1234  ") == "CVE-2021-1234"


class TestSearchCveCache:
    def setup_method(self) -> None:
        clear()

    def teardown_method(self) -> None:
        clear()

    def test_cache_hit_avoids_subprocess(self) -> None:
        """Second call for same CVE must not launch a subprocess."""
        call_count = 0

        def fake_query(cve_id: str, timeout: int) -> list[dict]:
            nonlocal call_count
            call_count += 1
            return [{"title": "test exploit", "edb_id": "99999", "path": "", "type": "remote", "platform": "linux", "date": "", "url": ""}]

        with patch("utils.searchsploit._query_searchsploit", side_effect=fake_query):
            search_cve("CVE-2021-44228")
            search_cve("CVE-2021-44228")

        assert call_count == 1, "subprocess called more than once for the same CVE"

    def test_sentinel_prevents_concurrent_duplicate_subprocess(self) -> None:
        """Concurrent threads for the same CVE must produce at most one subprocess call."""
        call_count = 0
        lock = threading.Lock()

        def slow_query(cve_id: str, timeout: int) -> list[dict]:
            nonlocal call_count
            time.sleep(0.05)
            with lock:
                call_count += 1
            return []

        clear()
        with patch("utils.searchsploit._query_searchsploit", side_effect=slow_query):
            threads = [
                threading.Thread(target=search_cve, args=("CVE-2023-9999",))
                for _ in range(6)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        assert call_count == 1, f"Expected 1 subprocess call, got {call_count}"

    def test_different_cves_each_query_once(self) -> None:
        call_log: list[str] = []

        def fake_query(cve_id: str, timeout: int) -> list[dict]:
            call_log.append(cve_id)
            return []

        with patch("utils.searchsploit._query_searchsploit", side_effect=fake_query):
            search_many(["CVE-2021-1", "CVE-2021-2", "CVE-2021-1"])

        assert call_log.count("CVE-2021-1") == 1
        assert call_log.count("CVE-2021-2") == 1

    def test_clear_resets_cache(self) -> None:
        call_count = 0

        def fake_query(cve_id: str, timeout: int) -> list[dict]:
            nonlocal call_count
            call_count += 1
            return []

        with patch("utils.searchsploit._query_searchsploit", side_effect=fake_query):
            search_cve("CVE-2020-0001")
            clear()
            search_cve("CVE-2020-0001")

        assert call_count == 2


class TestSummarize:
    def test_empty(self) -> None:
        assert summarize([]) == "no exploits found"

    def test_single(self) -> None:
        result = summarize([{"type": "remote", "title": "x", "edb_id": "1", "path": "", "platform": "", "date": "", "url": ""}])
        assert "1 exploit" in result
        assert "remote" in result

    def test_plural(self) -> None:
        exploits = [{"type": "local", "title": f"x{i}", "edb_id": str(i), "path": "", "platform": "", "date": "", "url": ""} for i in range(3)]
        result = summarize(exploits)
        assert "3 exploits" in result
