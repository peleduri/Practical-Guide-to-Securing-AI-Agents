#!/usr/bin/env python3
"""Test suite for exposure-report.py (stdlib unittest, no dependencies).

What is being set up and why (test-structure map):

    fixtures/watchlist-fixture.json     ollama (versioned 0.9.2, OSV-covered)
                                        cursor (no version source, no OSV data)
    fixtures/watchlist-patched.json     same, ollama versioned 0.9.9 ("patched")
    fixtures/osv-confirmed.json         OSV replay: one hit for the query
    fixtures/osv-empty.json             OSV replay: no vulns for the version
    fixtures/kev-fixture.json           KEV entries for Ollama + Cursor
    fixtures/pulse-fixture.json         pulse item mentioning the Ollama CVE

    Every E2E test runs main() with full replay flags + --now, so runs are
    deterministic and byte-stable — that property is itself asserted.

The single most load-bearing test is test_kev_patched_stays_possible: a KEV
name-match on a PATCHED install must never render as confirmed / actively
exploited. That is the anti-FUD rule this project's credibility rests on.
"""

import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(REPO, "tests", "fixtures")
SCRIPT = os.path.join(REPO, "templates", "discovery", "exposure-report.py")

spec = importlib.util.spec_from_file_location("exposure_report", SCRIPT)
er = importlib.util.module_from_spec(spec)
spec.loader.exec_module(er)


def fx(name):
    return os.path.join(FIX, name)


class RunMixin:
    """Runs main() into a temp out dir with an isolated cache dir."""

    def setUp(self):
        # Save and restore process-global state so this suite can't make a
        # later one order-dependent, or delete a real XDG_CACHE_HOME.
        self._prev_cwd = os.getcwd()
        self._prev_cache_env = os.environ.get("XDG_CACHE_HOME")
        os.chdir(REPO)  # fixture watchlists use repo-relative version-source roots
        self.out = tempfile.mkdtemp(prefix="exposure-test-")
        self.cache = tempfile.mkdtemp(prefix="exposure-cache-")
        os.environ["XDG_CACHE_HOME"] = self.cache

    def tearDown(self):
        shutil.rmtree(self.out, ignore_errors=True)
        shutil.rmtree(self.cache, ignore_errors=True)
        if self._prev_cache_env is None:
            os.environ.pop("XDG_CACHE_HOME", None)
        else:
            os.environ["XDG_CACHE_HOME"] = self._prev_cache_env
        os.chdir(self._prev_cwd)

    def run_main(self, *extra, watchlist="watchlist-fixture.json",
                 inventory="inventory-fixture.jsonl", osv="osv-confirmed.json",
                 kev="kev-fixture.json", feed="pulse-fixture.json"):
        argv = ["--watchlist", fx(watchlist), "--now", "2026-07-01",
                "--out", self.out]
        if inventory:
            argv += ["--inventory", fx(inventory)]
        if osv:
            argv += ["--osv", fx(osv)]
        if kev:
            argv += ["--kev", fx(kev)]
        if feed:
            argv += ["--feed", fx(feed)]
        argv += list(extra)
        rc = er.main(argv)
        md = report = None
        md_path = os.path.join(self.out, "exposure-report.md")
        json_path = os.path.join(self.out, "exposure-report.json")
        if os.path.exists(md_path):
            with open(md_path, encoding="utf-8") as fh:
                md = fh.read()
        if os.path.exists(json_path):
            with open(json_path, encoding="utf-8") as fh:
                report = json.load(fh)
        return rc, md, report


class TestConfirmedPath(RunMixin, unittest.TestCase):
    def test_confirmed_and_actively_exploited(self):
        rc, md, report = self.run_main()
        self.assertEqual(rc, 0)
        finding = next(f for f in report["findings"]
                       if f["id"] == "CVE-2026-99999")
        self.assertEqual(finding["confidence"], "confirmed")   # OSV version-hit
        self.assertTrue(finding["actively_exploited"])         # + KEV corroboration
        self.assertIn("ACTIVELY EXPLOITED", md)
        self.assertIn("CVE-2026-99999", md)
        self.assertIn("part-11-local-open-source-models.md", md)  # guide mapping
        self.assertIn("pulse", finding["sources"])                # enrichment

    def test_alias_merge_single_finding(self):
        # GHSA-test-0001 and CVE-2026-99999 are the same issue → ONE finding.
        rc, _, report = self.run_main()
        self.assertEqual(rc, 0)
        ids = [f["id"] for f in report["findings"]]
        self.assertNotIn("GHSA-test-0001", ids)
        self.assertEqual(ids.count("CVE-2026-99999"), 1)

    def test_byte_stable_reports(self):
        _, md1, _ = self.run_main()
        _, md2, _ = self.run_main()
        self.assertEqual(md1, md2)

    def test_never_says_clean(self):
        _, md, _ = self.run_main()
        self.assertNotRegex(md, r"(?i)\bclean\b")

    def test_coverage_footer_always_present(self):
        _, md, _ = self.run_main()
        self.assertIn("## Coverage", md)
        self.assertIn("Limited coverage", md)   # cursor has no OSV data
        self.assertIn("not** absence of risk", md)


class TestKevPatchedStaysPossible(RunMixin, unittest.TestCase):
    def test_kev_patched_stays_possible(self):
        """CREDIBILITY CRITICAL: patched install + KEV name-match must stay
        `possible` and must not carry actively-exploited wording."""
        rc, md, report = self.run_main(watchlist="watchlist-patched.json",
                                       osv="osv-empty.json")
        self.assertEqual(rc, 0)
        finding = next(f for f in report["findings"]
                       if f["id"] == "CVE-2026-99999")
        self.assertEqual(finding["confidence"], "possible")
        self.assertFalse(finding["actively_exploited"])
        self.assertNotIn("ACTIVELY EXPLOITED", md)


class TestDegradedAndFailurePaths(RunMixin, unittest.TestCase):
    def test_degraded_source_banner_exit_2(self):
        # KEV has no replay file; --offline + empty cache forces the skip
        # deterministically without ever opening a socket.
        rc, md, _ = self.run_main("--offline", kev=None, osv="osv-empty.json")
        self.assertEqual(rc, 2)
        self.assertIn("KEV: skipped", md)

    def test_all_sources_down_exit_3(self):
        rc = er.main(["--watchlist", fx("watchlist-fixture.json"),
                      "--inventory", fx("inventory-fixture.jsonl"),
                      "--now", "2026-07-01", "--out", self.out, "--offline"])
        self.assertEqual(rc, 3)

    def test_pulse_schema_mismatch_is_source_down(self):
        rc, md, _ = self.run_main(feed="pulse-bad-fixture.json")
        self.assertEqual(rc, 2)
        self.assertIn("PULSE: skipped", md)
        self.assertIn("schema mismatch", md)

    def test_malformed_inventory_line_skipped(self):
        rc, _, report = self.run_main(inventory="inventory-malformed.jsonl")
        self.assertEqual(rc, 0)
        ollama = next(p for p in report["products"] if p["product"] == "ollama")
        self.assertTrue(ollama["present"])

    def test_empty_inventory_no_matching_advisories(self):
        empty = os.path.join(self.out, "empty.jsonl")
        open(empty, "w").close()
        rc = er.main(["--watchlist", fx("watchlist-patched.json"),
                      "--inventory", empty, "--now", "2026-07-01",
                      "--out", self.out,
                      "--osv", fx("osv-empty.json"),
                      "--kev", fx("kev-fixture.json"),
                      "--feed", fx("pulse-fixture.json")])
        # ollama still present via its version source (metadata hit = presence)
        self.assertEqual(rc, 0)
        with open(os.path.join(self.out, "exposure-report.json"),
                  encoding="utf-8") as fh:
            report = json.load(fh)
        cursor = next(p for p in report["products"] if p["product"] == "cursor")
        self.assertFalse(cursor["present"])  # inventory empty, no version source


class TestUnits(unittest.TestCase):
    def test_sanitize_markdown_injection(self):
        s = er.sanitize("[evil](https://x) | `code` <img> # !")
        for ch in ("[", "]", "|", "`", "<", ">", "#", "!"):
            self.assertNotIn(ch, s.replace("\\" + ch, ""))

    def test_sanitize_strips_terminal_escapes(self):
        self.assertNotIn("\x1b", er.sanitize("evil\x1b[31mred"))

    def test_sanitize_caps_length(self):
        self.assertLessEqual(len(er.sanitize("x" * 5000)), er.MAX_FIELD + 1)

    def test_safe_url_rejects_non_http(self):
        self.assertEqual(er.safe_url("javascript:alert(1)"), "")
        self.assertEqual(er.safe_url("file:///etc/passwd"), "")
        self.assertTrue(er.safe_url("https://example.com/a?b=c"))

    def test_canonical_id_prefers_cve_alias(self):
        detail = {"id": "GHSA-x", "aliases": ["GHSA-y", "CVE-2026-1"]}
        self.assertEqual(er.canonical_id(detail, "GHSA-x"), "CVE-2026-1")
        self.assertEqual(er.canonical_id(None, "GHSA-x"), "GHSA-x")

    def test_probe_gating_off_by_default(self):
        src = {"command": ["echo", "9.9.9"], "version_pattern": r"(\d+\.\d+\.\d+)"}
        self.assertEqual(er.version_from_probe(src, False), (None, None))
        v, ev = er.version_from_probe(src, True)
        self.assertEqual(v, "9.9.9")
        self.assertTrue(ev.startswith("probe:"))

    def test_probe_rejects_non_list_command(self):
        self.assertEqual(
            er.version_from_probe({"command": "echo 1.2.3"}, True), (None, None))

    def test_kev_alone_never_confirms(self):
        installed = [{"product": "p", "present": True,
                      "version": None, "evidence": None}]
        watchlist = {"products": {"p": {"name": "P", "aliases": ["p"],
                                        "osv_queries": [], "guide": {}}}}
        kev = [{"cveID": "CVE-2026-2", "vendorProject": "P", "product": "p",
                "shortDescription": "x", "dateAdded": "2026-01-01"}]
        findings = er.build_findings(installed, watchlist, {}, kev, [])
        self.assertEqual(findings[0]["confidence"], "possible")
        self.assertFalse(findings[0]["actively_exploited"])

    def test_report_json_schema_keys(self):
        # minimal shape check used by downstream consumers (M2 fixture test)
        keys = {"schema_version", "generated", "probing", "products",
                "findings", "sources"}
        out = tempfile.mkdtemp()
        try:
            rc = er.main(["--watchlist", fx("watchlist-fixture.json"),
                          "--inventory", fx("inventory-fixture.jsonl"),
                          "--osv", fx("osv-confirmed.json"),
                          "--kev", fx("kev-fixture.json"),
                          "--feed", fx("pulse-fixture.json"),
                          "--now", "2026-07-01", "--out", out])
            self.assertEqual(rc, 0)
            with open(os.path.join(out, "exposure-report.json"),
                      encoding="utf-8") as fh:
                report = json.load(fh)
            self.assertEqual(keys, set(report.keys()))
        finally:
            shutil.rmtree(out, ignore_errors=True)


class TestAssessRegression(unittest.TestCase):
    """IRON-RULE REGRESSION: the existing assess.sh steps (inventory summary,
    posture, scorecard) must still run and emit after the exposure step lands,
    and a green run must include the exposure report."""

    def test_assess_end_to_end_fixture_mode(self):
        """Asserts CONTENT, not just existence: assess.sh creates each artifact
        by shell redirection with stderr discarded, so a broken discovery or
        scorecard step still leaves an EMPTY file behind. An existence-only
        check would pass while the steps this test exists to protect are dead.

        Note the watchlist is deliberately NOT injected via
        EXPOSURE_REPORT_ARGS — assess.sh refuses --watchlist from the
        environment (it would let anything that can set an env var choose the
        probe commands), so this exercises the real bundled watchlist with
        replayed feeds."""
        out = tempfile.mkdtemp(prefix="assess-e2e-")
        cache = tempfile.mkdtemp(prefix="assess-e2e-cache-")
        env = dict(os.environ)
        env["AGENT_ASSESSMENT_OUT"] = out
        env["XDG_CACHE_HOME"] = cache
        env["EXPOSURE_REPORT_ARGS"] = (
            "--osv %s --kev %s --feed %s --now 2026-07-01"
            % (fx("osv-empty.json"), fx("kev-fixture.json"),
               fx("pulse-fixture.json")))
        try:
            proc = subprocess.run(
                ["bash", os.path.join(REPO, "scripts", "assess.sh")],
                capture_output=True, text=True, env=env, timeout=180,
                cwd=REPO, check=False)
            self.assertEqual(proc.returncode, 0, proc.stderr)

            # pre-existing steps still produce REAL content
            with open(os.path.join(out, "scorecard.html"),
                      encoding="utf-8") as fh:
                self.assertIn("Maturity:", fh.read())
            with open(os.path.join(out, "posture.json"), encoding="utf-8") as fh:
                self.assertIn(json.load(fh)["maturity"],
                              ("crawl", "walk", "run"))
            with open(os.path.join(out, "inventory.jsonl"),
                      encoding="utf-8") as fh:
                lines = [l for l in fh.read().splitlines() if l.strip()]
            self.assertTrue(lines, "inventory.jsonl is empty")
            for line in lines:
                json.loads(line)   # every line must be valid JSON

            # and the new exposure step produced a real report
            with open(os.path.join(out, "exposure-report.md"),
                      encoding="utf-8") as fh:
                md = fh.read()
            self.assertIn("# Agentic stack exposure report", md)
            self.assertIn("## Coverage", md)
            with open(os.path.join(out, "exposure-report.json"),
                      encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["schema_version"], 1)
        finally:
            shutil.rmtree(out, ignore_errors=True)
            shutil.rmtree(cache, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
