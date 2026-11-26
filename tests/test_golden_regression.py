#!/usr/bin/env python3
"""End-to-end verification of CASE-01..CASE-20 Golden Suite, Local-Span Q4, Benign IDs, Lifecycle Stages, and Package Integrity."""
from __future__ import annotations

import difflib
import json
import re
import sys
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import prompt_negativity_audit as pna  # noqa: E402
import prose_lint as pl  # noqa: E402


def parse_golden_cases(md_text: str) -> dict:
    cases = {}
    sections = re.split(r"^## (CASE-\d+):", md_text, flags=re.MULTILINE)
    for i in range(1, len(sections), 2):
        case_id = sections[i].strip()
        body = sections[i + 1]

        req_match = re.search(r"### Required Ledger\n(.*?)\n### Forbidden Drift", body, flags=re.DOTALL)
        forb_match = re.search(r"### Forbidden Drift\n(.*?)\n### Input", body, flags=re.DOTALL)
        assert req_match and forb_match, f"{case_id} missing Required Ledger or Forbidden Drift"

        required = [m.group(1).strip() for m in re.finditer(r"^- `+(.*?)`*?$", req_match.group(1), flags=re.MULTILINE)]
        forbidden = [m.group(1).strip() for m in re.finditer(r"^- `+(.*?)`*?$", forb_match.group(1), flags=re.MULTILINE)]

        inp_m = re.search(r"### Input\n(`{3,})markdown\n(.*?)\n\1\n\n### Reference Output\n(`{3,})markdown\n(.*?)\n\3", body, flags=re.DOTALL)
        assert inp_m, f"{case_id} failed to parse Input / Reference Output blocks"

        cases[case_id] = {
            "required": required,
            "forbidden": forbidden,
            "input": inp_m.group(2),
            "output": inp_m.group(4),
        }
    return cases


class TestGoldenRegressionV113(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        golden_path = ROOT / "tests" / "golden-regression-cases.md"
        cls.cases = parse_golden_cases(golden_path.read_text(encoding="utf-8"))

    def test_all_twenty_cases_present(self) -> None:
        expected_ids = [f"CASE-{i:02d}" for i in range(1, 21)]
        self.assertEqual(sorted(self.cases.keys()), expected_ids)

    def test_required_ledger_100_percent_preserved_across_all_20_cases(self) -> None:
        for cid, data in self.cases.items():
            for token in data["required"]:
                self.assertIn(token, data["output"], f"[{cid}] Missing required token: {token}")

    def test_forbidden_drift_zero_occurrences_across_all_20_cases(self) -> None:
        for cid, data in self.cases.items():
            for bad_token in data["forbidden"]:
                self.assertNotIn(bad_token, data["output"], f"[{cid}] Forbidden drift present: {bad_token}")

    def test_pre_scan_preflight_stage_and_post_write_deterministic_stage(self) -> None:
        expected_before = {
            "CASE-01": {"FMT-01", "FMT-02", "FMT-03", "SEM-01", "SEM-02", "SEM-03", "SEM-04"},
            "CASE-02": {"FMT-06", "SEM-02"},
            "CASE-03": {"FMT-04"},
            "CASE-11": {"SEM-02", "SEM-03"},
            "CASE-14": {"FMT-03"},
            "CASE-15": {"FMT-04"},
            "CASE-17": {"SEM-04", "SEM-05"},
            "CASE-20": {"FMT-01", "FMT-03"},
        }
        for cid, req_codes in expected_before.items():
            _, before_issues, _, _, _ = pl.lint_text(self.cases[cid]["input"], fix=False, track="analytical")
            found = {iss.code for iss in before_issues}
            self.assertTrue(req_codes.issubset(found), f"[{cid}] Expected {req_codes}, got {found}")

        with tempfile.TemporaryDirectory() as tmp:
            for cid, data in self.cases.items():
                # 1. Read-only check on reference output must report Preflight Passed (NOT Deterministic Checks Passed)
                _, after_issues, _, _, metrics = pl.lint_text(
                    data["output"],
                    fix=False,
                    max_disclaimer_rate=0.08,
                    disallow_anchors=True,
                )
                hard_errors = [i for i in after_issues if i.category in ("security", "formatting")]
                self.assertEqual(hard_errors, [], f"[{cid}] Reference output has hard errors: {hard_errors}")
                self.assertTrue(metrics["passed"])
                self.assertEqual(metrics["pipeline_stage"], "Preflight Passed")

                # 2. Actual disk write + readback via main(--fix --output) promotes to Deterministic Checks Passed
                in_f = Path(tmp) / f"{cid}_in.md"
                out_f = Path(tmp) / f"{cid}_out.md"
                in_f.write_text(data["output"] + "\n", encoding="utf-8")
                buf = StringIO()
                with patch("sys.stdout", buf):
                    rc = pl.main(["--input", str(in_f), "--fix", "--output", str(out_f), "--disallow-anchors", "--json"])
                self.assertEqual(rc, 0)
                rep = json.loads(buf.getvalue())
                self.assertEqual(rep["metrics"]["pipeline_stage"], "Deterministic Checks Passed")

    def test_case11_to_case20_targeted_v113_behaviors(self) -> None:
        # CASE-11: Ordinary words produce 0 Q4 records
        _, _, _, q4_11, _ = pl.lint_text(self.cases["CASE-11"]["input"], fix=False)
        self.assertEqual(q4_11, [])

        # CASE-18: Multi-pack union preserves due-diligence ($), clinical (95% CI + 尚未排除), and legal (协议第 3.4 条 + 仅限于)
        _, _, _, q4_18, m_18 = pl.lint_text(self.cases["CASE-18"]["output"], fix=False)
        self.assertGreaterEqual(m_18["q4_protected_count"], 2)
        self.assertGreaterEqual(m_18["q4_candidate_count"], 1)
        self.assertEqual(m_18["mechanical_echo_clauses"], 0)

        # CASE-19: Mixed single sentence with "系统提示" AND "不得将...混为一谈" still extracts n=64 (Q4_PROTECTED) + 3 Q4_CANDIDATE spans AND 1 mechanical echo!
        _, _, _, q4_19, m_19 = pl.lint_text(self.cases["CASE-19"]["input"], fix=False)
        spans_19 = [r.matched_span for r in q4_19]
        self.assertTrue(any("n = 64" in s for s in spans_19))
        self.assertTrue(any("尚未证实因果关系" in s for s in spans_19))
        self.assertTrue(any("无法排除选择偏倚" in s for s in spans_19))
        self.assertTrue(any("仅适用于当前实验条件" in s for s in spans_19))
        self.assertEqual(m_19["mechanical_echo_clauses"], 1)

        # CASE-20: Benign DOI, SHA-256, ORCID, NCT, arXiv, RefSeq remain 100% unredacted in diff & FixRecord
        _, _, fixes_20, _, m_20 = pl.lint_text(self.cases["CASE-20"]["input"], fix=True)
        self.assertTrue(m_20["passed"])
        self.assertNotIn("[REDACTED", fixes_20[0].after)
        self.assertIn("10.1038/s41586-024-07998-6", fixes_20[0].after)

    def test_clean_human_controls_under_five_percent_diff(self) -> None:
        for cid in ("CASE-07", "CASE-08"):
            inp, out = self.cases[cid]["input"], self.cases[cid]["output"]
            change_rate = 1.0 - difflib.SequenceMatcher(None, inp, out).ratio()
            self.assertLess(change_rate, 0.05, f"[{cid}] Over-edited clean human prose by {change_rate:.1%}")

    def test_complete_skill_package_integrity_and_when_to_use_restored(self) -> None:
        required_files = {
            "SKILL.md": 220,
            "README.md": 130,
            "CHANGELOG.md": 130,
            "scripts/prose_lint.py": 1600,
            "scripts/prompt_negativity_audit.py": 300,
            "references/anti-rubric-echo.md": 160,
            "references/core-tells-zh-en.md": 180,
            "references/structure-dual-track.md": 140,
            "references/verification-and-roadmap.md": 140,
            "references/domain-packs/due-diligence.md": 110,
            "references/domain-packs/academic-clinical.md": 110,
            "references/domain-packs/engineering-legal.md": 110,
            "assets/stage2-writer-guardrail.md": 100,
            "assets/voice-card-template.md": 80,
        }
        skill_md = (ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("## When to Use", skill_md)
        self.assertIn("Long-Document Agent Protocol", skill_md)
        self.assertIn("| 位置 | 修改前原文 | 修改后表述 | 分流类别 (Q1-Q4/结构) | 语义风险确认 |", skill_md)
        roadmap_md = (ROOT / "references/verification-and-roadmap.md").read_text(encoding="utf-8")
        self.assertIn("| 位置 | 修改前原文 | 修改后表述 | 分流类别 (Q1-Q4/结构) | 语义风险确认 |", roadmap_md)
        golden_md = (ROOT / "tests/golden-regression-cases.md").read_text(encoding="utf-8")
        self.assertIn("v1.1.3 完整 20 组基准", golden_md)
        self.assertIn("CASE-01` 至 `CASE-20` 共 20 组", golden_md)
        self.assertIn("Preflight Passed", golden_md)
        for v_file in (
            "SKILL.md", "README.md", "scripts/prose_lint.py", "scripts/prompt_negativity_audit.py",
            "references/anti-rubric-echo.md", "references/structure-dual-track.md",
            "references/verification-and-roadmap.md", "assets/stage2-writer-guardrail.md",
            "assets/voice-card-template.md", "tests/golden-regression-cases.md",
        ):
            first_line = (ROOT / v_file).read_text(encoding="utf-8").splitlines()[0]
            for stale_ver in ("v1.1.0", "v1.1.1", "v1.1.2", "Voice Card v1.2)"):
                self.assertNotIn(stale_ver, first_line, f"{v_file} header still has stale {stale_ver}: {first_line}")

        for rel, max_lines in required_files.items():
            p = ROOT / rel
            self.assertTrue(p.is_file(), f"Missing required skill file: {rel}")
            txt = p.read_text(encoding="utf-8")
            self.assertLessEqual(len(txt.splitlines()), max_lines, f"{rel} exceeds {max_lines} lines")
            if p.suffix == ".md":
                self.assertNotIn("\u2014", txt, f"{rel} contains em-dash")
                self.assertNotIn("\u2013", txt, f"{rel} contains en-dash")
                rep = pna.audit_prompt_text(txt)
                self.assertIn("llm_semantic_review_agenda", rep)


if __name__ == "__main__":
    unittest.main()
