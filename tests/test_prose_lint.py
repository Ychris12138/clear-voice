#!/usr/bin/env python3
"""Unit tests for clear-voice v1.1.2 covering local-span Q4, unified token/path redaction, benign scientific IDs, and strict pipeline stage transitions."""
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import prompt_negativity_audit as pna  # noqa: E402
import prose_lint as pl  # noqa: E402


class TestOutputOverwriteAndSymlinkProtection(unittest.TestCase):
    def test_sec01_never_leaks_secret_in_snippet_or_cli_output(self) -> None:
        raw_secret = "sk-proj-SUPERSECRETKEY9876543210abcdef"
        gh_secret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
        sample = f"配置文件中包含 {raw_secret} 以及 {gh_secret} 凭据。\n"

        _, issues, fixes, _, metrics = pl.lint_text(sample, fix=True)
        self.assertEqual(metrics["status"], "blocked_security")
        self.assertEqual(metrics["pipeline_stage"], "Drafted")
        self.assertEqual(fixes, [])
        for issue in issues:
            self.assertNotIn(raw_secret, issue.snippet)
            self.assertNotIn("SUPERSECRETKEY", issue.snippet)
            self.assertNotIn(gh_secret, issue.snippet)
            self.assertIn("[REDACTED:", issue.snippet)

        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "leak.md"
            f.write_text(sample, encoding="utf-8")
            buf = StringIO()
            with patch("sys.stdout", buf), patch("sys.stderr", StringIO()):
                rc = pl.main(["--input", str(f), "--check", "--json"])
            self.assertEqual(rc, 2)
            self.assertNotIn("SUPERSECRETKEY", buf.getvalue())
            self.assertNotIn(gh_secret, buf.getvalue())

    def test_existing_output_rejected_by_default_and_allowed_only_with_overwrite(self) -> None:
        src_text = "博士记录支持[5][6]\u00a0测试。\n"
        existing_dst_text = "已存在的旧目标文件内容，严禁静默覆盖。\n"
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "draft.md"
            dst = Path(tmp) / "existing_out.md"
            src.write_text(src_text, encoding="utf-8")
            dst.write_text(existing_dst_text, encoding="utf-8")

            with patch("sys.stderr", StringIO()):
                self.assertEqual(pl.main(["--input", str(src), "--fix"]), 2)
            self.assertEqual(src.read_text(encoding="utf-8"), src_text)

            with patch("sys.stderr", StringIO()):
                self.assertEqual(pl.main(["--input", str(src), "--fix", "--output", str(dst)]), 2)
            self.assertEqual(dst.read_text(encoding="utf-8"), existing_dst_text)

            with patch("sys.stdout", StringIO()):
                self.assertEqual(pl.main(["--input", str(src), "--fix", "--output", str(dst), "--overwrite"]), 0)
            self.assertEqual(dst.read_text(encoding="utf-8"), "博士记录支持[5]、[6] 测试。\n")
            self.assertEqual(src.read_text(encoding="utf-8"), src_text)

    def test_same_path_and_symlink_to_input_or_existing_output(self) -> None:
        src_text = "支持[1][2]\u00a0记录。\n"
        other_text = "另一份已存在文件。\n"
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "input.md"
            other = Path(tmp) / "other.md"
            link_to_src = Path(tmp) / "link_to_input.md"
            link_to_other = Path(tmp) / "link_to_other.md"
            src.write_text(src_text, encoding="utf-8")
            other.write_text(other_text, encoding="utf-8")
            os.symlink(src, link_to_src)
            os.symlink(other, link_to_other)

            with patch("sys.stderr", StringIO()):
                self.assertEqual(pl.main(["--input", str(src), "--fix", "--output", str(src), "--overwrite"]), 2)
                self.assertEqual(pl.main(["--input", str(src), "--fix", "--output", str(link_to_src), "--overwrite"]), 2)
                self.assertEqual(pl.main(["--input", str(src), "--fix", "--output", str(link_to_other)]), 2)
            self.assertEqual(src.read_text(encoding="utf-8"), src_text)
            self.assertEqual(other.read_text(encoding="utf-8"), other_text)

            with patch("sys.stdout", StringIO()):
                self.assertEqual(pl.main(["--input", str(src), "--fix", "--output", str(link_to_other), "--overwrite"]), 0)
            self.assertTrue(link_to_other.is_symlink())
            self.assertEqual(other.read_text(encoding="utf-8"), "支持[1]、[2] 记录。\n")
            self.assertEqual(src.read_text(encoding="utf-8"), src_text)

            with patch("sys.stdout", StringIO()):
                self.assertEqual(pl.main(["--input", str(link_to_src), "--fix", "--in-place"]), 0)
            self.assertTrue(link_to_src.is_symlink())
            self.assertEqual(src.read_text(encoding="utf-8"), "支持[1]、[2] 记录。\n")

    def test_output_write_failure_and_idempotency(self) -> None:
        dirty = "1. 主结论\n\u00a0\u00a0- 子项记录[2][3] :contentReference[oaicite:1]{index=1}。\n"
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "dirty.md"
            out1 = Path(tmp) / "out1.md"
            out2 = Path(tmp) / "out2.md"
            src.write_text(dirty, encoding="utf-8")

            missing_dir_out = Path(tmp) / "missing_dir" / "out.md"
            with patch("sys.stderr", StringIO()):
                self.assertEqual(pl.main(["--input", str(src), "--fix", "--output", str(missing_dir_out)]), 2)

            buf1 = StringIO()
            with patch("sys.stdout", buf1):
                self.assertEqual(pl.main(["--input", str(src), "--fix", "--output", str(out1), "--diff", "--json"]), 0)
            rep1 = json.loads(buf1.getvalue())
            self.assertEqual(rep1["metrics"]["pipeline_stage"], "Deterministic Checks Passed")
            self.assertEqual(rep1["metrics"]["post_write_verification"], "verified")

            buf2 = StringIO()
            with patch("sys.stdout", buf2):
                self.assertEqual(pl.main(["--input", str(out1), "--fix", "--output", str(out2), "--diff", "--json"]), 0)
            rep2 = json.loads(buf2.getvalue())
            self.assertEqual(rep2["metrics"]["auto_fixed_lines"], 0)
            self.assertEqual(rep2["diff"], "")


class TestLocalSpanQ4ImprovementsV112(unittest.TestCase):
    def test_ordinary_words_are_not_misclassified_as_q4(self) -> None:
        false_friends = [
            "系统提示接口连接超时，请检查网关配置",
            "在编写提示词时不要堆砌空洞的形容词",
            "编写评审稿时不得将专用量子模拟与通用容错计算混为一谈",
            "禁止在正文中编造未经核实的财务数字",
            "团队今年计划扩大高校客户访谈样本量至 30 家",
        ]
        for clause in false_friends:
            state, _ = pl.classify_q4_clause(clause)
            self.assertEqual(state, "Q4_NOT_QUALIFICATION", f"False positive on: {clause}")

    def test_v112_new_candidate_and_protected_phrases_recognized(self) -> None:
        # Specifically required in v1.1.2 spec: 尚未证实因果关系 / 无法排除选择偏倚 / 仅适用于当前实验条件
        st_causal, r_causal = pl.classify_q4_clause("横断面相关性尚未证实因果关系")
        self.assertEqual(st_causal, "Q4_CANDIDATE")
        self.assertEqual(r_causal, "causal_non_establishment")

        st_bias, r_bias = pl.classify_q4_clause("单中心回顾性入组无法排除选择偏倚")
        self.assertEqual(st_bias, "Q4_CANDIDATE")
        self.assertEqual(r_bias, "bias_or_confounding_candidate")

        st_scope, r_scope = pl.classify_q4_clause("上述标定斜率仅适用于当前实验条件")
        self.assertEqual(st_scope, "Q4_CANDIDATE")
        self.assertEqual(r_scope, "experimental_or_scope_limit")

    def test_v112_mixed_sentence_ordinary_prompt_words_do_not_shadow_real_q4_spans(self) -> None:
        # Single sentence mixing "系统提示" / "提示词不要堆砌套话" / "不得将X混为一谈" WITH real Q4 spans AND mechanical echo!
        mixed_doc = (
            "系统提示任务跑完后，回归分析提示该标志物与预后相关但尚未证实因果关系，且标定参数仅适用于当前实验条件。\n"
            "提示词不要堆砌形容词，但回顾性队列无法排除选择偏倚（95% CI: 0.61-0.94），同时不得将专用模拟与通用计算混为一谈。\n"
            "商业团队拟扩大访谈样本量至 40 家，本次公开检索未取得回款水单。\n"
        )
        updated, issues, _, q4_items, metrics = pl.lint_text(mixed_doc, fix=True)
        # Python --fix must NEVER delete any prose
        self.assertEqual(updated, mixed_doc)
        matched_spans = [item.matched_span for item in q4_items]
        self.assertTrue(any("尚未证实因果关系" in s for s in matched_spans), f"Got: {matched_spans}")
        self.assertTrue(any("仅适用于当前实验条件" in s for s in matched_spans), f"Got: {matched_spans}")
        self.assertTrue(any("无法排除选择偏倚" in s for s in matched_spans), f"Got: {matched_spans}")
        self.assertTrue(any("95% CI: 0.61-0.94" in s for s in matched_spans), f"Got: {matched_spans}")
        # Verify every Q4SpanRecord explicitly forbids auto deletion
        self.assertTrue(all(item.auto_delete_authorized is False for item in q4_items))
        # Meanwhile, residual mechanical echoes in lines 2 and 3 ARE still independently counted!
        self.assertEqual(metrics["mechanical_echo_clauses"], 2)
        self.assertTrue(any(i.code == "SEM-02" for i in issues))
        self.assertIn("does NOT grant semantic deletion permission", str(metrics["q4_policy_note"]))


class TestUnifiedLogRedactionAndBenignIDsV112(unittest.TestCase):
    def test_v112_unknown_format_credentials_redacted_uniformly_in_sec01_fixrecord_and_diff(self) -> None:
        vendor_tok = "acme_live_9X8y7Z6w5V4u3T2s1R"
        entropy_tok = "Zk9mQ2pL7xR4wN8vB3tY6uJ1"
        jwt_tok = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyNDIifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6y"

        # 1. Verify SEC-01 catches unknown-format tokens and masks snippet completely
        for secret in (vendor_tok, entropy_tok, jwt_tok):
            _, issues, _, _, metrics = pl.lint_text(f"调试凭据 {secret} 残留。\n", fix=False)
            self.assertEqual(metrics["status"], "blocked_security", f"Missed secret: {secret}")
            self.assertNotIn(secret, issues[0].snippet)
            self.assertIn("[REDACTED:", issues[0].snippet)

        # 2. Verify redact_secrets and sanitize_log_text share identical token masking
        raw_log = f"header {vendor_tok} and {entropy_tok} and https://api.example.com/v1?api_key=MySecretKey987654321"
        s1 = pl.redact_sensitive_text(raw_log, mask_paths=True)
        s2 = pl.sanitize_log_text(raw_log, mask_user_paths=True)
        self.assertEqual(s1, s2)
        self.assertNotIn(vendor_tok, s2)
        self.assertNotIn(entropy_tok, s2)
        self.assertNotIn("MySecretKey987654321", s2)

    def test_v112_benign_doi_sha_scientific_ids_never_deleted_or_blocked(self) -> None:
        benign_doc = (
            "文献 DOI 为 10.1038/s41586-024-07998-6 与 arXiv:2409.14509v2，"
            "作者 ORCID 0000-0002-1825-0097，临床注册号 NCT04567890，"
            "转录本 NM_001126112.3、数据集 GSE123456、基因 ENSG00000141510.18、漏洞 CVE-2025-30144，"
            "镜像校验和 sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 "
            "及提交 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b[1][2]\u00a0。\n"
        )
        updated, issues, fixes, _, metrics = pl.lint_text(benign_doc, fix=True)
        self.assertTrue(metrics["passed"], f"False positive on benign IDs: {issues}")
        self.assertEqual(len(fixes), 1)
        for identifier in (
            "10.1038/s41586-024-07998-6",
            "arXiv:2409.14509v2",
            "0000-0002-1825-0097",
            "NCT04567890",
            "NM_001126112.3",
            "GSE123456",
            "ENSG00000141510.18",
            "CVE-2025-30144",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b",
        ):
            self.assertIn(identifier, updated)
            self.assertIn(identifier, fixes[0].after)

    def test_v112_cross_platform_path_redaction_in_fixrecord_and_diff_by_default(self) -> None:
        sample = (
            "macOS /Users/linwei/Desktop/bp.pdf 与 /Volumes/LinVault/raw.h5[1][2]\u00a0；\n"
            "Linux /home/chen/run.log、/media/chen/USB_Disk/a.csv、/run/media/chen/SecDrive/b.csv、/mnt/corp_nas/c.dat[3][4]；\n"
            "Windows C:\\Users\\wang\\Documents\\q.docx、C:\\Documents and Settings\\wang\\cfg.ini 与 \\\\filesrv01\\audit$\\p.xlsx[5][6]。\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "paths.md"
            dst = Path(tmp) / "paths_out.md"
            src.write_text(sample, encoding="utf-8")

            buf = StringIO()
            with patch("sys.stdout", buf):
                rc = pl.main(["--input", str(src), "--fix", "--output", str(dst), "--diff", "--json"])
            self.assertEqual(rc, 0)
            rep = json.loads(buf.getvalue())
            log_blob = json.dumps(rep["fixes"], ensure_ascii=False) + "\n" + rep["diff"]

            # Sensitive usernames, volume names, host/share names must be masked in FixRecord & diff by default!
            for sensitive_segment in ("linwei", "LinVault", "/home/chen", "/media/chen", "USB_Disk", "SecDrive", "corp_nas", "\\wang\\", "filesrv01", "audit$"):
                self.assertNotIn(sensitive_segment, log_blob, f"Leaked path segment in diff/FixRecord: {sensitive_segment}")
            self.assertIn("/Users/<USER>/Desktop/bp.pdf", log_blob)
            self.assertIn("/Volumes/<VOLUME>/raw.h5", log_blob)
            self.assertIn("/media/<USER>/<VOLUME>/a.csv", log_blob)
            self.assertIn("/mnt/<MOUNT>/c.dat", log_blob)
            self.assertIn("C:\\Users\\<USER>\\Documents\\q.docx", log_blob)
            self.assertIn("\\\\<HOST>\\<SHARE>\\p.xlsx", log_blob)

            # Meanwhile, the written output file itself must NOT have its reproducibility paths silently deleted!
            written = dst.read_text(encoding="utf-8")
            self.assertIn("/mnt/corp_nas/c.dat", written)


class TestPipelineLifecycleStateTransitionsV112(unittest.TestCase):
    def test_v112_readonly_check_returns_preflight_passed_never_deterministic_passed(self) -> None:
        clean_text = "这是一段格式完全干净的测试文本。\n"
        _, _, _, _, mem_metrics = pl.lint_text(clean_text, fix=False)
        self.assertEqual(mem_metrics["pipeline_stage"], "Preflight Passed")

        # Even in-memory fix=True without disk write/readback only reaches Preflight Passed!
        _, _, _, _, mem_fix_metrics = pl.lint_text("支持[1][2]测试。\n", fix=True)
        self.assertEqual(mem_fix_metrics["pipeline_stage"], "Preflight Passed")

        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "clean.md"
            f.write_text(clean_text, encoding="utf-8")
            buf = StringIO()
            with patch("sys.stdout", buf):
                rc = pl.main(["--input", str(f), "--check", "--json"])
            self.assertEqual(rc, 0)
            rep = json.loads(buf.getvalue())
            self.assertEqual(rep["metrics"]["pipeline_stage"], "Preflight Passed")
            self.assertNotEqual(rep["metrics"]["pipeline_stage"], "Deterministic Checks Passed")

    def test_v112_write_and_readback_required_for_deterministic_checks_passed(self) -> None:
        sample = "支持[1][2]\u00a0测试。\n"
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "in.md"
            dst = Path(tmp) / "out.md"
            src.write_text(sample, encoding="utf-8")

            # 1. Successful write + readback + recheck -> Deterministic Checks Passed
            buf_ok = StringIO()
            with patch("sys.stdout", buf_ok):
                rc_ok = pl.main(["--input", str(src), "--fix", "--output", str(dst), "--json"])
            self.assertEqual(rc_ok, 0)
            rep_ok = json.loads(buf_ok.getvalue())
            self.assertEqual(rep_ok["metrics"]["pipeline_stage"], "Deterministic Checks Passed")
            self.assertEqual(rep_ok["metrics"]["post_write_verification"], "verified")

            # 2. If formatting error remains (e.g., dangling #anchor), stage stays Drafted even after write!
            bad_anchor = "支持[1][2]且含[坏锚点](#missing-heading)。\n"
            src_bad = Path(tmp) / "bad.md"
            dst_bad = Path(tmp) / "bad_out.md"
            src_bad.write_text(bad_anchor, encoding="utf-8")
            buf_bad = StringIO()
            with patch("sys.stdout", buf_bad):
                rc_bad = pl.main(["--input", str(src_bad), "--fix", "--output", str(dst_bad), "--json"])
            self.assertEqual(rc_bad, 1)
            rep_bad = json.loads(buf_bad.getvalue())
            self.assertEqual(rep_bad["metrics"]["pipeline_stage"], "Drafted")

    def test_v112_semantic_and_human_stages_never_auto_promoted(self) -> None:
        forbidden_stages = {"Semantic Review Passed", "Human Approved"}
        samples = [
            "完全干净的自然段落。\n",
            "带格式修复[1][2]\u00a0的段落。\n",
            "带[悬空锚点](#none)的段落。\n",
            "带凭据 sk-proj-SUPERSECRETKEY9876543210abcdef 的段落。\n",
        ]
        with tempfile.TemporaryDirectory() as tmp:
            for idx, txt in enumerate(samples):
                src = Path(tmp) / f"s_{idx}.md"
                dst = Path(tmp) / f"d_{idx}.md"
                src.write_text(txt, encoding="utf-8")
                for argv in (
                    ["--input", str(src), "--check", "--json"],
                    ["--input", str(src), "--fix", "--output", str(dst), "--json"],
                ):
                    buf = StringIO()
                    with patch("sys.stdout", buf), patch("sys.stderr", StringIO()):
                        pl.main(argv)
                    if buf.getvalue().strip():
                        stage = json.loads(buf.getvalue())["metrics"]["pipeline_stage"]
                        self.assertNotIn(stage, forbidden_stages)
                        self.assertIn(stage, {"Drafted", "Preflight Passed", "Deterministic Checks Passed"})


class TestMarkdownMixedProtectionAndPromptAudit(unittest.TestCase):
    def test_variable_length_fences_multiline_html_attributes_math_frontmatter(self) -> None:
        sample = (
            "---\n"
            "local_ref: /Users/alice/private_deck.pdf\n"
            "---\n\n"
            "````markdown\n"
            "```python\n"
            "bad_cite = '[1][2]\u00a0'\n"
            "```\n"
            "[悬空假锚点](#should-be-ignored-inside-4-backtick-fence)\n"
            "````\n\n"
            "<div class=\"card\" data-expr=\"snr > 10\" title=\"keep[1][2]\u00a0\">\n"
            "  <span>多行 HTML 块内部文本[3][4]\u00a0保持不动</span>\n"
            "</div>\n\n"
            "行内带比较符属性 <span data-rule=\"a > b\" class=\"tag\">标签外正文[5][6]</span> 与 <kbd>[9][10]</kbd>。\n\n"
            "\\begin{align}\n"
            "E[1][2] &= mc^2\u00a0\n"
            "\\end{align}\n"
        )
        updated, issues, fixes, _, metrics = pl.lint_text(sample, fix=True, disallow_anchors=True)
        self.assertTrue(metrics["passed"], f"Unexpected hard errors: {issues}")
        self.assertEqual(len(fixes), 1)
        self.assertIn("标签外正文[5]、[6]", updated)
        self.assertIn("[悬空假锚点](#should-be-ignored-inside-4-backtick-fence)", updated)
        self.assertIn("多行 HTML 块内部文本[3][4]\u00a0保持不动", updated)

    def test_prompt_audit_surface_metrics_vs_semantic_agenda(self) -> None:
        sample = (
            "保留结构化列表以提高扫读效率。\n"
            "禁止在正文中保留任何列表。\n"
            "严禁篡改原始实验数字与量纲。\n"
            "不得篡改原始实验数字与量纲。\n"
        )
        rep = pna.audit_prompt_text(sample)
        m = rep["python_surface_metrics"]
        self.assertNotIn("HEALTHY", json.dumps(rep))
        self.assertGreaterEqual(m["lexical_conflict_cue_count"], 1)
        self.assertGreaterEqual(m["lexical_near_duplicate_count"], 1)
        self.assertEqual(len(rep["llm_semantic_review_agenda"]), 4)




class TestRedTeamAdversarialGatesV113(unittest.TestCase):
    """Covers all 10 mandatory Red-Team regression gates from the v1.1.2 independent audit."""

    def test_rt01_labeled_hex_uuid_bearer_url_and_multiline_pem_redacted_zero_leak(self) -> None:
        hex_sec = "0123456789abcdef0123456789abcdef"
        uuid_sec = "550e8400-e29b-41d4-a716-446655440000"
        bearer_sec = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b"
        url_path_sec = "sk-proj-SUPERSECRETKEY9876543210abcdef"
        redis_sec = "MyRedisSecretPassword99"
        pem_body = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQ"

        cases = [
            (f"api_key = {hex_sec}\n", hex_sec),
            (f"client_secret = {uuid_sec}\n", uuid_sec),
            (f"Authorization: Bearer {bearer_sec}\n", bearer_sec),
            (f"Endpoint: https://api.example.com/v1/keys/{url_path_sec}\n", "SUPERSECRETKEY"),
            (f"Cache: redis://:{redis_sec}@10.0.0.5:6379/0\n", redis_sec),
            (f"-----BEGIN ENCRYPTED PRIVATE KEY-----\n{pem_body}\n-----END ENCRYPTED PRIVATE KEY-----\n", pem_body),
        ]
        for text, secret_substr in cases:
            _, issues, _, _, metrics = pl.lint_text(text, fix=False)
            self.assertEqual(metrics["status"], "blocked_security", f"Missed secret in: {text}")
            for iss in issues:
                self.assertNotIn(secret_substr, iss.snippet, f"Leaked in SEC-01 snippet: {iss.snippet}")
            sanitized = pl.redact_sensitive_text(text, mask_paths=True)
            self.assertNotIn(secret_substr, sanitized, f"Leaked in redact_sensitive_text: {sanitized}")

    def test_rt02_benign_technical_identifiers_camel_snake_doi_paths_zero_false_positives(self) -> None:
        benign_inputs = [
            "SuperconductingQubitControllerV2026",
            "CryogenicReadoutAmplifier2025",
            "DilutionRefrigeratorModel400X",
            "ResNet50ImageNet1000Classifier",
            "Tip4pIceNucleation230K2000ns",
            "unit_test_coverage_report",
            "redis_prod_cluster_01",
            "max_token_budget_2048",
            "cache_key_generator_v2",
            "10.1145/ab_test_methodology_2025",
            "token: classification_head",
            "pwd = /opt/envoy/conf",
        ]
        for item in benign_inputs:
            _, issues, _, _, metrics = pl.lint_text(f"系统模块采用 {item} 进行基准测试。\n", fix=False)
            sec_issues = [i for i in issues if i.category == "security"]
            self.assertEqual(sec_issues, [], f"False-positive SEC-01 on '{item}': {sec_issues}")
            self.assertTrue(metrics["passed"], f"Failed on benign item '{item}': {issues}")

    def test_rt03_dual_dollar_currency_amounts_never_swallow_intervening_prose(self) -> None:
        s1 = "首轮融资$2.8M，详见[本地文件](/Users/linwei/Desktop/bp.pdf)[1][2]\u00a0及[死链](#missing)，订单金额$4.5M。\n"
        _, issues1, _, _, m1 = pl.lint_text(s1, fix=False)
        codes1 = {i.code for i in issues1}
        self.assertTrue({"FMT-01", "FMT-03", "FMT-06", "SEM-04"}.issubset(codes1), f"Swallowed prose! Got: {codes1}")
        self.assertGreaterEqual(m1["cjk_chars"], 15)

        s2 = "首轮融资 $2.8M（未取得回款水单[1][2]，详见[桌面](/Users/linwei/Desktop/bp.pdf)），次轮目标（$4.5M）。\n"
        _, issues2, _, _, _ = pl.lint_text(s2, fix=False)
        codes2 = {i.code for i in issues2}
        self.assertTrue({"FMT-03", "SEM-04"}.issubset(codes2), f"Swallowed parenthesized currency prose! Got: {codes2}")

    def test_rt04_pre_replace_verification_converges_and_zero_width_secret_never_touches_disk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            # Case A: [1][cite_start][2] converges cleanly in a single --fix --in-place run!
            chain_file = Path(tmp) / "chain.md"
            chain_file.write_text("实验记录支持[1][cite_start][2]结论。\n", encoding="utf-8")
            buf = StringIO()
            with patch("sys.stdout", buf):
                rc = pl.main(["--input", str(chain_file), "--fix", "--in-place", "--json"])
            self.assertEqual(rc, 0)
            self.assertEqual(chain_file.read_text(encoding="utf-8"), "实验记录支持[1]、[2]结论。\n")

            # Case B: Zero-width obfuscated secret is caught upfront, exits 2, creates NO output file, and leaves input untouched!
            zw_in = Path(tmp) / "zw_in.md"
            zw_out = Path(tmp) / "zw_out.md"
            orig_zw = "配置项 sk-proj-\u200bSUPERSECRETKEY9876543210abcdef 测试。\n"
            zw_in.write_text(orig_zw, encoding="utf-8")
            buf_zw = StringIO()
            with patch("sys.stdout", buf_zw):
                rc_zw = pl.main(["--input", str(zw_in), "--fix", "--output", str(zw_out), "--json"])
            self.assertEqual(rc_zw, 2)
            self.assertFalse(zw_out.exists(), "Secret output file must NEVER be written to disk!")
            self.assertEqual(zw_in.read_text(encoding="utf-8"), orig_zw)
            self.assertNotIn("SUPERSECRETKEY", buf_zw.getvalue())

    def test_rt05_list_nested_code_fences_blockquotes_and_indented_code_blocks_protected(self) -> None:
        sample = (
            "1. 部署核查步骤：\n"
            "    ```python\n"
            "    matrix_val = tensor[1][2]\n"
            "    cfg = '/Users/linwei/Desktop/dev.yaml'\n"
            "    # [非锚点注释](#not-an-anchor)\n"
            "    ```\n"
            "2. 引用访谈原话：\n"
            "    > 创始人原话：“我们暂不扩招销售[3][4]。”\n\n"
            "    indented_code_arr = grid[5][6]\n"
        )
        updated, issues, fixes, _, metrics = pl.lint_text(sample, fix=True)
        self.assertEqual(updated, sample)
        self.assertEqual(issues, [])
        self.assertEqual(fixes, [])
        self.assertTrue(metrics["passed"])

    def test_rt06_html_block_with_inline_backticks_unclosed_div_and_leading_hr(self) -> None:
        # 1. HTML block containing inline `<div>` backtick must NOT miscount depth
        s_html = (
            "<div>\n"
            "  请勿手写 `<div>` 标签\n"
            "</div>\n\n"
            "## 闭合后的正文章节\n\n"
            "错误[1][2]\u00a0与[悬空锚点](#missing)。\n"
        )
        _, issues_h, _, _, m_h = pl.lint_text(s_html, fix=False)
        codes_h = {i.code for i in issues_h}
        self.assertEqual(m_h["h2_sections"], 1)
        self.assertTrue({"FMT-01", "FMT-03", "FMT-06"}.issubset(codes_h), f"Got: {codes_h}")

        # 2. Unclosed <div class="note"> followed by blank line + ## Heading recovers via circuit breaker
        s_unclosed = "<div class=\"note\">\n\n## 后续正文章节\n\n测试[1][2]\u00a0。\n"
        _, issues_u, _, _, m_u = pl.lint_text(s_unclosed, fix=False)
        self.assertEqual(m_u["h2_sections"], 1)
        self.assertTrue({"FMT-01", "FMT-03"}.issubset({i.code for i in issues_u}))

        # 3. Standalone '---' horizontal rule on line 1 with no closing '---' must NOT swallow document
        s_hr = "---\n\n## 正文章节\n\n内容[1][2]\u00a0。\n"
        _, issues_hr, _, _, m_hr = pl.lint_text(s_hr, fix=False)
        self.assertEqual(m_hr["h2_sections"], 1)
        self.assertTrue({"FMT-01", "FMT-03"}.issubset({i.code for i in issues_hr}))

    def test_rt07_readonly_file_rejected_mode_0644_preserved_directory_and_dangling_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            # 1. Read-only 0444 file must be rejected on --in-place (unless running as root UID 0)
            ro = Path(tmp) / "readonly.md"
            ro.write_text("支持[1][2]测试。\n", encoding="utf-8")
            os.chmod(ro, 0o444)
            if os.geteuid() != 0:
                buf_ro = StringIO()
                with patch("sys.stdout", buf_ro):
                    self.assertEqual(pl.main(["--input", str(ro), "--fix", "--in-place", "--json"]), 2)
                self.assertEqual(ro.read_text(encoding="utf-8"), "支持[1][2]测试。\n")
            os.chmod(ro, 0o644)

            # 2. 0644 file updated with --in-place preserves 0644 mode (not clobbered to 0600!)
            p644 = Path(tmp) / "perm644.md"
            p644.write_text("支持[1][2]测试。\n", encoding="utf-8")
            os.chmod(p644, 0o644)
            with patch("sys.stdout", StringIO()):
                self.assertEqual(pl.main(["--input", str(p644), "--fix", "--in-place"]), 0)
            self.assertEqual(stat.S_IMODE(p644.stat().st_mode), 0o644)

            # 3. Directory target gives explicit directory error
            out_dir = Path(tmp) / "adir"
            out_dir.mkdir()
            buf_dir = StringIO()
            with patch("sys.stdout", buf_dir):
                self.assertEqual(pl.main(["--input", str(p644), "--fix", "--output", str(out_dir), "--json"]), 2)
            self.assertIn("directory", json.loads(buf_dir.getvalue())["error"])

            # 4. Dangling symlink pointing to non-existent parent dir is rejected and symlink stays intact!
            dangling = Path(tmp) / "dangling.md"
            os.symlink(Path(tmp) / "no_such_dir" / "target.md", dangling)
            with patch("sys.stdout", StringIO()):
                self.assertEqual(pl.main(["--input", str(p644), "--fix", "--output", str(dangling), "--overwrite", "--json"]), 2)
            self.assertTrue(dangling.is_symlink())

    def test_rt08_spaces_in_paths_bare_homedirs_dotfiles_and_chinese_anchors(self) -> None:
        sample = (
            "路径一 C:\\Users\\Lin Wei\\Documents\\bp.pdf[1][2]\u00a0；\n"
            "路径二 /Volumes/My Passport/raw_data.h5 与 /Users/linwei 与 /home/chen 及 C:\\Users\\wang[3][4]；\n"
            "路径三 ~/.ssh/id_ed25519_linwei 与 /private/var/folders/ab/cd/T/linwei_tmp.pdf；\n"
            "链接：[虚构章节](#根本不存在的中文锚点)。\n"
        )
        updated, issues, fixes, _, _ = pl.lint_text(sample, fix=True)
        # Chinese dangling anchor caught by FMT-06!
        self.assertTrue(any(i.code == "FMT-06" and "根本不存在的中文锚点" in i.message for i in issues))
        # Citations [3][4] right after C:\Users\wang preserved and fixed without eating '[3'!
        self.assertIn("C:\\Users\\wang[3]、[4]", updated)
        # Verify sanitized FixRecord/logs hide 'Lin Wei', 'My Passport', 'linwei', 'chen', 'wang', 'id_ed25519_linwei'
        sanitized_all = pl.sanitize_log_text(updated, mask_user_paths=True)
        for leak_tok in ("Lin Wei", "My Passport", "linwei", "/home/chen", "\\wang", "id_ed25519_linwei"):
            self.assertNotIn(leak_tok, sanitized_all, f"Path token leaked: {leak_tok} in {sanitized_all}")

    def test_rt09_inline_latex_stats_q4_english_sentence_splitting_and_anti_swallow_echo(self) -> None:
        # 1. Inline LaTeX math stats hit Q4_PROTECTED
        _, _, _, q4_math, _ = pl.lint_text("多变量回归显示显著差异（$p < 0.001$, $n = 64$, $\\pm 0.04$）。\n")
        self.assertGreaterEqual(len(q4_math), 2)
        self.assertTrue(all(r.state == "Q4_PROTECTED" for r in q4_math))

        # 2. 6-sentence English paragraph splits into 6 sentences (echo rate = 1/6, NOT 1/1!)
        en_para = (
            "We benchmarked the cryo-controller across four thermal cycles. "
            "Gate drift remained below 0.02 radians over twelve hours. "
            "Power dissipation dropped by 18% relative to baseline. "
            "Readout crosstalk stayed below the target threshold. "
            "Packaging yield reached 92% on the pilot wafer. "
            "Vendor revenue figures were not independently verified in this round.\n"
        )
        _, _, _, _, m_en = pl.lint_text(en_para)
        self.assertEqual(m_en["total_clauses"], 6)
        self.assertEqual(m_en["mechanical_echo_clauses"], 1)

        # 3. Same-sentence Q4 candidate + mechanical echo does NOT swallow the mechanical echo!
        mixed_echo_en = "Preliminary analysis suggests latency fell by 15% and cannot be equated with verified production SLA.\n"
        _, _, _, q4_me, m_me = pl.lint_text(mixed_echo_en)
        self.assertGreaterEqual(len(q4_me), 1)
        self.assertEqual(m_me["mechanical_echo_clauses"], 1)

        mixed_echo_zh = "甲方提供的演示样机受限于实验室环境且不代表公司现有量产能力。\n"
        _, _, _, _, m_mzh = pl.lint_text(mixed_echo_zh)
        self.assertEqual(m_mzh["mechanical_echo_clauses"], 1)

        # 4. Expanded Chinese & English Q4 candidate expressions
        extra_q4 = (
            "观察性队列未能证实因果关系，且不排除存在幸存者偏倚，结果可能受混杂因素影响。\n"
            "在当前样本量下未观察到统计学差异，该结论仅在 230 K 至 250 K 下成立。\n"
            "This correlation does not establish a causal relationship, we could not rule out selection biases, and the calibration holds only under ambient pressure.\n"
        )
        _, _, _, q4_ex, _ = pl.lint_text(extra_q4)
        self.assertGreaterEqual(len(q4_ex), 6, f"Got only {len(q4_ex)}: {q4_ex}")

    def test_rt10_heading_residue_anchor_consistency_and_json_on_all_error_exits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            # Scenario A: ## Summary [cite: 1] + [Summary](#summary) -> after FMT-04 fix, #summary is VALID (rc=0, Deterministic Checks Passed!)
            f_a = Path(tmp) / "a.md"
            o_a = Path(tmp) / "a_out.md"
            f_a.write_text("## Summary [cite: 1]\n\nSee [Summary](#summary).\n", encoding="utf-8")
            buf_a = StringIO()
            with patch("sys.stdout", buf_a):
                rc_a = pl.main(["--input", str(f_a), "--fix", "--output", str(o_a), "--json"])
            self.assertEqual(rc_a, 0)
            rep_a = json.loads(buf_a.getvalue())
            self.assertTrue(rep_a["metrics"]["passed"])
            self.assertEqual(rep_a["metrics"]["pipeline_stage"], "Deterministic Checks Passed")

            # Scenario B: ## Summary [cite: 1] + [Summary](#summary-cite-1) -> broken after fix (rc=1, Drafted!)
            f_b = Path(tmp) / "b.md"
            o_b = Path(tmp) / "b_out.md"
            f_b.write_text("## Summary [cite: 1]\n\nSee [Summary](#summary-cite-1).\n", encoding="utf-8")
            buf_b = StringIO()
            with patch("sys.stdout", buf_b):
                rc_b = pl.main(["--input", str(f_b), "--fix", "--output", str(o_b), "--json"])
            self.assertEqual(rc_b, 1)
            rep_b = json.loads(buf_b.getvalue())
            self.assertFalse(rep_b["metrics"]["passed"])
            self.assertEqual(rep_b["metrics"]["pipeline_stage"], "Drafted")

            # Scenario C: Missing file with --json MUST still emit parseable JSON to stdout!
            buf_err = StringIO()
            with patch("sys.stdout", buf_err):
                rc_err = pl.main(["--input", str(Path(tmp) / "missing.md"), "--check", "--json"])
            self.assertEqual(rc_err, 2)
            rep_err = json.loads(buf_err.getvalue())
            self.assertEqual(rep_err["metrics"]["pipeline_stage"], "Drafted")
            self.assertFalse(rep_err["metrics"]["gate_passed"])

    def test_SiblingListIndentAndPromptAuditFixes(self) -> None:
        # P1-07: Consecutive under-indented list siblings BOTH get fixed!
        sib = "1. 主项\n - 子项一\n - 子项二\n"
        fixed_sib, issues_sib, _, _, _ = pl.lint_text(sib, fix=True)
        self.assertEqual(len([i for i in issues_sib if i.code == "FMT-02"]), 2)
        self.assertEqual(fixed_sib, "1. 主项\n   - 子项一\n   - 子项二\n")

        # P2-01: prompt_negativity_audit handles 4-backtick outer fence + English multi-sentence splitting
        p_doc = (
            "````markdown\n"
            "Do not invent facts. Never drop citations. Avoid puffery.\n"
            "```python\n"
            "msg = '严禁在Python示例代码中误报；不得触发负向统计'\n"
            "```\n"
            "````\n"
        )
        rep = pna.audit_prompt_text(p_doc)
        self.assertEqual(rep["python_surface_metrics"]["total_clauses"], 3)
        self.assertEqual(rep["python_surface_metrics"]["negative_clause_count"], 3)


class TestCoreLifecycleAndProtectionSuite(unittest.TestCase):
    """Retains all earlier v1.0.1 - v1.1.2 unit regression coverage."""

    def test_existing_output_overwrite_and_symlink_guards(self) -> None:
        src_text = "支持[1][2]\u00a0记录。\n"
        other_text = "已存在输出文件。\n"
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "in.md"
            dst = Path(tmp) / "out.md"
            link_src = Path(tmp) / "link_in.md"
            src.write_text(src_text, encoding="utf-8")
            dst.write_text(other_text, encoding="utf-8")
            os.symlink(src, link_src)

            with patch("sys.stderr", StringIO()):
                self.assertEqual(pl.main(["--input", str(src), "--fix"]), 2)
                self.assertEqual(pl.main(["--input", str(src), "--fix", "--output", str(dst)]), 2)
                self.assertEqual(pl.main(["--input", str(src), "--fix", "--output", str(link_src), "--overwrite"]), 2)
            self.assertEqual(dst.read_text(encoding="utf-8"), other_text)

            with patch("sys.stdout", StringIO()):
                self.assertEqual(pl.main(["--input", str(src), "--fix", "--output", str(dst), "--overwrite"]), 0)
            self.assertEqual(dst.read_text(encoding="utf-8"), "支持[1]、[2] 记录。\n")

    def test_preflight_vs_deterministic_and_no_auto_promotion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "c.md"
            o = Path(tmp) / "o.md"
            f.write_text("干净的自然测试文本。\n", encoding="utf-8")
            b1, b2 = StringIO(), StringIO()
            with patch("sys.stdout", b1):
                self.assertEqual(pl.main(["--input", str(f), "--check", "--json"]), 0)
            self.assertEqual(json.loads(b1.getvalue())["metrics"]["pipeline_stage"], "Preflight Passed")

            with patch("sys.stdout", b2):
                self.assertEqual(pl.main(["--input", str(f), "--fix", "--output", str(o), "--json"]), 0)
            self.assertEqual(json.loads(b2.getvalue())["metrics"]["pipeline_stage"], "Deterministic Checks Passed")

    def test_benign_doi_sha_scientific_ids_preserved(self) -> None:
        doc = (
            "DOI 10.1038/s41586-024-07998-6, arXiv:2409.14509v2, ORCID 0000-0002-1825-0097, "
            "NCT04567890, NM_001126112.3, GSE123456, ENSG00000141510.18, CVE-2025-30144, "
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855[1][2]\u00a0。\n"
        )
        updated, _, fixes, _, m = pl.lint_text(doc, fix=True)
        self.assertTrue(m["passed"])
        self.assertNotIn("[REDACTED", fixes[0].after)
        self.assertIn("10.1038/s41586-024-07998-6", updated)


if __name__ == "__main__":
    unittest.main()
