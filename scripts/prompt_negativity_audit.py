#!/usr/bin/env python3
"""Surface metrics & LLM semantic audit guide for upstream prompts (clear-voice v1.1.3).

Separates deterministic Python surface counts from semantic prompt quality checks
that require LLM or human judgment. Supports variable-length nested code fences,
multi-backtick inline code, English/Chinese sentence splitting, and embedded
```markdown / ```prompt template auditing.
"""
from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List, Optional, Tuple


@dataclass
class NegativeClauseHit:
    line: int
    operator: str
    triage_hint: str  # "candidate_for_deterministic_linter" | "candidate_for_positive_schema"
    clause: str


@dataclass
class NearDuplicatePair:
    line_a: int
    line_b: int
    similarity: float
    clause_a: str
    clause_b: str


@dataclass
class LexicalConflictCue:
    topic: str
    positive_line: int
    negative_line: int
    note: str


NEGATIVE_RE = re.compile(
    r"(?:严禁|不得|禁止|切忌|切勿|绝不(?:可|能|允许)?|请勿|不要|"
    r"\b(?:do\s+not|don't|never|avoid|refrain\s+from|must\s+not|cannot|prohibited)\b)",
    re.IGNORECASE,
)
MECHANICAL_HINT_RE = re.compile(
    r"(?:空格|缩进|破折号|字数|行数|格式|链接|路径|括号|符号|emoji|markdown|"
    r"\b(?:dash|whitespace|indent|link|url|bracket|character|word\s+count|format)\b)",
    re.IGNORECASE,
)
VAGUE_IMPERATIVE_RE = re.compile(
    r"(?:更加自然|通俗易懂|高质量|专业感|恰当处理|适当润色|行文流畅|"
    r"\b(?:more\s+natural|high[- ]quality|appropriate\s+tone|engaging\s+prose|smoothly)\b)",
    re.IGNORECASE,
)

TOPIC_CONFLICT_PROBES = [
    ("列表/Bullets", re.compile(r"(?:保留|使用|采用).{0,10}(?:列表|bullet)", re.I), re.compile(r"(?:禁止|不要|删掉|避免).{0,10}(?:列表|bullet)", re.I)),
    ("加粗/Bold", re.compile(r"(?:保留|使用|采用).{0,10}(?:加粗|粗体|bold)", re.I), re.compile(r"(?:禁止|不要|去掉|避免).{0,10}(?:加粗|粗体|bold)", re.I)),
    ("摘要表/Table", re.compile(r"(?:必须|放置|保留).{0,10}(?:速览表|摘要表|表格|table)", re.I), re.compile(r"(?:禁止|不要|避免).{0,10}(?:速览表|摘要表|表格|table)", re.I)),
    ("被动语态/Passive", re.compile(r"(?:保留|允许).{0,10}(?:被动|passive)", re.I), re.compile(r"(?:禁止|绝不|严禁).{0,10}(?:被动|passive)", re.I)),
]

FENCE_OPEN_RE = re.compile(r"^[ ]{0,3}(`{3,}|~{3,})(.*)$")
HEADING_RE = re.compile(r"^#{1,6}\s+")
INLINE_CODE_RE = re.compile(r"(?P<bt>`+)(?!`)(?:.+?)(?<!`)(?P=bt)(?!`)")
SENTENCE_SPLIT_RE = re.compile(
    r"[。！？!?；;]+|(?<!\bvs)(?<!\bal)(?<!\beg)(?<!\bie)(?<!\bcf)(?<!\bDr)(?<!\bMr)(?<!\bMs)(?<!\bJr)(?<!\bSr)(?<!\bNo)(?<!\bFig)(?<!\bEqs)(?<!\bSec)(?<!\bArt)(?<!\bInc)(?<!\bLtd)(?<!\betc)(?<![A-Z0-9])\.(?=\s+[A-Z\"'(\[])"
)
PROMPT_FENCE_LANGS = {"markdown", "md", "prompt", "system-prompt", "text", "txt"}


def has_valid_yaml_frontmatter(lines: List[str]) -> bool:
    if not lines or lines[0].strip() != "---":
        return False
    saw_kv = False
    for idx in range(1, min(len(lines), 80)):
        s = lines[idx].strip()
        if s in ("---", "..."):
            return saw_kv or idx == 1
        if HEADING_RE.match(s):
            return False
        if re.match(r"^[A-Za-z0-9_.-]+\s*:", s) or s.startswith("#") or s.startswith("- "):
            saw_kv = True
    return False


def is_closing_fence(line: str, ch: str, length: int) -> bool:
    return bool(re.match(rf"^[ \t]*{re.escape(ch)}{{{length},}}[ \t]*$", line))


def audit_prompt_text(text: str, audit_embedded_prompt_fences: bool = True) -> dict:
    lines = text.splitlines()
    in_fm = has_valid_yaml_frontmatter(lines)

    # Stack of (fence_char, fence_len, is_auditable_prompt_block)
    fence_stack: List[Tuple[str, int, bool]] = []

    indexed_clauses: List[Tuple[int, str]] = []
    negative_hits: List[NegativeClauseHit] = []
    vague_clauses: List[Tuple[int, str]] = []

    for idx, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if in_fm:
            if idx > 1 and stripped in ("---", "..."):
                in_fm = False
            continue

        # Variable-length nested fence stack handling
        if fence_stack and is_closing_fence(raw_line, fence_stack[-1][0], fence_stack[-1][1]):
            fence_stack.pop()
            continue

        m_fence = FENCE_OPEN_RE.match(raw_line)
        if m_fence and not (m_fence.group(1)[0] == "`" and "`" in m_fence.group(2)):
            ch = m_fence.group(1)[0]
            flen = len(m_fence.group(1))
            lang = m_fence.group(2).strip().split()[0].lower() if m_fence.group(2).strip() else ""
            parent_auditable = fence_stack[-1][2] if fence_stack else True
            is_prompt_block = bool(audit_embedded_prompt_fences and parent_auditable and lang in PROMPT_FENCE_LANGS)
            fence_stack.append((ch, flen, is_prompt_block))
            continue

        if fence_stack and not fence_stack[-1][2]:
            continue

        if not stripped or HEADING_RE.match(stripped) or re.match(r"^\|[\s:|-]+\|$", stripped):
            continue
        # Skip before/after rewrite showcase lines inside markdown examples
        if re.match(r"^(?:改前|改后|原文|处理|\[病灶|\[Q\d)", stripped):
            continue

        masked = INLINE_CODE_RE.sub("`CODE`", stripped)
        clauses = [c.strip().rstrip(".") for c in SENTENCE_SPLIT_RE.split(masked) if len(c.strip()) >= 5]
        for clause in clauses:
            indexed_clauses.append((idx, clause))
            m_neg = NEGATIVE_RE.search(clause)
            if m_neg:
                hint = (
                    "candidate_for_deterministic_linter"
                    if MECHANICAL_HINT_RE.search(clause)
                    else "candidate_for_positive_schema"
                )
                negative_hits.append(NegativeClauseHit(idx, m_neg.group(0), hint, clause[:110]))
            if VAGUE_IMPERATIVE_RE.search(clause) and len(clause) < 35:
                vague_clauses.append((idx, clause[:110]))

    near_duplicates: List[NearDuplicatePair] = []
    for i in range(len(indexed_clauses)):
        la, ca = indexed_clauses[i]
        if len(ca) < 12:
            continue
        for j in range(i + 1, len(indexed_clauses)):
            lb, cb = indexed_clauses[j]
            if len(cb) < 12:
                continue
            sim = difflib.SequenceMatcher(None, ca, cb).ratio()
            if sim >= 0.78:
                near_duplicates.append(NearDuplicatePair(la, lb, round(sim, 3), ca[:90], cb[:90]))

    conflict_cues: List[LexicalConflictCue] = []
    for topic, pos_re, neg_re in TOPIC_CONFLICT_PROBES:
        pos_lines = [ln for ln, cl in indexed_clauses if pos_re.search(cl)]
        neg_lines = [ln for ln, cl in indexed_clauses if neg_re.search(cl)]
        if pos_lines and neg_lines:
            conflict_cues.append(
                LexicalConflictCue(
                    topic=topic,
                    positive_line=pos_lines[0],
                    negative_line=neg_lines[0],
                    note=f"Both positive (L{pos_lines[0]}) and negative (L{neg_lines[0]}) directives touch {topic}; verify section/genre scoping.",
                )
            )

    total = len(indexed_clauses)
    neg_ratio = (len(negative_hits) / total) if total > 0 else 0.0
    if neg_ratio > 0.25:
        band = "elevated_negative_concentration"
    elif neg_ratio >= 0.10:
        band = "moderate_negative_concentration"
    else:
        band = "low_negative_concentration"

    return {
        "python_surface_metrics": {
            "note": "Surface lexical counts only. A low negative ratio does NOT guarantee semantic clarity, completeness, or conflict-free instructions.",
            "total_clauses": total,
            "negative_clause_count": len(negative_hits),
            "negative_clause_ratio": round(neg_ratio, 4),
            "negative_concentration_band": band,
            "mechanical_ban_candidates": sum(1 for h in negative_hits if h.triage_hint == "candidate_for_deterministic_linter"),
            "lexical_near_duplicate_count": len(near_duplicates),
            "lexical_conflict_cue_count": len(conflict_cues),
            "short_vague_directive_count": len(vague_clauses),
        },
        "surface_findings": {
            "negative_clauses": [asdict(h) for h in negative_hits],
            "near_duplicates": [asdict(d) for d in near_duplicates],
            "lexical_conflict_cues": [asdict(c) for c in conflict_cues],
            "short_vague_directives": [{"line": ln, "clause": cl} for ln, cl in vague_clauses],
        },
        "llm_semantic_review_agenda": [
            {
                "dimension": "semantic_duplication",
                "question": "Are identical constraints stated multiple times in different words across sections?",
            },
            {
                "dimension": "implicit_rule_conflict",
                "question": "Do brevity/naturalness instructions collide with mandatory citation, attribution, or Q4 qualification retention when unscoped?",
            },
            {
                "dimension": "constraint_coverage",
                "question": "Does the prompt explicitly protect all 5 Fact Ledger layers (facts, entity attribution, evidentiary grade, scope conditions, unresolved gaps)?",
            },
            {
                "dimension": "executability_and_verifiability",
                "question": "Does every instruction specify a concrete decision rule or output mapping rather than subjective adjectives?",
            },
        ],
    }


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Surface metrics & semantic review guide for prompts (v1.1.3).")
    ap.add_argument("--input", "-i", required=True, help="Path to prompt or Markdown file.")
    f_grp = ap.add_mutually_exclusive_group()
    f_grp.add_argument("--include-markdown-fences", dest="include_md_fences", action="store_true", default=True, help="Audit embedded ```markdown/```prompt/```text template blocks (default: enabled).")
    f_grp.add_argument("--skip-markdown-fences", dest="include_md_fences", action="store_false", help="Skip embedded ```markdown/```prompt/```text blocks.")
    ap.add_argument("--max-negative-ratio", type=float, default=0.25, help="Optional CI warning ceiling (default: 0.25).")
    ap.add_argument("--fail-above-max", action="store_true", help="Exit 1 if negative_clause_ratio > --max-negative-ratio.")
    ap.add_argument("--json", action="store_true", help="Output structured JSON.")
    args = ap.parse_args(argv)

    path = Path(args.input)
    if not path.is_file():
        if args.json:
            print(json.dumps({"error": f"file not found: {path}"}, ensure_ascii=False))
        else:
            print(f"Error: file not found: {path}", file=sys.stderr)
        return 2

    report = audit_prompt_text(path.read_text(encoding="utf-8"), audit_embedded_prompt_fences=args.include_md_fences)
    metrics = report["python_surface_metrics"]

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(
            f"[SURFACE METRICS] negative_ratio={metrics['negative_clause_ratio']:.1%} "
            f"({metrics['negative_clause_count']}/{metrics['total_clauses']}) | band={metrics['negative_concentration_band']} | "
            f"near_dups={metrics['lexical_near_duplicate_count']} | conflict_cues={metrics['lexical_conflict_cue_count']}"
        )
        print(f"  Note: {metrics['note']}")
        for item in report["surface_findings"]["negative_clauses"]:
            print(f"  - [NEG L{item['line']}] ({item['triage_hint']}): {item['clause']}")
        for dup in report["surface_findings"]["near_duplicates"]:
            print(f"  - [DUP L{dup['line_a']}~L{dup['line_b']} sim={dup['similarity']}]: {dup['clause_a']}")
        for cue in report["surface_findings"]["lexical_conflict_cues"]:
            print(f"  - [CONFLICT CUE] {cue['note']}")
        print("[LLM SEMANTIC REVIEW REQUIRED]: semantic_duplication, implicit_rule_conflict, constraint_coverage, executability_and_verifiability")

    if args.fail_above_max and metrics["negative_clause_ratio"] > args.max_negative_ratio:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
