#!/usr/bin/env python3
"""Deterministic hygiene, file-safe auto-fixer, and heuristic linter for clear-voice (v1.1.3).

Pipeline stages emitted by Python:
  - Drafted                     : Security blocked, formatting errors present, or write/readback failed.
  - Preflight Passed            : Read-only --check (or in-memory lint) passed security & formatting checks (NO disk write verified).
  - Deterministic Checks Passed : --fix completed pre-verified atomic disk write, disk readback, and clean re-lint verification.
  (Note: Semantic Review Passed and Human Approved are NEVER emitted by Python; they require actual semantic/human review.)

Q4 Local-Span Tri-State Classification:
  - Q4_PROTECTED         : Local span with structured quantitative intervals/tests or clause-numbered statutory obligations.
  - Q4_CANDIDATE         : Local span with contextual scientific, causal, bias/error, scope, or unnumbered contractual bounds (preserved by default).
  - Q4_NOT_QUALIFICATION : No explicit Q4 span detected (does NOT grant semantic deletion permission; uncertain content must be kept).
"""
from __future__ import annotations

import argparse
import difflib
import json
import math
import os
import re
import stat
import sys
import tempfile
import urllib.parse
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class Issue:
    code: str
    category: str  # "security" | "formatting" | "semantic_warning"
    severity: str  # "blocked" | "error" | "auto_fixed" | "warning"
    line: int
    message: str
    snippet: str


@dataclass
class FixRecord:
    line: int
    codes: List[str]
    before: str
    after: str


@dataclass
class Q4SpanRecord:
    line: int
    state: str  # "Q4_PROTECTED" | "Q4_CANDIDATE"
    reason: str
    matched_span: str
    clause_preview: str
    auto_delete_authorized: bool = False


SPACE_LIKE = {"\u00a0": "U+00A0 NBSP", "\u2002": "U+2002 EN", "\u2003": "U+2003 EM", "\u2009": "U+2009 THIN", "\u3000": "U+3000 IDEOGRAPHIC"}
ZERO_WIDTH = {"\u200b": "U+200B ZWSP", "\u200c": "U+200C ZWNJ", "\u200d": "U+200D ZWJ", "\ufeff": "U+FEFF BOM"}
ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\ufeff]")

# Multi-line PEM block (catches RSA, EC, OPENSSH, DSA, PGP, ENCRYPTED PRIVATE KEY, PKCS#8 PRIVATE KEY)
PEM_BLOCK_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|$)"
)
PEM_HEADER_RE = re.compile(r"-----(?:BEGIN|END) [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*")

# Phase A: Explicit high-confidence secret patterns (run BEFORE benign hex/UUID/URL stashing!)
EXPLICIT_SECRET_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("PRIVATE_KEY", PEM_HEADER_RE),
    ("API_KEY", re.compile(
        r"\b(?:sk-(?:proj-|ant-|live-|test-)?[A-Za-z0-9_-]{12,}|"
        r"rk-(?:live-|test-)?[A-Za-z0-9_-]{12,}|"
        r"AIza[0-9A-Za-z_-]{35}|"
        r"hf_[A-Za-z0-9]{24,}|"
        r"glpat-[A-Za-z0-9_-]{16,}|"
        r"npm_[A-Za-z0-9]{24,}|"
        r"pypi-[A-Za-z0-9_-]{32,})\b"
    )),
    ("GITHUB_TOKEN", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{12,}\b|https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9_-]+")),
    ("JWT_TOKEN", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("URL_CREDENTIAL", re.compile(r"(?<=://)[^/\s:@`]*:(?!(?:pass(?:word)?|secret|token|<[^>]+>|\*+|x+)@)[^/\s@`\"'<>]{6,}@")),
    ("URL_QUERY_SECRET", re.compile(
        r"(?i)([?&](?:[a-z0-9_.-]*?(?:api[_-]?key|access[_-]?token|client[_-]?secret|auth[_-]?token|"
        r"token|secret|signature|sig|password|passwd)|key|auth)=)(?!<[^>]+>)([^&\s#/,\"'`)\]}>，。；：！？、（）]{8,})"
    )),
    ("AUTH_HEADER", re.compile(r"(?i)\b(Bearer|Basic)\s+([A-Za-z0-9_./+=-]{12,})")),
]

LABELED_SECRET_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret[_-]?key|aws[_-]?secret[_-]?access[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|client[_-]?secret|private[_-]?key|db[_-]?pass(?:word)?|"
    r"password|passwd|pwd|secret|token)(['\"]?\s*[:=]\s*)(['\"]?)([^\s'\"`,;)}\]>]{10,})\3"
)
VENDOR_PREFIX_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9._-])([a-z]{2,10}_(?:live|test|prod|sec|secret|key|tok|token|pat|prv)_([A-Za-z0-9_-]{12,}))(?![A-Za-z0-9._-])"
)
CANDIDATE_TOKEN_RE = re.compile(r"(?<![/\\A-Za-z0-9._-])([A-Za-z0-9_-]{18,})(?![/\\A-Za-z0-9._-])")

# Phase B: Benign scientific, bibliographic, cryptographic-digest, and standard IDs
BENIGN_IDENTIFIER_RE = re.compile(
    r"(?:"
    r"\b10\.\d{4,9}/[-._;()/:A-Za-z0-9]+\b|"                                       # DOI
    r"\barXiv:\d{4}\.\d{4,5}(?:v\d+)?\b|"                                          # arXiv ID
    r"\b\d{4}-\d{4}-\d{4}-\d{3}[\dX]\b|"                                           # ORCID
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b|"  # UUID
    r"\b(?:sha256:|sha1:|md5:)?[0-9a-fA-F]{32,64}\b|"                              # MD5 / SHA-1 / SHA-256 hex digest
    r"\b[0-9a-f]{7,40}\b|"                                                         # Lowercase git commit SHA
    r"\b(?:NCT\d{8}|GSE\d{4,8}|GSM\d{4,8}|PRJNA\d+|SRR\d+|ERR\d+|"                 # ClinicalTrials / GEO / SRA
    r"NM_\d+(?:\.\d+)?|NP_\d+(?:\.\d+)?|NR_\d+(?:\.\d+)?|"                         # NCBI RefSeq
    r"ENS[A-Z]*[GT]\d{11}(?:\.\d+)?|rs\d{4,12}|CVE-\d{4}-\d{4,7})\b"               # Ensembl / dbSNP / CVE
    r")"
)
URL_SPAN_RE = re.compile(r"https?://[^\s)\]>\"'`，。；：！？、]+")

RESIDUE_PATTERNS = [
    ("oaicite block", re.compile(r":contentReference\[oaicite:\d+\]\{index=\d+\}")),
    ("oaicite token", re.compile(r"\boaicite:\d+\b")),
    ("turn-search token", re.compile(r"\bturn\d+(?:search|view|news|image)\d+\b")),
    ("cite bracket tag", re.compile(r"\[cite:\s*[\d,\s-]+\]")),
    ("cite boundary tag", re.compile(r"\[cite_(?:start|end)\]")),
    ("span boundary tag", re.compile(r"\[span_\d+\]\((?:start|end)_span\)")),
    ("platform card residue", re.compile(r"\b(?:grok_card|ppl-ai-file-upload)\b")),
]

PATH_STOP = r"[^\s)\]>\[`\"'，。；：！？、（）《》「」]"
WIN_SEG_WITH_SPACES = r"[A-Za-z0-9._-]+(?: [A-Za-z0-9._-]+)*"

# Cross-platform Privacy-Sensitive Paths (SEM-04)
PRIVACY_PATH_RE = re.compile(
    rf"(?:"
    rf"file:///(?:[A-Za-z]:/)?(?:Users|home|Documents(?:%20| )and(?:%20| )Settings)/{PATH_STOP}+|"
    rf"(?<![A-Za-z0-9_])/(?:Users|home)/[A-Za-z0-9._-]+(?:/{PATH_STOP}+)?(?=[/\s,.;:!?，。；：！？、（）)\]>\[`\"']|$)|"
    rf"(?<![A-Za-z0-9_])(?:/private)?/var/folders/{PATH_STOP}+|"
    rf"(?<![A-Za-z0-9_])(?:/run)?/media/[A-Za-z0-9._-]+/{WIN_SEG_WITH_SPACES}(?:/{PATH_STOP}*)?|"
    rf"(?<![A-Za-z0-9_])/Volumes/{WIN_SEG_WITH_SPACES}(?:/{PATH_STOP}*)?|"
    rf"(?<![A-Za-z0-9_])~/(?:Documents|Desktop|Downloads|Library|\.ssh|\.aws|\.config)(?:/{PATH_STOP}*)?|"
    rf"\b[A-Za-z]:\\(?:Users|Documents and Settings)\\{WIN_SEG_WITH_SPACES}(?:\\{PATH_STOP}*)*|"
    rf"\\\\[A-Za-z0-9._-]+\\[A-Za-z0-9$._-]+(?:\\{PATH_STOP}*)*"
    rf")"
)

# General System / Reproducibility Paths (SEM-05)
GENERAL_LOCAL_PATH_RE = re.compile(
    rf"(?:"
    rf"file:///{PATH_STOP}+|"
    rf"(?<![A-Za-z0-9_:/])/(?:opt|srv|etc|tmp|mnt|var|root|working_dir|Applications|Library)/[A-Za-z0-9._-]+(?:/{PATH_STOP}+)*|"
    rf"\b[A-Za-z]:\\(?:Program Files(?: \(x86\))?|Windows|Temp|Data|Projects|Work|opt|srv|mnt)\\{PATH_STOP}+"
    rf")"
)

# Support Unicode / Chinese & URL-encoded anchors (#锚点, #sec-1)
ANCHOR_LINK_RE = re.compile(r"\[([^\]]+)\]\(#([^\s)#\"'`]+)\)")
HTML_ANCHOR_RE = re.compile(r"""<(?:a|span|div|section|h[1-6])\b(?:(?:"[^"]*"|'[^']*'|[^'">])*)?\b(?:id|name)=["']([^"']+)["']""", re.IGNORECASE)
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
MD_LINK_UNWRAP_RE = re.compile(r"\[([^\]]+)\]\([^)]+\)")
TABLE_XREF_RE = re.compile(r"(?:详见|参见|出处见|具体见|见)\s*(?:第\s*[一二三四五六七八九十百\d]+\s*[节章部分条]|下文|后文)")

DISCLAIMER_ECHO_PATTERNS = [
    re.compile(r"不能与[^，。；,;]{1,24}混为一谈"),
    re.compile(r"(?:不得|禁止|切忌)将[^，。；,;]{1,24}(?:混为一谈|等同于)"),
    re.compile(r"不(?:能)?代表(?:本公司|公司|现有|实际|已实现|当前)[^，。；,;]*"),
    re.compile(r"不等于(?:本公司|公司|现有|已交付|实际|已实现)[^，。；,;]*"),
    re.compile(r"并非(?:本公司|公司|实测|现有|已交付)[^，。；,;]*"),
    re.compile(r"本(?:次|轮|稿)(?:公开检索|核验|调查|检索)?(?:均|尚)?未(?:取得|发现|实机运行|实际运行|核实|验证)[^，。；,;]*"),
    re.compile(r"尚不足以(?:支持|证明|确认)(?:技术领先|投资定价|真实收入|商业化)"),
    re.compile(r"暂不计入当前能力"),
    re.compile(r"没有给出归属本公司的[^，。；,;]*"),
    re.compile(r"\bcannot be equated with\b[^,.;]*", re.IGNORECASE),
    re.compile(r"\bdoes not represent verified company\b[^,.;]*", re.IGNORECASE),
    re.compile(r"\bnot independently verified in this round\b[^,.;]*", re.IGNORECASE),
]

Q4_LOCAL_FALSE_FRIEND_RE = re.compile(
    r"(?:"
    r"提示词(?:工程|模板|结构|设计)?|系统提示|弹窗提示|错误提示|报错提示|温馨提示|命令行提示(?:符)?|页面提示|"
    r"(?:不得|禁止|切忌|不要)(?:将[^，。；,;]{1,24}(?:混为一谈|等同于?)|编造|虚构|(?:在[^，。；,;]{0,8})?(?:堆砌|使用)[^，。；,;]{1,14}(?:词汇|套话|形容词|列表))|"
    r"(?:扩大|增加|补充|收集|拓展)[^，。；,;]{0,10}(?:访谈|调研|客户|用户|测试)?样本量(?:至\s*\d+\s*[家名例个]?)?"
    r")",
    re.IGNORECASE,
)

ECHO_TAIL_STOP = r"(?=\s+(?:and|but|while)\s+(?:cannot\s+be\s+equated|does\s+not\s+represent|not\s+independently\s+verified)\b|[，。；,;!?(（）)]|\.(?:\s|$)|(?:且|但)?(?:不(?:能)?代表|不等于|并非(?:本公司|公司|实测)|不能与)|$)"

# Q4_PROTECTED: Hard quantitative intervals/tests or clause-numbered statutory obligations (supports multi-clause obligations under same Section/第X条!)
Q4_PROTECTED_SPAN_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("structured_stat_interval", re.compile(
        r"(?:\b95\\?%\s*CI\s*[:=\[\(]?\s*[\d.-]+(?:\s*[-~至]\s*[\d.-]+)?|\b95\\?%\s*CI\b|\bCI\s*[:=\[\(]\s*[\d.-]+|"
        r"(?<![A-Za-z])\bp\s*[<=>≤≥]\s*0?\.\d+|(?:±|\\pm)\s*\d+(?:\.\d+)?|"
        r"\b(?:SD|SEM|IQR|HR|OR|RR)\s*[:=,(\[]\s*[\d.-]+|(?<![A-Za-z])\bn\s*=\s*\d+)",
        re.I,
    )),
    ("statutory_clause_obligation", re.compile(
        r"(?:(?:依据|根据|按照)?[^。；;]{0,14}(?:协议|合同|条例|法规|法案|办法|条款)\s*第\s*[\d.一二三四五六七八九十百]+\s*[条款项][^。；;]{0,90}?(?:应当|不得|禁止|仅限于|受限于|有权|承担|免除)[^。；;]*|"
        r"\b(?:pursuant to|under|per)\s+(?:Section|Article|Clause)\s+[\d.]+[^.;]{0,100}?\b(?:shall|shall not|must|solely for|subject to)\b[^.;]*)",
        re.I,
    )),
]

# Q4_CANDIDATE: Bounded non-greedy prose scientific, causal, bias/error, temperature/condition, or unnumbered contractual bounds
Q4_CANDIDATE_SPAN_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("causal_non_establishment", re.compile(
        r"(?:(?:尚未|未能?|尚不足以|不足以|不能|无法)(?:证实|证明|确立|推断)[^，。；,;]{0,18}?因果(?:关系|联系|效应|方向)?|"
        r"仅反映相关性而非因果|"
        r"\b(?:does not|cannot|insufficient to|failed to)\s+(?:establish|prove|demonstrate|infer)\s+(?:a\s+)?causal(?:\s+relationship|ity)?\b)"
        + ECHO_TAIL_STOP,
        re.I,
    )),
    ("bias_or_confounding_candidate", re.compile(
        r"(?:(?:尚未|未能?|无法|不能|难以|不)排除(?:存在)?[^，。；,;]{0,24}?(?:偏倚|混杂(?:因素)?|有限尺寸效应|系统误差|批次效应|干扰|效应)|"
        r"可能受[^，。；,;]{1,18}?(?:混杂|偏倚|误差)[^，。；,;]{0,8}?影响|"
        r"\b(?:cannot|could not|unable to|does not)\s+(?:rule out|exclude)\s+[^,.;]{0,36}?\b(?:selection\s+bias(?:es)?|survivorship\s+bias|confounding|finite-size(?:\s+effects?)?|systematic\s+errors?|batch\s+effects?|bias(?:es)?|artifacts?)\b)"
        + ECHO_TAIL_STOP,
        re.I,
    )),
    ("experimental_or_scope_limit", re.compile(
        r"(?:仅适用于[^，。；,;]{2,28}?(?:实验条件|当前条件|特定条件|温区|压强|样本|场景|人群|阶段|范围)|"
        r"仅在[^，。；,;]{1,28}?下(?:成立|有效|适用|验证)|适用范围限于[^，。；,;]{2,24}?|"
        r"\b(?:holds|valid|applicable|applies)\s+only\s+(?:under|within|to|for)\s+[^,.;]{3,36}?|"
        r"\bonly\s+applicable\s+(?:to|under|within|for)\s+[^,.;]{3,36}?)"
        + ECHO_TAIL_STOP,
        re.I,
    )),
    ("scientific_hedging_candidate", re.compile(
        r"(?:(?:结果|数据|轨迹|比值|观察|分析|曲线|模型|回归|趋势)[^，。；,;]{0,10}?提示[^，。；,;]{2,32}?|"
        r"与[^，。；,;]{2,22}?(?:假说|模型|预期|机制)一致|"
        r"在当前样本量下未观察到[^，。；,;]{2,24}?|"
        r"受[^，。；,;]{0,12}?样本量[^，。；,;]{0,8}?(?:所限|较小|不足|偏小|限制)|样本量(?:较小|不足|偏小|有限)|"
        r"\b(?:results?|data|findings?|analysis|observations?)\s+(?:suggests?|indicates?|is consistent with)\s+[^,.;]{3,42}?|"
        r"\blimited by [^,.;]{0,18}?sample size\b)"
        + ECHO_TAIL_STOP,
        re.I,
    )),
    ("unanchored_legal_modal_candidate", re.compile(
        r"(?:(?:甲方|乙方|买方|卖方|供应商|运营方|接收方|许可方|服务方)[^，。；,;]{0,12}?(?:应当|不得|仅限于|受限于)[^，。；,;]{1,28}?|"
        r"(?:补偿|授权|许可|用途|责任|积分)[^，。；,;]{0,10}?(?:仅限于|受限于)[^，。；,;]{1,28}?|"
        r"\b(?:licensee|licensor|operator|recipient|supplier|buyer)\s+shall(?:\s+not)?\s+[^,.;]{3,36}?|"
        r"\bsolely for the purpose of\s+[^,.;]{3,36}?)"
        + ECHO_TAIL_STOP,
        re.I,
    )),
]

WORKFLOW_LEAK_RE = re.compile(r"(?:\bHTTP\s*[45]\d{2}\b|爬虫超时|抓取超时|检索超时|\bReadTimeout\b|\bConnectionError\b|SSL\s*(?:证书错误|error)|\bWiki\s*ID\b|按已完成的?\s*Wiki|未新增调查)")

LIST_ITEM_RE = re.compile(r"^([ ]*)([-*+]|\d+[.)])([ ]+)(.*)$")
FENCE_OPEN_RE = re.compile(r"^([ ]*)(`{3,}|~{3,})(.*)$")
MATH_BLOCK_OPEN_RE = re.compile(r"^[ ]{0,3}(\$\$|\\\[|\\begin\{([A-Za-z]+\*?)\})")
# Exclude variable_name[0][1] code-style zero/identifier indexing when outside code blocks; citations start at 1
ADJ_CIT_RE = re.compile(r"(?<![A-Za-z0-9]_[A-Za-z0-9])(\[(?:注|来源|Ref|ref)?\s*[1-9]\d*\])(?=\[(?:注|来源|Ref|ref)?\s*[1-9]\d*\])")

# Safe sentence splitter for Chinese + English (sparing decimals 0.003, Section 4.2, and common abbreviations)
SENTENCE_SPLIT_RE = re.compile(
    r"[。！？!?；;]+|(?<!\bvs)(?<!\bal)(?<!\beg)(?<!\bie)(?<!\bcf)(?<!\bDr)(?<!\bMr)(?<!\bMs)(?<!\bJr)(?<!\bSr)(?<!\bNo)(?<!\bFig)(?<!\bEqs)(?<!\bSec)(?<!\bArt)(?<!\bInc)(?<!\bLtd)(?<!\betc)(?<![A-Z0-9])\.(?=\s+[A-Z\"'(\[])"
)

HTML_RAW_TAGS = ("script", "style", "pre", "svg")
HTML_BLOCK_TAGS = (
    "table", "thead", "tbody", "tfoot", "tr", "td", "th", "div", "section",
    "article", "aside", "details", "summary", "figure", "figcaption", "svg",
    "script", "style", "pre", "iframe", "form", "fieldset", "dl", "ul", "ol",
)
HTML_BLOCK_OPEN_RE = re.compile(
    rf"^[ ]{{0,3}}<({'|'.join(HTML_BLOCK_TAGS)})\b(?:(?:\"[^\"]*\"|'[^']*'|[^'\">])*)?>",
    re.IGNORECASE,
)

# Currency token recognizer (e.g. $2.8M, $450 万, $35,000) so dual-$ amounts NEVER swallow prose as LaTeX math!
CURRENCY_AMOUNT_PATTERN = r"(?<!\\)\$\d[\d,]*(?:\.\d+)?(?:\s*(?:[KMBTkmbt]\b|万|亿|百万|千万|美元|加元|新元))?(?![A-Za-z0-9_\\}])"

# Pandoc-safe inline math: no CJK full-width sentence punctuation inside single-$ math, and closing $ cannot precede a digit!
INLINE_MATH_SINGLE_DOLLAR = r"(?<!\\)\$(?!\s)(?:\\.|[^$\\\n，。；：！？、（）《》「」])+?(?<!\s)\$(?![0-9])"

PROTECTED_INLINE_RE = re.compile(
    rf"("
    rf"(?P<bt1>`+)(?!`)(?:.+?)(?<!`)(?P=bt1)(?!`)|"
    rf"\$\$[^$]+\$\$|\\\[.+?\\\]|\\\(.+?\\\)|"
    rf"<(?P<ipair>code|kbd|samp|var|math|svg|script|style)\b(?:(?:\"[^\"]*\"|'[^']*'|[^'\">])*)?>.*?</(?P=ipair)\s*>|"
    rf"<!--[\s\S]*?-->|"
    rf"</[A-Za-z][A-Za-z0-9-]*\s*>|"
    rf"<[A-Za-z][A-Za-z0-9-]*(?:\s+(?:[A-Za-z_:][A-Za-z0-9_.:-]*(?:\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s\"'=<>`]+))?))*\s*/?>|"
    rf"{INLINE_MATH_SINGLE_DOLLAR}"
    rf")",
    re.IGNORECASE,
)

NON_MATH_PROTECTED_INLINE_RE = re.compile(
    r"("
    r"(?P<bt2>`+)(?!`)(?:.+?)(?<!`)(?P=bt2)(?!`)|"
    r"<(?P<ipair2>code|kbd|samp|var|svg|script|style)\b(?:(?:\"[^\"]*\"|'[^']*'|[^'\">])*)?>.*?</(?P=ipair2)\s*>|"
    r"<!--[\s\S]*?-->|"
    r"</[A-Za-z][A-Za-z0-9-]*\s*>|"
    r"<[A-Za-z][A-Za-z0-9-]*(?:\s+(?:[A-Za-z_:][A-Za-z0-9_.:-]*(?:\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s\"'=<>`]+))?))*\s*/?>"
    r")",
    re.IGNORECASE,
)
INLINE_MATH_UNWRAP_RE = re.compile(
    rf"\$\$([^$]+)\$\$|\\\[(.+?)\\\]|\\\((.+?)\\\)|({INLINE_MATH_SINGLE_DOLLAR})"
)

CJK_CHAR_RE = re.compile(r"[\u4e00-\u9fff\u3400-\u4dbf]")
EN_WORD_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9'-]*\b")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    counts: Dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_likely_labeled_secret_value(label: str, val: str) -> bool:
    """Distinguish real labeled secret values from filesystem paths (`pwd = /opt/...`) or snake_case config names."""
    v = val.strip("'\"")
    if len(v) < 10:
        return False
    # Filesystem paths (e.g. pwd = /opt/envoy/conf or path-like strings) are NOT secret keys
    if v.startswith(("/", "~/", "./", "../")) or re.match(r"^[A-Za-z]:\\", v):
        return False
    # Pure alphabetic or plain snake_case/kebab-case config words without random entropy (e.g. classification_head, bearer_auth_mode)
    if re.fullmatch(r"[a-z]+(?:[_-][a-z]{2,})+", v) or re.fullmatch(r"[A-Za-z]+", v):
        return False
    if re.fullmatch(r"[a-z]+(?:_[a-z0-9]{1,8})+", v) and shannon_entropy(v) < 3.7:
        return False
    return True


def is_likely_vendor_token(full_tok: str, suffix: str) -> bool:
    """Validate `prefix_(live|test|prod|...)_suffix` so snake_case names like `unit_test_coverage_report` are spared."""
    if len(suffix) < 12:
        return False
    # Reject suffixes containing readable lowercase snake_case words like coverage_report or cluster_01
    if re.search(r"[a-z]{3,}_[a-z]{2,}", suffix) or re.fullmatch(r"[a-z_]+", suffix):
        return False
    has_letter = bool(re.search(r"[A-Za-z]", suffix))
    digit_cnt = len(re.findall(r"\d", suffix))
    return has_letter and (digit_cnt >= 3 or shannon_entropy(suffix) >= 3.8)


def is_unknown_credential_token(tok: str) -> bool:
    """Detect high-entropy unknown-format secret tokens while sparing PascalCase/camelCase technical names."""
    if len(tok) < 18 or "_" in tok:
        # Snake_case is checked by VENDOR_PREFIX or LABELED_SECRET; standalone snake_case identifiers are code names
        if "_" in tok and re.search(r"[A-Za-z]{3,}_[A-Za-z]{3,}", tok):
            return False
    if len(tok) < 18:
        return False
    if re.fullmatch(r"[0-9a-fA-F_-]+", tok):
        return False
    has_upper = bool(re.search(r"[A-Z]", tok))
    has_lower = bool(re.search(r"[a-z]", tok))
    digits = len(re.findall(r"\d", tok))
    if not (has_upper and has_lower and digits >= 3):
        return False

    # Measure coverage by natural CamelCase / English vowel-bearing words ([A-Z]?[a-z]{3,})
    natural_words = [
        m.group(0)
        for m in re.finditer(r"[A-Z][a-z]{2,}|[a-z]{3,}", tok)
        if re.search(r"[aeiouy]", m.group(0), re.I)
    ]
    alpha_total = len(re.findall(r"[A-Za-z]", tok))
    natural_alpha = sum(len(w) for w in natural_words)
    if alpha_total > 0 and (natural_alpha / alpha_total) >= 0.55:
        return False

    # Count scattered digit runs (random tokens scatter digits across >= 4 separate runs; model names group 2026 / 230K / 50)
    digit_runs = len(re.findall(r"\d+", tok))
    ent = shannon_entropy(tok)
    transitions = sum(
        1
        for i in range(1, len(tok))
        if (tok[i].isdigit() != tok[i - 1].isdigit()) or (tok[i].isupper() != tok[i - 1].isupper())
    )
    return ent >= 4.0 and digit_runs >= 3 and transitions >= 7


def mask_cross_platform_paths(text: str) -> str:
    """Mask personal usernames, volume labels, temp user dirs, dotfile secrets, and UNC shares across OSes."""
    out = text
    out = re.sub(
        r"(file:///(?:[A-Za-z]:/)?(?:Users|home|Documents(?:%20| )and(?:%20| )Settings)/)[^/\s)\]>\[`\"'，。；：！？、]+",
        r"\1<USER>",
        out,
    )
    out = re.sub(
        r"(?<![A-Za-z0-9_])(/(?:Users|home)/)[A-Za-z0-9._-]+(?=[/\s,.;:!?，。；：！？、（）)\]>\[`\"']|$)",
        r"\1<USER>",
        out,
    )
    out = re.sub(
        rf"((?:/run)?/media/)[A-Za-z0-9._-]+/{WIN_SEG_WITH_SPACES}",
        r"\1<USER>/<VOLUME>",
        out,
    )
    out = re.sub(
        rf"(/Volumes/){WIN_SEG_WITH_SPACES}",
        r"\1<VOLUME>",
        out,
    )
    out = re.sub(r"(/mnt/)[A-Za-z0-9._-]+", r"\1<MOUNT>", out)
    out = re.sub(
        r"((?:/private)?/var/folders/)[^\s)\]>\[`\"'，。；：！？、]+",
        r"\1<REDACTED_TEMP_PATH>",
        out,
    )
    out = re.sub(
        r"(~/(?:\.ssh|\.aws|\.config)/)[^\s)\]>\[`\"'，。；：！？、]+",
        r"\1<REDACTED_FILE>",
        out,
    )
    out = re.sub(
        rf"(\b[A-Za-z]:\\(?:Users|Documents and Settings)\\){WIN_SEG_WITH_SPACES}(?=\\|[\s,.;:!?，。；：！？、（）)\]>\[`\"']|$)",
        r"\1<USER>",
        out,
    )
    out = re.sub(r"(\\\\)[A-Za-z0-9._-]+\\[A-Za-z0-9$._-]+", r"\1<HOST>\\<SHARE>", out)
    return out


def detect_secrets_in_text(text: str) -> List[Tuple[int, List[str], str]]:
    """Scan full text (including multi-line PEM blocks and zero-width-obfuscated secrets).

    Returns list of (line_number, matched_labels, raw_line_or_block).
    """
    zw_clean_full = ZERO_WIDTH_RE.sub("", text)
    findings: Dict[int, List[str]] = {}
    lines = text.splitlines()

    # 1. Multi-line PEM block scan
    for m_pem in PEM_BLOCK_RE.finditer(zw_clean_full):
        line_no = zw_clean_full[: m_pem.start()].count("\n") + 1
        findings.setdefault(line_no, []).append("PRIVATE_KEY")

    # 2. Per-line zero-width-normalized scan
    for idx, raw_line in enumerate(lines, start=1):
        norm_l = ZERO_WIDTH_RE.sub("", raw_line)
        labels: List[str] = []

        for label, pat in EXPLICIT_SECRET_PATTERNS:
            if label == "AUTH_HEADER":
                for m_ah in pat.finditer(norm_l):
                    if is_likely_labeled_secret_value(m_ah.group(1), m_ah.group(2)):
                        labels.append(label)
            elif pat.search(norm_l):
                labels.append(label)

        for m_ls in LABELED_SECRET_RE.finditer(norm_l):
            if is_likely_labeled_secret_value(m_ls.group(1), m_ls.group(4)):
                labels.append("LABELED_SECRET")

        # Shield DOIs/benign IDs first, check VENDOR_PREFIX (including inside URLs), then shield benign URLs before UNKNOWN_CREDENTIAL_TOKEN
        shielded = BENIGN_IDENTIFIER_RE.sub(lambda m: " " * len(m.group(0)), norm_l)
        for m_vp in VENDOR_PREFIX_CANDIDATE_RE.finditer(shielded):
            if is_likely_vendor_token(m_vp.group(1), m_vp.group(2)):
                labels.append("VENDOR_PREFIX_TOKEN")
        shielded = URL_SPAN_RE.sub(lambda m: " " * len(m.group(0)), shielded)

        for m_tok in CANDIDATE_TOKEN_RE.finditer(shielded):
            if is_unknown_credential_token(m_tok.group(1)):
                labels.append("UNKNOWN_CREDENTIAL_TOKEN")

        if labels:
            findings.setdefault(idx, []).extend(labels)

    result: List[Tuple[int, List[str], str]] = []
    for ln in sorted(findings.keys()):
        raw_l = lines[ln - 1] if 1 <= ln <= len(lines) else ""
        result.append((ln, sorted(set(findings[ln])), raw_l))
    return result


def redact_sensitive_text(text: str, mask_paths: bool = True) -> str:
    """Unified redaction engine: explicit & labeled secrets FIRST -> shield benign IDs/URLs -> unknown tokens -> paths."""
    # Step 0: Normalize zero-width obfuscation if any secret indicator is present on normalized text, and redact multi-line PEM
    working = PEM_BLOCK_RE.sub("[REDACTED:PRIVATE_KEY]", ZERO_WIDTH_RE.sub("", text) if detect_secrets_in_text(text) else text)

    # Step 1 (CRITICAL P0-01 FIX): Redact explicit & context-labeled secrets FIRST (before stashing hex/UUID/URLs!)
    for label, pat in EXPLICIT_SECRET_PATTERNS:
        if label == "URL_QUERY_SECRET":
            working = pat.sub(r"\1[REDACTED:URL_QUERY_SECRET]", working)
        elif label == "AUTH_HEADER":
            working = pat.sub(
                lambda m: f"{m.group(1)} [REDACTED:AUTH_HEADER]"
                if is_likely_labeled_secret_value(m.group(1), m.group(2))
                else m.group(0),
                working,
            )
        else:
            working = pat.sub(f"[REDACTED:{label}]", working)

    def _redact_labeled(m: re.Match[str]) -> str:
        lbl, sep, quote, val = m.groups()
        if is_likely_labeled_secret_value(lbl, val):
            return f"{lbl}{sep}{quote}[REDACTED:LABELED_SECRET]{quote}"
        return m.group(0)

    working = LABELED_SECRET_RE.sub(_redact_labeled, working)

    # Step 2: Now stash benign DOIs, SHAs, UUIDs, ORCIDs, clinical/genomic IDs, and already-cleaned URLs
    placeholders: List[str] = []

    def _stash(val: str) -> str:
        idx = len(placeholders)
        placeholders.append(val)
        return f"\x00BENIGN{idx}\x00"

    working = BENIGN_IDENTIFIER_RE.sub(lambda m: _stash(m.group(0)), working)
    working = VENDOR_PREFIX_CANDIDATE_RE.sub(
        lambda m: "[REDACTED:VENDOR_PREFIX_TOKEN]" if is_likely_vendor_token(m.group(1), m.group(2)) else m.group(0),
        working,
    )
    working = URL_SPAN_RE.sub(lambda m: _stash(m.group(0)), working)

    # Step 3: Redact unknown high-entropy tokens
    working = CANDIDATE_TOKEN_RE.sub(
        lambda m: "[REDACTED:UNKNOWN_TOKEN]" if is_unknown_credential_token(m.group(1)) else m.group(0),
        working,
    )

    # Step 4: Mask cross-platform paths when enabled
    if mask_paths:
        working = mask_cross_platform_paths(working)

    # Step 5: Restore protected benign scientific/hash/DOI/URL tokens
    for idx, val in enumerate(placeholders):
        working = working.replace(f"\x00BENIGN{idx}\x00", val)
    return working


def redact_secrets(line: str) -> str:
    return redact_sensitive_text(line, mask_paths=True)[:90]


def sanitize_log_text(text: str, mask_user_paths: bool = True) -> str:
    return redact_sensitive_text(text, mask_paths=mask_user_paths)


def prepare_line_for_q4_scan(line: str) -> str:
    """Strip inline code/HTML while unwrapping inline LaTeX math ($p < 0.001$ -> p < 0.001) so math stats hit Q4!"""
    no_code_html = NON_MATH_PROTECTED_INLINE_RE.sub(lambda m: " " * len(m.group(0)), line)

    def _unwrap_math(m: re.Match[str]) -> str:
        raw = m.group(0)
        if raw.startswith("$$") and raw.endswith("$$"):
            inner = raw[2:-2]
        elif (raw.startswith(r"\[") and raw.endswith(r"\]")) or (raw.startswith(r"\(") and raw.endswith(r"\)")):
            inner = raw[2:-2]
        elif raw.startswith("$") and raw.endswith("$"):
            inner = raw[1:-1]
        else:
            inner = raw
        inner = inner.replace(r"\pm", "±").replace(r"\%", "%").replace(r"\le", "≤").replace(r"\ge", "≥")
        return f" {inner} "

    return INLINE_MATH_UNWRAP_RE.sub(_unwrap_math, no_code_html)


def analyze_q4_spans(sentence: str, line_no: int) -> Tuple[List[Q4SpanRecord], str]:
    """Extract local Q4_PROTECTED and Q4_CANDIDATE spans without letting ordinary words shadow them."""
    work = Q4_LOCAL_FALSE_FRIEND_RE.sub(lambda m: " " * len(m.group(0)), sentence)
    records: List[Q4SpanRecord] = []
    occupied: List[Tuple[int, int]] = []

    def _overlaps(s: int, e: int) -> bool:
        return any(not (e <= os_ or s >= oe_) for os_, oe_ in occupied)

    for reason, pat in Q4_PROTECTED_SPAN_PATTERNS:
        for m in pat.finditer(work):
            if not _overlaps(m.start(), m.end()):
                occupied.append((m.start(), m.end()))
                records.append(
                    Q4SpanRecord(
                        line=line_no,
                        state="Q4_PROTECTED",
                        reason=reason,
                        matched_span=m.group(0).strip(),
                        clause_preview=sentence[:110],
                        auto_delete_authorized=False,
                    )
                )

    for reason, pat in Q4_CANDIDATE_SPAN_PATTERNS:
        for m in pat.finditer(work):
            if not _overlaps(m.start(), m.end()):
                occupied.append((m.start(), m.end()))
                records.append(
                    Q4SpanRecord(
                        line=line_no,
                        state="Q4_CANDIDATE",
                        reason=reason,
                        matched_span=m.group(0).strip(),
                        clause_preview=sentence[:110],
                        auto_delete_authorized=False,
                    )
                )

    chars = list(sentence)
    for s, e in occupied:
        for pos in range(s, min(e, len(chars))):
            chars[pos] = " "
    return records, "".join(chars)


def classify_q4_clause(clause: str) -> Tuple[str, str]:
    prepared = prepare_line_for_q4_scan(clause)
    recs, _ = analyze_q4_spans(prepared, line_no=0)
    for r in recs:
        if r.state == "Q4_PROTECTED":
            return "Q4_PROTECTED", r.reason
    for r in recs:
        if r.state == "Q4_CANDIDATE":
            return "Q4_CANDIDATE", r.reason
    return "Q4_NOT_QUALIFICATION", "no_explicit_q4_span_detected"


def mask_protected_inline(line: str) -> str:
    # Shield standalone currency tokens first so dual-$ currency amounts never form an inline math pair
    currency_spans: List[Tuple[int, int, str]] = [
        (m.start(), m.end(), m.group(0)) for m in re.finditer(CURRENCY_AMOUNT_PATTERN, line)
    ]
    chars = list(line)
    for s, e, _ in currency_spans:
        if chars[s] == "$":
            chars[s] = "C"  # Neutralize currency '$' during inline math scan
    neutralized = "".join(chars)
    masked = PROTECTED_INLINE_RE.sub(lambda m: " " * len(m.group(0)), neutralized)
    out_chars = list(masked)
    for s, e, orig in currency_spans:
        if out_chars[s] != " ":
            out_chars[s] = "$"
    return "".join(out_chars)


def split_preserving_protected_inline(line: str) -> List[Tuple[bool, str]]:
    """Split line into (is_protected, substring) while keeping currency '$2.8M' as unprotected normal text."""
    currency_positions = {m.start() for m in re.finditer(CURRENCY_AMOUNT_PATTERN, line)}
    chars = list(line)
    for pos in currency_positions:
        chars[pos] = "C"
    probe = "".join(chars)

    result: List[Tuple[bool, str]] = []
    last = 0
    for m in PROTECTED_INLINE_RE.finditer(probe):
        if m.start() > last:
            result.append((False, line[last : m.start()]))
        result.append((True, line[m.start() : m.end()]))
        last = m.end()
    if last < len(line):
        result.append((False, line[last:]))
    return result


def transform_outside_protected_inline(line: str) -> Tuple[str, List[str], int]:
    """Clean FMT-04 residue FIRST, then fix FMT-03 adjacent citations SECOND so [1][cite_start][2] converges in 1 pass!"""
    m_lead = re.match(r"^([ ]*)(.*)$", line)
    lead_ws, body = m_lead.groups() if m_lead else ("", line)

    # Step 1: Strip FMT-04 copy-paste residue first
    segs1 = split_preserving_protected_inline(body)
    res_labels: List[str] = []
    res_parts: List[str] = []
    for is_prot, seg in segs1:
        if is_prot:
            res_parts.append(seg)
        else:
            cur = seg
            for label, pat in RESIDUE_PATTERNS:
                cur, cnt = pat.subn("", cur)
                if cnt > 0:
                    res_labels.append(label)
            if res_labels:
                cur = re.sub(r" +([,.;:!?，。；：！？])", r"\1", re.sub(r"[ ]{2,}", " ", cur))
            res_parts.append(cur)
    after_res = lead_ws + "".join(res_parts)

    # Step 2: Fix FMT-03 adjacent citations on the residue-cleaned text (loop until convergent for chains like [1][2][3])
    sep = "、" if re.search(r"[\u4e00-\u9fff]", after_res) else ", "
    cit_total = 0
    cur_line = after_res
    for _ in range(4):
        segs2 = split_preserving_protected_inline(cur_line)
        pass_cnt = 0
        cit_parts: List[str] = []
        for is_prot, seg in segs2:
            if is_prot:
                cit_parts.append(seg)
            else:
                new_s, cnt = ADJ_CIT_RE.subn(rf"\1{sep}", seg)
                pass_cnt += cnt
                cit_parts.append(new_s)
        cur_line = "".join(cit_parts)
        cit_total += pass_cnt
        if pass_cnt == 0:
            break

    return cur_line, res_labels, cit_total


def normalize_spaces_outside_inline(line: str) -> str:
    segs = split_preserving_protected_inline(line)
    rebuilt: List[str] = []
    for is_prot, seg in segs:
        if is_prot:
            rebuilt.append(seg)
        else:
            s = ZERO_WIDTH_RE.sub("", seg)
            for ch in ("\u00a0", "\u2002", "\u2003", "\u2009"):
                s = s.replace(ch, " ")
            rebuilt.append(s)
    joined = "".join(rebuilt)
    if re.match(r"^[\u3000 ]*\u3000[\u3000 ]*(?:[-*+]|\d+[.)])\s", joined):
        joined = re.sub(r"^[\u3000 ]+", lambda m: " " * len(m.group(0)), joined)
    return joined


def has_valid_yaml_frontmatter(lines: List[str]) -> bool:
    """Pre-scan lines 1..80 so a standalone '---' horizontal rule on line 1 NEVER swallows the whole document."""
    if not lines or lines[0].strip() != "---":
        return False
    saw_yaml_kv = False
    for idx in range(1, min(len(lines), 80)):
        s = lines[idx].strip()
        if s in ("---", "..."):
            return saw_yaml_kv or idx == 1
        if re.match(r"^#{1,6}\s+", s):
            return False
        if re.match(r"^[A-Za-z0-9_.-]+\s*:", s) or s.startswith("#") or s.startswith("- "):
            saw_yaml_kv = True
    return False


def is_closing_fence(line: str, fence_ch: str, fence_len: int) -> bool:
    return bool(re.match(rf"^[ \t]*{re.escape(fence_ch)}{{{fence_len},}}[ \t]*$", line))


def update_html_block_depth(line: str, tag: str, current_depth: int) -> int:
    """Mask inline code spans & HTML comments BEFORE counting HTML block open/close tags."""
    cleaned = re.sub(r"(?P<bt>`+)(?!`)(?:.+?)(?<!`)(?P=bt)(?!`)|<!--[\s\S]*?-->", "", line)
    open_pat = re.compile(rf"<{tag}\b(?:(?:\"[^\"]*\"|'[^']*'|[^'\">])*)(?<!/)>", re.IGNORECASE)
    close_pat = re.compile(rf"</{tag}\s*>", re.IGNORECASE)
    return current_depth + len(open_pat.findall(cleaned)) - len(close_pat.findall(cleaned))


def slugify_heading(text: str) -> str:
    return re.sub(r"\s+", "-", re.sub(r"[^\w\u4e00-\u9fff -]", "", text.strip().lower()))


def normalize_anchor_target(raw_slug: str) -> str:
    decoded = urllib.parse.unquote(raw_slug).strip().lower()
    return slugify_heading(decoded) if re.search(r"[\u4e00-\u9fff\s]", decoded) else decoded


def collect_defined_anchors(lines: List[str]) -> set[str]:
    anchors: set[str] = set()
    slug_counts: Dict[str, int] = {}
    in_fm = has_valid_yaml_frontmatter(lines)
    in_fence, fence_ch, fence_len = False, "", 0
    in_comment = False
    for idx, line in enumerate(lines, start=1):
        if in_fm:
            if idx > 1 and line.strip() in ("---", "..."):
                in_fm = False
            continue
        if in_comment:
            if "-->" in line:
                in_comment = False
            continue
        if line.lstrip().startswith("<!--"):
            if "-->" not in line:
                in_comment = True
            continue
        if not in_fence:
            m_f = FENCE_OPEN_RE.match(line)
            if m_f and len(m_f.group(1)) <= 12 and not (m_f.group(2)[0] == "`" and "`" in m_f.group(3)):
                in_fence, fence_ch, fence_len = True, m_f.group(2)[0], len(m_f.group(2))
                continue
        else:
            if is_closing_fence(line, fence_ch, fence_len):
                in_fence = False
            continue
        for m_h_id in HTML_ANCHOR_RE.finditer(line):
            anchors.add(m_h_id.group(1).lower())
        m_h = HEADING_RE.match(line)
        if m_h:
            base_slug = slugify_heading(m_h.group(2))
            cnt = slug_counts.get(base_slug, 0)
            anchors.add(base_slug if cnt == 0 else f"{base_slug}-{cnt}")
            slug_counts[base_slug] = cnt + 1
    return anchors


def detect_track(lines: List[str], requested: str) -> str:
    if requested in ("analytical", "narrative"):
        return requested
    has_table = bool(re.search(r"^\|.+\|\s*$\n^\|[\s:|-]+\|\s*$", "\n".join(lines[:60]), re.MULTILINE))
    has_bold = len(re.findall(r"^\s*[-*+]\s+\*\*[^*]+\*\*", "\n".join(lines), re.MULTILINE)) >= 3
    return "analytical" if (has_table or has_bold) else "narrative"


def lint_text(
    text: str,
    fix: bool = False,
    track: str = "auto",
    max_disclaimer_rate: float = 0.08,
    disallow_anchors: bool = False,
    mask_user_paths_in_log: bool = True,
) -> Tuple[str, List[Issue], List[FixRecord], List[Q4SpanRecord], dict]:
    issues: List[Issue] = []
    fixes: List[FixRecord] = []
    q4_records: List[Q4SpanRecord] = []
    lines = text.splitlines(keepends=False)

    # 1. Zero-width-normalized & multi-line-aware security gate
    secret_hits = detect_secrets_in_text(text)
    if secret_hits:
        for ln, labels, raw_l in secret_hits:
            issues.append(
                Issue(
                    code="SEC-01",
                    category="security",
                    severity="blocked",
                    line=ln,
                    message=f"Unredacted credential pattern ({', '.join(labels)}). Redact before processing.",
                    snippet=redact_secrets(raw_l),
                )
            )
        return text, issues, fixes, q4_records, {
            "status": "blocked_security",
            "pipeline_stage": "Drafted",
            "formatting_error_count": 0,
            "semantic_warning_count": 0,
            "passed": False,
            "gate_passed": False,
        }

    resolved_track = detect_track(lines, track)

    in_fm = has_valid_yaml_frontmatter(lines)
    in_fence, fence_ch, fence_len = False, "", 0
    in_indented_code = False
    prev_blank_for_code = True
    in_math_block, math_env = False, ""
    in_html_comment = False
    html_block_tag: Optional[str] = None
    html_block_depth = 0
    prev_line_blank = True
    table_started, table_ended = False, False

    # Stack of (raw_indent, fixed_indent, required_child_indent)
    list_stack: List[Tuple[int, int, int]] = []
    deferred_anchor_checks: List[Tuple[int, str]] = []

    total_sents, echo_sents, q4_prot_cnt, q4_cand_cnt, no_q4_sents, consec_echo, max_consec = 0, 0, 0, 0, 0, 0, 0
    cjk_chars, en_words, h2_count = 0, 0, 0
    out_lines: List[str] = []
    sev_fix = "auto_fixed" if fix else "error"

    for idx, raw_line in enumerate(lines, start=1):
        line = raw_line

        # Protected Region 1: Pre-validated YAML Frontmatter
        if in_fm:
            out_lines.append(line)
            if idx > 1 and line.strip() in ("---", "..."):
                in_fm = False
                prev_blank_for_code = True
                prev_line_blank = True
            continue

        # Protected Region 2: Variable-length Fenced Code Blocks (supports top-level & list-nested indents!)
        max_fence_indent = (list_stack[-1][2] + 4) if list_stack else 3
        if not in_fence:
            m_f = FENCE_OPEN_RE.match(line)
            if m_f and len(m_f.group(1)) <= max_fence_indent and not (m_f.group(2)[0] == "`" and "`" in m_f.group(3)):
                in_fence, fence_ch, fence_len = True, m_f.group(2)[0], len(m_f.group(2))
                in_indented_code = False
                out_lines.append(line)
                prev_line_blank = False
                continue
        else:
            out_lines.append(line)
            if is_closing_fence(line, fence_ch, fence_len):
                in_fence = False
            prev_line_blank = False
            continue

        # Protected Region 2b: Indented Code Blocks (4-space/tab after blank line, or list_child_indent+4 inside tight list)
        lead_sp = len(line) - len(line.lstrip(" "))
        is_indented_code_line = (
            line.startswith("\t")
            or (prev_blank_for_code and lead_sp >= 4)
            or (in_indented_code and lead_sp >= 4)
            or (bool(list_stack) and lead_sp >= list_stack[-1][2] + 4)
        )
        if in_indented_code:
            if (lead_sp >= 4 or line.startswith("\t") or line.strip() == "") and not LIST_ITEM_RE.match(line):
                out_lines.append(line)
                prev_line_blank = line.strip() == ""
                continue
            in_indented_code = False
        elif is_indented_code_line and not LIST_ITEM_RE.match(line) and not line.lstrip().startswith((">", "<")):
            in_indented_code = True
            out_lines.append(line)
            prev_line_blank = False
            continue

        # Protected Region 3: Multi-line / Standalone LaTeX Math Blocks
        if not in_math_block:
            m_mb = MATH_BLOCK_OPEN_RE.match(line)
            if m_mb:
                delim, env_name = m_mb.group(1), m_mb.group(2) or ""
                stripped_m = line.strip()
                is_single_line = (
                    (delim == "$$" and stripped_m.endswith("$$") and len(stripped_m) > 4)
                    or (delim == r"\[" and stripped_m.endswith(r"\]") and len(stripped_m) > 4)
                    or (env_name and f"\\end{{{env_name}}}" in stripped_m)
                )
                if not is_single_line:
                    in_math_block, math_env = True, env_name
                out_lines.append(line)
                prev_line_blank = False
                continue
        else:
            out_lines.append(line)
            if math_env:
                if f"\\end{{{math_env}}}" in line:
                    in_math_block, math_env = False, ""
            elif re.search(r"(\$\$|\\\])\s*$", line):
                in_math_block = False
            prev_line_blank = False
            continue

        # Protected Region 4: Multi-line HTML Comments & Paired HTML Blocks (with inline-backtick shield & blank-line circuit breaker)
        if in_html_comment:
            out_lines.append(line)
            if "-->" in line:
                in_html_comment = False
            prev_line_blank = False
            continue
        if line.lstrip().startswith("<!--"):
            if "-->" not in line:
                in_html_comment = True
            out_lines.append(line)
            prev_line_blank = False
            continue
        if re.match(r"^[ ]{0,3}<(?:![A-Za-z]|[\?])", line):
            out_lines.append(line)
            prev_line_blank = False
            continue

        if html_block_tag is not None:
            # CommonMark §4.6 safety breaker: non-raw unclosed HTML block terminates if blank line precedes a Markdown heading
            if html_block_tag not in HTML_RAW_TAGS and prev_line_blank and HEADING_RE.match(line):
                html_block_tag, html_block_depth = None, 0
            else:
                html_block_depth = update_html_block_depth(line, html_block_tag, html_block_depth)
                out_lines.append(line)
                prev_line_blank = line.strip() == ""
                if html_block_depth <= 0:
                    html_block_tag, html_block_depth = None, 0
                continue

        m_hb = HTML_BLOCK_OPEN_RE.match(line)
        if m_hb:
            tag = m_hb.group(1).lower()
            depth = update_html_block_depth(line, tag, 0)
            if depth > 0:
                html_block_tag, html_block_depth = tag, depth
            out_lines.append(line)
            prev_line_blank = False
            continue

        # Protected Region 5: Verbatim Blockquotes (top-level or nested inside lists!)
        max_bq_indent = (list_stack[-1][2] + 4) if list_stack else 3
        if re.match(rf"^[ ]{{0,{max_bq_indent}}}>", line):
            out_lines.append(line)
            prev_line_blank = False
            prev_blank_for_code = False
            continue

        if line.strip() == "":
            out_lines.append(line)
            prev_line_blank = True
            prev_blank_for_code = True
            if table_started and not table_ended:
                table_ended = True
            continue

        prev_line_blank = False
        prev_blank_for_code = False

        is_heading = bool(HEADING_RE.match(line))
        if re.match(r"^##\s+", line):
            h2_count += 1

        line_fix_codes: List[str] = []
        non_inline = mask_protected_inline(line)

        # Count body prose words/chars (excluding headings and unwrapping [text](url) -> text)
        if not is_heading and not re.match(r"^\|[\s:|-]+\|$", non_inline.strip()):
            prose_for_count = MD_LINK_UNWRAP_RE.sub(r"\1", non_inline)
            prose_for_count = URL_SPAN_RE.sub(" ", prose_for_count)
            cjk_chars += len(CJK_CHAR_RE.findall(prose_for_count))
            en_words += len(EN_WORD_RE.findall(prose_for_count))

        # FMT-01: Abnormal Unicode whitespace
        found_uni = [nm for ch, nm in ZERO_WIDTH.items() if ch in non_inline]
        found_uni += [nm for ch, nm in SPACE_LIKE.items() if ch != "\u3000" and ch in non_inline]
        if re.match(r"^[\u3000 ]*\u3000[\u3000 ]*(?:[-*+]|\d+[.)])\s", non_inline):
            found_uni.append(SPACE_LIKE["\u3000"])
        norm_line = normalize_spaces_outside_inline(line)
        if found_uni:
            issues.append(
                Issue(
                    "FMT-01",
                    "formatting",
                    sev_fix,
                    idx,
                    f"Abnormal Unicode whitespace: {', '.join(sorted(set(found_uni)))}.",
                    sanitize_log_text(raw_line, mask_user_paths_in_log)[:80],
                )
            )
            if fix and norm_line != line:
                line = norm_line
                line_fix_codes.append("FMT-01")

        # FMT-02: CommonMark W+N nested list indentation (properly handles consecutive under-indented siblings!)
        probe = line if fix else norm_line
        m_list = LIST_ITEM_RE.match(probe)
        if m_list:
            ind_s, marker, post_s, rest = m_list.groups()
            raw_ind, m_width = len(ind_s), len(marker) + len(post_s)

            # Check if this item is an under-indented sibling of the current top of stack
            if list_stack and raw_ind == list_stack[-1][0] and list_stack[-1][0] != list_stack[-1][1]:
                target_ind = list_stack[-1][1]
                issues.append(Issue("FMT-02", "formatting", sev_fix, idx, f"Nested list indent {raw_ind} < required {target_ind}.", sanitize_log_text(probe, mask_user_paths_in_log)[:80]))
                if fix:
                    line = (" " * target_ind) + f"{marker}{post_s}{rest}"
                    line_fix_codes.append("FMT-02")
                list_stack[-1] = (raw_ind, target_ind, target_ind + m_width)
            else:
                while list_stack and raw_ind <= list_stack[-1][0]:
                    list_stack.pop()

                if not list_stack:
                    fixed_ind = raw_ind
                    if raw_ind == 1:
                        issues.append(Issue("FMT-02", "formatting", sev_fix, idx, "Ambiguous 1-space top-level list indent.", sanitize_log_text(probe, mask_user_paths_in_log)[:80]))
                        fixed_ind = 0
                        if fix:
                            line = f"{marker}{post_s}{rest}"
                            line_fix_codes.append("FMT-02")
                    list_stack.append((raw_ind, fixed_ind, fixed_ind + m_width))
                else:
                    p_raw, p_fixed, req_ind = list_stack[-1]
                    fixed_ind = raw_ind
                    if p_raw < raw_ind < req_ind:
                        issues.append(Issue("FMT-02", "formatting", sev_fix, idx, f"Nested list indent {raw_ind} < required {req_ind}.", sanitize_log_text(probe, mask_user_paths_in_log)[:80]))
                        fixed_ind = req_ind
                        if fix:
                            line = (" " * req_ind) + f"{marker}{post_s}{rest}"
                            line_fix_codes.append("FMT-02")
                    list_stack.append((raw_ind, fixed_ind, fixed_ind + m_width))
        elif is_heading or lead_sp == 0:
            list_stack.clear()

        # FMT-04 (first) & FMT-03 (second): Convergent single-pass cleanup!
        transformed_line, res_labels, cit_cnt = transform_outside_protected_inline(line)
        if res_labels:
            issues.append(Issue("FMT-04", "formatting", sev_fix, idx, f"Copy-paste residue: {', '.join(sorted(set(res_labels)))}.", sanitize_log_text(line, mask_user_paths_in_log)[:80]))
            if fix:
                line_fix_codes.append("FMT-04")
        if cit_cnt > 0:
            issues.append(Issue("FMT-03", "formatting", sev_fix, idx, f"Adjacent citation brackets ({cit_cnt}x).", sanitize_log_text(line, mask_user_paths_in_log)[:80]))
            if fix:
                line_fix_codes.append("FMT-03")
        if fix and (res_labels or cit_cnt > 0):
            line = transformed_line

        if fix and line != raw_line:
            fixes.append(
                FixRecord(
                    line=idx,
                    codes=line_fix_codes,
                    before=sanitize_log_text(raw_line, mask_user_paths_in_log),
                    after=sanitize_log_text(line, mask_user_paths_in_log),
                )
            )

        masked = mask_protected_inline(line)
        deferred_anchor_checks.append((idx, masked))

        # SEM-04 & SEM-05: Non-destructive path warnings (deduplicated & non-overlapping)
        priv_spans: List[Tuple[int, int]] = []
        for m_priv in PRIVACY_PATH_RE.finditer(masked):
            priv_spans.append((m_priv.start(), m_priv.end()))
            shown = sanitize_log_text(m_priv.group(0), mask_user_paths_in_log)
            issues.append(
                Issue(
                    "SEM-04",
                    "semantic_warning",
                    "warning",
                    idx,
                    f"Privacy-sensitive personal/mounted path detected ('{shown}'); replace personal dead links with plain page notes, or anonymize if unneeded.",
                    shown[:80],
                )
            )
        seen_gen_spans: List[Tuple[int, int]] = []
        for m_gen in GENERAL_LOCAL_PATH_RE.finditer(masked):
            gs, ge = m_gen.start(), m_gen.end()
            if any(not (ge <= ps or gs >= pe) for ps, pe in priv_spans):
                continue
            if any(not (ge <= s0 or gs >= e0) for s0, e0 in seen_gen_spans):
                continue
            seen_gen_spans.append((gs, ge))
            raw_gen = m_gen.group(0)
            issues.append(
                Issue(
                    "SEM-05",
                    "semantic_warning",
                    "warning",
                    idx,
                    f"General local/system path detected ('{raw_gen}'); keep if needed for engineering/scientific reproducibility, otherwise review.",
                    sanitize_log_text(raw_gen, mask_user_paths_in_log)[:80],
                )
            )

        # SEM-01: Scoped strictly to top summary tables (within first 45 lines & before 2nd H2 section!)
        stripped = masked.strip()
        if stripped.startswith("|") and stripped.endswith("|") and idx <= 45 and h2_count <= 1:
            if not table_ended:
                table_started = True
                if resolved_track == "analytical" and not re.match(r"^\|[\s:|-]+\|$", stripped):
                    m_x = TABLE_XREF_RE.search(stripped)
                    if m_x:
                        issues.append(Issue("SEM-01", "semantic_warning", "warning", idx, f"Summary table pointer '{m_x.group(0)}'; consider placing key facts directly in the cell.", sanitize_log_text(line, mask_user_paths_in_log)[:85]))
        elif table_started and not table_ended:
            table_ended = True

        # SEM-03: Workflow / crawler residue
        m_leak = WORKFLOW_LEAK_RE.search(masked)
        if m_leak:
            issues.append(Issue("SEM-03", "semantic_warning", "warning", idx, f"Possible workflow/crawler residue ('{m_leak.group(0)}'); verify if intended for readers.", sanitize_log_text(line, mask_user_paths_in_log)[:85]))

        # Local-span Q4 extraction (using math-unwrapped text!) + English/Chinese sentence splitting
        if stripped and not is_heading and not re.match(r"^\|[\s:|-]+\|$", stripped):
            q4_ready_line = prepare_line_for_q4_scan(line)
            sentences = [s.strip() for s in SENTENCE_SPLIT_RE.split(q4_ready_line) if len(s.strip()) >= 6]
            block_echo = False
            for sent in sentences:
                total_sents += 1
                span_recs, residual_sent = analyze_q4_spans(sent, idx)
                if span_recs:
                    q4_records.extend(span_recs)
                    q4_prot_cnt += sum(1 for r in span_recs if r.state == "Q4_PROTECTED")
                    q4_cand_cnt += sum(1 for r in span_recs if r.state == "Q4_CANDIDATE")
                else:
                    no_q4_sents += 1
                if residual_sent.strip() and any(p.search(residual_sent) for p in DISCLAIMER_ECHO_PATTERNS):
                    echo_sents += 1
                    block_echo = True
            if sentences:
                consec_echo = (consec_echo + 1) if block_echo else 0
                max_consec = max(max_consec, consec_echo)

        out_lines.append(line)

    # Evaluate FMT-06 against defined_anchors collected from the FINAL out_lines (prevents Pass-1 vs Pass-2 anchor drift!)
    defined_anchors = collect_defined_anchors(out_lines)
    for anc_line_no, masked_l in deferred_anchor_checks:
        for m_anc in ANCHOR_LINK_RE.finditer(masked_l):
            raw_slug = m_anc.group(2)
            norm_slug = normalize_anchor_target(raw_slug)
            if disallow_anchors or norm_slug not in defined_anchors:
                issues.append(Issue("FMT-06", "formatting", "error", anc_line_no, f"Dangling or unsupported anchor '#{raw_slug}'.", m_anc.group(0)))

    issues.sort(key=lambda x: (x.line == 0, x.line, x.code))

    echo_rate = (echo_sents / total_sents) if total_sents > 0 else 0.0
    if echo_sents > 0 and (echo_rate > max_disclaimer_rate or max_consec >= 2):
        issues.append(
            Issue(
                "SEM-02",
                "semantic_warning",
                "warning",
                0,
                f"Heuristic disclaimer-echo notice: {echo_sents}/{total_sents} sentences ({echo_rate:.1%}, ref {max_disclaimer_rate:.1%}), "
                f"consecutive={max_consec} (Q4_PROTECTED spans={q4_prot_cnt}, Q4_CANDIDATE spans={q4_cand_cnt} preserved).",
                f"echo_rate={echo_rate:.3f}",
            )
        )

    updated = "\n".join(out_lines) + ("\n" if text.endswith("\n") else "")
    hard_errors = [i for i in issues if i.severity in ("error", "blocked")]
    sem_warnings = [i for i in issues if i.category == "semantic_warning"]
    long_doc_triggered = (cjk_chars >= 3000) or (en_words >= 1800) or (h2_count >= 4)

    metrics: Dict[str, object] = {
        "status": "ok" if not hard_errors else "formatting_error",
        "pipeline_stage": "Preflight Passed" if not hard_errors else "Drafted",
        "track_hint": resolved_track,
        "cjk_chars": cjk_chars,
        "en_words": en_words,
        "h2_sections": h2_count,
        "long_doc_agent_protocol_recommended": long_doc_triggered,
        "long_doc_mode_recommended": long_doc_triggered,
        "total_clauses": total_sents,
        "mechanical_echo_clauses": echo_sents,
        "q4_protected_count": q4_prot_cnt,
        "q4_candidate_count": q4_cand_cnt,
        "q4_not_qualification_count": no_q4_sents,
        "q4_policy_note": "Q4_NOT_QUALIFICATION means no explicit Q4 span was matched; it does NOT grant semantic deletion permission. Preserve uncertain content.",
        "mechanical_echo_rate": round(echo_rate, 4),
        "max_consecutive_echo_blocks": max_consec,
        "auto_fixed_lines": len(fixes),
        "formatting_error_count": len(hard_errors),
        "semantic_warning_count": len(sem_warnings),
        "passed": len(hard_errors) == 0,
        "gate_passed": len(hard_errors) == 0,
    }
    return updated, issues, fixes, q4_records, metrics


def compute_unified_diff(before: str, after: str, from_label: str, to_label: str, mask_user_paths: bool = True) -> str:
    safe_from = sanitize_log_text(from_label, mask_user_paths=mask_user_paths)
    safe_to = sanitize_log_text(to_label, mask_user_paths=mask_user_paths)
    raw_diff = "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=safe_from,
            tofile=safe_to,
        )
    )
    return sanitize_log_text(raw_diff, mask_user_paths=mask_user_paths)


def paths_refer_to_same_file(p1: Path, p2: Path) -> bool:
    try:
        if p1.exists() and p2.exists() and os.path.samefile(p1, p2):
            return True
    except OSError:
        pass
    try:
        return Path(os.path.realpath(p1)) == Path(os.path.realpath(p2))
    except OSError:
        return os.path.abspath(p1) == os.path.abspath(p2)


def is_writable_existing_file(p: Path) -> bool:
    try:
        st = p.stat()
        if (st.st_mode & 0o222) == 0:
            return False
    except OSError:
        return False
    return os.access(p, os.W_OK)


def validate_output_target(in_path: Path, output_arg: Optional[str], in_place: bool, overwrite: bool) -> Tuple[Optional[Path], Optional[str]]:
    if output_arg and in_place:
        return None, "Error: specify either --output <file> or --in-place, not both."
    if not output_arg and not in_place:
        return None, "Error: --fix refuses to modify files without explicit target. Pass --output <new_file> or --in-place."

    if in_place:
        if overwrite:
            return None, "Error: --overwrite is only for --output <existing_file>; --in-place already authorizes updating --input."
        resolved_in = Path(os.path.realpath(in_path)) if in_path.is_symlink() else in_path
        if not resolved_in.exists():
            return None, f"Error: input symlink '{in_path}' points to non-existent target '{resolved_in}'."
        if not is_writable_existing_file(resolved_in):
            return None, f"Error: input file '{in_path}' is read-only; refusing --in-place overwrite."
        return resolved_in, None

    out_path = Path(output_arg)  # type: ignore[arg-type]
    if out_path.exists() and out_path.is_dir():
        return None, f"Error: output path '{out_path}' is an existing directory, not a file."
    if paths_refer_to_same_file(in_path, out_path):
        return None, "Error: --output refers to the same file as --input (directly or via symlink/hardlink). Use --in-place to authorize modifying the input file."

    if out_path.is_symlink():
        if not overwrite:
            return None, f"Error: output symlink '{out_path}' already exists. Pass --overwrite to authorize writing through it, or choose a new path."
        real_target = Path(os.path.realpath(out_path))
        if paths_refer_to_same_file(in_path, real_target):
            return None, "Error: --output symlink resolves to --input. Refusing to overwrite input without --in-place."
        if real_target.exists() and real_target.is_dir():
            return None, f"Error: output symlink '{out_path}' points to a directory '{real_target}'."
        if not real_target.parent.exists() or not real_target.parent.is_dir():
            return None, f"Error: dangling symlink '{out_path}' points to missing parent directory '{real_target.parent}'; refusing to destroy symlink."
        if real_target.exists() and not is_writable_existing_file(real_target):
            return None, f"Error: symlink target '{real_target}' is read-only; refusing overwrite."
        return real_target, None

    if out_path.exists():
        if not overwrite:
            return None, f"Error: output file '{out_path}' already exists. Pass --overwrite to authorize replacing it, or choose a new path."
        if not is_writable_existing_file(out_path):
            return None, f"Error: output file '{out_path}' is read-only; refusing overwrite."

    return out_path, None


def atomic_write_and_verify(
    write_target: Path,
    read_handle_path: Path,
    expected_text: str,
    original_non_empty: bool,
    track: str,
    max_disclaimer_rate: float,
    disallow_anchors: bool,
) -> Tuple[bool, str, Optional[dict]]:
    """Write to tmp_path, run readback & re-lint BEFORE os.replace, preserve permissions, then atomically replace!"""
    parent = write_target.parent
    if not parent.exists() or not parent.is_dir():
        return False, f"Output directory does not exist: {parent}", None

    existing_mode: Optional[int] = None
    if write_target.exists():
        try:
            existing_mode = stat.S_IMODE(write_target.stat().st_mode)
        except OSError:
            existing_mode = None

    tmp_path: Optional[Path] = None
    try:
        fd, tmp_name = tempfile.mkstemp(prefix=".clear_voice_", suffix=".tmp", dir=str(parent))
        tmp_path = Path(tmp_name)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(expected_text)
            fh.flush()
            os.fsync(fh.fileno())

        # Preserve original file mode (e.g. 0644) or apply current process umask for new files (never force 0600!)
        if existing_mode is not None:
            os.chmod(tmp_path, existing_mode)
        else:
            um = os.umask(0)
            os.umask(um)
            os.chmod(tmp_path, 0o666 & ~um)

        # CRITICAL P0-04 FIX: Read back and re-lint tmp_path BEFORE os.replace touches write_target!
        tmp_read_back = tmp_path.read_text(encoding="utf-8")
        if original_non_empty and len(tmp_read_back.strip()) == 0:
            tmp_path.unlink(missing_ok=True)
            return False, "Pre-replace verification failed: output content is unexpectedly empty.", None
        if tmp_read_back != expected_text:
            tmp_path.unlink(missing_ok=True)
            return False, "Pre-replace verification failed: temp disk bytes do not match expected output.", None

        _, recheck_issues, _, _, recheck_metrics = lint_text(
            tmp_read_back,
            fix=False,
            track=track,
            max_disclaimer_rate=max_disclaimer_rate,
            disallow_anchors=disallow_anchors,
        )
        residual_auto = [i for i in recheck_issues if i.code in ("SEC-01", "FMT-01", "FMT-02", "FMT-03", "FMT-04")]
        if residual_auto:
            tmp_path.unlink(missing_ok=True)
            return False, f"Pre-replace re-lint failed with residual issues: {[i.code for i in residual_auto]}", None

        # Safe to atomically replace now
        os.replace(str(tmp_path), str(write_target))
        tmp_path = None
    except OSError as exc:
        if tmp_path and tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        return False, f"Atomic write failed for '{write_target}': {exc}", None

    # Final post-replace readback check through user's handle (including symlink if applicable)
    try:
        final_back = read_handle_path.read_text(encoding="utf-8")
    except OSError as exc:
        return False, f"Post-write readback failed for '{read_handle_path}': {exc}", None
    if final_back != expected_text:
        return False, "Post-write verification failed: disk content does not match expected output.", None

    return True, "verified", recheck_metrics


def emit_error(as_json: bool, message: str) -> int:
    if as_json:
        payload = {
            "metrics": {
                "status": "error",
                "pipeline_stage": "Drafted",
                "formatting_error_count": 0,
                "semantic_warning_count": 0,
                "passed": False,
                "gate_passed": False,
            },
            "error": message,
            "issues": [],
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(message, file=sys.stderr)
    return 2


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Safe deterministic prose linter for clear-voice (v1.1.3).")
    ap.add_argument("--input", "-i", required=True, help="Input Markdown/text file.")
    ap.add_argument("--output", "-o", help="New output file path when using --fix (refuses existing file unless --overwrite).")
    ap.add_argument("--overwrite", action="store_true", help="Authorize overwriting an existing --output file (never overwrites --input).")
    ap.add_argument("--in-place", action="store_true", help="Authorize updating --input in place with --fix.")
    grp = ap.add_mutually_exclusive_group()
    grp.add_argument("--check", action="store_true", help="Read-only check; certifies at most 'Preflight Passed' (default).")
    grp.add_argument("--fix", action="store_true", help="Apply deterministic fixes, verify disk readback, and certify 'Deterministic Checks Passed'.")
    ap.add_argument("--diff", action="store_true", help="Include sanitized unified diff of auto-fixes.")
    path_grp = ap.add_mutually_exclusive_group()
    path_grp.add_argument("--mask-user-paths-in-log", dest="mask_paths", action="store_true", default=True, help="Mask personal/mounted paths in logs & diffs (default: enabled).")
    path_grp.add_argument("--no-mask-paths-in-log", dest="mask_paths", action="store_false", help="Disable path masking in local debug logs.")
    ap.add_argument("--track", choices=["auto", "analytical", "narrative"], default="auto")
    ap.add_argument("--max-disclaimer-rate", type=float, default=0.08, help="Heuristic warning reference rate (default: 0.08).")
    ap.add_argument("--disallow-anchors", action="store_true")
    ap.add_argument("--fail-on-warning", action="store_true", help="Exit 1 on semantic warnings too (off by default).")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    in_path = Path(args.input)
    if in_path.is_symlink() and not in_path.exists():
        return emit_error(args.json, f"Error: input symlink '{in_path}' is broken.")
    if not in_path.is_file():
        return emit_error(args.json, f"Error: input file not found: {in_path}")

    write_target: Optional[Path] = None
    read_handle: Optional[Path] = None
    if args.fix:
        write_target, err_msg = validate_output_target(in_path, args.output, args.in_place, args.overwrite)
        if err_msg:
            return emit_error(args.json, err_msg)
        read_handle = in_path if args.in_place else Path(args.output)  # type: ignore[arg-type]

    try:
        raw = in_path.read_text(encoding="utf-8")
    except OSError as exc:
        return emit_error(args.json, f"Error: failed to read '{in_path}': {exc}")

    updated, issues, fixes, q4_records, metrics = lint_text(
        raw,
        fix=args.fix,
        track=args.track,
        max_disclaimer_rate=args.max_disclaimer_rate,
        disallow_anchors=args.disallow_anchors,
        mask_user_paths_in_log=args.mask_paths,
    )
    if any(i.category == "security" for i in issues):
        if args.json:
            print(json.dumps({"metrics": metrics, "issues": [asdict(i) for i in issues]}, ensure_ascii=False, indent=2))
        else:
            print(f"[BLOCKED] {issues[0].code} L{issues[0].line}: {issues[0].message} | {issues[0].snippet}")
        return 2

    diff_text = ""
    if args.fix and write_target is not None and read_handle is not None:
        diff_text = compute_unified_diff(raw, updated, str(in_path), str(read_handle), mask_user_paths=args.mask_paths)
        ok, verify_msg, recheck_metrics = atomic_write_and_verify(
            write_target,
            read_handle,
            updated,
            original_non_empty=bool(raw.strip()),
            track=args.track,
            max_disclaimer_rate=args.max_disclaimer_rate,
            disallow_anchors=args.disallow_anchors,
        )
        metrics["post_write_verification"] = verify_msg
        if not ok or recheck_metrics is None:
            return emit_error(args.json, f"Error: {verify_msg}")

        # Synchronize final pass/error counts strictly with post-write recheck!
        recheck_passed = bool(recheck_metrics["passed"])
        metrics["passed"] = recheck_passed
        metrics["formatting_error_count"] = recheck_metrics["formatting_error_count"]
        metrics["status"] = "ok" if recheck_passed else "formatting_error"
        metrics["pipeline_stage"] = "Deterministic Checks Passed" if recheck_passed else "Drafted"

    warn_fail = bool(args.fail_on_warning and int(metrics["semantic_warning_count"]) > 0)  # type: ignore[arg-type]
    exit_fail = (not bool(metrics["passed"])) or warn_fail
    metrics["gate_passed"] = not exit_fail
    if warn_fail and bool(metrics["passed"]):
        metrics["status"] = "warning_failed"

    if args.json:
        payload = {
            "metrics": metrics,
            "issues": [asdict(i) for i in issues],
            "fixes": [asdict(f) for f in fixes],
            "q4_items": [asdict(q) for q in q4_records],
        }
        if args.diff or args.fix:
            payload["diff"] = diff_text
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        status = "FAIL" if exit_fail else "PASS"
        print(
            f"[{status}] stage={metrics['pipeline_stage']} | fmt_errors={metrics['formatting_error_count']} | "
            f"sem_warnings={metrics['semantic_warning_count']} | echo_rate={metrics['mechanical_echo_rate']:.1%} "
            f"(Q4_PROTECTED={metrics['q4_protected_count']}, Q4_CANDIDATE={metrics['q4_candidate_count']})"
        )
        for i in issues:
            loc = f"L{i.line}" if i.line > 0 else "DOC"
            print(f"  - [{i.category.upper()}:{i.severity.upper()}] {i.code} ({loc}): {i.message}")
        if args.diff and diff_text:
            print("\n--- Unified Diff ---")
            print(diff_text, end="")

    return 1 if exit_fail else 0


if __name__ == "__main__":
    sys.exit(main())
