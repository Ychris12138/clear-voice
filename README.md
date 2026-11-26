# clear-voice (v1.1.3): 面向专业报告与叙事文稿的审改与质控 Agent Skill

`clear-voice` 用于提升中英文专业报告（投研尽调、BP 评审、学术审稿、工程复盘）与叙事文稿的清晰度、自然度与易读性，同时严格保全原始材料的事实精度、归属边界与必要专业限定。

核心裁决优先级：**事实准确性 > 证据与归属边界 > 专业结构 > 语言自然度 > 表面去 AI 味**。

## 本地科研版

当前安装入口为 [SKILL.md](SKILL.md)。它融合了 `evidence-led-editing` 的科研写作方法，并默认采用轻量语义复核。以下是原版 v1.1.3 的功能和历史测试说明。已知格式误判、原地写入和日志限制见 [本地使用说明](references/verification-and-roadmap.md)。科研稿使用只读检查。

## 一、核心能力与实现边界

1. **五维事实账本（5-Layer Fact Ledger）与语义修改追踪表（`Semantic Change Trace`）**：改写前锁定确定性事实、主体与归属关系、证据等级、适用条件及未确定事项；改写后按五列标准追踪表（位置 / 修改前原文 / 修改后表述 / 分流类别 / 语义风险确认）核对极性、不确定度、因果强弱与归属变化，严禁推断源材料未提供的事实。
2. **局部语义片段级 Q4 识别与 Q1-Q4 分流**：
   - 支持行内 LaTeX 统计量拆壳识别（如 `$p < 0.001$`、`$n = 64$`、`$\pm 0.04$`）、中英文双语安全分句及有界非贪婪 `Q4` 提取：同句出现普通提示语（“系统提示”、“提示词”）、真实科学/法务限定（“尚未证实因果关系”、“无法排除选择偏倚”、“仅适用于当前实验条件”、跨分句法定义务）与机械免责回声时互不覆盖、互不吞噬。
   - `Q4_NOT_QUALIFICATION` 仅代表 Python 未匹配到显式限定片段，**绝不代表获得语义删除授权**；凡不确定的限定内容默认保留，Python 严禁自动删除正文句子。
3. **两层体裁路由、多领域包并集与长文 Agent 协议**：
   - 支持文档级与章节级两层路由（分析文档文首速览表可选，叙事文档保留功能性清单）及多 `domain-packs/*.md` 并集加载。
   - **长文模式边界声明**：正文（剥离标题与链接 URL 后）达 `>= 3,000` 中文字符、`>= 1,800` 英文单词或 `>= 4` 个 `##` 章节时启用 **Agent 执行协议**（全局字典锁定 -> 按节改写 -> 跨节合龙），并非 Python 自动分段引擎。
4. **严格五阶段状态生命周期与全分支 JSON 契约**：
   - `Drafted`（草稿/阻断/异常态） -> `Preflight Passed`（只读 `--check` 通过） -> `Deterministic Checks Passed`（`--fix` 完成写前临时文件预重检、原子替换、回读与锚点同构重检通过） -> `Semantic Review Passed` -> `Human Approved`；启用 `--json` 时所有退出码（`0 / 1 / 2`）均输出合法 JSON，支持 `--fail-on-warning` 显式门禁字段 `gate_passed`。

## 二、Markdown 保护范围与统一日志脱敏（与实测用例严格一致）

1. **受保护语法范围**（已由 36 项自动化测试与 `CASE-01..20` 验证）：预校验 YAML Frontmatter（首行独立 `---` 分割线不会误判吞文）、顶层与列表内嵌可变长度代码围栏、4 空格/Tab 缩进代码块、CommonMark 任意反引号长度行内代码（含内嵌单反引号如 ```` `` `<div>` `` ````）、独立与行内 LaTeX 公式（同行双 `$2.8M` 货币金额绝不误判为公式吞没正文）、带行内反引号屏蔽与未闭合断路保护的多行/行内 HTML 标签及引号属性、顶层与列表内 `>` 原文引用块。
2. **文件防覆盖、权限保持与统一日志脱敏**：
   - `--fix` 在临时文件上完成回读与二次重检通过后才执行 `os.replace`，保留原文件权限（如 `0644`），拒绝只读目标（`0444`）、目录目标与悬空软链接覆盖，并拦截零宽字符混淆密钥。
   - `redact_sensitive_text` 先拦截显式密钥、多行私钥、连接串密码、URL 参数密钥与带上下文标签凭据（含带标签 Hex/UUID 与 JSON 引号键名），再保护良性技术标识符（PascalCase/snake_case 术语、`DOI`、`SHA-256 / Git SHA`、`ORCID`、`UUID`、`arXiv`、`NCT / GSE / NM_ / ENSG`、`CVE` 与配置路径），并对含空格用户名/卷名、无尾斜杠主目录及 `~/.ssh` 等敏感路径默认脱敏。

## 三、命令示例与测试说明

```bash
# 只读预检（最高返回 Preflight Passed）
python3 clear-voice/scripts/prose_lint.py --input draft.md --check --json

# 原版试验命令，仅用于可丢弃副本。先确认引用与公式，逐条复核差异
python3 clear-voice/scripts/prose_lint.py --input draft.md --fix --output draft.cleaned.md --diff

# 审计提示词模板（默认支持嵌套围栏、中英文分句及内嵌 ```markdown/```prompt/```text 块）
python3 clear-voice/scripts/prompt_negativity_audit.py --input prompt.md --include-markdown-fences --json

# 运行全部 36 个自动化单元、红队对抗门禁与 CASE-01..CASE-20 黄金基准测试
cd clear-voice && PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p "test_*.py" -v
```

> **测试覆盖诚实声明**：当前 Python 测试套件（36 个自动化测试方法，含 15 项核心测试、11 项红队对抗回归测试、3 项生命周期套件与 7 项覆盖 20 组静态黄金样例的回归测试）仅验证确定性安全脱敏、文件与权限保护、局部 Q4 提取、Markdown 保护边界、状态流转与静态参考输出合规性；针对在线大模型的动态改写评测（`v1.2.0`）尚未执行，不标记为已通过。

## License

MIT License
