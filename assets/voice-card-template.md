# 个人或团队专属文风卡配置模板（Voice Card v1.1.3）

在 `SKILL.md` 的 Step 2 加载本卡并在 Step 5 按参数执行。文风偏好排在“事实准确性、证据归属边界、领域必要限定（Q4）”之后生效：当个人简练偏好与必要科学/法务限定冲突时，始终优先保留必要限定。

## 一、结构化文风配置

```yaml
voice_profile_name: "研究团队直白审慎风"
default_intensity: "standard"        # light（仅清格式与自白）| standard（标准重铸）| deep（深度重组）
document_baseline: "analytical"      # analytical | narrative（各章节仍可按内容局部切换）
use_summary_table: "when_multi_dim"  # always | when_multi_dim | never

sentence_cadence:
  target_zh_chars: "18-32"           # 主力句长参考区间
  short_verdict_mix: true            # 穿插简短明确判断句
  max_paragraph_lines: 5             # 自然段视觉高度参考

preferred_practices:
  - "开篇第一句直接给分诊或审稿核心判断，省去客套寒暄"
  - "讲技术方案时先算物理账和经济账，写明收益与工程卡点"
  - "未核实信息直接写‘未披露/待核对’，不绕弯子"

lexicon_map:
  "赋能": "支持 / 省去"
  "抓手": "切入点 / 具体工具"
  "闭环": "跑通全流程"
  "拉齐颗粒度": "核对具体口径"
```

## 二、样文语感锚点（可选，粘贴 1 至 3 段本人代表作）

提供真实手写片段后，Step 5 会对齐其句间转折方式、专业术语密度与判断口吻，同时避免机械模仿口头禅：

```text
[粘贴你本人满意的真实段落，作为句法节奏参考基线]
```
