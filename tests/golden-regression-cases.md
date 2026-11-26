# `clear-voice` 黄金回归测试集（v1.1.3 完整 20 组基准）

收录 `CASE-01` 至 `CASE-20` 共 20 组静态基准样例，覆盖五维 Fact Ledger、`Q1-Q4`（含局部语义片段级 `Q4_PROTECTED / Q4_CANDIDATE / Q4_NOT_QUALIFICATION` 三态正反例与混合句验证）、多长度代码围栏与多行/引号属性 HTML 混合保护、跨平台路径分级警告与默认日志脱敏、正常科研工程标识符（DOI / SHA-256 / ORCID / 生信注册号）免误删、多领域保护包并集加载，以及人类自然文本停手负样本。

（注：本文件供 `tests/test_golden_regression.py` 执行只读静态基准对齐校验（对应 `Preflight Passed`）与临时文件落盘回读校验（对应 `Deterministic Checks Passed`），不等同于在线多模型 LLM 动态生成实测。）

## CASE-01: 初创尽调工作流自白剥离与币种未确定状态保护

### Required Ledger
- `8 物理比特`
- `280 万`
- `2028`
- `99.9%`
- `原文记为 $`
- `https://nvidia.github.io/cuda-quantum/latest/using/backends/hardware/superconducting.html`

### Forbidden Drift
- `280 万美元`
- `已确认收入`
- `已实测达到 99.9%`

### Input
```markdown
# 超导量子项目评审

本稿按已完成的 Wiki 整理，新增开篇信息卡，未新增调查；子页面爬虫超时（HTTP 504）。

| 项目 | 关键信息 |
| :--- | :--- |
| **技术路线** | 超导门模型，参数门的引入实现了频率拥挤的缓解，详见[材料第5页](</Users/analyst/Desktop/Deck2025.pdf>)。 |
| **创始团队** | 两位创始人均有海外名校博士背景[5][6]，具体履历详见第四节。 |
| **硬件进展** | 框架列示 8 物理比特后端，见[接口文档](https://nvidia.github.io/cuda-quantum/latest/using/backends/hardware/superconducting.html)；本轮未实机运行设备。 |
| **订单披露** | 截至去年底有 $280 万采购订单，本次未取得验收与回款资料，尚不足以确认真实收入。 |

1. **核心技术拆解**
  - 材料列出的 99.9% 是路线表最佳值，不代表公司现有水平；千比特属于 2028 年目标，暂不计入当前能力。
```

### Reference Output
```markdown
# 超导量子项目评审

资料核验截至 2026 年 11 月 15 日（除外部公开链接外，内部进展均引自项目 BP 单方披露，待尽调核验）。

| 项目 | 关键信息 |
| :--- | :--- |
| **技术路线** | 超导门模型，改用参数门错开工作频率以减轻串扰（BP 第 5 页）。 |
| **创始团队** | 两位创始人均在加州理工完成超导量子方向博士训练（校方学位目录 [5]、[6]），全职到岗状态未披露。 |
| **硬件进展** | 外部开发框架已收录其 8 物理比特硬件接口（见 [CUDA-Q 接口文档](https://nvidia.github.io/cuda-quantum/latest/using/backends/hardware/superconducting.html)），整机实测性能未披露。 |
| **订单披露** | BP 披露累计签署 280 万采购订单（原文记为 $，具体币种、验收节点与回款比例未披露）。 |

1. **关键指标归属与规划边界**
   - **区分文献基准与远期路线图：** BP 列出的 99.9% 保真度引自行业公开文献，1000 比特为 2028 年路线图目标；公司当前 8 比特样机的实测门保真度需在技术交流中索取标定记录。
```

## CASE-02: 主体归属切割与去免责复读

### Required Ledger
- `铷（Rb）`
- `锶（Sr）`
- `2000`
- `99.7%`
- `高校实验室`

### Forbidden Drift
- `公司已建成 2000`
- `实测达到 99.7%`

### Input
```markdown
## 技术与进展评估

公司规划了铷（Rb）光镊阵列与锶（Sr）容错平台两条线，前一条主打专用模拟，不能与通用纠错计算混为一谈。[BP第17页](#source-bp)

团队介绍中提到做过 2000 规模无缺陷阵列，但没有给出归属本公司的测试记录，不等于公司现有工程能力。[BP第13页](#source-bp)

材料提出双比特门保真度大于 99.7%，但本次公开检索均未取得本机测试方法与逻辑错误率数据，并非本公司实测结果。
```

### Reference Output
```markdown
## 技术与进展评估

- **产品线分阶段定位：** 近期推进铷（Rb）光镊专用模拟器，远期规划锶（Sr）通用容错平台（BP 第 17 页）。
- **核心阵列记录归属高校履历：** 材料展示的“2000 规模无缺陷阵列”出自创始人过往高校实验室成果（BP 第 13 页）；公司自身平台按计划今年刚启动设备采购搭建，尚未披露本机测试记录。
- **门保真度仍属规划目标：** BP 将双比特门保真度目标定为高于 99.7%，本机测试方法与逻辑错误率均未披露，待后续核对。
```

## CASE-03: 学术审稿保护证据等级对冲词与数学公式

### Required Ledger
- `230 K`
- `2 μs`
- `95% CI: 1.4-2.1`
- `提示`
- `可能参与`
- `尚未排除`
- `$\Delta G^*$`

### Forbidden Drift
- `证实了界面预有序层主导`
- `直接导致了成核`
- `排除了有限尺寸效应`

### Input
```markdown
感谢作者提交这篇极具创新性且工作量饱满的手稿，本研究首次全面填补了过冷水成核机制的重大空白 :contentReference[oaicite:1]{index=1}。

更关键的是：在 230 K 无偏置 2 μs 分子动力学轨迹中，局域四面体序涨落的增强实现了成核势垒 $\Delta G^*$ 的降低，速率比值提示（95% CI: 1.4-2.1）界面预有序层可能参与了临界核形成，但当前有限盒子尺寸尚未排除周期性边界条件带来的有限尺寸效应。总而言之，期待作者在未来取得更加辉煌的成果。
```

### Reference Output
```markdown
本文基于 230 K 下长达 2 μs 的无偏置分子动力学轨迹分析了过冷水结冰微观路径。模拟测得的速率比值（95% CI: 1.4-2.1）提示固液界面预有序层可能参与降低了临界成核势垒 $\Delta G^*$；受限于当前模拟盒子尺寸，结果尚未排除周期性边界条件引入的有限尺寸效应。建议作者补充大尺寸盒子对照轨迹，并说明自由能剖面的误差棒统计口径。
```

## CASE-04: 工程复盘与法定权责限定保护

### Required Ledger
- `14:02`
- `14:19`
- `34%`
- `503`
- `仅限于`
- `应当`

### Forbidden Drift
- `尽量在 5 个工作日`
- `一般用于抵扣`

### Input
```markdown
## 支付网关异常复盘

在本次日常变更过程中，错误的空路由策略被意外下发至生产集群，导致在 14:02 至 14:19 期间约 34% 的请求返回 503 状态码。根据服务协议第 4.2 条，故障补偿积分仅限于抵扣次月网关调用费，运营方应当在 5 个工作日内出具根因报告。后续我们将全面赋能运维闭环，拉齐颗粒度，强化安全红线意识，杜绝此类问题再次发生。
```

### Reference Output
```markdown
## 支付网关异常复盘

- **故障经过与影响面：** 14:02 至 14:19 期间，发布脚本跳过了路由前缀非空校验，将空白路由策略下发至生产网关集群，导致约 34% 的请求返回 503 状态码。
- **协议履约条件：** 根据服务协议第 4.2 条，故障补偿积分仅限于抵扣次月网关调用费，运营方应当在 5 个工作日内出具书面根因报告。
- **工程防呆整改：** 在网关发布流水线增加空路由校验门禁，检测到空表时自动返回非零退出码并中止下发。
```

## CASE-05: 中文专栏拆解伪列表与鸡汤结尾

### Required Ledger
- `1974`
- `37 分钟`
- `贝尔实验室`

### Forbidden Drift
- `美好未来`
- `伟大丰碑`

### Input
```markdown
在当今科技飞速发展的时代背景下，科研节奏的变化值得我们每个人深思。

- **时间碎片化：** 研究人员每天被无数会议切割得支离破碎。
- **考核短期化：** 大家都在追逐短平快的热点指标。
- **耐心缺失化：** 很少有人愿意花五年去啃一块硬骨头。

值得注意的是：1974 年贝尔实验室的走廊里，工程师们曾经为了一个低温噪声异常在地下室连续守了整整七个月，哪怕每天只有 37 分钟的有效观测窗口。这不仅是技术的胜利，更是长期主义精神的伟大丰碑。总而言之，让我们重拾初心，共同迈向更加美好的科学未来！
```

### Reference Output
```markdown
1974 年，贝尔实验室的工程师为了排查一段低温噪声异常，在地下室连续守了整整七个月，哪怕每天只有 37 分钟的有效观测窗口。

如今仪器精密了许多，整块的研究时间却常被密集的会议和短期考核切碎，越来越少有人愿意花五年时间死磕一块硬骨头。当快发论文成了默认生存策略时，守着每天 37 分钟窗口熬过七个月的耐心，反而成了最难复制的条件。
```

## CASE-06: 英文评论消除套话前奏与分词尾巴

### Required Ledger
- `42%`
- `11 milliseconds`
- `Postgres`

### Forbidden Drift
- `pivotal cornerstone`
- `serves as a testament`

### Input
```markdown
In today's rapidly evolving cloud landscape, database architecture stands as a pivotal cornerstone of engineering reliability. Our migration back to a single primary Postgres cluster serves as a testament to simplicity, slashing tail latency by 42% down to 11 milliseconds, highlighting our unwavering commitment to operational excellence and fostering seamless developer productivity.
```

### Reference Output
```markdown
Migrating back to a single primary Postgres cluster cut tail latency by 42%, down to 11 milliseconds, while simplifying day-to-day operations for the engineering team.
```

## CASE-07: 停手负样本一：已自然直白的中文技术简评

### Required Ledger
- `120 mK`
- `48 路`
- `35 万美元`

### Forbidden Drift
- `赋能`
- `里程碑`

### Input
```markdown
这套测控机箱把室温电子学板卡压到了单台 48 路通道，单通道硬件报价约比进口方案低三成。不过他们在 120 mK 冷台以下仍依赖外购低温低噪放，整机交付周期受上游放大器交期制约，目前两家高校试用客户合同总额为 35 万美元。下次访谈直接核对低温串扰实测谱和首批尾款到账时间即可。
```

### Reference Output
```markdown
这套测控机箱把室温电子学板卡压到了单台 48 路通道，单通道硬件报价约比进口方案低三成。不过他们在 120 mK 冷台以下仍依赖外购低温低噪放，整机交付周期受上游放大器交期制约，目前两家高校试用客户合同总额为 35 万美元。下次访谈直接核对低温串扰实测谱和首批尾款到账时间即可。
```

## CASE-08: 停手负样本二：已自然克制的英文工程记录

### Required Ledger
- `18 hours`
- `64 GB`
- `v2.4.1`

### Forbidden Drift
- `seamlessly`

### Input
```markdown
Upgrading the worker pool to v2.4.1 fixed the file-descriptor leak that previously crashed nodes every 18 hours under peak load. Memory usage stayed flat below 64 GB across the weekend soak test, so we rolled the patch out to the remaining three regions on Monday morning.
```

### Reference Output
```markdown
Upgrading the worker pool to v2.4.1 fixed the file-descriptor leak that previously crashed nodes every 18 hours under peak load. Memory usage stayed flat below 64 GB across the weekend soak test, so we rolled the patch out to the remaining three regions on Monday morning.
```

## CASE-09: 两层路由：无摘要表混合章节与引用块原貌保护

### Required Ledger
- `2024 年 9 月`
- `140 万`
- `“我们今年先把高校定制机柜交付稳住，暂不盲目扩招销售[1][2]。”`

### Forbidden Drift
- `| 项目 |`

### Input
```markdown
## 背景与商业核查

该公司成立于 2024 年 9 月，最初为高校低温测试课题组提供定制线缆，随后转向整机机柜装配。

> 创始人原话：“我们今年先把高校定制机柜交付稳住，暂不盲目扩招销售[1][2]。”

- **订单现状：** 账面列示 140 万框架合同，数据的披露实现了初步意向的展示，但本轮公开检索未取得回款水单，不等于确定性收入。
```

### Reference Output
```markdown
## 背景与商业核查

该公司成立于 2024 年 9 月，早期围绕高校低温测试课题组做定制线缆，随后延伸至整机机柜装配。

> 创始人原话：“我们今年先把高校定制机柜交付稳住，暂不盲目扩招销售[1][2]。”

- **框架合同尚待核对回款：** 材料列示 140 万框架合同，目前仅反映初步合作意向，回款水单与具体履约进度未披露。
```

## CASE-10: 两层路由：保留功能性步骤列表的叙事文稿

### Required Ledger
- `4 K`
- `50 欧姆`
- `1. 室温预检`
- `2. 液氮温区复测`
- `3. 4 K 终检`

### Forbidden Drift
- `总而言之`

### Input
```markdown
在当今低温实验领域，一根同轴线虚焊往往会毁掉整周的降温时间。工程师进舱封盖前固定执行三步排查：

1. 室温预检：用万用表核对 50 欧姆阻抗匹配。
2. 液氮温区复测：观察冷缩后接头回波损耗是否跳变。
3. 4 K 终检：记录基线热噪声谱留档。

总而言之，严谨的流程必将助力科研事业迈向辉煌！
```

### Reference Output
```markdown
低温实验里，一根同轴线虚焊就可能白费整整一周的抽真空与降温时间。因此老练的实验员在合上杜瓦封盖前，总会按顺序走完三道排查：

1. 室温预检：用万用表核对 50 欧姆阻抗匹配。
2. 液氮温区复测：观察冷缩后接头回波损耗是否跳变。
3. 4 K 终检：记录基线热噪声谱留档。
```

## CASE-11: Q4 反例验证：日常“提示 / 样本量 / 不得”不误判为必要限定

### Required Ledger
- `30 家`
- `专用模拟器`

### Forbidden Drift
- `混为一谈`
- `爬虫超时`

### Input
```markdown
系统提示子页面爬虫超时（HTTP 502）。编写本分诊摘录时不得将专用模拟器与通用容错计算混为一谈，禁止把团队学术论文直接等同于公司产品。商业团队今年计划将潜在高校客户访谈样本量扩大至 30 家，但本次公开检索未取得正式合同。
```

### Reference Output
```markdown
产品目前定位为专用模拟器，容错计算仍处早期概念规划，既往论文成果均出自创始团队高校时期。商业团队计划今年完成 30 家高校潜在客户访谈，目前已签署的正式商业合同未披露。
```

## CASE-12: Q4 正例与候选验证：`Q4_PROTECTED` 定量区间与 `Q4_CANDIDATE` 语境限定双保留

### Required Ledger
- `HR = 0.72`
- `95% CI: 0.58-0.89`
- `p = 0.003`
- `提示`
- `受当前队列样本量较小所限`

### Forbidden Drift
- `彻底证实了`
- `完全消除了复发风险`

### Input
```markdown
本研究具有极其深远的临床里程碑意义！多变量回归显示无进展生存风险下降（HR = 0.72, 95% CI: 0.58-0.89, p = 0.003）。值得注意的是：亚组生物标志物曲线提示高表达人群可能获益更明显，但受当前队列样本量较小所限，该亚组趋势尚待独立前瞻性队列验证。
```

### Reference Output
```markdown
多变量回归显示试验组无进展生存风险降低（HR = 0.72, 95% CI: 0.58-0.89, p = 0.003）。亚组生物标志物分析提示高表达人群可能获益更明显；但受当前队列样本量较小所限，该亚组趋势尚待独立前瞻性队列验证。
```

## CASE-13: 法律条款正反成对验证：带条款号法定约束保留 vs 空泛规则复述剔除

### Required Ledger
- `保密协议第 6.1 条`
- `不得向第三方披露`
- `仅限于`

### Forbidden Drift
- `混为一谈`
- `尽量保密`

### Input
```markdown
根据保密协议第 6.1 条，接收方不得向第三方披露测试集原始权重，数据用途仅限于本轮并购技术评估。同时需要注意，评审时不得将内部演示样机与量产交付混为一谈，本轮未核实产线良率。
```

### Reference Output
```markdown
根据保密协议第 6.1 条，接收方不得向第三方披露测试集原始权重，数据用途仅限于本轮并购技术评估。标的公司目前展示的仍为内部演示样机，量产产线良率数据未披露。
```

## CASE-14: 多长度代码围栏保护：四反引号嵌套三反引号代码块零误改

### Required Ledger
- ````markdown
- `[示例死链](#do-not-touch)`
- `raw_cite = "[1][2]"`
- `16 通道`

### Forbidden Drift
- `raw_cite = "[1]、[2]"`

### Input
`````markdown
测控固件文档给出了 16 通道配置模板，推进了接入效率的提升[3][4]：

````markdown
以下为原始模板示例，必须原样保留：
```python
raw_cite = "[1][2]"
```
参考锚点写法：[示例死链](#do-not-touch)
````
`````

### Reference Output
`````markdown
测控固件文档提供了 16 通道配置模板，简化了外部硬件接入流程 [3]、[4]：

````markdown
以下为原始模板示例，必须原样保留：
```python
raw_cite = "[1][2]"
```
参考锚点写法：[示例死链](#do-not-touch)
````
`````

## CASE-15: 多行 HTML 块与带引号 `>` 属性行内标签保护

### Required Ledger
- `<div class="spec-box" data-check="snr > 15" title="raw[1][2]">`
- `<td>内部单元格[3][4]</td>`
- `<span data-limit="latency > 5ms">阈值告警</span>`

### Forbidden Drift
- `<td>内部单元格[3]、[4]</td>`

### Input
```markdown
网关监控模块集成了 <span data-limit="latency > 5ms">阈值告警</span> 功能 :contentReference[oaicite:2]{index=2}。

<div class="spec-box" data-check="snr > 15" title="raw[1][2]">
  <table>
    <tr><td>内部单元格[3][4]</td></tr>
  </table>
</div>
```

### Reference Output
```markdown
网关监控模块集成了 <span data-limit="latency > 5ms">阈值告警</span> 功能。

<div class="spec-box" data-check="snr > 15" title="raw[1][2]">
  <table>
    <tr><td>内部单元格[3][4]</td></tr>
  </table>
</div>
```

## CASE-16: Frontmatter、块级公式、行内公式与引用原文混合保护

### Required Ledger
- `archive_src: /Users/researcher/raw_notes.md`
- `\begin{align}`
- `k_{12}[1][2]`
- `> 审稿人原话：“当前轨迹不得直接外推至热力学极限[5][6]。”`

### Forbidden Drift
- `k_{12}[1]、[2]`

### Input
```markdown
---
archive_src: /Users/researcher/raw_notes.md
---

耦合矩阵元的引入实现了跃迁速率 $k_{12}[1][2]$ 的收敛：

\begin{align}
\Gamma[3][4] &= 2\pi |V|^2 \rho(E)
\end{align}

> 审稿人原话：“当前轨迹不得直接外推至热力学极限[5][6]。”
```

### Reference Output
```markdown
---
archive_src: /Users/researcher/raw_notes.md
---

引入耦合矩阵元后，跃迁速率 $k_{12}[1][2]$ 趋于收敛：

\begin{align}
\Gamma[3][4] &= 2\pi |V|^2 \rho(E)
\end{align}

> 审稿人原话：“当前轨迹不得直接外推至热力学极限[5][6]。”
```

## CASE-17: 跨平台本机路径分级处理：清理个人桌面隐私死链 vs 保留服务器复现路径

### Required Ledger
- `/opt/envoy/conf/listeners.yaml`
- `/mnt/lustre/cryo_run04/traj.h5`
- `测试报告第 8 页`

### Forbidden Drift
- `/Users/linwei/Desktop/bench.pdf`

### Input
```markdown
故障复现可直接检查网关容器内的 `/opt/envoy/conf/listeners.yaml` 或集群共享存储路径 /mnt/lustre/cryo_run04/traj.h5；压测曲线详见[本地报告第8页](</Users/linwei/Desktop/bench.pdf>)。
```

### Reference Output
```markdown
故障复现可直接检查网关容器内的 `/opt/envoy/conf/listeners.yaml` 或集群共享存储路径 /mnt/lustre/cryo_run04/traj.h5；压测曲线见测试报告第 8 页。
```

## CASE-18: 多领域保护包并集加载：医疗 AI 并购尽调（商业 + 临床 + 法务三包叠加）

### Required Ledger
- `450 万`
- `原文记为 $`
- `95% CI: 0.84-0.93`
- `尚未排除中心间设备型号偏倚`
- `数据合规协议第 3.4 条`
- `仅限于`

### Forbidden Drift
- `450 万美元确认收入`
- `彻底消除了设备偏倚`

### Input
```markdown
标的披露签署 $450 万医院采购意向订单，本次未取得中标通知书与回款凭证，不能等同于确认收入。多中心回顾性验证灵敏度达 0.89（95% CI: 0.84-0.93），但尚未排除中心间设备型号偏倚。依据数据合规协议第 3.4 条，模型推理镜像仅限于三甲医院本地内网部署，不得回传患者原始影像。
```

### Reference Output
```markdown
- **商业意向待核实履约：** 材料披露累计签署 450 万医院采购意向订单（原文记为 $，具体币种、中标通知书及回款进度未披露）。
- **临床验证指标与偏倚边界：** 多中心回顾性验证灵敏度为 0.89（95% CI: 0.84-0.93），目前尚未排除中心间设备型号偏倚。
- **合规部署硬约束：** 依据数据合规协议第 3.4 条，模型推理镜像仅限于三甲医院本地内网部署，不得回传患者原始影像。
```

## CASE-19: 同句混合普通提示词与多类科学限定候选（Local-Span Q4 互不覆盖验证）

### Required Ledger
- `尚未证实因果关系`
- `无法排除选择偏倚`
- `仅适用于当前实验条件`
- `n = 64`

### Forbidden Drift
- `已证实因果关系`
- `混为一谈`

### Input
```markdown
系统提示批处理任务完成后，相关性分析（n = 64）提示该指标与响应率存在关联但尚未证实因果关系，且单中心入组无法排除选择偏倚，上述经验阈值仅适用于当前实验条件；编写纪要时不得将回顾性观察与前瞻性试验证据混为一谈。
```

### Reference Output
```markdown
回顾性相关性分析（n = 64）提示该指标与响应率存在关联，但尚未证实因果关系；同时单中心入组无法排除选择偏倚，上述经验阈值仅适用于当前实验条件。
```

## CASE-20: 正常 DOI、SHA-256、ORCID 与生信临床标识符免误删验证

### Required Ledger
- `10.1038/s41586-024-07998-6`
- `arXiv:2409.14509v2`
- `0000-0002-1825-0097`
- `NCT04567890`
- `NM_001126112.3`
- `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

### Forbidden Drift
- `[REDACTED`

### Input
```markdown
复现包对应论文 DOI 为 10.1038/s41586-024-07998-6（预印本 arXiv:2409.14509v2，通讯作者 ORCID 0000-0002-1825-0097），关联队列注册号 NCT04567890 与参考转录本 NM_001126112.3，归档镜像校验值为 sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855[1][2] 。
```

### Reference Output
```markdown
复现包对应论文 DOI 为 10.1038/s41586-024-07998-6（预印本 arXiv:2409.14509v2，通讯作者 ORCID 0000-0002-1825-0097），关联队列注册号 NCT04567890 与参考转录本 NM_001126112.3，归档镜像校验值为 sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 [1]、[2]。
```
