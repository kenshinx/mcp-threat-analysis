---
title: L3 语义 / LLM 分析层 · 系统设计
tags:
  - mcp
  - detection
  - llm
  - semantic
  - L3
created: 2026-04-26
status: v1.0
---

# L3 语义 / LLM 分析层 · 系统设计

> 上位文档：[[恶意 MCP 检测可执行技术方案]] §5
> 目标读者：L3 层开发负责人

---

## 1. 职责与边界

### 1.1 职责

承担 L2 静态规则**无法判别**的 MCP 特有威胁：
- TPA（Tool Poisoning Attack）语义判别
- Tool Shadowing / Name Squatting 跨 Server 检测
- Schema-Code 一致性检测（声明 vs 实现差异）
- Toxic Flow（单 Server 内）检测
- Untrusted Content 处理审计（W011）
- 字符层异常（隐藏 Unicode / ANSI Escape）

### 1.2 输入 / 输出

| 项 | 内容 |
|---|---|
| **输入** | `(server_id, version)` + `static_summary`（来自 L2）+ `tools/list` 协议快照（来自 L0/L1） |
| **输出** | `List[Finding]` 写入 `findings` 表，`layer='L3'` |
| **副产物** | `tools.description_emb`（pgvector）写入；`tool_capabilities` 缓存 |

### 1.3 不在 L3 范围内

- 单文件 SAST → L2
- 跨 Server 跨用户配置的 Toxic Flow → 暂不支持（按主方案 v2.1 保持现状）
- 版本对比 / 漂移 → L4
- 动态行为 → L5

---

## 2. 模块划分

```
l3/
├── orchestrator.py
├── detectors/
│   ├── base.py
│   ├── char_layer.py            # 5.1.1 隐藏 Unicode / ANSI Escape
│   ├── tpa_text_rules.py        # 5.1.2 Semgrep 文本规则命中（复用 L2 引擎结果）
│   ├── tpa_llm.py               # 5.1.4 LLM 语义判别
│   ├── shadowing.py             # 5.2 Name + 语义相似度
│   ├── schema_code_alignment.py # 5.3 Schema-Code 一致性
│   ├── toxic_flow.py            # 5.4 单 Server 内
│   └── untrusted_content.py     # 5.5 W011
├── alignment/                   # 借鉴 Cisco BehavioralCodeAnalyzer 的拆分
│   ├── orchestrator.py          # AlignmentOrchestrator
│   ├── prompt_builder.py        # AlignmentPromptBuilder
│   ├── llm_client.py            # AlignmentLLMClient（统一封装）
│   ├── response_validator.py    # AlignmentResponseValidator
│   └── cross_file_dataflow.py   # 跨文件 dataflow 抽取（基于 tree-sitter，复用 L2 ast_extractor）
├── prompts/
│   ├── tpa_detection.md
│   ├── code_alignment.md
│   ├── tool_capability_classification.md
│   ├── boilerplate_protection.md
│   └── unified_response_schema.md
├── embeddings/
│   ├── encoder.py               # 统一 embedding 入口
│   └── shadowing_index.py       # pgvector 检索封装
├── llm/
│   ├── client.py               # 统一 LLM 客户端（anthropic / openai_compatible 双 provider）
│   ├── budget.py                # 成本预算与限流
│   └── cache.py                 # 按 (model, prompt_sha, input_sha) 缓存
├── models.py
├── persistence.py
└── tests/
```

---

## 3. 子模块设计

### 3.1 orchestrator

```python
class L3Orchestrator:
    def run(self, target: ScanTarget) -> L3Result:
        summary = self.persistence.load_static_summary(target)
        tools = self.persistence.load_remote_snapshot_tools(target)

        # 串行依赖：char_layer + text_rules → 决定是否需要 LLM
        findings = []
        findings += self.char_layer.run(tools)
        findings += self.tpa_text_rules.run(tools, summary)

        # LLM 兜底：仅对未被规则确认 malicious 的工具调用
        unresolved = [t for t in tools if not is_confirmed_malicious(t, findings)]
        findings += self.tpa_llm.run(unresolved)

        # 独立检测器（可并行）
        with parallel():
            findings += self.shadowing.run(tools)
            findings += self.schema_code_alignment.run(summary, tools)
            findings += self.toxic_flow.run(tools)
            findings += self.untrusted_content.run(tools, summary)

        self.persistence.save(target, findings)
        return L3Result(findings=findings)
```

**幂等键**：`(server_id, version, detector, tool_name|null, content_hash)`。content_hash 用于 LLM 输入相同时复用结果。

### 3.2 char_layer

实现按主方案 §5.1.1，无 LLM 调用，纯规则。
作用对象：`tool.description / annotations / inputSchema 任意字符串字段`。

输出 Finding：`detector=char:hidden-unicode | char:ansi-escape`。

### 3.3 tpa_text_rules

**策略**：不在 L3 重新跑 Semgrep；从 L2 已写入的 `findings(layer='L2', detector LIKE 'semgrep:%_injection|tool_poisoning|...')` 中**继承**与 tool 关联的命中。

为什么放 L3：这些命中针对的是「文本/描述层」，本质属于语义层威胁；L2 是执行场所，但语义归属在 L3。

**实现**：在 L3 启动时通过 SQL 视图把 L2 文本类规则的 finding 复制为 L3 上下文（不重复持久化，只在内存中聚合 confidence）。

### 3.4 tpa_llm

**调用条件**：
- tool 未被 `tpa_text_rules` 命中 critical
- 该 tool description 长度 > 30 字符（短描述 LLM 价值低）
- 该 server popularity 在 Top-50% **或** L2 已有任意 finding（缩小 LLM 范围）

**调用方式**：
- Provider 由 `MTA_LLM_PROVIDER` 决定：`anthropic` 或 `openai_compatible`
- Anthropic Batch API（首选，50% 折扣）；非紧急任务统一用 batch
- 紧急 / Top 1% server：实时 messages API
- OpenAI-compatible 端点（Volcengine Ark、DeepSeek 等）通过 `MTA_LLM_BASE_URL` 配置

**Prompt**：`prompts/tpa_detection.md`，输出遵循 `unified_response_schema.md`：
```json
{
  "verdict": "clean | suspicious | malicious",
  "categories": ["instruction_override", "role_hijack", "data_exfil", "tool_chain_hijack", "hidden_format", "other"],
  "confidence": 0.0,
  "evidence_quotes": ["..."],
  "explanation": "..."
}
```

**预算**：每天单 detector LLM 成本上限可配置；超额时退化为只跑 Top popularity 子集。

### 3.5 shadowing

**步骤**：
1. 写入 / 更新 `tools.description_emb`
2. 对每个 tool 做：
   - 名字编辑距离 ≤ 2 检索
   - 描述向量 cosine ≥ 0.93 检索
3. 跨 `server_id` 命中 → 输出 finding；同 server 不算

**严重等级**：
- 名字完全相同 + server 不同 → high
- 名字 lev≤2 + server 不同 → medium
- 描述相似 + 一方 popularity 显著低 → medium
- 仅描述相似 → low（信息）

**索引维护**：tool schema 变更时增量重算，避免全量重建。

### 3.6 schema_code_alignment（核心模块）

借鉴 Cisco `BehavioralCodeAnalyzer` 的组件拆分（见主方案 §5.3）：

```
[L2 static_summary.tool_handlers]
        │
        ▼
CrossFileDataflowAnalyzer
  - 解析跨文件 import / call graph
  - 把 callee 函数的 IO summary 合并到调用者
  - 输出 EnrichedToolHandler
        │
        ▼
AlignmentOrchestrator
        │
        ├─ AlignmentPromptBuilder
        │     输入：declared(name/desc/schema) + enriched IO summary
        │     输出：完整 prompt（截断 / 结构化模板）
        │
        ├─ AlignmentLLMClient
        │     - 重试、超时、batch 支持
        │     - 成本归账到 detector budget
        │
        └─ AlignmentResponseValidator
              - 强制 unified_response_schema
              - 解析 alignment_score, behavioral_diff_items
              - 失败 → 重试一次，仍失败丢弃并打 ops 告警
```

**关键工程实践**（主方案 §5.3 已确立）：
- LLM 不看完整源码，只看摘要
- 摘要含：dataflow（参数 → IO）、call graph、network/file/subprocess 列表、condition branches、可疑代码片段（按需展开）
- alignment_score ≤ 6 → finding，severity 与 score 反比

**Finding 输出**：
```python
Finding(
  detector="llm:schema-code-inconsistency",
  layer="L3",
  issue_code="E001",
  severity="critical" if score <= 3 else "high" if score <= 5 else "medium",
  confidence=llm_confidence,
  evidence={
    "tool": tool_name,
    "declared": ...,
    "behavioral_diff_items": [...],
    "llm_reasoning": ...,
    "llm_model": model_id,
    "prompt_sha": ...,
  }
)
```

### 3.7 toxic_flow

按主方案 §5.4，**仅单 Server 内**：

```python
def run(self, tools):
    capabilities = self.classify(tools)        # LLM 分类，cache by tool content hash
    findings = []
    for pattern in TOXIC_FLOW_PATTERNS:
        sources = match(capabilities, pattern["source_capabilities"])
        sinks = match(capabilities, pattern["sink_capabilities"])
        if sources and sinks:
            findings.append(make_finding(pattern, sources, sinks))
    return findings
```

`classify` 用 LLM 把 tool 归类到固定 capability 集合（`fetch_url, send_email, execute_shell, ...`）；结果缓存，命中后无 LLM。

### 3.8 untrusted_content

简单启发式：tool 返回 `web_fetch / read_email / search_web` 类内容时，检查：
- description / annotations 是否声明 untrusted marker
- 实现是否对返回内容做 sanitization（结合 `static_summary.tool_handlers.io_summary` 中是否有 `escape / sanitize / markdown_strip` 调用）

无 LLM；输出 W011 finding。

---

## 4. LLM 子系统

### 4.1 统一客户端

```python
class LLMClient:
    def call(self, prompt: str, *, model: str, response_schema: dict,
             cache_key: str | None = None,
             mode: Literal["batch", "realtime"] = "batch") -> LLMResponse: ...
```

封装：
- **双 Provider 支持**：通过 `MTA_LLM_PROVIDER` 选择 `"anthropic"` 或 `"openai_compatible"`
  - `anthropic`：Anthropic Messages API，支持 ephemeral prompt caching，模型路由默认 Claude Haiku 4.5 (batch) / Sonnet 4.6 (realtime)
  - `openai_compatible`：任何 OpenAI Chat Completions 兼容端点（Volcengine Ark、DeepSeek、vLLM、Together 等），通过 `MTA_LLM_BASE_URL` + `MTA_LLM_API_KEY` + `MTA_LLM_MODEL_BATCH` / `MTA_LLM_MODEL_REALTIME` 配置
- 重试（指数退避，max 3）
- response_schema 强制（结构化输出），OpenAI-compatible 端点不支持 `response_format=json_object` 时依赖 prompt 引导 + balanced-brace salvage
- 缓存（按 `(model, prompt_sha256, input_sha256)`，TTL 30 天）
- Prompt caching（Anthropic ext），自动加 `cache_control` 标记 prompt 模板部分
- 成本追踪：已知模型（`_PRICES` dict）精确计费，未知模型报告 0.0（budget 仍然生效）

### 4.2 Batch runner

- 每 30 分钟收集一批 pending LLM 任务
- 提交 Anthropic Batch（< 24h 完成）
- 完成后回写 finding；超时仍未返回 → 降级到 realtime 或 mark deferred

### 4.3 Budget

每个 detector 配置：
```python
BUDGET = {
  "tpa_llm":              {"daily_usd": 50,  "monthly_usd": 1000},
  "schema_code_alignment":{"daily_usd": 100, "monthly_usd": 2000},
  "tool_capability":      {"daily_usd": 20,  "monthly_usd": 400},
}
```

超额：打 ops 告警，detector 进入「只服务高 popularity」降级模式。

### 4.4 Prompt 管理

- 所有 prompt 存 `prompts/*.md`，文件头含 `version`、`model_compat`、`schema_ref`
- 修改 prompt = 升 version；缓存 key 包含 prompt version
- `unified_response_schema.md` 是单一事实源；validator 据此生成 jsonschema

---

## 5. 数据契约

### 5.1 Finding 扩展字段

复用主方案 §3.1 `findings`；L3 的 `evidence` 必含：
- `tool_name`（如适用）
- `llm_model` + `prompt_version` + `prompt_sha`（如使用 LLM）
- `confidence` 来源标注（rule | llm | combined）

### 5.2 tool_capability 表（缓存）

```sql
CREATE TABLE tool_capabilities (
    tool_id        UUID PRIMARY KEY REFERENCES tools(id),
    classified_at  TIMESTAMPTZ,
    capabilities   TEXT[],          -- 固定枚举集合
    classifier     TEXT,            -- 'llm:claude-haiku-4-5'
    content_hash   TEXT             -- (description + schema) sha
);
```

### 5.3 LLM 调用日志

```sql
CREATE TABLE llm_calls (
    id          UUID PRIMARY KEY,
    detector    TEXT,
    model       TEXT,
    prompt_sha  TEXT,
    input_sha   TEXT,
    tokens_in   INT,
    tokens_out  INT,
    cost_usd    NUMERIC(10,4),
    status      TEXT,
    finding_id  UUID NULL,
    created_at  TIMESTAMPTZ
);
```

供成本与质量审计。

---

## 6. 性能与成本

| 项 | 目标 |
|---|---|
| 单 server L3 完成 P50（batch 路径） | < 6h（受 Anthropic Batch 节奏制约） |
| 单 server L3 完成 P50（realtime 路径） | < 5min |
| LLM 调用缓存命中率 | ≥ 60%（重复 server / 版本） |
| 单 server LLM 成本 P50 | < $0.05 |

---

## 7. 错误处理

| 错误 | 处理 |
|---|---|
| LLM 返回非合法 JSON | 重试一次，仍失败丢弃 + ops |
| LLM 拒绝（safety） | 记录 + skip，不视为 malicious |
| Batch 超时 | 转 realtime 或下个窗口 |
| pgvector 检索失败 | shadowing detector skip，其他继续 |
| static_summary 缺失 | schema_code_alignment skip 该 tool |

---

## 8. 与上下游接口

### 8.1 上游

L2 完成后通过队列触发；同时 L0 在新 remote_snapshot 写入后也可独立触发 L3（仅 metadata 类 detector）。

### 8.2 下游

- L4：直接读 `findings(layer='L3')` 做漂移对比
- L6：每条 finding 落库即被增量聚合

---

## 9. 测试策略

| 类型 | 内容 |
|---|---|
| **MCPTox 1312 样本** | TPA detector 黄金集；precision/recall 持续追踪 |
| **postmark-mcp** | 端到端 schema_code_alignment 必命中 |
| **shadowing 合成集** | 用 100 个真实 tool + 自动构造的 typosquat 子集 |
| **prompt 回归** | prompt 改版后跑全部黄金集，禁止指标退步 |
| **LLM 模拟** | 单测中用 fixture 替换 LLMClient |

---

## 10. 开发顺序建议

1. `models` + `persistence` + `LLMClient` + `prompts` 骨架
2. `unified_response_schema` 确定 + validator
3. `char_layer`（无 LLM，最快可上线）
4. `shadowing`（pgvector 集成）
5. `tpa_text_rules`（拼接 L2 结果）
6. `tpa_llm`（接入 batch runner）
7. `alignment/cross_file_dataflow`（依赖 L2 ast_extractor）
8. `schema_code_alignment`（核心模块，最重）
9. `toxic_flow` + `untrusted_content`
10. orchestrator 联调 + 集成测试

---

## 11. 开放问题

- LLM model 选型：Claude Haiku 4.5 vs Sonnet 4.6 的精度/成本拐点 — 上线后实测；openai_compatible provider 允许使用其他模型（如 Volcengine Ark Doubao 系列），需单独校准
- pgvector 维度选择 — 当前 1536 暂定，绑定 OpenAI text-embedding-3-small；切换模型时表结构如何演进暂不处理（出现需求再说）
- TPA 规则与 LLM 的 confidence 融合公式 — 上线后用人工标注集校准
- Cross-file dataflow 在动态语言（Python / JS）中的精度上限 — 看实测

---

> v1.0 · 2026-04-26 · 初版
