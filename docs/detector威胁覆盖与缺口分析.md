# Detector 威胁覆盖与缺口分析

本文对照 [恶意 MCP 检测技术方案](./恶意%20MCP%20检测技术方案.md) 的威胁模型，列出当前代码中每类 detector 能发现的威胁类型，并标出未覆盖或只部分覆盖的缺口。

## 结论摘要

当前实现覆盖最完整的是 **A. 元数据层** 与 **C. package 代码层**：TPA、prompt injection、hidden unicode、tool shadowing、untrusted content，以及 command injection/path traversal/SSRF/secrets/SCA 等都有对应 detector 或规则。

缺口主要在四块：

1. **时间维度 L4 未实现**：Sleeper、Rug Pull、Silent Capability Expansion、remote hot-swap 都缺少版本/快照 diff detector。
2. **动态/行为 L5 未实现**：schema-behavior、targeted response、动态 egress/FS/syscall、sandbox fuzzing 没有 producer。
3. **remote-response 等价 L2' 不完整**：remote 已能同步 tools 并复用部分 L3 规则，但设计里的 `remote_response_analyzer.py`、响应文本 secret scan、响应混淆/entropy、server_info 审计尚未实现。
4. **分发层 E 基本缺失**：Typosquatting、Platform Breach、Namespace Reuse 没有专门 detector；`ReputationAnalyzer` 只能提供弱供应链声誉信号。

## 当前 Detector 清单

| 层级 | Detector / Analyzer | 产生的 detector id | 能发现的威胁类型 | 适用对象 | 主要输入 |
|---|---|---|---|---|---|
| L2 static | `SemgrepAnalyzer` | `semgrep:*` | command injection、path traversal、SSRF、dynamic exec、obfuscated base64 exec、sensitive file/cloud metadata access、hardcoded secret fallback、silent BCC/exfil、credential harvesting、prompt injection、tool poisoning、data exfiltration 文本模式 | package | 源码、README、配置文本 |
| L2 static | `CodeQLAnalyzer` | `codeql:<rule_id>` | command injection、path/path traversal、SSRF、SQL injection 等 CodeQL security-extended 可发现问题 | package | CodeQL database / SARIF |
| L2 static | `SecretAnalyzer` | `secret:trufflehog:*`, `secret:gitleaks:*` | hardcoded secrets / credential exposure | package | filesystem scan |
| L2 static | `SCAAnalyzer` | `sca:osv:*`, `sca:npm:*`, `sca:pip-audit:*` | vulnerable dependencies / CVE 级依赖脆弱性 | package | lockfile / package metadata |
| L2 static | `ManifestAnalyzer` | `manifest:install-hook-network-or-exec`, `manifest:bin-remote-url`, `manifest:fake-mcp-package`, `manifest:server-json-invalid`, `manifest:py-script-network-or-exec` | install hook 执行/联网、remote bin、伪 MCP 包、无效 server.json、Python script 入口可疑执行 | package | `package.json`, `pyproject.toml`, `server.json` |
| L2 static | `ObfuscationAnalyzer` | `obfuscation:composite` | malware payload / rug-pull 代码投毒的弱信号：高熵、minified、eval/base64/VM 执行 | package | 文本文件和字符串 |
| L2 static | `ReputationAnalyzer` | `reputation:low-rep-npm` | 低下载量/新包供应链风险弱信号 | package | npm registry metadata |
| L3 semantic | `CharLayerDetector` | `char:hidden-unicode`, `char:ansi-escape` | hidden unicode、ANSI escape、metadata obfuscation | package, remote | tool description / annotations / input schema |
| L3 semantic | `TPATextRulesDetector` | `tpa-rule:*` | 将静态 Semgrep 文本类 TPA/prompt injection/credential harvesting/data exfil findings 提升到语义层并关联 tool | package, remote-like DB rows | DB 中 static findings + handlers |
| L3 semantic | `TPALLMDetector` | `tpa-llm` | LLM 判别的 tool poisoning、恶意元数据、数据外泄意图 | package, remote | tool metadata |
| L3 semantic | `ShadowingDetector` | `shadow:name-collision`, `shadow:semantic-clone` | tool shadowing、name collision、semantic clone | package, remote | tools 表 + pgvector |
| L3 semantic | `UntrustedContentDetector` | `untrusted-content:unmarked` | 外部内容返回未标记 / 缺少 sanitizer 的 W011 | package, remote | tool name/description/handler string literals |
| L3 semantic | `SchemaCodeAlignmentDetector` | `llm:schema-code-*` | package 侧 schema-code 不一致：description/schema 声称 X，代码实际做 X+Y | package | static summary handler + LLM |
| L3 semantic | `ToxicFlowDetector` | `toxic-flow:*` | 单 server 内 tool 组合形成 untrusted read -> sensitive write / external write 等 toxic flow | package, remote | tool capability cache/LLM classification |
| remote_analysis | `detect_tls` | `remote:tls-self-signed`, `remote:tls-near-expiry` | TLS hygiene 风险 | remote | TLS cert snapshot |
| remote_analysis | `detect_auth_missing` | `remote:auth-missing` | 未鉴权暴露 tools/list 元数据面 | remote | live probe result |
| remote_analysis | `detect_protocol_version` | `remote:protocol-version-mismatch` | 协议版本异常 / server_info 弱异常 | remote | initialize response |
| L6 risk | `Aggregator`, `CrossValidator`, `TriageRouter` | 不产生一手威胁 finding | 聚合 active findings、交叉验证 boost、P0/P1 triage | all | findings 表 |

## 威胁模型覆盖矩阵

| 威胁模型条目 | 当前覆盖状态 | 对应 detector | 覆盖说明 | 缺口 |
|---|---|---|---|---|
| A1 Tool Poisoning (TPA) | **较强覆盖** | `semgrep:tool-poisoning-*`, `tpa-rule:*`, `tpa-llm` | 文本规则 + LLM 双路径；package 和 remote tools metadata 均可进入 L3 | remote-response L2' 专用 analyzer 未实现；缺少 kind-aware 路由声明 |
| A2 Tool Shadowing | **中等覆盖** | `shadow:name-collision`, `shadow:semantic-clone` | 名称碰撞和 embedding 语义克隆检测已实现 | 依赖 DB/pgvector；没有 namespace/registry 级 squatting 归因 |
| A3 Prompt Injection in description | **较强覆盖** | `semgrep:prompt-injection-*`, `semgrep:mcp-prompt-injection-multilang`, `tpa-rule:*`, `tpa-llm` | README/源码文本和 tool description 可检测 override/hijack/sentinel 注入 | remote resources/prompts 文本尚无独立 L2' 扫描入口 |
| A4 Hidden Unicode / ANSI Escape | **较强覆盖** | `char:hidden-unicode`, `char:ansi-escape` | description/annotations/input_schema 逐字符扫描 | 对 README/manifest 全文的 char-layer 不直接覆盖，除非进入 tools metadata |
| A5 Untrusted Content | **中等覆盖** | `untrusted-content:unmarked` | 基于 tool 描述中的 fetch/search/browse/read_email 等外部内容动词和 untrusted marker/sanitizer 判断 | 未观察真实返回值；不能验证 runtime sanitization；remote resource content 未覆盖 |
| B1 Sleeper Attack | **未覆盖** | 无 | 设计要求版本/时间维度检测 | 无 version-trigger detector、无历史行为比较 |
| B2 Rug Pull | **弱覆盖** | `obfuscation:composite`, `manifest:*`, `semgrep:*` | 可发现某个版本已经投毒的静态信号 | 无版本 diff，不能识别“后续版本突然投毒” |
| B3 Silent Capability Expansion | **未覆盖** | 无 | 设计要求 package version diff / remote snapshot diff | 无 tool-added、schema-loosened、capability drift detector |
| C1 Command Injection | **中等覆盖** | `semgrep:mcp-tool-shell-injection-*`, `semgrep:mcp-tool-dynamic-exec-*`, `codeql:*command-injection*` | package 源码可静态发现 shell injection / dynamic exec | 无动态 fuzz 验证；remote 不适用源码路径 |
| C2 Path Traversal | **中等覆盖** | `semgrep:mcp-tool-path-traversal-*`, `codeql:*path*` | package 源码可静态发现不安全路径访问 | 无沙箱 FS observation；source/sink 覆盖取决于规则 |
| C3 SSRF | **中等覆盖** | `semgrep:mcp-tool-ssrf-*`, `codeql:*ssrf*`, `semgrep:sensitive_file_access` cloud metadata | package 源码可发现非 allowlist URL fetch 和 metadata endpoint | 无动态 egress 验证；remote server-side SSRF 只能靠未来 L5' |
| C4 Malware Payload | **部分覆盖** | `obfuscation:composite`, `semgrep:mcp-obfuscated-base64-exec-*`, `semgrep:mcp-tool-dynamic-exec-*`, `manifest:install-hook-network-or-exec` | 可发现混淆 payload、install hook、动态执行等强静态信号 | 无 sandbox syscall/network/process 行为检测；无 YARA/AV payload 分类 |
| C5 Hardcoded Secrets | **较强覆盖(package)** | `secret:*`, `semgrep:mcp-hardcoded-secret-pattern` | TruffleHog/Gitleaks + Semgrep fallback | remote 响应文本 secret scan 未实现 |
| C6 Credential Mishandling | **部分覆盖** | `semgrep:credential-harvesting-*`, `secret:*`, `tpa-llm` | 可发现采集/暴露 key 的文本或 secret 信号 | 无 runtime credential flow / misuse tracking |
| D1 Toxic Flows | **部分覆盖** | `toxic-flow:*` | 单 server 内 source/sink capability 组合可发现 | 依赖 LLM/cached capability；跨 server toxic flow 未实现 |
| D2 Cross-Server Data Exfiltration | **未覆盖** | 无 | 设计要求跨实体关系分析 | 无跨 server graph、无动态 egress/recipient correlation |
| E1 Typosquatting | **未覆盖** | 无 | threat model 明确 package-only | 无名称相似度/registry namespace detector |
| E2 Platform Breach | **未覆盖** | 无 | 需要 registry/hosting 事件和作者身份变化信号 | 当前仓库不含 discovery/canonicalization/registry monitor |
| E3 Namespace Reuse | **未覆盖** | 无 | 需要 registry namespace lifecycle / owner history | 无 namespace reuse detector |
| F1 Targeted Response | **未覆盖** | 无 | 需要多 UA/IP/时间 probe 比较 | 当前 remote P1 只做单快照 |
| F2 TLS Fingerprint Drift | **部分覆盖** | `remote:tls-self-signed`, `remote:tls-near-expiry` | 单次 TLS hygiene 已覆盖 | 无 TLS fingerprint drift / historical diff |
| F3 Server-side Hot-swap of Tools | **未覆盖** | 无 | 需要 remote snapshot diff | 无 tool-added/removed/description-mutated/schema-loosened detector |
| G1 Package vs Live-Response Divergence | **未覆盖** | 无 | hybrid-only 核心检测 | 无 hybrid view join/diff detector |

## 与设计文档的实现差异

| 设计项 | 设计位置 | 当前状态 | 影响 |
|---|---|---|---|
| detector 声明 `applies_to: set[Kind]` 并由 orchestrator 按 kind 路由 | §1.2 | 未实现统一字段；现有 detector base 只有 `name`/`is_llm` | hybrid/remote/package 的“不适用”无法被系统性记录 |
| L2' `remote_response_analyzer.py` | §4.5 | 未实现 | remote response 的文本 SAST、secret scan、entropy/server_info 审计不完整 |
| L3' schema-behavior 一致性 | §5.6 | 未实现 | remote 无源码场景缺少“声明 vs 实际行为”检测 |
| L4 package version diff | Detector 适用矩阵 | 未实现 | Sleeper/Rug Pull/Silent Capability Expansion 无法识别时间变化 |
| L4 remote snapshot diff | Detector 适用矩阵 | 未实现 | targeted response、hot-swap、TLS drift 无法识别 |
| L4 hybrid divergence | §6.5 | 未实现 | package 稳定但 remote 投毒的核心 hybrid 场景缺口 |
| L5 package sandbox / L5' online behavior observation | §7 | 未实现 | 动态 egress、FS、syscall、副作用、schema-behavior 都缺少事实来源 |
| L6 cross-validator 引用的 `dynamic-egress:*` / `version-diff:*` | `risk_scoring/cross_validator.py` | consumer 已有，producer 缺失 | boost 规则中部分路径永远不会触发，除非外部系统写入这些 findings |

## 优先级建议

| 优先级 | 建议补齐项 | 理由 | 最小可交付 |
|---|---|---|---|
| P0 | Remote snapshot diff | 直接覆盖 Silent Capability Expansion、Targeted Response 的基础数据结构，也是 hot-swap/TLS drift 的前置 | 对同一 remote server 最近两次 `remote_observations` 比较 tools set、description hash、schema hash、TLS sha256 |
| P0 | Hybrid divergence detector | 威胁模型里明确标注为 hybrid 核心检测，且 MCP 双发布场景风险高 | 对同一 canonical server 的 package `static_summaries/tools` 与 remote latest `tools` 做 tools/description/schema diff |
| P1 | `remote_response_analyzer.py` | 让 remote 侧具备与 package L2 文本检测等价的覆盖 | 将 latest remote tools/resources/prompts materialize 成临时文本并复用 Semgrep text rules + char/entropy |
| P1 | Schema-behavior detector | Remote 无源码时最关键的行为一致性等价物 | 先从 remote tool call / observation 表消费 `observed_egress_domains`、`observed_side_effects`，再与 description/schema 对齐 |
| P1 | Typosquatting / namespace reuse | 分发层完全缺失，且实现可先不依赖动态沙箱 | 对 canonical/package name 做 edit distance、confusable、known namespace owner history 检测 |
| P2 | Dynamic sandbox producer | 补强静态误报和发现 malware payload/credential mishandling | 最小化记录 subprocess、file reads/writes、network egress，不必先做全 fuzz |
| P2 | Kind-aware detector metadata | 让覆盖矩阵进入代码而不是文档 | 在 `Detector`/`Analyzer` 增加 `applies_to`，orchestrator 跳过并记录 skipped reason |
