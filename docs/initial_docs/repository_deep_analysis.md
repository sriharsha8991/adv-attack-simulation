# Deep Analysis — Three Repositories

> **Purpose**: Fact-checked, research-backed analysis of each repository. Corrects misconceptions from initial notes and documents exactly what we can learn, borrow, or ignore from each.

---

## Repository 1: Shannon

**Repository**: https://github.com/KeygraphHQ/shannon  
**Stars**: 23.3K | **Forks**: 2.3K | **Language**: TypeScript 87.3% | **License**: AGPL-3.0  
**Tagline**: "Fully autonomous AI hacker to find actual exploits in your web apps"

---

### What Shannon ACTUALLY Is (Critical Correction)

> **Initial assumption in first_thoughts.md was WRONG.** The notes called Shannon an "attack graph engine." It is NOT.

Shannon is a **fully autonomous AI pentester** built on **Anthropic's Claude Agent SDK** (TypeScript). It is designed to:

- Perform **4-phase pentesting**: Reconnaissance → Vulnerability Analysis → Exploitation → Reporting
- **Actually execute real exploits** (not simulate) — inject SQL, bypass auth, SSRF, XSS
- Operate as **white-box only** — requires access to the application's source code
- Run **entirely via Docker** with Temporal for workflow orchestration

Shannon is **NOT**:
- An attack graph engine
- A graph database or graph reasoning tool
- A vulnerability scanner only (it actually exploits)
- Compatible with open-source-only models (requires Anthropic API key)

### Architecture (Verified from README + Source)

```
                    ┌──────────────────────┐
                    │    Reconnaissance    │  ← Nmap, Subfinder, WhatWeb,
                    └──────────┬───────────┘    browser automation
                               │                Source code analysis
                               ▼
                    ┌──────────┴───────────┐
                    │          │           │
                    ▼          ▼           ▼
        ┌─────────────┐ ┌─────────────┐ ┌──────┐
        │ Vuln        │ │ Vuln        │ │ ...  │ ← Parallel per OWASP category
        │ Analysis    │ │ Analysis    │ │      │   Data flow analysis
        │ (Injection) │ │ (XSS)      │ │      │   Input → Sink tracing
        └──────┬──────┘ └──────┬──────┘ └──┬───┘
               │               │           │
               ▼               ▼           ▼
        ┌─────────────┐ ┌─────────────┐ ┌──────┐
        │ Exploitation│ │ Exploitation│ │ ...  │ ← Parallel: real browser
        │ (Injection) │ │ (XSS)      │ │      │   attacks, command exec
        └──────┬──────┘ └──────┬──────┘ └──┬───┘
               │               │           │
               └───────┬───────┴───────────┘
                       ▼
                ┌──────────────┐
                │   Reporting  │  ← "No Exploit, No Report" policy
                └──────────────┘    Only proven vulnerabilities included
```

**Key architectural details**:
- **Core reasoning engine**: Anthropic's Claude Agent SDK
- **Orchestration**: Temporal (workflow engine with checkpointing, resume support)
- **Workspace system**: Each run creates a workspace in `audit-logs/`. Supports resume via git commits per agent
- **Tools**: Nmap, Subfinder, WhatWeb, Schemathesis (OpenAPI testing), browser automation
- **Config**: YAML-based per-target configuration (auth flows, 2FA/TOTP, focus/avoid rules)
- **Output**: `audit-logs/{hostname}_{sessionId}/` containing session.json, per-agent logs, prompt snapshots, final report

### Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | TypeScript (87.3%), JavaScript (7.3%), Shell (3.9%) |
| LLM | Anthropic Claude (required) — Claude 4.5 Sonnet mentioned |
| Orchestration | Temporal (workflow engine) |
| Browser | Built-in browser automation for exploit execution |
| Containers | Docker Compose (worker + Temporal + web UI) |
| Tools | Nmap, Subfinder, WhatWeb, Schemathesis |
| Cost | ~$50 USD per full run (1-1.5 hours) |

### Key Capabilities (Verified from Sample Reports)

Shannon achieved on real applications:
- **OWASP Juice Shop**: 20+ critical vulns. Complete auth bypass + full DB exfiltration via injection. Privilege escalation via registration workflow bypass. IDOR exploitation. SSRF for internal network recon.
- **c{api}tal API**: 15 critical/high vulns. Root-level injection via hidden debug endpoint. Auth bypass via legacy v1 API. Mass Assignment privilege escalation. Zero false positives on XSS.
- **OWASP crAPI**: 15+ critical vulns. JWT attacks (Algorithm Confusion, alg:none, weak kid). Full PostgreSQL DB compromise via injection. SSRF forwarding auth tokens.
- **XBOW Benchmark**: 96.15% success rate (hint-free, source-aware)

### What's NOT in Shannon (Important for Our Use Case)

| Feature We Need | Shannon Has It? | Notes |
|----------------|-----------------|-------|
| Attack graph database | NO | No graph DB, no Neo4j, no knowledge graph |
| Graph-based path finding | NO | Paths are discovered by Claude, not computed |
| CVE database lookup | NO | Finds vulns by code analysis + exploitation, not CVE matching |
| MITRE ATT&CK mapping | NO | Not present in output |
| CWE/CAPEC enrichment | NO | Not present |
| Threat intelligence | NO | Not present |
| Open-source model support | EXPERIMENTAL ONLY | Router mode is "UNSUPPORTED", quality is degraded |
| Python codebase | NO | TypeScript only |

### What We CAN Learn from Shannon

| Lesson | What to borrow | How to adapt |
|--------|---------------|-------------|
| **4-phase architecture** | Recon → Analysis → Exploitation → Report is a clean pipeline | Our pipeline: Recon Analysis → Attack Path Detection → Advisory Report |
| **"No Exploit, No Report" policy** | Only report what's proven — shows rigour | "No Graph Path, No Finding" — only report what Cypher traversal proves |
| **Workspace/resume system** | Each run saves state, can resume | Save agent state + Neo4j graph snapshot per run |
| **Parallel vulnerability analysis** | Different OWASP categories run in parallel | Could parallel-run different attack path queries |
| **YAML-based target config** | Clean target specification format | Use YAML/JSON for target definition |

### Verdict for Our Project

**DISCARDED from active use. Incompatible with requirements.**

Reasons:
1. Requires Anthropic API key (proprietary)
2. TypeScript codebase (we use Python)
3. No graph reasoning capability
4. No CVE/MITRE grounding
5. White-box only (needs source code access)
6. AGPL-3.0 license complications

**Value**: Architectural inspiration only. The 4-phase pipeline and "no exploit no report" philosophy are strong patterns.

---

## Repository 2: CAI (Cybersecurity AI)

**Repository**: https://github.com/aliasrobotics/cai  
**Stars**: 7.2K | **Forks**: 1K | **Language**: Python 98.6% | **License**: MIT  
**Tagline**: "Cybersecurity AI (CAI), the framework for AI Security"

---

### What CAI ACTUALLY Is

CAI is a **lightweight, open-source framework for building cybersecurity AI agents**. It is the most actively developed and academically rigorous project of the three.

CAI is designed to:
- Build and deploy AI-powered offensive and defensive automation
- Support 300+ models via LiteLLM (including Ollama with Qwen2.5, Llama, etc.)
- Provide modular agent architecture with ReACT pattern
- Be "bug bounty-ready" — tested on HackTheBox CTFs and real bug bounty programmes
- Serve as a research platform (8 published arXiv papers)

### Architecture (Verified from README Source)

CAI builds on 8 pillars:

```
                  ┌───────────────┐           ┌───────────┐
                  │      HITL     │◀──────────│   Turns   │
                  └───────┬───────┘           └───────────┘
                          │
                          ▼
┌───────────┐       ┌───────────┐       ┌───────────┐      ┌───────────┐
│  Patterns │◀─────▶│  Handoffs │◀─────▶│   Agents  │◀─────│    LLMs   │
└───────────┘       └─────┬─────┘       └─────┬─────┘      └───────────┘
                          │                   │
                          │                   ▼
┌────────────┐       ┌────┴──────┐       ┌───────────┐     ┌────────────┐
│ Extensions │◀─────▶│  Tracing  │       │   Tools   │◀───▶│ Guardrails │
└────────────┘       └───────────┘       └───────────┘     └────────────┘
                                              │
                          ┌─────────────┬─────┴────┬─────────────┐
                          ▼             ▼          ▼             ▼
                    ┌───────────┐┌───────────┐┌────────────┐┌───────────┐
                    │ LinuxCmd  ││ WebSearch ││    Code    ││ SSHTunnel │
                    └───────────┘└───────────┘└────────────┘└───────────┘
```

### The 8 Pillars — Detailed

#### 1. Agents
- Core abstraction. Each Agent implements the **ReACT** (Reasoning and Action) model
- Defined via: `name`, `instructions` (system prompt), `tools` (list), `model` (LLM config), `handoffs` (list of agents to delegate to)
- Uses `AsyncOpenAI` client internally — OpenAI-compatible API
- Stateless between calls (full conversation history passed each time via Chat Completions API)

**Code pattern** (verified from README):
```python
from cai.sdk.agents import Agent, Runner, OpenAIChatCompletionsModel
agent = Agent(
    name="Custom Agent",
    instructions="You are a Cybersecurity expert Leader",
    model=OpenAIChatCompletionsModel(
        model="openai/gpt-4o",  # or ollama model
        openai_client=AsyncOpenAI(),
    )
)
result = await Runner.run(agent, "Analyse this target")
```

#### 2. Tools
- Built-in tools organised by **security kill chain**:
  1. **Reconnaissance** — `generic_linux_command`, `execute_code`, `web_search`
  2. **Exploitation** — exploit execution tools
  3. **Privilege Escalation** — escalation tools
  4. **Lateral Movement** — lateral movement tools
  5. **Data Exfiltration** — exfiltration tools
  6. **Command & Control** — C2 tools
- Custom tools via `@function_tool` decorator
- Agent-as-tool: one agent can call another like a tool

**Code pattern**:
```python
from cai.sdk.agents import function_tool

@function_tool
def execute_cli_command(command: str) -> str:
    return run_command(command)
```

#### 3. Handoffs
- Allow agent-to-agent delegation
- Implemented as tools for the LLM (LLM calls a "transfer_to_X" function)
- Enable security validation chains (e.g., CTF agent → flag discriminator)

**Code pattern**:
```python
ctf_agent = Agent(
    name="CTF agent",
    tools=[execute_cli_command],
    model=OpenAIChatCompletionsModel(model="qwen2.5:14b", ...),
    handoffs=[flag_discriminator]  # delegate to this agent
)
```

#### 4. Patterns
Formally defined as tuple: AP = (A, H, D, C, E) — Agents, Handoffs, Decision Mechanism, Communication Protocol, Execution Model.

Available patterns:

| Pattern | Description | Our Relevance |
|---------|-------------|---------------|
| **Swarm** (Decentralised) | Peer-to-peer, dynamic handoffs | Not needed for demo |
| **Hierarchical** | Top-level planner → specialised sub-agents | Good fit for multi-agent |
| **Chain-of-Thought** (Sequential) | Agent A → Agent B → Agent C, linear | **Best fit for our 3-agent pipeline** |
| **Auction-Based** | Agents bid on tasks | Overkill |
| **Recursive** | Agent refines its own output iteratively | Useful for report quality |

#### 5. Turns and Interactions
- **Interaction**: One agent executing one reasoning step + zero-to-n tool calls. Defined in `process_interaction()` in `core.py`
- **Turn**: One or more interactions until agent returns `None` (nothing more to do). Defined in `run()` in `core.py`

#### 6. Tracing
- OpenTelemetry standard via Phoenix (Arize AI)
- Detailed visibility into agent interactions, tool usage, token consumption
- Critical for debugging and demo

#### 7. Guardrails
- Input guardrails: prompt injection detection (pattern matching, Unicode homograph, AI-powered)
- Output guardrails: prevent dangerous commands (reverse shells, fork bombs, data exfiltration)
- Multi-layered: input → processing → execution stages
- Base64/Base32 aware
- Configurable via `CAI_GUARDRAILS` env var

#### 8. Human-In-The-Loop (HITL)
- Real-time human intervention via `Ctrl+C` in CLI
- Human can guide, override, or redirect agent
- Design principle: fully autonomous systems are premature for cybersecurity

### Model Support (Verified)

CAI supports 300+ models via LiteLLM:
- **Anthropic**: Claude 3.7, 3.5, 3, Claude 3 Opus
- **OpenAI**: O1, O1 Mini, O3 Mini, GPT-4o, GPT-4.5 Preview
- **DeepSeek**: V3, R1
- **Ollama**: Qwen2.5 72B/14B, etc.
- **OpenRouter**: Any model available on OpenRouter
- **Azure OpenAI**: Enterprise Azure-hosted models
- **Custom endpoint**: Via `OLLAMA_API_BASE` env var → works with Groq!

### MCP Support (Verified)

CAI supports Model Context Protocol for external tool integration:
- **SSE transport**: `CAI>/mcp load http://localhost:9876/sse burp` (load Burp Suite tools)
- **STDIO transport**: `CAI>/mcp load stdio myserver python mcp_server.py`
- Dynamic tool addition: `CAI>/mcp add burp redteam_agent` — adds MCP tools to any agent at runtime
- Demonstrated with 20 Burp Suite tools loaded dynamically

### Key Dependencies

- **LiteLLM**: Model routing layer (300+ models)
- **Phoenix/OpenTelemetry**: Tracing and observability
- **AsyncOpenAI**: Core LLM client (OpenAI-compatible API)
- **Python 3.12**: Required
- **Optional: Docker Compose with Kali Linux**: For full tool availability

### What We CAN Learn/Borrow from CAI

| What | How to use it | Priority |
|------|--------------|----------|
| **Agent abstraction** | `Agent(name, instructions, tools, model)` — clean pattern | HIGH — define our 3 agents this way |
| **@function_tool decorator** | Register any Python function as an agent tool | HIGH — register our Neo4j/CVE/MITRE tools |
| **ReACT implementation** | `process_interaction()` loop in core.py | HIGH — study and replicate in ~150 lines |
| **OpenAI-compatible client** | `AsyncOpenAI()` with custom base URL | HIGH — point at Groq API |
| **Handoffs pattern** | Agent A transfers to Agent B | MEDIUM — useful for our 3-agent chain |
| **Guardrails concept** | Validate agent outputs before execution | LOW — mention in architecture explanation |
| **Kill chain tool organisation** | Tools grouped by attack phase | MEDIUM — reference in design docs |
| **MCP support** | External tool integration | LOW — defer to future version |

### What We Should NOT Use from CAI

| What | Why not |
|------|---------|
| The full CAI framework as dependency | Heavy dependency. Many agents assume Kali Linux. Telemetry collection. |
| Built-in Linux command tools | Tools assume Kali environment. We don't need shell execution. |
| The CLI REPL interface | We're building our own CLI with `click` + `rich` |
| LiteLLM dependency | Unnecessary when we just need `openai` library pointed at Groq |

### Verdict for Our Project

**Inspiration source only — we build our own lightweight agent inspired by CAI's patterns.**

Why we chose to build custom instead of using CAI directly:
1. CAI is ~7K+ lines of code — we need ~150 lines for the core ReACT loop
2. CAI's tools assume Kali Linux environment
3. CAI adds LiteLLM + Phoenix + telemetry overhead
4. Building our own demonstrates understanding of agent internals (interview signal)
5. We only need the OpenAI-compatible client pattern, which is trivial to implement directly

---

## Repository 3: RedAmon (Red Team Automation)

**Repository**: https://github.com/samugit83/redamon  
**Stars**: ~200+ | **Forks**: ~50+ | **Language**: Python + JavaScript | **License**: MIT  
**Tagline**: "Red Team Automation with AI-powered Security Assessment"

---

### What RedAmon ACTUALLY Is

RedAmon is the **most complete reference** for what we're building. It's essentially a working implementation of the system we're designing, with a different tech stack and proprietary models.

RedAmon is:
- A full-stack red team automation platform with **Neo4j attack surface graph**
- A **6-phase reconnaissance pipeline** with automated enrichment
- An **AI-powered security agent** using LangGraph ReAct pattern
- A **Next.js web application** with interactive graph visualisation
- A **Docker Compose stack** (~15 GB total)

### Architecture (Verified from GitHub Research)

```
User Input (domain)
       │
       ▼
┌──────────────────────────────────────────────────────┐
│              6-Phase Reconnaissance Pipeline          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────┐ │
│  │ Domain   │→│ Port     │→│ HTTP     │→│Resource │ │
│  │ Discovery│ │ Scanning │ │ Probing  │ │ Enum    │ │
│  └──────────┘ └──────────┘ └──────────┘ └─────────┘ │
│  ┌──────────────┐ ┌────────────────────┐             │
│  │ Vulnerability│→│ MITRE Enrichment   │             │
│  │ Scanning     │ │ (CWE/CAPEC/ATT&CK) │             │
│  └──────────────┘ └────────────────────┘             │
└───────────────────────────┬──────────────────────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │    Neo4j Graph DB    │
                 │  17 Node Types       │
                 │  20+ Relationship    │
                 │  Types               │
                 └──────────┬───────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │  LangGraph ReAct     │
                 │  Agent               │
                 │  (Text-to-Cypher)    │
                 └──────────┬───────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │  Next.js WebApp      │
                 │  Interactive         │
                 │  Graph Visualisation │
                 └──────────────────────┘
```

### Neo4j Graph Schema — THE MOST VALUABLE ASSET

RedAmon's graph schema is the single most valuable thing across all three repos. It's production-quality and directly reusable.

**17 Node Types** (from graph_db/readmes/GRAPH.SCHEMA.md):

| Category | Node Type | Properties | Purpose |
|----------|-----------|-----------|---------|
| **Infrastructure** | `Domain` | name, registrar, created, updated | Root target anchor |
| | `Subdomain` | name, has_dns, dns_type | Attack surface enumeration |
| | `IP` | address, is_cdn, is_cloud, org, asn | Network location |
| | `Port` | number, protocol, state, reason | Open service identification |
| | `Service` | name, product, version, extra_info, banner | Running software + version |
| | `Technology` | name, version, category | Fingerprinted tech stack |
| | `BaseURL` | url, status_code, content_type | Web application entry points |
| | `Endpoint` | path, method, parameters | API/web endpoints |
| | `Parameter` | name, type, location | Input parameters (injection targets) |
| **Knowledge** | `Vulnerability` | id, name, severity, source, description | Detected vulnerabilities |
| | `CVE` | id, cvss, severity, description, published | Known CVEs from NVD |
| | `MitreData` | cwe_id, cwe_name, description | Weakness classification |
| | `Capec` | capec_id, name, severity, execution_flow | Attack patterns |
| **Enrichment** | `SecretFinding` | type, file_path, entropy, author | Leaked secrets/keys |
| | `Technology` (reused) | — | Shared between infra and knowledge |
| | `GvmResult` | oid, name, severity, qod, solution_type | OpenVAS network scan results |
| | Custom per project | — | Extensible schema |

**20+ Relationship Types**:

| Relationship | From → To | Meaning |
|-------------|-----------|---------|
| `HAS_SUBDOMAIN` | Domain → Subdomain | DNS hierarchy |
| `RESOLVES_TO` | Subdomain → IP | DNS resolution |
| `HAS_PORT` | IP → Port | Open port on host |
| `RUNS_SERVICE` | Port → Service | Service on port |
| `USES_TECHNOLOGY` | Service → Technology | Tech stack |
| `HAS_BASE_URL` | Service → BaseURL | Web app hosted on service |
| `HAS_ENDPOINT` | BaseURL → Endpoint | API/web route |
| `HAS_PARAMETER` | Endpoint → Parameter | Input parameter |
| `HAS_VULNERABILITY` | Technology → Vulnerability | Vulnerable tech |
| `MAPS_TO_CVE` | Vulnerability → CVE | CVE mapping |
| `CVE_HAS_CWE` | CVE → MitreData | Weakness classification |
| `CWE_HAS_CAPEC` | MitreData → Capec | Attack pattern |
| `HAS_SECRET` | Various → SecretFinding | Exposed secrets |
| `FOUND_BY_GVM` | IP → GvmResult | Network vuln scan result |

### 6-Phase Recon Pipeline

| Phase | What it does | Tool | Output |
|-------|-------------|------|--------|
| 1. Domain Discovery | Subdomain enumeration | Subfinder, Amass | Subdomains list |
| 2. Port Scanning | TCP/UDP port scan | Naabu (projectdiscovery) | Open ports |
| 3. HTTP Probing | Alive check, headers, tech | httpx, curl | Live hosts + tech |
| 4. Resource Enumeration | Directories, endpoints, params | brute-force, crawling | Attack surface map |
| 5. Vulnerability Scanning | CVE detection, injection testing | Nuclei, OpenVAS/GVM | Vulnerability list |
| 6. MITRE Enrichment | CWE, CAPEC, ATT&CK mapping | CVE2CAPEC, NVD API | Knowledge graph |

### MCP Tool Servers

RedAmon implements MCP servers for each major tool:
- **Naabu MCP**: Port scanning via MCP protocol
- **Curl MCP**: HTTP requests and header analysis
- **Nuclei MCP**: Vulnerability scanning (~10K+ templates)
- **Metasploit MCP**: Exploit framework integration

### AI Agent Implementation

- **Framework**: LangGraph (part of LangChain ecosystem)
- **Pattern**: ReAct agent with phase transitions
- **Text-to-Cypher**: Natural language → Neo4j queries
- **Phase transitions**: Informational → Exploitation → Post-Exploitation
- **Models used**: Claude Opus 4.6, GPT-5.2 (proprietary — needs adaptation)
- **180+ configurable parameters** per project

### GitHub Secret Hunter

RedAmon includes a Shannon entropy-based secret detection system:
- Scans Git repos for exposed credentials
- Uses Shannon entropy to identify high-entropy strings (potential keys/tokens)
- Stores findings as `SecretFinding` nodes in Neo4j
- Detects: API keys, private keys, passwords, tokens, connection strings

### What We MUST Borrow from RedAmon

| What | Priority | Effort |
|------|----------|--------|
| **Neo4j graph schema** (17 node types, 20+ relationships) | **CRITICAL** | Adapt to our simplified 12-node schema |
| **MITRE enrichment logic** (CVE → CWE → CAPEC mapping) | **HIGH** | Port the CVE2CAPEC approach |
| **6-phase pipeline architecture** | **HIGH** | Adapt as our 3-agent sequential pipeline |
| **Cypher query patterns** for attack path detection | **HIGH** | Study and adapt for our attack path tool |
| **NVD/CVE data loading approach** | **MEDIUM** | Follow same NVD JSON feed parsing |

### What We Should NOT Copy from RedAmon

| What | Why not |
|------|---------|
| LangGraph/LangChain dependency | Heavy framework, complex API. We use lightweight custom agent. |
| Proprietary model usage (Claude, GPT) | We must use open-source models via Groq |
| Full Docker Compose stack (~15GB) | Way too heavy for a prototype demo |
| Next.js web application | We use CLI; web UI is out of scope |
| Live scanning infrastructure | We use pre-loaded simulated data |
| 180+ configuration parameters | Overkill for prototype; use sensible defaults |

### Verdict for Our Project

**Primary architecture reference. Borrow graph schema, enrichment logic, and Cypher patterns.**

RedAmon is the "production version" of what we're building as a prototype. Our job is to take the best architectural ideas and implement them cleanly in a fraction of the complexity:

| RedAmon | Our Prototype |
|---------|---------------|
| 6-phase pipeline with live scanning | 3-agent pipeline with pre-loaded data |
| 17 node types | 12 node types (pruned to essential) |
| LangGraph ReAct agent | Custom ~150-line ReACT loop |
| Claude/GPT | Qwen3 32B / Llama 3.3 70B via Groq |
| Next.js web app + Neo4j Browser | CLI with `rich` + optional Pyvis export |
| Docker Compose (~15GB) | pip install + Neo4j Aura Free |
| 180+ config params | ~10 config values in .env |

---

## Cross-Repository Comparison Matrix

| Feature | Shannon | CAI | RedAmon | Our Prototype |
|---------|---------|-----|---------|---------------|
| **Primary Purpose** | Autonomous exploit execution | Agent framework for security AI | Full-stack red team automation | Post-recon reasoning + reporting |
| **Language** | TypeScript | Python | Python + JS | Python |
| **LLM Models** | Claude only | 300+ (Ollama, OpenAI, etc.) | Claude, GPT | Qwen3 32B, Llama 70B (Groq) |
| **Agent Pattern** | Multi-phase (4 phases) | ReACT with patterns | LangGraph ReAct | Custom ReACT loop (3 agents) |
| **Graph Database** | None | None | Neo4j (17 node types) | Neo4j (12 node types) |
| **Attack Path Detection** | Via LLM exploit attempts | Via agent tool use | Via Cypher queries | Via Cypher queries (deterministic) |
| **CVE Grounding** | None (finds via exploitation) | None (not built-in) | NVD + MITRE enrichment | Local NVD subset + MITRE |
| **MITRE ATT&CK** | None | None | CWE + CAPEC + ATT&CK | CWE + CAPEC + ATT&CK |
| **Threat Intelligence** | None | None | Limited | Pre-curated actor → CVE mapping |
| **Live Scanning** | Yes (Nmap, Subfinder) | Yes (via tools) | Yes (6-phase pipeline) | No (pre-loaded simulated data) |
| **Output** | Markdown report | CLI interaction | Web app + graph viz | CLI + Markdown report + graph |
| **License** | AGPL-3.0 | MIT | MIT | N/A (demo) |
| **Complexity** | High (Docker + Temporal) | Medium (pip install) | Very High (~15GB Docker) | Low (pip install + Neo4j Aura) |
| **Setup Time** | 30+ minutes | 5 minutes | 1+ hour | 2 minutes |

---

## What Each Repository Teaches Us

### From Shannon: The "Why" of Separation
Shannon proves that LLM-driven exploit discovery works but is expensive, slow, and proprietary-dependent. It validates our approach: **separate deterministic reasoning (graph) from generative AI (explanation)**. Shannon uses Claude for everything; we use Cypher for paths and LLM only for interpretation.

### From CAI: The "How" of Agent Construction
CAI provides the exact Python patterns we need: Agent definition, tool registration via decorators, ReACT loop implementation, OpenAI-compatible client usage. Our custom agent is essentially "CAI's core concepts in 150 lines, without the framework overhead."

### From RedAmon: The "What" of Security Domain Modelling
RedAmon provides the domain-specific knowledge we need: graph schema, node types, relationship types, Cypher query patterns, MITRE enrichment logic, and CVE data pipeline. It's the security domain blueprint.

### Combined: Our Unique Contribution
None of these repos combine all three:
1. Deterministic graph reasoning (not LLM reasoning) for attack paths
2. Open-source models for interpretation
3. Structured grounding (CVE + MITRE + Threat Intel)

Our prototype's unique value is this combination, built cleanly in ~2000 lines of Python.
