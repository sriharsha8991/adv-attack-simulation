User: refer to #file:first_thoughts.md for intial context 

Do a good research about the repositories we have to build the agentic system (with some attack graph technique we can use mcps or list of tools ) along with some threat intelligence :
https://github.com/KeygraphHQ/shannon
 
https://github.com/aliasrobotics/cai
 
https://github.com/samugit83/redamon
 

we are not allowed to use any proprietory models we have to use opensource models from on premise , 
as per the discussion : given a domain link how can simulate some kind of pentest with agent to identify threats vulnerabilities upfront , and get some report on resources that gets effected from threats what are current vulnerabilities and how we can avoid them.

what I proposed is that using attack graph and Reasoning  combination agent uses the tools identify if there any permission escalations or any lateral movements possible they also suggested the idea of threat intellegence usage as an extra layer and for grounding I suggested for grounding we can use some CVE (common vulunerabilities Exposures ) as one of the tool . 

what they wanted from me is a simple agentic system running locally to check my AI agent engineering capabilities . 

what Im thinking is delivering more than what was expected 120% of expectation , 

Based on all of these tell me the next steps and first do a thorough analysis of how the repositories can be utilised , do the deep thinking and then answer all of them in a structured way and we can discuss on more pointers'

do not decide anything even if you have minimal confusion ask for any clarification questions or doubts 

GitHub Copilot: 

 I'll start by deeply researching all three repositories to understand their capabilities, architecture, and how they can fit into your system. Let me launch parallel research tasks.Now let me research all three repositories in parallel — their README, architecture, tools, and code structure:   



Fetched 2 resources



Fetched 2 resources



Fetched 2 resources

Excellent, I now have deep research on all three repositories. There are **critical corrections** to the initial assumptions in your notes that we need to address before proceeding. Let me present the structured analysis and then clarify some important decisions.

---

## Repository Deep Analysis — Corrected Assessment

### 1. Shannon (KeygraphHQ/shannon) — MAJOR CORRECTION NEEDED

**Your initial notes assumed Shannon is an "attack graph engine." This is WRONG.**

Shannon is actually a **fully autonomous AI pentester** built on **Anthropic's Claude Agent SDK** (TypeScript, 87.3%). It does NOT do attack graph reasoning. It:

- Performs 4-phase pentesting: Recon → Vuln Analysis → Exploitation → Reporting
- **Requires Anthropic API key** (Claude models) — proprietary!
- Uses Nmap, Subfinder, WhatWeb, Schemathesis as recon tools
- Is white-box only (needs source code access)
- The "Router Mode" for alternative providers is marked **"EXPERIMENTAL - UNSUPPORTED"**
- AGPL-3.0 license

**Verdict: Shannon is fundamentally incompatible with your requirements** (open-source-only models, on-premise). Its architecture is Claude-native. Forking and converting it would be more work than building from scratch.

**What you CAN learn from Shannon:**
- Its 4-phase architecture pattern (Recon → Analysis → Exploitation → Report)
- How it structures pentest reports with proof-of-concepts
- Its use of Temporal for workflow orchestration

---

### 2. CAI (aliasrobotics/cai) — BEST FIT for Agent Framework

CAI is a **lightweight, open-source cybersecurity AI framework** (Python 98.6%) that is highly aligned with your needs:

**Why CAI is your strongest candidate:**
- **Natively supports Ollama** (Qwen2.5 72B/14B, etc.) via LiteLLM — 300+ models
- Implements **ReACT agent model** (Reasoning + Action) — exactly what you proposed
- Tools organized by the **security kill chain**: Reconnaissance, Exploitation, Privilege Escalation, Lateral Movement, Data Exfiltration, C&C
- Supports **MCP** (Model Context Protocol) for external tool integration
- Has **Handoffs** for multi-agent delegation (e.g., CTF agent → flag discriminator)
- Multiple **Agentic Patterns**: Swarm, Hierarchical, Chain-of-Thought, Recursive
- Built-in **Guardrails** (prompt injection protection, dangerous command blocking)
- **Human-in-the-loop** (HITL) support
- **Tracing** via OpenTelemetry/Phoenix
- Battle-tested in HackTheBox CTFs and real bug bounties
- MIT license

**How to use it:**
- Use CAI as your **agent orchestration runtime**
- Point it at Ollama with local open-source models
- Add custom tools for: CVE lookup, Neo4j graph queries, MITRE mapping
- Build a custom agentic pattern (Hierarchical) for your pentest pipeline

---

### 3. RedAmon (samugit83/redamon) — BEST FIT for Architecture Reference

RedAmon is the **most complete reference** for what you want to build. It's essentially the system you're describing, already built:

**What RedAmon already has:**
- **Neo4j attack surface graph** with 17 node types, 20+ relationship types
- **Graph schema**: Domain → Subdomain → IP → Port → Service → Technology → Vulnerability → CVE
- **6-phase recon pipeline**: Domain Discovery → Port Scanning → HTTP Probing → Resource Enum → Vuln Scanning → **MITRE Enrichment**
- **CVE enrichment** from NVD with CVSS scores
- **MITRE CWE/CAPEC mapping** — automatic enrichment
- **MCP tool servers**: Naabu (port scan), Curl (HTTP), Nuclei (vuln scan), Metasploit (exploit)
- **LangGraph-based ReAct agent** with phase transitions (Informational → Exploitation → Post-Exploitation)
- **Text-to-Cypher** — natural language to Neo4j queries
- **GitHub Secret Hunter** with Shannon entropy analysis
- **GVM/OpenVAS** network-level scanning (170K+ NVTs)
- 180+ configurable parameters per project
- Next.js webapp with interactive graph visualization
- Docker Compose stack (~15GB total)

**BUT — RedAmon uses proprietary models** (Claude Opus 4.6, GPT-5.2) via LangChain. It would need adaptation to use Ollama/local models.

**How to use it:**
- Fork RedAmon's **Neo4j graph schema and Cypher queries** (this is the attack graph you want)
- Reuse its **recon pipeline architecture** (6-phase pattern)
- Study its **MCP tool server pattern** (dedicated servers per tool)
- Adapt the **agent orchestrator** to use open-source models via Ollama
- Reuse its **CVE enrichment and MITRE mapping logic**

---

Now I have some important clarification questions before I can design the final architecture: 

Asked 4 questions (Strategy, LLM Hardware, Timeline, Scope)

Now I have everything I need. Here's the comprehensive plan.

---

## Plan: Hybrid Agentic Pentest Simulation Engine

**TL;DR**: Build a local agentic pentest simulation engine combining CAI's agent framework (with Ollama-powered open-source LLMs) and RedAmon's Neo4j graph schema for attack surface modeling. Pre-load realistic recon data into Neo4j, build deterministic attack path detection via Cypher, and use the LLM purely for interpretation/explanation — never for discovering paths. The agent uses a ReACT loop with custom tools (CVE lookup, graph query, MITRE mapper, threat intel enricher). Given 8GB VRAM, target Qwen2.5 7B or Llama 3.1 8B via Ollama. 2-week timeline with simulated recon data + real graph reasoning.

**Key architectural decision**: The LLM is an *interpreter*, not the *reasoner*. Neo4j + Cypher handles deterministic attack path computation. This separation is exactly what demonstrates senior-level AI system design thinking.

---

**Steps**

### Phase 1 — Foundation (Days 1–3)

1. **Set up project structure** — Create a Python project with the following layout:
   ```
   cloud_security/
   ├── agent/              # Agent orchestration (CAI-based)
   │   ├── core.py         # Main ReACT loop
   │   ├── agents.py       # Agent definitions
   │   └── patterns.py     # Agentic patterns
   ├── tools/              # Agent tools
   │   ├── graph_query.py  # Neo4j Cypher queries
   │   ├── cve_lookup.py   # CVE grounding
   │   ├── mitre_mapper.py # MITRE ATT&CK mapping  
   │   ├── threat_intel.py # Threat intelligence enrichment
   │   └── attack_path.py  # Attack path detection
   ├── graph/              # Neo4j logic
   │   ├── schema.py       # Graph ontology & setup
   │   ├── loader.py       # Data loader (pre-loaded recon data)
   │   └── queries.py      # Cypher query library
   ├── models/             # LLM wrapper
   │   └── ollama_wrapper.py
   ├── data/               # Pre-loaded datasets
   │   ├── recon_samples/  # Simulated recon JSON
   │   ├── nvd_cve/        # NVD CVE database subset
   │   └── mitre/          # MITRE ATT&CK + CWE/CAPEC
   ├── output/             # Generated reports
   ├── agent.py            # CLI entry point
   └── requirements.txt
   ```

2. **Install CAI framework** — `pip install cai-framework` in a Python 3.12 virtual environment. Configure `.env` with Ollama endpoint. Study CAI's `Agent`, `Tools`, `Handoffs`, and `Runner` abstractions from [src/cai/sdk/agents](https://github.com/aliasrobotics/cai/blob/main/src/cai/sdk/agents) and [src/cai/tools](https://github.com/aliasrobotics/cai/tree/main/src/cai/tools).

3. **Set up Ollama** — Install Ollama on Windows, pull `qwen2.5:7b` (best reasoning at 8GB VRAM — Q4 quantized fits ~4.5GB). Fallback: `llama3.1:8b` or `mistral:7b`. Test basic completions.

4. **Connect Neo4j Aura** — Use the free instance you already created. Test connection with `neo4j` Python driver. Later migrate to Docker for fully on-prem demo.

### Phase 2 — Graph Schema & Data Loading (Days 4–6)

5. **Implement RedAmon-inspired graph schema** — Adapt RedAmon's 17 node types to your use case. Focus on the attack-relevant subset:

   **Node types** (from [RedAmon's schema](https://github.com/samugit83/redamon/blob/master/graph_db/readmes/GRAPH.SCHEMA.md)):
   - `Domain`, `Subdomain`, `IP`, `Port`, `Service`, `Technology`, `BaseURL`, `Endpoint`, `Parameter`
   - `Vulnerability`, `CVE`, `MitreData` (CWE), `Capec` (attack patterns)
   - `Access` (custom: represents privilege levels), `Asset` (custom: crown jewels)

   **Edge types**:
   - `HAS_SUBDOMAIN`, `RESOLVES_TO`, `HAS_PORT`, `RUNS_SERVICE`, `USES_TECHNOLOGY`
   - `HAS_VULNERABILITY`, `MAPS_TO_CVE`, `CVE_HAS_CWE`, `CWE_HAS_CAPEC`
   - `ALLOWS_ACCESS`, `CAN_ESCALATE_TO`, `CAN_MOVE_TO` (custom: lateral movement)

6. **Create realistic pre-loaded recon datasets** — Build 2-3 JSON files simulating scan outputs for fictional targets (e.g., a company with Apache 2.4.49, exposed Redis, misconfigured SSH). Include:
   - Subdomain discovery results (5-10 subdomains)
   - Port scan results (common ports + some interesting ones)
   - Service/version detection
   - Known vulnerable technologies (Apache 2.4.49 → CVE-2021-41773, etc.)

7. **Build graph loader** — Write `graph/loader.py` that takes recon JSON and creates the full Neo4j graph. This replaces the live scanning — the graph appears as if a real scan was performed.

### Phase 3 — CVE Grounding & MITRE Enrichment (Days 5–7)

8. **Build CVE lookup tool** — Download a subset of the NVD JSON feed (focus on CVEs for technologies your simulated targets use: Apache, Nginx, Redis, OpenSSH, MySQL, Node.js, WordPress, etc.). Build a local JSON-based lookup that matches `(technology, version)` → `[CVE list with CVSS, description, impact]`. This is the grounding layer — no LLM hallucination possible.

9. **Build MITRE mapper tool** — Download MITRE ATT&CK Enterprise JSON and CWE/CAPEC datasets. Map:
   - CVE → CWE (weakness classification)
   - CWE → CAPEC (attack pattern)
   - CVE → MITRE ATT&CK technique (e.g., T1190 Exploit Public-Facing Application, T1078 Valid Accounts)
   
   RedAmon uses the [CVE2CAPEC repository](https://github.com/nqminds/CVE2CAPEC) for this mapping — reuse this approach.

10. **Build threat intelligence enricher** — Create a simple enrichment layer that adds context: "CVE-2021-41773 was used by APT groups in real-world campaigns." Use a pre-compiled JSON of high-profile CVE → threat actor mappings (publicly available from MITRE ATT&CK groups data).

### Phase 4 — Attack Path Engine (Days 7–9) — THE CRITICAL DIFFERENTIATOR

11. **Implement deterministic attack path detection via Cypher** — This is where you show graph reasoning capability. Write Cypher queries that:

    - **Find all privilege escalation paths**: 
      `MATCH p = shortestPath((i:Internet)-[*]->(a:Access {level: "root"})) RETURN p`
    - **Detect lateral movement**: 
      Find paths from one compromised service to another internal service
    - **Compute risk-weighted shortest paths**: 
      Weight edges by CVSS severity, find highest-risk attack chains
    - **Identify exposed crown jewels**: 
      How many hops from Internet to Database/Asset nodes?
    - **Find all nodes reachable from a compromise point**

12. **Build risk scoring formula** — Compute per-path risk scores:
    ```
    risk_score = sum(cvss_of_each_vuln_in_path) * exposure_factor * (1 / path_length)
    ```
    Rank attack paths by risk score. This gives deterministic, auditable risk assessment.

13. **Create the `attack_path.py` tool** — Wraps all Cypher-based attack path queries as a tool the agent can invoke. Returns structured JSON with paths, risk scores, and involved CVEs.

### Phase 5 — Agent Orchestration (Days 9–12)

14. **Build the agent using CAI's SDK** — Define 3 specialized agents following CAI's agent abstraction:

    - **Recon Analyst Agent**: Queries Neo4j graph to understand attack surface, identifies exposed services, correlates technologies with CVEs
    - **Attack Path Analyzer Agent**: Runs deterministic Cypher queries for privilege escalation and lateral movement, ranks paths by risk
    - **Security Advisor Agent**: Takes graph results + attack paths, uses LLM to explain findings, provides remediation recommendations, maps to MITRE ATT&CK

    Use CAI's **Hierarchical pattern**: Planner agent delegates to specialists via `Handoffs`.

15. **Implement the ReACT loop** — Each agent follows: Observe (query graph) → Reason (LLM interprets results) → Act (call next tool) → Stop (all paths found). Implement using CAI's `Runner.run()` with custom `function_tool` definitions.

16. **Register tools with agents** — Using CAI's `@function_tool` decorator:
    - `query_attack_surface` — queries Neo4j for target overview
    - `lookup_cve` — matches technology/version to CVEs
    - `find_attack_paths` — runs Cypher shortest-path queries
    - `enrich_mitre` — maps CVE → MITRE technique
    - `assess_risk` — computes risk score for each path
    - `get_threat_intel` — retrieves real-world threat context

### Phase 6 — CLI & Report Generation (Days 12–14)

17. **Build CLI entry point** — `python agent.py --domain example.com --project demo`
    - Loads pre-built recon data into Neo4j (or uses existing graph)
    - Launches the agent pipeline
    - Shows structured logging of each step
    - Generates final report

18. **Generate structured report** — JSON + Markdown output including:
    - Executive summary (LLM-generated)
    - Attack surface overview (from graph)
    - Vulnerability inventory (from CVE grounding)
    - Attack paths ranked by risk (from Cypher queries)
    - MITRE ATT&CK mapping
    - Remediation recommendations (LLM-generated)
    - Reasoning trace (log of all agent decisions)

19. **Add structured logging** — Every tool invocation, agent decision, and result is logged:
    ```
    [INFO] Agent: Querying attack surface for example.com
    [INFO] Graph: 42 nodes, 67 relationships loaded
    [INFO] CVE: 3 vulnerable services detected
    [INFO] Attack Path: 2 privilege escalation chains found
    [INFO] Risk: Critical path score 9.2/10
    [INFO] MITRE: T1190, T1059.004, T1068 mapped
    [INFO] Generating analysis using Qwen2.5 7B...
    ```

20. **Optional: Graph visualization export** — Export the attack graph as a Graphviz DOT file or interactive HTML (using `pyvis` or Neo4j Browser screenshot). Visual attack path diagram strengthens the demo significantly.

---

**Verification**

1. **Unit tests**: Test each tool independently — CVE lookup returns correct matches, Cypher queries find expected paths, MITRE mapper returns valid techniques
2. **Integration test**: Run full pipeline against pre-loaded "vulnerable company" dataset, verify report contains all expected vulnerabilities and attack paths
3. **Demo script**: Prepare a rehearsed CLI demo: 
   - `python agent.py --domain vulncorp.com`
   - Show graph populating in Neo4j Browser (http://localhost:7474 or Aura)
   - Walk through agent's reasoning trace
   - Show final report with attack path visualization
4. **LLM sanity check**: Verify the open-source model (Qwen2.5 7B) produces coherent security explanations. If not, try `mistral:7b` or `llama3.1:8b` and compare

---

**Decisions**

- **Shannon discarded**: It's a Claude-native autonomous pentester, NOT an attack graph engine. Incompatible with open-source-only requirement. The initial notes were based on incorrect assumptions.
- **CAI over LangChain**: CAI provides native Ollama support, security-specific tools, and the ReACT pattern out of the box. LangChain (used by RedAmon) is heavier and less security-focused.
- **RedAmon's graph schema reused**: Its Neo4j ontology with 17 node types is production-quality and exactly what you need. No need to reinvent it.
- **Pre-loaded data over live scanning**: Given 2-week timeline and demo context, pre-loaded realistic data is more reliable for demo. Shows the same architectural depth without Kali Linux infra setup.
- **Qwen2.5 7B as primary model**: Best reasoning capability at 8GB VRAM (Q4 quantized). Good structured output and instruction following. Fallback: Mistral 7B.
- **Deterministic graph reasoning > LLM reasoning**: All attack path computation via Cypher, LLM only interprets. This is the key architectural insight that distinguishes this from a toy project.
- **Neo4j Aura Free for prototype → Docker for final**: As you already decided. Minimal code change needed to switch connection string.

> ## 2nd Conversation

User: Small changes since its just a demo : 
instead relying on cpu memory or basic gpu lets use GROQ api to simulate opensource models response , PLan accordingly and document everything cleanly for easier implementation 

GitHub Copilot: 

 Good pivot. Groq gives you access to much more powerful open-source models (Qwen3 32B, Llama 3.3 70B) with blazing fast inference — perfect for a demo. Let me look at what models are available from your Groq response and revise the plan.  

Read [](file:///d%3A/Sriharsha/professional/cloud_security/tests/response.json#1-1), lines 1 to 1

Read [](file:///d%3A/Sriharsha/professional/cloud_security/tests)

Read [](file:///d%3A/Sriharsha/professional/cloud_security/tests/groq_test.ipynb)

Asked a question (CAI Usage)

Good choice. Here's the revised, clean plan optimized for Groq + custom lightweight agent.

---

## Plan: Agentic Pentest Simulation Engine (Revised — Groq Edition)

**TL;DR**: Build a local agentic pentest simulation engine with a custom lightweight ReACT agent loop, Groq API for fast open-source model inference (Qwen3 32B / Llama 3.3 70B), and Neo4j for deterministic attack graph reasoning. Pre-load realistic recon data, compute attack paths via Cypher, and use the LLM purely for interpretation and reporting. The system demonstrates AI agent engineering, graph-based security reasoning, CVE grounding, and clean separation between deterministic computation and generative AI.

**Interview framing**: "The models run open-source (Qwen3, Llama) — Groq is just accelerating inference. In production, swap Groq URL for `localhost:11434` (Ollama) or a vLLM endpoint. Zero code change — it's OpenAI-compatible."

---

### Groq Model Selection (from your API response)

| Model | Best For | Context | Max Output |
|---|---|---|---|
| `qwen/qwen3-32b` | **Primary reasoning agent** — best structured output + analysis | 131K | 40K |
| `llama-3.3-70b-versatile` | **Complex security explanation** — strongest reasoning | 131K | 32K |
| `llama-3.1-8b-instant` | **Fast tool routing** — low latency for agent decisions | 131K | 131K |
| `meta-llama/llama-4-scout-17b-16e-instruct` | **Backup** — good balance | 131K | 8K |

**Recommended config**: `qwen/qwen3-32b` for main agent reasoning, `llama-3.1-8b-instant` for fast tool selection/routing.

---

### Steps

#### Phase 1 — Foundation (Days 1–3)

**Step 1**: Create project structure

```
cloud_security/
├── agent/
│   ├── __init__.py
│   ├── core.py           # ReACT loop engine
│   ├── agents.py          # Agent definitions (instructions, tools)
│   ├── tool_registry.py   # Tool registration & dispatch
│   └── state.py           # Agent state management
├── tools/
│   ├── __init__.py
│   ├── graph_query.py     # Neo4j attack surface queries
│   ├── attack_path.py     # Cypher-based path detection
│   ├── cve_lookup.py      # CVE grounding from local NVD data
│   ├── mitre_mapper.py    # CVE → CWE → CAPEC → ATT&CK mapping
│   ├── threat_intel.py    # Threat actor / campaign enrichment
│   └── risk_scorer.py     # Per-path risk computation
├── graph/
│   ├── __init__.py
│   ├── schema.py          # Neo4j constraints + indexes
│   ├── loader.py          # Load recon JSON → Neo4j graph
│   ├── queries.py         # Cypher query library
│   └── connection.py      # Neo4j driver wrapper
├── llm/
│   ├── __init__.py
│   └── groq_client.py     # Groq OpenAI-compatible client wrapper
├── data/
│   ├── recon/
│   │   ├── vulncorp.json          # Simulated recon for fictional target
│   │   └── testcompany.json       # Second target for variety
│   ├── cve/
│   │   └── nvd_subset.json        # Curated CVE database (~200 relevant CVEs)
│   ├── mitre/
│   │   ├── attack_techniques.json # ATT&CK Enterprise techniques
│   │   ├── cwe_capec_map.json     # CWE → CAPEC mapping
│   │   └── cve_to_technique.json  # CVE → ATT&CK technique mapping
│   └── threat_intel/
│       └── threat_actors.json     # Known APT → CVE usage data
├── output/
│   └── reports/                   # Generated reports go here
├── config.py              # Central config (Groq key, Neo4j URI, model selection)
├── agent.py               # CLI entry point
├── requirements.txt
├── .env                   # GROQ_API_KEY, NEO4J_URI, NEO4J_PASSWORD
└── README.md
```

**Step 2**: Set up Groq LLM client — `llm/groq_client.py`

Since Groq exposes an OpenAI-compatible API, the client is simply:
- Use `openai` Python library pointed at `https://api.groq.com/openai/v1`
- Build a wrapper with: `chat()` (standard), `chat_with_tools()` (function calling), `chat_json()` (force JSON output)
- Support model switching via config (Qwen3 32B for reasoning, Llama 8B for fast routing)
- Add retry logic, token counting, and cost tracking

**Step 3**: Set up Neo4j connection — `graph/connection.py`

- Use the `neo4j` Python driver with your Aura Free instance credentials
- Create a connection wrapper with `run_query()`, `run_write()`, `clear_project()` methods
- Credentials loaded from .env
- Note to interviewer: "Swap URI to `bolt://localhost:7687` for Docker deployment"

**Step 4**: `requirements.txt`

```
openai>=1.30.0          # Groq uses OpenAI-compatible API
neo4j>=5.20.0           # Neo4j Python driver
python-dotenv>=1.0.0    # Environment variable management
rich>=13.7.0            # Beautiful CLI output + logging
pydantic>=2.7.0         # Structured data models
click>=8.1.0            # CLI framework
```

No heavy frameworks. Minimal, professional dependencies.

---

#### Phase 2 — Custom ReACT Agent Engine (Days 3–5)

**Step 5**: Build the ReACT loop — `agent/core.py`

The heart of the system. A lightweight ReACT engine (~150 lines) that:

1. Takes a **goal** (e.g., "Analyze attack surface for vulncorp.com and identify all privilege escalation paths")
2. Sends the goal + available tools to the LLM via Groq's function calling API
3. LLM responds with either a **tool call** or a **final answer**
4. If tool call → execute the tool, append result to conversation history, loop back
5. If final answer → return result
6. Stop conditions: max iterations reached, or agent signals completion

Key design decisions:
- **Stateless between turns** (like CAI) — full conversation history passed each time
- **Structured tool definitions** — each tool registered as an OpenAI-format function schema
- **Observation/Action logging** — every step logged with timestamps for reasoning trace
- **Configurable max iterations** (default: 20)
- **Error handling** — if tool fails, error is passed back to LLM to reason about

**Step 6**: Define agents — `agent/agents.py`

Three agent personas with distinct system prompts and tool access:

1. **Recon Analyst**: "You are a security analyst examining a target's attack surface stored in a Neo4j graph. Query the graph to understand exposed services, technologies, and vulnerabilities. Be systematic: first map the surface, then identify vulnerabilities, then assess risk."
   - Tools: `query_attack_surface`, `lookup_cve`, `enrich_mitre`

2. **Attack Path Analyzer**: "You are a penetration testing expert. Using the attack graph, identify all possible privilege escalation chains and lateral movement paths. Rank by risk. Be deterministic — only report what the graph proves."
   - Tools: `find_attack_paths`, `find_lateral_movement`, `compute_risk_score`

3. **Security Advisor**: "You are a senior security consultant. Given the attack surface analysis and discovered attack paths, write a clear executive summary, explain each risk in business terms, and provide specific remediation steps. Map all findings to MITRE ATT&CK tactics."
   - Tools: `get_threat_intel`, `generate_report_section`

**Step 7**: Build orchestrator — `agent/core.py` (the `run_pipeline()` function)

A sequential orchestration that runs all three agents in order:
1. Recon Analyst runs → produces structured attack surface summary
2. Attack Path Analyzer runs → produces ranked list of attack paths
3. Security Advisor runs → produces final report

Each agent's output feeds into the next agent's context. This is a simple Chain-of-Thought pattern (no complex handoffs needed for demo).

---

#### Phase 3 — Neo4j Graph Schema & Data Loading (Days 4–6)

**Step 8**: Define graph schema — `graph/schema.py`

Adapted from RedAmon's proven schema. Create these constraints and indexes:

**Node labels** (12 types):
- `Domain` (name, registrar, created)
- `Subdomain` (name, has_dns)
- `IP` (address, is_cdn)
- `Port` (number, protocol, state)
- `Service` (name, product, version, banner)
- `Technology` (name, version, category)
- `Vulnerability` (id, name, severity, source, description)
- `CVE` (id, cvss, severity, description, published)
- `MitreData` (cwe_id, cwe_name)
- `Capec` (capec_id, name, severity, execution_flow)
- `Access` (level: "internet" | "user" | "admin" | "root" | "database")
- `Asset` (name, type, criticality: "low" | "medium" | "high" | "critical")

**Relationship types** (15):
- `HAS_SUBDOMAIN`, `RESOLVES_TO`, `HAS_PORT`, `RUNS_SERVICE`
- `USES_TECHNOLOGY`, `HAS_VULNERABILITY`, `MAPS_TO_CVE`
- `CVE_HAS_CWE`, `CWE_HAS_CAPEC`
- `EXPOSES` (Internet → Service), `ALLOWS_ACCESS` (Vuln → Access level)
- `CAN_ESCALATE_TO` (Access → Access), `CAN_MOVE_TO` (Service → Service)
- `CAN_ACCESS` (Access → Asset), `EXPLOITED_BY` (CVE → Technique)

**Step 9**: Create realistic simulated recon data — `data/recon/vulncorp.json`

A fictional company "VulnCorp" with realistic vulnerabilities:

```
vulncorp.com
├── www.vulncorp.com     → 192.168.1.10 → Port 80 (Apache 2.4.49), Port 443 (HTTPS)
├── api.vulncorp.com     → 192.168.1.11 → Port 8080 (Node.js 16.x), Port 443
├── mail.vulncorp.com    → 192.168.1.12 → Port 25 (Postfix 3.5.6), Port 143 (Dovecot)
├── db.vulncorp.com      → 192.168.1.20 → Port 3306 (MySQL 5.7.38), Port 6379 (Redis 6.0 NO AUTH)
├── admin.vulncorp.com   → 192.168.1.10 → Port 8443 (WordPress 5.8.1)
└── dev.vulncorp.com     → 192.168.1.30 → Port 22 (OpenSSH 7.6), Port 9200 (Elasticsearch 7.10)
```

**Pre-mapped vulnerabilities:**
- Apache 2.4.49 → CVE-2021-41773 (Path Traversal + RCE, CVSS 9.8)
- MySQL 5.7.38 → CVE-2022-21417 (Auth bypass, CVSS 7.5)
- Redis 6.0 no auth → CVE-2022-0543 (RCE via Lua sandbox escape, CVSS 10.0)
- WordPress 5.8.1 → CVE-2021-44223 (Privilege escalation, CVSS 9.8)
- OpenSSH 7.6 → CVE-2018-15473 (User enumeration, CVSS 5.3)
- Elasticsearch 7.10 → CVE-2021-22145 (Info disclosure, CVSS 6.5)

**Pre-built attack paths (what Cypher should find):**
1. Internet → Apache RCE → User Shell → Redis (no auth) → Root → Database (critical)
2. Internet → WordPress Admin → Privilege Escalation → Admin → LAN → SSH to Dev Server
3. Internet → Elasticsearch Info Disclosure → API credentials → API Server

**Step 10**: Build graph loader — `graph/loader.py`

Reads `vulncorp.json`, creates all nodes and relationships in Neo4j. Also creates the `Access` and `Asset` nodes needed for attack path reasoning. The loader:
- Clears existing project data
- Creates infrastructure nodes (Domain → Subdomain → IP → Port → Service)
- Creates technology nodes and links
- Creates vulnerability and CVE nodes from the curated CVE data
- Creates privilege-level nodes (Internet, User, Admin, Root)
- Creates edges representing how vulnerabilities grant access
- Logs node/relationship counts

---

#### Phase 4 — Tool Implementation (Days 6–9)

**Step 11**: `tools/graph_query.py` — Attack Surface Query Tool

Functions the agent can call:
- `get_attack_surface(domain)` → Returns summary: subdomains, IPs, open ports, services, technologies
- `get_vulnerabilities(domain)` → Returns all vulnerabilities grouped by severity
- `get_service_details(ip, port)` → Returns detailed info about a specific service
- `get_technologies_with_cves(domain)` → Returns technologies matched to known CVEs

Each function runs a Cypher query and returns structured JSON.

**Step 12**: `tools/attack_path.py` — Attack Path Detection Tool (THE DIFFERENTIATOR)

Deterministic graph-based attack path reasoning:
- `find_escalation_paths(domain)` → Cypher: finds all paths from Internet node to root/admin Access nodes via vulnerability exploitation edges
- `find_lateral_movement(domain)` → Cypher: finds paths between internal services reachable after initial compromise
- `find_shortest_path_to_asset(domain, asset_type)` → Cypher: shortest weighted path from Internet to critical assets
- `get_all_reachable_nodes(start_node)` → Cypher: compute reachable subgraph from a compromise point

Key Cypher example for privilege escalation:
```cypher
MATCH p = (internet:Access {level: "internet"})-[:EXPOSES]->
  (s:Service)-[:HAS_VULNERABILITY]->(v:Vulnerability)-[:MAPS_TO_CVE]->(c:CVE)
  -[:ALLOWS_ACCESS]->(a1:Access)-[:CAN_ESCALATE_TO*1..3]->(a2:Access {level: "root"})
WHERE c.cvss >= 7.0
RETURN p, reduce(risk = 0, c IN nodes(p) WHERE c:CVE | risk + c.cvss) AS path_risk
ORDER BY path_risk DESC
```

This is pure graph computation. No LLM. Deterministic. Auditable.

**Step 13**: `tools/cve_lookup.py` — CVE Grounding Tool

- `lookup_cve(technology, version)` → Searches local NVD subset JSON, returns matching CVEs with CVSS, description, impact
- `get_cve_details(cve_id)` → Returns full CVE record
- `get_critical_cves(domain)` → Returns all CVEs with CVSS >= 9.0

Data source: Pre-curated `data/cve/nvd_subset.json` containing ~200 CVEs for common technologies. Downloaded from NVD JSON feeds, filtered to relevant technologies.

**Step 14**: `tools/mitre_mapper.py` — MITRE Enrichment Tool

- `map_cve_to_mitre(cve_id)` → Returns: CWE weakness + CAPEC attack pattern + ATT&CK technique
- `get_attack_tactics(domain)` → Returns all ATT&CK tactics/techniques found across all CVEs
- `get_kill_chain_coverage(domain)` → Maps findings to Cyber Kill Chain phases

Data source: Pre-curated from MITRE's STIX/JSON exports.

Example mapping:
```
CVE-2021-41773 → CWE-22 (Path Traversal) → CAPEC-126 (Path Traversal)
  → T1190 (Exploit Public-Facing Application) → Initial Access tactic
```

**Step 15**: `tools/threat_intel.py` — Threat Intelligence Enrichment

- `get_threat_context(cve_id)` → Returns known threat actor usage, real-world campaigns
- `get_exploitability(cve_id)` → Returns EPSS score, known-exploited status (CISA KEV)

Pre-curated from public sources:
```json
{
  "CVE-2021-41773": {
    "known_exploited": true,
    "cisa_kev": true,
    "threat_actors": ["APT groups", "Ransomware operators"],
    "first_seen_wild": "2021-10",
    "epss_score": 0.975
  }
}
```

**Step 16**: `tools/risk_scorer.py` — Risk Scoring

- `compute_path_risk(path)` → Formula: `sum(cvss) × (1/path_length) × exposure_factor × exploitability_factor`
- `rank_all_paths(domain)` → Returns all paths ranked by composite risk score
- `compute_domain_risk(domain)` → Overall risk score for the target

---

#### Phase 5 — CLI & Report Generation (Days 10–12)

**Step 17**: Build CLI entry point — `agent.py`

Using `click` for clean CLI:
```bash
python agent.py scan --domain vulncorp.com
python agent.py report --domain vulncorp.com --format markdown
python agent.py graph --domain vulncorp.com --export graphviz
```

The `scan` command:
1. Loads recon data into Neo4j (simulating a scan)
2. Runs the 3-agent pipeline
3. Prints structured logs using `rich` library
4. Generates report in `output/reports/`

**Step 18**: Structured logging using `rich`

```
[12:00:01] ▶ Loading attack surface for vulncorp.com
[12:00:02] ✓ Graph loaded: 42 nodes, 67 relationships
[12:00:02] ▶ Agent 1/3: Recon Analyst starting...
[12:00:03]   → Tool: query_attack_surface("vulncorp.com")
[12:00:03]   ← Result: 6 subdomains, 12 open ports, 8 services
[12:00:04]   → Tool: lookup_cve("Apache", "2.4.49")
[12:00:04]   ← Result: CVE-2021-41773 (CVSS 9.8, RCE)
[12:00:05] ✓ Recon Analyst complete: 6 vulnerabilities identified
[12:00:05] ▶ Agent 2/3: Attack Path Analyzer starting...
[12:00:06]   → Tool: find_escalation_paths("vulncorp.com")
[12:00:06]   ← Result: 3 privilege escalation paths found
[12:00:07]   → Tool: compute_risk_score(path_1)
[12:00:07]   ← Result: Risk score 9.4/10 (CRITICAL)
[12:00:08] ✓ Attack Path Analyzer complete: 3 paths, max risk 9.4
[12:00:08] ▶ Agent 3/3: Security Advisor starting... [Qwen3 32B]
[12:00:12] ✓ Report generated: output/reports/vulncorp_report.md
```

**Step 19**: Report generation — Markdown report with sections:

1. **Executive Summary** (LLM-generated, 3-5 sentences)
2. **Attack Surface Overview** (from graph — nodes, edges, stats table)
3. **Vulnerability Inventory** (from CVE grounding — table with severity, CVSS, affected service)
4. **Attack Paths** (from Cypher — each path visualized as chain with risk score)
5. **MITRE ATT&CK Mapping** (from MITRE mapper — table of techniques per finding)
6. **Threat Intelligence Context** (from threat intel tool — real-world relevance)
7. **Remediation Recommendations** (LLM-generated, specific per vulnerability)
8. **Reasoning Trace** (full agent tool-call log — shows engineering maturity)

**Step 20**: Optional — `pyvis` interactive graph export

Export Neo4j attack graph as an interactive HTML file. Nodes colored by type, edges labeled with relationship type, attack paths highlighted in red. Opens in browser for demo.

---

#### Phase 6 — Polish & Demo Prep (Days 12–14)

**Step 21**: Create a second target dataset (`testcompany.json`) for variety. Different vulnerability profile to show the system generalizes.

**Step 22**: Prepare demo script:
1. Show the architecture diagram (draw.io or ASCII)
2. Run `python agent.py scan --domain vulncorp.com` — watch the agent work
3. Open Neo4j Browser (Aura) — show the attack graph visually
4. Show the generated report
5. Explain architectural decisions
6. Show how easy it is to swap Groq for Ollama (change 1 env var)

**Step 23**: Create `README.md` with:
- Architecture diagram
- Setup instructions
- Design decisions
- How to add new tools
- How to swap to on-premise (Ollama)

---

### Verification

1. **Tool unit tests**: Each tool returns expected output for known inputs
2. **Integration test**: Full pipeline produces valid report for `vulncorp.com`
3. **LLM output quality**: Run same pipeline with Qwen3 32B vs Llama 3.3 70B, compare report quality
4. **Failover test**: Set Groq key to invalid → system should error gracefully with clear message
5. **Demo rehearsal**: Timed run-through, target < 5 min for full scan-to-report

### Decisions

- **Groq over Ollama**: Groq provides Qwen3 32B and Llama 3.3 70B at 500+ tokens/sec. Ollama on 8GB VRAM limits you to Qwen2.5 7B. For demo quality, Groq is massively better. Tell interviewer: "Same open-source models — just faster inference. Swap one URL for on-prem."
- **Primary model — `qwen/qwen3-32b`**: 131K context, 40K max output, strong structured JSON output and security reasoning. Llama 3.3 70B is backup.
- **Custom agent over CAI**: ~150 lines vs heavy framework. Shows you understand agent internals, not just framework usage. CAI's patterns (ReACT, Handoffs, Guardrails) are referenced in architecture explanation.
- **Sequential 3-agent pipeline over complex multi-agent**: For a demo, reliability beats complexity. Three focused agents chained sequentially is debuggable and explainable.
- **`rich` library for CLI output**: Beautiful terminal output with colors, tables, progress bars. Makes the demo visually impressive with minimal effort.
- **Pre-curated CVE/MITRE data over live API calls**: NVD API has rate limits and can be slow. Pre-curated JSON is instant, reliable, and the data quality is identical. Tell interviewer: "Production version adds NVD API refresh — same grounding, live data."