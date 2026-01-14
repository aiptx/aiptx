# AIPT v2 Architecture
## Built ON TOP of 8 AI Pentesting Frameworks

### Module Origins

```
aipt_v2/
├── llm/                    # FROM: AIPTx (litellm-based, 100+ providers)
│   ├── llm.py             # AIPTx: LLM class with caching, vision, reasoning
│   ├── memory.py          # AIPTx: MemoryCompressor (80% threshold)
│   ├── config.py          # AIPTx: LLMConfig dataclass
│   └── utils.py           # AIPTx: Tool invocation parsing
│
├── runtime/               # FROM: AIPTx + HackSynth
│   ├── docker.py          # AIPTx: DockerRuntime (399 lines)
│   ├── terminal.py        # AIPTx: TerminalSession (447 lines)
│   └── sandbox.py         # HackSynth: Container isolation patterns
│
├── tools/                 # FROM: AIPTx + ez-ai-agent
│   ├── executor.py        # AIPTx: Tool executor
│   ├── terminal/          # AIPTx: Terminal tools
│   ├── browser/           # AIPTx: Playwright browser (533 lines)
│   ├── proxy/             # AIPTx: MITM proxy (785 lines)
│   └── security/          # NEW: Security tool wrappers
│       ├── nmap.py
│       ├── nuclei.py
│       ├── sqlmap.py
│       └── ...
│
├── intelligence/          # FROM: pentest-agent + PentestAssistant
│   ├── cve.py             # pentest-agent: CVE scoring (946 lines)
│   ├── exploit_search.py  # pentest-agent: GitHub/ExploitDB searchers
│   ├── rag.py             # PentestAssistant: BGE embeddings
│   └── tool_selection.py  # PentestAssistant: Tool planning
│
├── agents/                # FROM: AIPTx + PentestGPT
│   ├── base.py            # AIPTx: BaseAgent (518 lines)
│   ├── state.py           # AIPTx: Agent state management
│   ├── pentest_agent.py   # NEW: Security-focused agent
│   └── ptt.py             # PentestGPT: Penetration Testing Tree
│
├── interface/             # FROM: AIPTx
│   ├── tui.py             # AIPTx: Rich TUI (1,274 lines)
│   ├── cli.py             # AIPTx: CLI interface
│   └── utils.py           # AIPTx: UI utilities
│
├── database/              # FROM: VulnBot + AIPT v1
│   ├── models.py          # VulnBot: SQLAlchemy models
│   ├── repository.py      # AIPT v1: CRUD operations
│   └── kb.py              # VulnBot: Knowledge base
│
└── api/                   # FROM: AIPT v1
    └── app.py             # AIPT v1: FastAPI endpoints
```

### Feature Matrix

| Feature | Source | Lines | Status |
|---------|--------|-------|--------|
| LLM (litellm) | AIPTx | 513 | Copy |
| Memory Compression | AIPTx | 212 | Copy |
| Docker Runtime | AIPTx | 399 | Copy |
| Terminal Session | AIPTx | 447 | Copy |
| Browser Automation | AIPTx | 533 | Copy |
| Proxy/MITM | AIPTx | 785 | Copy |
| TUI Interface | AIPTx | 1,274 | Copy |
| CVE Intelligence | pentest-agent | 946 | Adapt |
| Exploit Search | pentest-agent | 1,200+ | Adapt |
| Tool RAG | PentestAssistant | 200 | Adapt |
| PTT Tracking | PentestGPT | 400 | Adapt |
| Knowledge Base | VulnBot | 500+ | Adapt |
| Database | AIPT v1 | 616 | Keep |
| REST API | AIPT v1 | 384 | Keep |
| Security Tools | ez-ai-agent | 364 | Adapt |
| Container Setup | HackSynth | 61 | Reference |

### Total Expected Lines: ~8,000-10,000

### Key Improvements Over Individual Tools

1. **Unified LLM Layer** - litellm supports 100+ providers (better than any single tool)
2. **Complete Toolset** - Browser + Terminal + Proxy (from AIPTx)
3. **Security Intelligence** - CVE + Exploit search (from pentest-agent)
4. **Smart Tool Selection** - RAG-based (from PentestAssistant)
5. **Progress Tracking** - PTT (from PentestGPT)
6. **Knowledge Persistence** - Database + KB (from VulnBot + AIPT v1)
7. **Professional Interface** - Rich TUI (from AIPTx)
8. **REST API** - Programmatic access (from AIPT v1)
