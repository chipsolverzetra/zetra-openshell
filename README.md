# zetra-openshell

Behavioral security layer for NVIDIA OpenShell.

**OpenShell controls what your agent can touch.  
Zetra controls what your agent is allowed to decide.**

## The Gap

OpenShell enforces at the infrastructure layer — filesystem, 
network, process boundaries. It cannot see what an agent is 
deciding across a session.

Zetra analyzes behavioral sequences — the multi-step decision 
paths that infrastructure controls cannot see. When a pattern 
matches a known attack sequence, Zetra emits a 
DetectionFindingEvent [OCSF 2004] and hot-reloads a blocking 
policy into OpenShell before the next action executes.

## How It Works

1. Consumes OpenShell's OCSF event stream (NetworkActivityEvent 
   [4001], ProcessActivityEvent [1007])
2. Builds a DFS behavioral graph across the live session
3. Detects known attack sequences in real time
4. Emits DetectionFindingEvent [2004] — natively compatible 
   with any OCSF-compatible SIEM
5. Hot-reloads blocking policy into OpenShell

## Quickstart

### Prerequisites

- [OpenShell](https://github.com/NVIDIA/OpenShell) installed 
  and running
- Rust 1.88+
- A running OpenShell sandbox

### Install
```bash
cargo add zetra-openshell
```

### Run
```bash
# Start monitoring a sandbox
zetra monitor --sandbox <sandbox-id>

# View behavioral graph for a running session
zetra graph --sandbox <sandbox-id>

# Show current BES score
zetra score --sandbox <sandbox-id>
```

### Example Output
```
[ZETRA] Monitoring sandbox abc123...
[ZETRA] Ingested: process.spawn → network.egress → file.write
[ZETRA] PATTERN DETECTED: exfiltration sequence
[ZETRA] Emitting DetectionFindingEvent [2004]
[ZETRA] Policy hot-reloaded → egress blocked
```

## Architecture
```
Agent (OpenClaw, Claude Code, etc.)
        ↓ actions
    OpenShell
  • Filesystem enforcement
  • Network enforcement  
  • Process enforcement
  • OCSF event stream ──────────→ Zetra
  • Policy hot-reload ←────────── Zetra
                              (behavioral graph +
                               pattern detection +
                               BES scoring)
```

## Why This Exists

- CrowdStrike announced "intent-aware controls" at GTC 2026 — 
  listed as in progress
- TrendAI identified agent decision logic as unaddressed in 
  their OpenShell integration
- Futurum analysts stated OpenShell needs a governance layer 
  beyond runtime enforcement

Zetra is that layer.

## Contributing

Zetra uses the same philosophy as OpenShell: 
**agent-assisted, human-accountable.**

You may use AI to write code. You must be able to explain 
every line you submit. PRs where the author cannot answer 
basic questions about their changes will be closed.

### Before You Open a PR

- Read the architecture section above
- Run `cargo test` and ensure all tests pass
- Run `cargo clippy -- -D warnings` with zero warnings
- Run `cargo fmt --check` with no formatting issues

### Commit Style

This project uses Conventional Commits:
```
feat(graph): add cross-session behavioral continuity
fix(ocsf): correct NetworkActivityEvent field mapping
docs: update quickstart with sandbox ID flag
```

### What We Welcome

- New attack pattern definitions in `src/patterns/`
- OCSF event class support expansions
- Performance improvements to the graph traversal
- Integration examples for specific agent types
- Bug fixes with clear reproduction steps

### What We Don't Accept

- AI-generated code the author cannot explain
- PRs without tests
- Changes to core graph methodology without 
  discussion first — this is patent-pending IP

### Opening an Issue

Bug reports should include:
- OpenShell version
- Zetra version  
- The OCSF event sequence that triggered the issue
- Expected vs actual behavior

Feature requests should explain the behavioral 
security use case, not just the technical change.

## Patent

Core DFS-based behavioral graph methodology is patent-pending.

## License

Apache 2.0 — see LICENSE file.

---

Built on top of [openshell-ocsf](https://github.com/NVIDIA/OpenShell) 
(PR #489). Follows OCSF v1.7.0.
