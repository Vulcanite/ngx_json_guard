# Diagram sources (Mermaid)

Single source of truth for every diagram rendered in the documentation
site (`docs-site/`). Each diagram below is hand-authored Mermaid — no
AI-diagram service was used to generate or render them. The Docusaurus
site renders these blocks client-side via `@docusaurus/theme-mermaid`;
GitHub renders the same blocks natively in this file.

> Note: the original request was to draw these with the Eraser MCP and
> export as Mermaid. That MCP server is not connected in this
> environment, so the diagrams were written directly as Mermaid source —
> which is the same format Eraser exports. If the Eraser MCP becomes
> available, these sources can be round-tripped through it unchanged.

Chart data comes exclusively from the 2026-08-24 benchmark runs
(`BENCHMARK.md`, commit `08851ee`).

---

## 1. Request architecture

*Used on: Why it was built.*

```mermaid
flowchart LR
    C([Client]) --> N[NGINX reads / spools body]
    N --> G{json_guard<br/>structural check}
    G -- "malformed → 400" --> X1([Rejected at the edge])
    G -- "over limit → 413" --> X2([Rejected at the edge])
    G -- "valid structure" --> M[ModSecurity + CRS<br/>full inspection]
    M -- "attack found → 403" --> X3([Blocked])
    M -- "clean → 200" --> U([Upstream app])
    style G fill:#eef4ff,stroke:#3b74d2,stroke-width:2px
    style M fill:#fff3e0,stroke:#e08c2e,stroke-width:2px
    style C fill:#e8f5e9,stroke:#3d9a4f
    style U fill:#e8f5e9,stroke:#3d9a4f
    style X1 fill:#fdecea,stroke:#c0392b
    style X2 fill:#fdecea,stroke:#c0392b
    style X3 fill:#fdecea,stroke:#c0392b
```

## 2. Request lifecycle (sequence)

*Used on: How it works.*

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant N as NGINX (json_guard)
    participant P as Streaming parser
    participant M as ModSecurity + CRS
    participant U as Upstream app

    C->>N: POST /api (Content-Type: application/json)
    N->>N: ngx_http_read_client_request_body()<br/>memory buffers or temp file
    N->>P: feed body in 64 KiB chunks
    alt malformed JSON
        P-->>N: reject
        N-->>C: 400 (body never proxied)
    else over structural limit
        P-->>N: reject
        N-->>C: 413 (body never proxied)
    else valid structure
        P-->>N: OK ($json_guard_inspection_us set)
        N->>M: request continues, body preserved
        M->>U: full inspection, then proxy
    end
```

## 3. Memory model

*Used on: How it works.*

```mermaid
flowchart TB
    subgraph per_request["Per request (pool-allocated)"]
        S["jg_parser_t — fixed ~96 KiB<br/>container stack ≤1024 · limits · counters"]
    end
    subgraph body["Body storage (NGINX-owned)"]
        B1["r->request_body bufs<br/>memory chain"] --> W
        B2["client_body temp file"] --> W["Walker reads<br/>64 KiB chunks"]
    end
    W --> S
    S --> O["Reject / Accept only<br/>no document retained"]
    style S fill:#eef4ff,stroke:#3b74d2,stroke-width:2px
    style W fill:#f3eefc,stroke:#7a4fd2,stroke-width:2px
    style O fill:#e8f5e9,stroke:#3d9a4f
    style B1 fill:#fff8e6,stroke:#c9a227
    style B2 fill:#fff8e6,stroke:#c9a227
```

## 4. Structural classes rejected at the edge

*Used on: Engine comparison.* Count of violation classes (of 11) each
engine rejects itself, from the 51-case structural corpus.

```mermaid
xychart-beta
    title "Structural violation classes rejected at the edge (of 11)"
    x-axis ["Baseline", "JSON Guard", "ModSecurity", "Coraza"]
    y-axis "Classes rejected" 0 --> 11
    bar [0, 11, 7, 6]
```

## 5. Parser throughput by body size

*Used on: Performance results.* Median of 15 passes, single thread,
idle host.

```mermaid
xychart-beta
    title "Parser throughput by body size (MiB/s, single thread)"
    x-axis ["100 KiB", "1 MiB", "10 MiB", "20 MiB"]
    y-axis "MiB/s" 0 --> 300
    bar [260, 271, 265, 264]
```

## 6. Guard inspection time by body size

*Used on: Performance results.* `$json_guard_inspection_us`, median,
guard + ModSecurity + full CRS, 4 workers.

```mermaid
xychart-beta
    title "Guard inspection time by body size (ms, median)"
    x-axis ["~100 B", "1 MiB", "20 MiB"]
    y-axis "milliseconds" 0 --> 100
    bar [0.01, 4.1, 96.3]
```

## 7. Large-body throughput by engine

*Used on: Performance results.* Processor suites, 4 workers. Guard-only
exceeds baseline because the corpus contains bodies the guard rejects
early; baseline must proxy every byte.

```mermaid
xychart-beta
    title "Large-body throughput by engine (MiB/s, 4 workers)"
    x-axis ["Baseline", "Guard only", "ModSecurity", "Guard+ModSecurity", "Coraza"]
    y-axis "MiB/s" 0 --> 180
    bar [127.2, 167.2, 74.8, 105.8, 55.7]
```

## 8. 20 MiB body latency by outcome

*Used on: Performance results.* Median latency: accepted vs CRS-blocked
vs guard-rejected.

```mermaid
xychart-beta
    title "20 MiB body: latency by outcome (ms, median)"
    x-axis ["Accepted (CRS scans)", "Tail SQLi (CRS blocks)", "Malformed tail (guard 400)", "Over limit (guard 413)"]
    y-axis "milliseconds" 0 --> 3000
    bar [2920, 2031, 313, 241]
```

---

### Style conventions used

- Flowcharts: rounded `([...])` terminals for actors/outcomes, straight
  `[...]` for processing stages, `{...}` for decisions; three-color
  semantic palette (blue = guard, orange = ModSecurity/CRS, red = reject,
  green = pass-through) applied via `classDef`-equivalent inline `style`.
- Sequence diagrams: `autonumber`, `alt` lanes for the three validation
  outcomes, `<br/>` for two-line labels to keep frames narrow.
- Charts: `xychart-beta` bars, y-axis maxima set one round step above the
  tallest bar so labels never clip.
