# Rubrik Sentinel — System Design

A snapshot-based data protection and threat detection engine that simulates ransomware attack detection, blast radius analysis, and cyber recovery planning.

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         SentinelEngine                              │
│                    (Main Orchestrator + Simulation Runner)          │
└────────┬──────────────┬──────────────┬──────────────┬──────────────┘
         │              │              │              │
         ▼              ▼              ▼              ▼
    ┌─────────┐   ┌──────────┐  ┌──────────┐  ┌──────────┐
    │  core/  │   │ threat/  │  │recovery/ │  │ policy/  │
    │Snapshot │   │ Threat   │  │ Recovery │  │   SLA    │
    │ Layer   │   │Detection │  │ Planner  │  │  Policy  │
    │         │   │ Pipeline │  │          │  │          │
    └─────────┘   └──────────┘  └──────────┘  └──────────┘
```

---

## Component Diagram

```mermaid
graph TB
    SE[SentinelEngine<br/>Orchestrator]

    subgraph core ["Core Layer — Snapshot & Storage"]
        SM[SnapshotManager<br/>Creates snapshots,<br/>computes SHA-256 + entropy]
        MS[MetadataStore<br/>Thread-safe dual-indexed store<br/>byId / byTime / bySource]
        SN[Snapshot<br/>Immutable point-in-time backup<br/>status: CLEAN / SUSPICIOUS / COMPROMISED]
        FM[FileMetadata<br/>filePath, contentHash,<br/>sizeBytes, shannonEntropy]
    end

    subgraph threat ["Threat Detection Pipeline"]
        TD[ThreatDetector<br/>Orchestrates detection phases]
        IoC[IoCScanEngine<br/>Signature matching<br/>hash / extension / filename pattern]
        AD[AnomalyDetector<br/>Behavioral analysis<br/>entropy spikes / mass mods / ext mutation]
        BR[BlastRadiusAnalyzer<br/>Chain walk,<br/>affected file aggregation]
        TR[ThreatReport<br/>Findings model<br/>severity / affected files / blast %]
    end

    subgraph recovery ["Recovery"]
        RP[RecoveryPlanner<br/>Finds clean recovery point,<br/>generates actionable plan]
    end

    subgraph policy ["Policy"]
        SLA[SLAPolicy<br/>Gold / Silver / Bronze<br/>RPO / retention / scan level]
    end

    SE --> SM
    SE --> TD
    SE --> BR
    SE --> RP

    SM --> MS
    SM --> SN
    SM --> FM
    SN --> FM

    TD --> IoC
    TD --> AD
    TD --> TR
    TD --> MS
    AD --> SN

    BR --> MS
    BR --> SN

    RP --> MS
    RP --> SN

    SE -.->|governed by| SLA
```

---

## Data Flow: Snapshot Creation

```mermaid
sequenceDiagram
    participant SE as SentinelEngine
    participant SM as SnapshotManager
    participant MS as MetadataStore
    participant SN as Snapshot

    SE->>SM: createFromMetadata(sourceId, fileMap)
    SM->>MS: getLatest(sourceId) — get parentId
    MS-->>SM: parentSnapshot (or null)
    SM->>SM: generate snapshotId
    SM->>SM: compute SHA-256 per file
    SM->>SM: compute Shannon entropy per file
    SM->>SN: new Snapshot(id, sourceId, files, parentId)
    Note over SN: files wrapped in<br/>unmodifiableMap()
    SM->>MS: put(snapshot)
    MS->>MS: index byId
    MS->>MS: index byTime (SkipListMap)
    MS->>MS: index bySource
    SM-->>SE: Snapshot
```

---

## Data Flow: Threat Detection Pipeline

```mermaid
sequenceDiagram
    participant SE as SentinelEngine
    participant TD as ThreatDetector
    participant IoC as IoCScanEngine
    participant AD as AnomalyDetector
    participant MS as MetadataStore
    participant SN as Snapshot

    SE->>TD: analyze(snapshotId)
    TD->>MS: get(snapshotId)
    MS-->>TD: current snapshot

    rect rgb(240, 248, 255)
        Note over TD,IoC: Phase 1 — IoC Scan
        TD->>IoC: scan(snapshot)
        loop For each file × IoC rule
            IoC->>IoC: match FILE_HASH / FILE_NAME_PATTERN / FILE_EXTENSION
        end
        IoC-->>TD: List<Finding>
    end

    rect rgb(255, 248, 240)
        Note over TD,AD: Phase 2 — Anomaly Detection
        TD->>MS: get(parentId) — baseline snapshot
        MS-->>TD: baseline
        TD->>AD: detect(current, baseline)
        AD->>SN: current.diffFrom(baseline)
        SN-->>AD: Set<changedFilePaths>
        AD->>AD: check mass modification (>40% → CRITICAL, >15% → MEDIUM)
        AD->>AD: check entropy spikes (Δ>1.5 bits/byte AND >7.8 abs)
        AD->>AD: check extension mutation (double-ext pattern)
        AD-->>TD: List<Finding>
    end

    TD->>TD: aggregate findings
    TD->>SN: markStatus(COMPROMISED / SUSPICIOUS / CLEAN)
    TD-->>SE: ThreatReport
```

---

## Data Flow: Blast Radius Analysis

```mermaid
sequenceDiagram
    participant SE as SentinelEngine
    participant BR as BlastRadiusAnalyzer
    participant MS as MetadataStore
    participant SN as Snapshot

    SE->>BR: analyze(compromisedSnapshotId)
    BR->>MS: get(compromisedSnapshotId)
    MS-->>BR: compromised snapshot
    BR->>MS: getBySource(sourceId)
    MS-->>BR: full snapshot chain (sorted by time)

    loop Walk chain backwards from compromise index
        BR->>SN: current.diffFrom(previous)
        SN-->>BR: Set<changedFiles>
        BR->>BR: count high-entropy files in diff (>7.8 bits/byte)
        alt >30% of diffs are high-entropy
            BR->>BR: add to affectedFiles + affectedSnapshots
        else no high-entropy changes
            BR->>BR: mark as lastClean snapshot → stop walk
        end
    end

    BR->>BR: compute directory breakdown map
    BR-->>SE: BlastRadius(compromised, lastClean, affectedFiles, dirBreakdown)
```

---

## Data Flow: Recovery Planning

```mermaid
sequenceDiagram
    participant SE as SentinelEngine
    participant RP as RecoveryPlanner
    participant MS as MetadataStore
    participant SN as Snapshot

    SE->>RP: createRecoveryPlan(sourceId)
    RP->>MS: getBySource(sourceId)
    MS-->>RP: snapshot chain (newest first)

    loop Walk chain backwards
        RP->>SN: snapshot.status == CLEAN?
        alt CLEAN
            RP->>RP: record as recoveryPoint
            RP->>RP: compute dataLossSeconds
            note over RP: Stop walk
        else COMPROMISED / SUSPICIOUS
            RP->>RP: increment skippedSnapshots
        end
    end

    RP->>RP: generate steps:<br/>1. Halt writes<br/>2. Verify target snapshot<br/>3. Restore N files<br/>4. Validate hashes<br/>5. Re-enable writes<br/>6. Investigate compromised snaps
    RP-->>SE: RecoveryPlan(sourceId, recoveryPoint, steps)
```

---

## Simulation Scenario: 4-Day Ransomware Attack

```mermaid
timeline
    title Ransomware Attack Timeline
    Day 1 : Snapshot snap-0001
          : 10 business files
          : Entropy 4.0–7.2 bits/byte
          : Status CLEAN ✓
    Day 2 : Snapshot snap-0002
          : 2 files edited (normal churn)
          : Low entropy change
          : Status CLEAN ✓
    Day 3 : Snapshot snap-0003
          : 8/10 files encrypted (entropy → 7.95+)
          : Ransom notes dropped
          : CRITICAL IoC hits + mass mods + entropy spikes
          : Status COMPROMISED ✗
    Day 4 : Snapshot snap-0004
          : Remaining 2 files encrypted
          : Continued high entropy
          : Status COMPROMISED ✗
```

**Blast Radius:** 10 affected files across snap-0003 and snap-0004
**Recovery Target:** snap-0002 (Day 2) — 1 day data loss window

---

## Anomaly Detection Thresholds

| Check | Threshold | Severity |
|---|---|---|
| Mass file modification | > 40% of files changed | CRITICAL |
| Mass file modification | > 15% of files changed | MEDIUM |
| Per-file entropy spike | Δ > 1.5 bits/byte AND absolute > 7.8 | HIGH |
| Extension mutation | Double-extension pattern (e.g. `.docx.locked`) | HIGH |
| IoC: ransomware extension | `.locked`, `.encrypted`, `.wnry`, `.cerber`, `.zepto` | HIGH |
| IoC: ransom note | Filename matches `README-DECRYPT`, `restore_files`, etc. | CRITICAL |

---

## SLA Policy Tiers

```
┌──────────────────────────────────────────────────────────────────┐
│  GOLD     │ RPO: 4h   │ Retention: 30d │ Scan: FULL             │
│           │           │                │ (IoC + Anomaly + Blast) │
├──────────────────────────────────────────────────────────────────┤
│  SILVER   │ RPO: 12h  │ Retention: 14d │ Scan: BASIC (IoC only) │
├──────────────────────────────────────────────────────────────────┤
│  BRONZE   │ RPO: 24h  │ Retention: 7d  │ Scan: NONE             │
└──────────────────────────────────────────────────────────────────┘
```

---

## MetadataStore — Indexing Strategy

```
MetadataStore
│
├── byId: ConcurrentHashMap<snapshotId → Snapshot>
│         O(1) lookup by ID
│
├── byTime: ConcurrentSkipListMap<Instant → Snapshot>
│           Ordered; supports getInRange(from, to) time-window queries
│
└── bySource: ConcurrentHashMap<sourceId → List<Snapshot>>
              Lists all snapshots per workload, sorted by creation time
```

---

## Key Design Decisions

| Decision | Rationale |
|---|---|
| Immutable `Snapshot` (unmodifiableMap) | Models air-gapped backups; prevents runtime tampering |
| Entropy pre-computed at ingest | Enables real-time detection without re-reading file data |
| Dual-indexed `MetadataStore` | O(1) by-ID access + ordered time-range queries |
| IoC + Anomaly combined | Catches known threats (signatures) and zero-day (behavior) |
| Chain-walk for blast radius | Determines exactly which snapshots belong to the attack window |
| `volatile` status field on `Snapshot` | Thread-safe status transitions during concurrent detection |
| Stateless detectors | Independently testable; enables parallel execution |
| Policy-driven SLA tiers | Separates governance (what) from execution (how) |

---
