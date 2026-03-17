# Sentinel Engine

**A snapshot-based data protection and threat detection engine built in Java — modeled after core patterns used in modern data security platforms (e.g., Rubrik Security Cloud).**

---

## Why This Project Exists

Modern data security platforms protect enterprise data across cloud, SaaS, and on‑prem environments — but at their core, they solve a deeply technical problem:

> *How do you detect that a ransomware attack has compromised your backups, figure out exactly how far the damage goes, and automatically find the safest point to recover from — across petabytes of data?*

This project implements a working miniature of that pipeline. It's not a toy — the algorithms (Shannon entropy analysis, IoC pattern matching, blast radius graph traversal) are the same foundational techniques used in production threat detection systems.

---

## What It Does

Sentinel simulates a **4-day ransomware attack scenario** and demonstrates five capabilities that map to common features in enterprise data security products:

| Sentinel Component | Industry Feature Equivalent | What It Does |
|---|---|---|
| `SnapshotManager` | Immutable Snapshots | Creates immutable, versioned point-in-time captures with SHA-256 content hashing |
| `IoCScanEngine` | Threat Monitoring | Scans backup data against known Indicators of Compromise (file hashes, ransomware extensions, ransom note patterns) |
| `AnomalyDetector` | Anomaly Detection | Detects behavioral attack signals: entropy spikes, mass file modification, extension mutation |
| `BlastRadiusAnalyzer` | Threat Hunt | Walks the snapshot chain backwards to map exactly which files and snapshots were affected |
| `RecoveryPlanner` | Cyber Recovery | Identifies the optimal clean recovery point and generates an actionable recovery plan |

---

## Architecture

```
                    ┌──────────────────────────────────────────┐
                    │           SentinelEngine (main)          │
                    │         Orchestrates the pipeline        │
                    └────────┬──────────┬──────────┬───────────┘
                             │          │          │
              ┌──────────────▼──┐  ┌────▼────┐  ┌─▼──────────────┐
              │ SnapshotManager │  │ Threat  │  │ RecoveryPlanner │
              │                 │  │Detector │  │                 │
              │ • File walking  │  │         │  │ • Chain walking │
              │ • SHA-256 hash  │  │ • IoC   │  │ • Clean point   │
              │ • Entropy calc  │  │ • Anomal│  │   identification│
              │ • Immutability  │  │ • Blast │  │ • Plan gen      │
              └────────┬────────┘  └────┬────┘  └────────┬────────┘
                       │               │                 │
                       └───────────────▼─────────────────┘
                              ┌──────────────┐
                              │MetadataStore │
                              │              │
                              │ • ConcurrentHashMap (by ID)
                              │ • ConcurrentSkipListMap (by time)
                              │ • Source index (by workload)
                              └──────────────┘
```

### Key Design Decisions

**1. Immutability as a security primitive**
Every `Snapshot` wraps its file map in `Collections.unmodifiableMap()`. This isn't just good practice — it's the software analog of air‑gapped, immutable backups used by modern platforms. If you can't mutate a snapshot after creation, an attacker who compromises the application can't silently alter backup data.

**2. Entropy-based detection over signature-only**
Signature-based IoC scanning catches known threats but misses zero-day ransomware. Shannon entropy analysis catches the *behavior* of encryption regardless of the specific malware variant. Sentinel runs both in parallel — a common pattern in production threat detection pipelines.

**3. Dual-indexed metadata store**
The `MetadataStore` maintains both a hash map (O(1) by ID) and a skip list map (ordered by time) concurrently. This supports the two dominant access patterns in backup systems: "get me snapshot X" and "show me all snapshots between Tuesday and Thursday." In large-scale architectures, this dual-index often lives in a distributed metadata store.

**4. Blast radius as a graph problem**
When an attack is detected, the `BlastRadiusAnalyzer` doesn't just flag the current snapshot. It walks the entire snapshot chain backwards, using entropy analysis at each step to determine which snapshots are part of the attack versus normal operations. This is what enables "last known good" recovery in enterprise platforms.

---

## Running It

### Prerequisites
- Java 17+
- Maven 3.8+

### Build & Run
```bash
# Build the project
mvn clean package -q

# Run the ransomware simulation
java -jar target/rubrik-sentinel-1.0.0.jar
```

### Run Tests
```bash
mvn test
```

The test suite covers 16 cases across snapshot management, threat detection, and recovery planning.

---

## Sample Output

```
═══ DAY 3 — ⚠ RANSOMWARE ATTACK ⚠ ═══════════════════════════
Created: Snapshot{id='snap-production-fileserver-0003', files=12, status=CLEAN}
  Changed files: 12 — mass modification!

═══ RUNNING THREAT DETECTION PIPELINE ═════════════════════════
Scanning Day 3 (attack day)...
  Result: ✗ THREATS FOUND
╔══════════════════════════════════════════════════╗
║           SENTINEL THREAT REPORT                ║
║  Scanned      : 12    files                     ║
║  Affected     : 10    files  (83.3% blast radius)║
║  Severity     : CRITICAL                        ║
║  [CRITICAL] IoC match: Ransomware decryption instructions detected
║    → File: how.to.decrypt.html
║  [HIGH] Entropy spike: 4.30 → 7.98 bits/byte (+3.68). File likely encrypted.
║    → File: finance/q4-report.xlsx.locked
╚══════════════════════════════════════════════════╝

═══ CYBER RECOVERY PLAN ═══════════════════════════════════════
║  1. HALT all writes to source 'production-fileserver'
║  2. VERIFY recovery target snapshot: snap-production-fileserver-0002
║  3. RESTORE 10 files from snapshot to production environment.
║  4. VALIDATE restored data integrity using content hashes.
║  5. RE-ENABLE writes after validation passes.
║  6. INVESTIGATE 2 compromised snapshots for forensic analysis.
```

---

## Project Structure

```
rubrik-sentinel/
├── pom.xml
├── README.md
├── docs/
│   └── DESIGN.md              # Detailed design rationale
├── src/
│   ├── main/java/com/sentinel/
│   │   ├── SentinelEngine.java        # Entry point + simulation
│   │   ├── core/
│   │   │   ├── FileMetadata.java      # Immutable file metadata record
│   │   │   ├── Snapshot.java          # Immutable snapshot with diffing
│   │   │   ├── SnapshotManager.java   # Snapshot creation + SHA-256 + entropy
│   │   │   └── MetadataStore.java     # Dual-indexed concurrent store
│   │   ├── threat/
│   │   │   ├── ThreatReport.java      # Findings model with severity
│   │   │   ├── IoCScanEngine.java     # Pattern-matching IoC scanner
│   │   │   ├── AnomalyDetector.java   # Entropy + behavioral analysis
│   │   │   ├── BlastRadiusAnalyzer.java  # Attack scope computation
│   │   │   └── ThreatDetector.java    # Pipeline orchestrator
│   │   ├── recovery/
│   │   │   └── RecoveryPlanner.java   # Clean recovery point + plan gen
│   │   └── policy/
│   │       └── SLAPolicy.java         # Declarative SLA definitions
│   └── test/java/com/sentinel/
│       ├── SnapshotManagerTest.java
│       ├── ThreatDetectorTest.java
│       └── RecoveryPlannerTest.java
```

---

## Alignment with Data Security Engineering Domains

This project was designed to demonstrate competencies across multiple data security engineering domains (for example, teams you’d find at vendors like Rubrik):

**Data Threat Analytics (DTA)**
- IoC scanning engine with extensible rule database
- Shannon entropy-based ransomware detection
- Blast radius computation across snapshot chains

**Cloud Native Protection**
- Immutable snapshot abstraction with content-addressable hashing
- SLA-policy-driven architecture (declarative, not imperative)
- Designed for extensibility to cloud workloads (the `sourceId` abstraction)

**Continuous Product Development (CPD)**
- Distributed data structures (ConcurrentSkipListMap, ConcurrentHashMap)
- Filesystem traversal with fault tolerance (partial-success model)
- Clean separation of concerns: core / threat / recovery / policy

---

## What I'd Build Next

If this were a production system, the natural extensions would be:

1. **Distributed execution** — Partition the snapshot scan across worker nodes using consistent hashing, so scanning scales linearly with cluster size.
2. **YARA rule integration** — Replace the simple IoC pattern matching with a YARA engine for industry-standard threat signatures.
3. **Incremental snapshots** — Use content-defined chunking (like Rubrik's CDC) to only capture changed blocks, reducing storage by 10-50x.
4. **gRPC API layer** — Expose the pipeline as a set of gRPC services for integration with cloud-native orchestration.
5. **Real-time streaming** — Process file change events as a stream (Kafka/Kinesis) instead of batch snapshots for sub-minute RPO.

---

*Built as a portfolio project to demonstrate systems engineering and security thinking in the data protection and threat detection domain.*
