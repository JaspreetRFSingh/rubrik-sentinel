# Sentinel Engine — Design Document

## 1. Problem Statement

Enterprise organizations face a critical vulnerability: traditional backup systems create copies of data but have no awareness of whether that data has been compromised. When ransomware encrypts production data, it often also encrypts recent backups — leaving organizations with no trustworthy recovery point.

Rubrik addresses this by treating backup data as a **security asset**, not just an operational one. Every snapshot becomes a sensor that can detect threats, and the snapshot chain becomes a timeline that can pinpoint exactly when an attack began and how far it spread.

Sentinel implements this philosophy in a self-contained Java application.

---

## 2. Core Abstractions

### 2.1 FileMetadata
**Why immutable records?** In a threat detection system, you need absolute confidence that the metadata you're analyzing hasn't been tampered with after capture. By making `FileMetadata` a final class with no setters, we get compile-time guarantees that analysis results are based on authentic capture-time data.

**Why store entropy at capture time?** Computing Shannon entropy is O(n) in file size. By computing it once during snapshot creation and storing the result, every subsequent analysis (anomaly detection, blast radius) can use it in O(1). This is the same amortization strategy used in production systems where re-reading petabytes of data for each analysis pass would be prohibitively expensive.

### 2.2 Snapshot
The `Snapshot` abstraction has three critical properties:

1. **Immutability** — Once created, the file map cannot be altered. This is the software equivalent of Rubrik's write-once storage.

2. **Chain linkage** — Each snapshot stores its `parentId`, forming a singly-linked list. This enables efficient chain traversal for blast radius analysis without requiring a separate graph data structure.

3. **Status marking** — The `status` field uses `volatile` for thread-safe reads. This is the one mutable field, deliberately designed this way because threat status is *discovered* after creation, not known at creation time.

### 2.3 MetadataStore
The dual-index design deserves explanation:

- **ConcurrentHashMap** (by ID): O(1) amortized lookup. Used when we know which snapshot we want (e.g., following a parent chain).
- **ConcurrentSkipListMap** (by time): O(log n) range queries. Used for time-windowed searches (e.g., "show me all snapshots from the last 24 hours").
- **Source index**: Groups snapshots by protected workload. Enables efficient chain reconstruction without scanning the entire store.

In Rubrik's production architecture, these indexes live in their distributed metadata store (Atlas). The access patterns are identical — the main difference is that Atlas distributes the indexes across a cluster for horizontal scalability.

---

## 3. Threat Detection Pipeline

The pipeline runs three detection engines in sequence:

### 3.1 IoC Scan (Known Threats)
**Approach:** Pattern matching against a database of known Indicators of Compromise.

**Types supported:**
- File hash matching (SHA-256 against known malicious hashes)
- Filename pattern matching (regex against ransomware note filenames)
- Extension matching (known ransomware file extensions)

**Trade-off:** Fast and precise for known threats, but blind to novel attacks. This is why it's paired with anomaly detection.

### 3.2 Anomaly Detection (Unknown Threats)
**Approach:** Statistical comparison between consecutive snapshots.

**Three signals analyzed:**

| Signal | What It Detects | Threshold | False Positive Rate |
|---|---|---|---|
| Entropy spike | Individual file encryption | Δ > 1.5 bits AND absolute > 7.8 | Low (compressed files are already high entropy but stable) |
| Mass modification | Bulk encryption campaign | > 40% of files changed | Medium (large deployments can trigger this) |
| Extension mutation | Ransomware file renaming | Double extension with known suffixes | Very low |

**Why entropy works:** Encryption is mathematically distinguishable from normal data. Encrypted data has Shannon entropy approaching the theoretical maximum of 8.0 bits/byte, while normal documents, code, and images sit between 3.5 and 6.0. A file jumping from 4.2 to 7.98 between snapshots is almost certainly encrypted.

**Why mass modification works:** Normal business operations change 1-5% of files per day. Ransomware typically encrypts 80-100% of accessible files. A 40% threshold catches attacks while avoiding false positives from legitimate bulk operations (though a production system would use adaptive baselines).

### 3.3 Blast Radius Analysis
**Approach:** Backward chain traversal with entropy-aware boundary detection.

Starting from the compromised snapshot, the analyzer walks backwards through the chain. At each step, it checks whether the changes between consecutive snapshots include high-entropy modifications (indicating attack activity). When it reaches a pair of snapshots where changes are normal, it marks the older one as the boundary — the last clean snapshot.

This is a critical distinction from naive approaches that just mark "everything after time T as bad." Ransomware doesn't always attack all files simultaneously — it may encrypt files in waves, and different directories may be hit at different times.

---

## 4. Recovery Planning

The `RecoveryPlanner` answers the most important question after an attack: *"Which snapshot do I recover from?"*

**Algorithm:**
1. Get the full snapshot chain for the affected source
2. Walk backwards from the most recent snapshot
3. Skip any snapshot marked as COMPROMISED or SUSPICIOUS
4. The first CLEAN snapshot found is the recovery target
5. Calculate the data loss window (time between recovery target and latest snapshot)
6. Generate step-by-step recovery instructions

**Why walking backwards matters:** The most recent clean snapshot minimizes data loss. Walking forward from the oldest snapshot would work logically but would miss the opportunity to recover more recent (still clean) data.

---

## 5. Concurrency Model

The system is designed for concurrent access:

- `MetadataStore` uses `ConcurrentHashMap` and `ConcurrentSkipListMap` — both are lock-free for reads and use fine-grained locking for writes.
- `Snapshot.status` is `volatile` — reads are always fresh, writes are atomic for enum values.
- `SnapshotManager.snapshotCounter` uses `AtomicLong` — lock-free monotonic ID generation.

In a production distributed system, these would be replaced with distributed consensus (Raft/Paxos) for the metadata store and distributed counters for ID generation. The concurrency patterns, however, remain conceptually similar.

---

## 6. Extensibility Points

The architecture is designed with clear extension points:

| Extension | Where | How |
|---|---|---|
| New threat detectors | `ThreatDetector` | Add new detection engines alongside IoC and Anomaly |
| Custom IoC rules | `IoCScanEngine.addIoC()` | Inject customer-specific or feed-sourced IoCs at runtime |
| New SLA tiers | `SLAPolicy` | Define new policy presets with custom scan levels |
| Cloud sources | `SnapshotManager` | Replace filesystem walker with cloud API client |
| Storage backends | `MetadataStore` | Swap in-memory maps for a persistent distributed store |

---

## 7. Testing Philosophy

Tests are organized around the three subsystems:

- **SnapshotManagerTest** — Verifies immutability guarantees, diff correctness, entropy computation accuracy, and metadata store indexing.
- **ThreatDetectorTest** — Tests each detection engine independently and in combination. Verifies that clean data passes and attack data is flagged.
- **RecoveryPlannerTest** — Tests recovery point selection logic, edge cases (all compromised, single snapshot), and plan generation.

Each test is independent and creates its own `MetadataStore` instance — no shared state between tests.
