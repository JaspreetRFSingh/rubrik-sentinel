package com.sentinel.core;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.stream.Collectors;

/**
 * Thread-safe, indexed metadata store for snapshot management.
 *
 * In Rubrik's architecture, the metadata store is a distributed, strongly-consistent
 * database (built on top of their custom Atlas distributed filesystem) that tracks
 * every snapshot, every protected object, and every SLA policy. It must support:
 *   - O(1) lookup by snapshot ID
 *   - Time-range queries (find all snapshots between T1 and T2)
 *   - Source-based filtering (all snapshots for a given workload)
 *
 * This implementation uses ConcurrentSkipListMap (ordered by time) backed by a
 * ConcurrentHashMap (indexed by ID) to support both access patterns lock-free.
 * This mirrors the dual-index pattern common in distributed metadata stores.
 */
public class MetadataStore {

    // Primary index: snapshotId -> Snapshot (O(1) lookup)
    private final ConcurrentHashMap<String, Snapshot> byId = new ConcurrentHashMap<>();

    // Time index: createdAt -> snapshotId (ordered, supports range queries)
    private final ConcurrentSkipListMap<Instant, List<String>> byTime = new ConcurrentSkipListMap<>();

    // Source index: sourceId -> ordered list of snapshotIds
    private final ConcurrentHashMap<String, List<String>> bySource = new ConcurrentHashMap<>();

    /** Stores a snapshot. Idempotent — re-storing the same ID is a no-op. */
    public void put(Snapshot snapshot) {
        if (byId.putIfAbsent(snapshot.snapshotId(), snapshot) != null) {
            return; // already exists
        }

        byTime.computeIfAbsent(snapshot.createdAt(), k -> Collections.synchronizedList(new ArrayList<>()))
              .add(snapshot.snapshotId());

        bySource.computeIfAbsent(snapshot.sourceId(), k -> Collections.synchronizedList(new ArrayList<>()))
                .add(snapshot.snapshotId());
    }

    /** O(1) lookup by snapshot ID. */
    public Optional<Snapshot> get(String snapshotId) {
        return Optional.ofNullable(byId.get(snapshotId));
    }

    /** Returns all snapshots for a source, ordered by creation time. */
    public List<Snapshot> getBySource(String sourceId) {
        return bySource.getOrDefault(sourceId, List.of()).stream()
                .map(byId::get)
                .filter(Objects::nonNull)
                .sorted(Comparator.comparing(Snapshot::createdAt))
                .collect(Collectors.toUnmodifiableList());
    }

    /** Range query: all snapshots between two instants (inclusive). */
    public List<Snapshot> getInRange(Instant from, Instant to) {
        return byTime.subMap(from, true, to, true).values().stream()
                .flatMap(Collection::stream)
                .map(byId::get)
                .filter(Objects::nonNull)
                .sorted(Comparator.comparing(Snapshot::createdAt))
                .collect(Collectors.toUnmodifiableList());
    }

    /** Returns the most recent snapshot for a source, or empty if none exist. */
    public Optional<Snapshot> getLatest(String sourceId) {
        List<Snapshot> chain = getBySource(sourceId);
        return chain.isEmpty() ? Optional.empty() : Optional.of(chain.get(chain.size() - 1));
    }

    /** Total number of snapshots stored. */
    public int size() {
        return byId.size();
    }
}
