package com.sentinel.core;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.stream.Collectors;

/**
 * Where all snapshots live. Keeps three indexes so lookups are fast no matter
 * how you query — by ID, by time window, or by which workload you care about.
 *
 * All three indexes use concurrent data structures, so this is safe to use
 * from multiple threads without any explicit locking. The SkipListMap keeps
 * snapshots sorted by time automatically, which makes range queries easy.
 */
public class MetadataStore {

    // Primary index: snapshotId -> Snapshot (O(1) lookup)
    private final ConcurrentHashMap<String, Snapshot> byId = new ConcurrentHashMap<>();

    // Time index: createdAt -> snapshotId (ordered, supports range queries)
    private final ConcurrentSkipListMap<Instant, List<String>> byTime = new ConcurrentSkipListMap<>();

    // Source index: sourceId -> ordered list of snapshotIds
    private final ConcurrentHashMap<String, List<String>> bySource = new ConcurrentHashMap<>();

    /** Stores a snapshot and updates all three indexes. Re-storing the same ID is a no-op. */
    public void put(Snapshot snapshot) {
        if (byId.putIfAbsent(snapshot.snapshotId(), snapshot) != null) {
            return; // already exists
        }

        byTime.computeIfAbsent(snapshot.createdAt(), k -> Collections.synchronizedList(new ArrayList<>()))
              .add(snapshot.snapshotId());

        bySource.computeIfAbsent(snapshot.sourceId(), k -> Collections.synchronizedList(new ArrayList<>()))
                .add(snapshot.snapshotId());
    }

    /** Looks up a snapshot by its ID. */
    public Optional<Snapshot> get(String snapshotId) {
        return Optional.ofNullable(byId.get(snapshotId));
    }

    /** Returns the full snapshot history for a workload, oldest first. */
    public List<Snapshot> getBySource(String sourceId) {
        return bySource.getOrDefault(sourceId, List.of()).stream()
                .map(byId::get)
                .filter(Objects::nonNull)
                .sorted(Comparator.comparing(Snapshot::createdAt))
                .collect(Collectors.toUnmodifiableList());
    }

    /** Returns all snapshots whose creation time falls within the given window (inclusive). */
    public List<Snapshot> getInRange(Instant from, Instant to) {
        return byTime.subMap(from, true, to, true).values().stream()
                .flatMap(Collection::stream)
                .map(byId::get)
                .filter(Objects::nonNull)
                .sorted(Comparator.comparing(Snapshot::createdAt))
                .collect(Collectors.toUnmodifiableList());
    }

    /** Returns the newest snapshot for a workload, or empty if none have been stored yet. */
    public Optional<Snapshot> getLatest(String sourceId) {
        List<Snapshot> chain = getBySource(sourceId);
        return chain.isEmpty() ? Optional.empty() : Optional.of(chain.get(chain.size() - 1));
    }

    /** Total number of snapshots stored. */
    public int size() {
        return byId.size();
    }
}
