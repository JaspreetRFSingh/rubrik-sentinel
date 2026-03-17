package com.sentinel.core;

import java.time.Instant;
import java.util.*;

/**
 * A freeze-frame of a workload's filesystem at a specific point in time.
 *
 * The files map is wrapped in an unmodifiable view so nothing can tamper with
 * a snapshot after it's created. That immutability is what makes it trustworthy
 * as a recovery target — even if an attacker owns the production environment,
 * they can't reach back and corrupt the backup chain.
 *
 * Status starts as CLEAN and gets updated by the threat detection pipeline
 * after analysis runs.
 */
public final class Snapshot {

    public enum Status { CLEAN, SUSPICIOUS, COMPROMISED }

    private final String                       snapshotId;
    private final String                       sourceId;      // identifies the protected workload
    private final Instant                      createdAt;
    private final Map<String, FileMetadata>    files;         // path -> metadata
    private final String                       parentId;      // previous snapshot in chain (null for first)
    private volatile Status                    status;        // set by threat analysis

    public Snapshot(String snapshotId, String sourceId, Instant createdAt,
                    Map<String, FileMetadata> files, String parentId) {
        this.snapshotId = Objects.requireNonNull(snapshotId);
        this.sourceId   = Objects.requireNonNull(sourceId);
        this.createdAt  = Objects.requireNonNull(createdAt);
        this.files      = Collections.unmodifiableMap(new LinkedHashMap<>(files));
        this.parentId   = parentId;
        this.status     = Status.CLEAN;
    }

    public String                    snapshotId() { return snapshotId; }
    public String                    sourceId()   { return sourceId; }
    public Instant                   createdAt()  { return createdAt; }
    public Map<String, FileMetadata> files()      { return files; }
    public String                    parentId()   { return parentId; }
    public Status                    status()     { return status; }
    public int                       fileCount()  { return files.size(); }

    public void markStatus(Status s) { this.status = s; }

    /** Looks up a file by path. Returns empty if it wasn't in this snapshot. */
    public Optional<FileMetadata> getFile(String path) {
        return Optional.ofNullable(files.get(path));
    }

    /** Returns all file paths that were added, changed, or deleted relative to an older snapshot. */
    public Set<String> diffFrom(Snapshot older) {
        Set<String> changed = new LinkedHashSet<>();

        // Files modified or added
        for (var entry : this.files.entrySet()) {
            FileMetadata oldMeta = older.files.get(entry.getKey());
            if (oldMeta == null || !oldMeta.contentEquals(entry.getValue())) {
                changed.add(entry.getKey());
            }
        }

        // Files deleted
        for (String path : older.files.keySet()) {
            if (!this.files.containsKey(path)) {
                changed.add(path);
            }
        }

        return Collections.unmodifiableSet(changed);
    }

    @Override
    public String toString() {
        return String.format("Snapshot{id='%s', source='%s', files=%d, status=%s, at=%s}",
                snapshotId, sourceId, files.size(), status, createdAt);
    }
}
