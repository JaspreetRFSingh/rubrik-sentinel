package com.sentinel.core;

import java.time.Instant;
import java.util.*;

/**
 * An immutable, versioned point-in-time capture of a data source.
 *
 * This models Rubrik's core abstraction: every backup is an immutable snapshot
 * that can never be modified or deleted before its SLA-defined retention expires.
 * This immutability is Rubrik's "air gap" — even if an attacker compromises the
 * production environment, the snapshot chain remains trustworthy.
 *
 * Each snapshot stores a map of filePath -> FileMetadata. In production Rubrik,
 * this would be backed by a distributed metadata store (like their Atlas filesystem);
 * here we use an unmodifiable Map for the same semantic guarantee.
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

    /** Returns metadata for a specific file path, or empty if not present. */
    public Optional<FileMetadata> getFile(String path) {
        return Optional.ofNullable(files.get(path));
    }

    /** Returns the set of file paths that differ between this snapshot and another. */
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
