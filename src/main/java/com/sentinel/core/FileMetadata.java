package com.sentinel.core;

import java.time.Instant;
import java.util.Objects;

/**
 * Immutable representation of a file's metadata captured at snapshot time.
 *
 * This is analogous to the metadata Rubrik stores per-object in its distributed
 * metadata store. By capturing content hash, size, and Shannon entropy at each
 * snapshot, we can later detect anomalies (e.g., mass encryption by ransomware)
 * without needing to store full file contents in memory.
 *
 * Design decision: We compute Shannon entropy at ingest time because entropy is
 * the single strongest signal for ransomware detection — encrypted files exhibit
 * entropy > 7.9 bits/byte, while normal documents sit between 4–6.
 */
public final class FileMetadata {

    private final String filePath;
    private final String contentHash;   // SHA-256 of content
    private final long   sizeBytes;
    private final double shannonEntropy; // 0.0 – 8.0 bits per byte
    private final Instant capturedAt;

    public FileMetadata(String filePath, String contentHash, long sizeBytes,
                        double shannonEntropy, Instant capturedAt) {
        this.filePath       = Objects.requireNonNull(filePath);
        this.contentHash    = Objects.requireNonNull(contentHash);
        this.sizeBytes      = sizeBytes;
        this.shannonEntropy = shannonEntropy;
        this.capturedAt     = Objects.requireNonNull(capturedAt);
    }

    public String  filePath()       { return filePath; }
    public String  contentHash()    { return contentHash; }
    public long    sizeBytes()      { return sizeBytes; }
    public double  shannonEntropy() { return shannonEntropy; }
    public Instant capturedAt()     { return capturedAt; }

    /**
     * Two metadata records refer to the same logical content if their hashes match.
     * This is how we detect which files changed between snapshots.
     */
    public boolean contentEquals(FileMetadata other) {
        return this.contentHash.equals(other.contentHash);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FileMetadata m)) return false;
        return filePath.equals(m.filePath) && contentHash.equals(m.contentHash);
    }

    @Override
    public int hashCode() {
        return Objects.hash(filePath, contentHash);
    }

    @Override
    public String toString() {
        return String.format("FileMetadata{path='%s', hash=%s..., size=%d, entropy=%.2f}",
                filePath, contentHash.substring(0, 8), sizeBytes, shannonEntropy);
    }
}
