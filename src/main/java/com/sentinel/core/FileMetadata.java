package com.sentinel.core;

import java.time.Instant;
import java.util.Objects;

/**
 * Everything we care about for a single file at the moment it was backed up.
 *
 * We don't store actual file contents — just the fingerprint. The SHA-256 hash
 * tells us if the content changed, and Shannon entropy tells us if it looks
 * encrypted (encrypted files are nearly random noise, pushing entropy close to
 * 8.0 bits/byte, while normal documents sit around 4–6).
 *
 * Entropy is computed at ingest time so detection later stays fast — no need
 * to re-read files when we're scanning for ransomware.
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
     * Same hash means same content — this is how we tell if a file actually
     * changed between two snapshots, ignoring any metadata-only differences.
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
