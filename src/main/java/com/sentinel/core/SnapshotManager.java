package com.sentinel.core;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Creates immutable snapshots from a live filesystem.
 *
 * This component models the Rubrik CDM (Cloud Data Management) ingest pipeline:
 *   1. Walk the target filesystem tree
 *   2. For each file, compute content hash (dedup key) and Shannon entropy
 *   3. Package everything into an immutable Snapshot and store it
 *
 * In production Rubrik, this process runs incrementally — only changed blocks
 * are captured using change block tracking (CBT). Our implementation captures
 * full file metadata each time but detects changes via hash comparison, which
 * demonstrates the same architectural concept.
 *
 * Thread Safety: This class is stateless and safe for concurrent use.
 */
public class SnapshotManager {

    private final MetadataStore store;
    private final AtomicLong    snapshotCounter = new AtomicLong(0);

    public SnapshotManager(MetadataStore store) {
        this.store = Objects.requireNonNull(store);
    }

    /**
     * Creates a new immutable snapshot of the given directory.
     *
     * @param sourceId  logical identifier for the protected workload
     * @param rootPath  directory to snapshot
     * @return the created Snapshot
     */
    public Snapshot createSnapshot(String sourceId, Path rootPath) throws IOException {
        if (!Files.isDirectory(rootPath)) {
            throw new IllegalArgumentException("Root path must be a directory: " + rootPath);
        }

        String snapshotId = generateSnapshotId(sourceId);
        String parentId   = store.getLatest(sourceId).map(Snapshot::snapshotId).orElse(null);

        Map<String, FileMetadata> files = new LinkedHashMap<>();
        Instant now = Instant.now();

        Files.walkFileTree(rootPath, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                if (Files.isRegularFile(file) && Files.isReadable(file)) {
                    byte[] content   = Files.readAllBytes(file);
                    String relPath   = rootPath.relativize(file).toString();
                    String hash      = sha256(content);
                    double entropy   = shannonEntropy(content);

                    files.put(relPath, new FileMetadata(relPath, hash, content.length, entropy, now));
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException exc) {
                // Log and skip inaccessible files — mirrors Rubrik's partial-success model
                System.err.println("[WARN] Skipping inaccessible file: " + file + " (" + exc.getMessage() + ")");
                return FileVisitResult.CONTINUE;
            }
        });

        Snapshot snapshot = new Snapshot(snapshotId, sourceId, now, files, parentId);
        store.put(snapshot);
        return snapshot;
    }

    /**
     * Creates a snapshot from pre-built metadata (useful for testing and simulation).
     */
    public Snapshot createFromMetadata(String sourceId, Map<String, FileMetadata> files) {
        String snapshotId = generateSnapshotId(sourceId);
        String parentId   = store.getLatest(sourceId).map(Snapshot::snapshotId).orElse(null);

        Snapshot snapshot = new Snapshot(snapshotId, sourceId, Instant.now(), files, parentId);
        store.put(snapshot);
        return snapshot;
    }

    // ─── Hashing & Entropy ─────────────────────────────────────────────

    /** SHA-256 content hash — the deduplication key in Rubrik's storage layer. */
    static String sha256(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * Computes Shannon entropy of a byte array (0.0 to 8.0 bits per byte).
     *
     * This is the foundation of ransomware detection:
     *   - Normal text/documents:  ~4.0 – 5.5 bits/byte
     *   - Compressed files:       ~7.5 – 7.9 bits/byte
     *   - Encrypted (ransomware): ~7.95 – 8.0 bits/byte
     *
     * A sudden jump in entropy across many files between two snapshots is
     * a strong indicator that ransomware has encrypted the data.
     */
    public static double shannonEntropy(byte[] data) {
        if (data.length == 0) return 0.0;

        int[] freq = new int[256];
        for (byte b : data) {
            freq[b & 0xFF]++;
        }

        double entropy = 0.0;
        double len = data.length;
        for (int f : freq) {
            if (f > 0) {
                double p = f / len;
                entropy -= p * (Math.log(p) / Math.log(2));
            }
        }
        return entropy;
    }

    private String generateSnapshotId(String sourceId) {
        return String.format("snap-%s-%04d", sourceId, snapshotCounter.incrementAndGet());
    }
}
