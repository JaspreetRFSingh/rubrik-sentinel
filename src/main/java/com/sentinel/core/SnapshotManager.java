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
 * Turns a filesystem (or simulated file data) into an immutable snapshot.
 *
 * For each file it encounters, it computes a SHA-256 hash and Shannon entropy,
 * then packages everything into a Snapshot and hands it off to the store. The
 * parent link is resolved automatically from the store, so callers don't need
 * to track the chain manually.
 *
 * Entropy is computed eagerly here because it's the key signal used by anomaly
 * detection, and it's cheaper to compute once at ingest than repeatedly later.
 *
 * This class is stateless and safe for concurrent use.
 */
public class SnapshotManager {

    private final MetadataStore store;
    private final AtomicLong    snapshotCounter = new AtomicLong(0);

    public SnapshotManager(MetadataStore store) {
        this.store = Objects.requireNonNull(store);
    }

    /**
     * Walks the given directory, hashes every readable file, and stores the result
     * as a new snapshot linked to the previous one for this source.
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
     * Creates a snapshot from pre-built file metadata instead of a real filesystem.
     * Handy for tests and the simulation where we control the data directly.
     */
    public Snapshot createFromMetadata(String sourceId, Map<String, FileMetadata> files) {
        String snapshotId = generateSnapshotId(sourceId);
        String parentId   = store.getLatest(sourceId).map(Snapshot::snapshotId).orElse(null);

        Snapshot snapshot = new Snapshot(snapshotId, sourceId, Instant.now(), files, parentId);
        store.put(snapshot);
        return snapshot;
    }

    // ─── Hashing & Entropy ─────────────────────────────────────────────

    /** Returns the SHA-256 hex digest of the given bytes — used as the file's deduplication key. */
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
     * Measures how "random" the bytes in a file are, on a scale of 0.0 to 8.0.
     *
     * Normal documents land around 4–5. Compressed files are higher, around
     * 7.5–7.9. Encrypted data looks like pure noise and pushes close to 8.0.
     * A sudden jump to near 8.0 across many files between snapshots is a
     * strong sign that ransomware has been at work.
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
