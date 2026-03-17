package com.sentinel;

import com.sentinel.core.*;
import org.junit.jupiter.api.*;

import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Covers the core snapshot behaviors — immutability guarantees, how diffs work,
 * parent chain tracking, entropy math, and time-range queries on the store.
 */
class SnapshotManagerTest {

    private MetadataStore store;
    private SnapshotManager manager;

    @BeforeEach
    void setUp() {
        store = new MetadataStore();
        manager = new SnapshotManager(store);
    }

    @Test
    @DisplayName("Snapshot is immutable — files map cannot be modified")
    void snapshotImmutability() {
        Map<String, FileMetadata> files = new HashMap<>();
        files.put("test.txt", new FileMetadata("test.txt", "abc123", 100, 4.0, Instant.now()));

        Snapshot snap = manager.createFromMetadata("src-1", files);

        assertThrows(UnsupportedOperationException.class, () ->
            snap.files().put("evil.txt", new FileMetadata("evil.txt", "bad", 1, 0, Instant.now()))
        );
    }

    @Test
    @DisplayName("Diff correctly identifies added, modified, and deleted files")
    void snapshotDiff() {
        Instant t = Instant.now();
        Map<String, FileMetadata> v1 = Map.of(
            "a.txt", new FileMetadata("a.txt", "hash-a1", 100, 4.0, t),
            "b.txt", new FileMetadata("b.txt", "hash-b1", 200, 4.5, t),
            "c.txt", new FileMetadata("c.txt", "hash-c1", 300, 5.0, t)
        );
        Map<String, FileMetadata> v2 = Map.of(
            "a.txt", new FileMetadata("a.txt", "hash-a1", 100, 4.0, t),  // unchanged
            "b.txt", new FileMetadata("b.txt", "hash-b2", 210, 4.6, t),  // modified
            "d.txt", new FileMetadata("d.txt", "hash-d1", 150, 3.8, t)   // added (c.txt deleted)
        );

        Snapshot snap1 = manager.createFromMetadata("src-1", v1);
        Snapshot snap2 = manager.createFromMetadata("src-1", v2);

        Set<String> diff = snap2.diffFrom(snap1);
        assertTrue(diff.contains("b.txt"), "Modified file should appear in diff");
        assertTrue(diff.contains("c.txt"), "Deleted file should appear in diff");
        assertTrue(diff.contains("d.txt"), "Added file should appear in diff");
        assertFalse(diff.contains("a.txt"), "Unchanged file should NOT appear in diff");
        assertEquals(3, diff.size());
    }

    @Test
    @DisplayName("Snapshot chain tracks parent IDs correctly")
    void snapshotChainParentTracking() {
        Snapshot s1 = manager.createFromMetadata("src-1", Map.of(
            "a.txt", new FileMetadata("a.txt", "h1", 10, 4.0, Instant.now())
        ));
        Snapshot s2 = manager.createFromMetadata("src-1", Map.of(
            "a.txt", new FileMetadata("a.txt", "h2", 10, 4.0, Instant.now())
        ));

        assertNull(s1.parentId(), "First snapshot should have no parent");
        assertEquals(s1.snapshotId(), s2.parentId(), "Second snapshot should reference first as parent");
    }

    @Test
    @DisplayName("Shannon entropy: zeros → 0.0, random → ~8.0, text → 4-5")
    void shannonEntropyComputation() {
        // All zeros: minimum entropy
        byte[] zeros = new byte[1024];
        assertEquals(0.0, SnapshotManager.shannonEntropy(zeros), 0.01);

        // Uniform distribution (all 256 byte values equally): maximum entropy
        byte[] uniform = new byte[256 * 100];
        for (int i = 0; i < uniform.length; i++) {
            uniform[i] = (byte) (i % 256);
        }
        double uniformEntropy = SnapshotManager.shannonEntropy(uniform);
        assertTrue(uniformEntropy > 7.9, "Uniform distribution should have entropy near 8.0, got " + uniformEntropy);

        // ASCII text: moderate entropy
        byte[] text = "The quick brown fox jumps over the lazy dog. ".repeat(50).getBytes();
        double textEntropy = SnapshotManager.shannonEntropy(text);
        assertTrue(textEntropy > 3.5 && textEntropy < 5.5,
                "English text entropy should be 3.5-5.5, got " + textEntropy);
    }

    @Test
    @DisplayName("MetadataStore supports time-range queries")
    void metadataStoreTimeRange() {
        Instant t1 = Instant.parse("2025-01-01T00:00:00Z");
        Instant t2 = Instant.parse("2025-01-02T00:00:00Z");
        Instant t3 = Instant.parse("2025-01-03T00:00:00Z");

        store.put(new Snapshot("s1", "src", t1, Map.of(), null));
        store.put(new Snapshot("s2", "src", t2, Map.of(), "s1"));
        store.put(new Snapshot("s3", "src", t3, Map.of(), "s2"));

        List<Snapshot> range = store.getInRange(
                Instant.parse("2025-01-01T12:00:00Z"),
                Instant.parse("2025-01-03T12:00:00Z")
        );
        assertEquals(2, range.size());
        assertEquals("s2", range.get(0).snapshotId());
        assertEquals("s3", range.get(1).snapshotId());
    }
}
