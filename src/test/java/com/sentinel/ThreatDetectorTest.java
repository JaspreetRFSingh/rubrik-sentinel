package com.sentinel;

import com.sentinel.core.*;
import com.sentinel.threat.*;
import com.sentinel.threat.ThreatReport.Severity;
import org.junit.jupiter.api.*;

import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Checks that the threat pipeline correctly identifies ransomware across all
 * three detection strategies: IoC signatures, anomaly behavior, and blast radius.
 */
class ThreatDetectorTest {

    private MetadataStore store;
    private SnapshotManager snapshotManager;
    private ThreatDetector detector;
    private BlastRadiusAnalyzer blastAnalyzer;

    @BeforeEach
    void setUp() {
        store = new MetadataStore();
        snapshotManager = new SnapshotManager(store);
        detector = new ThreatDetector(store);
        blastAnalyzer = new BlastRadiusAnalyzer(store);
    }

    @Test
    @DisplayName("Clean snapshot produces no findings")
    void cleanSnapshotProducesNoFindings() {
        Snapshot clean = snapshotManager.createFromMetadata("src", Map.of(
            "report.xlsx", meta("report.xlsx", "aabb", 5000, 4.2),
            "readme.md",   meta("readme.md",   "ccdd", 1000, 3.8)
        ));

        ThreatReport report = detector.analyze(clean.snapshotId());
        assertTrue(report.isClean(), "Clean snapshot should produce no findings");
        assertEquals(Severity.INFO, report.overallSeverity());
    }

    @Test
    @DisplayName("IoC scan detects ransomware extensions")
    void iocDetectsRansomwareExtensions() {
        Snapshot infected = snapshotManager.createFromMetadata("src", Map.of(
            "data.xlsx.locked",    meta("data.xlsx.locked",   "eeee01", 5000, 7.95),
            "notes.docx.encrypted", meta("notes.docx.encrypted", "eeee02", 3000, 7.98)
        ));

        ThreatReport report = detector.analyze(infected.snapshotId());
        assertFalse(report.isClean());

        long iocFindings = report.findings().stream()
                .filter(f -> f.detectorName().equals("IoCScanEngine"))
                .count();
        assertTrue(iocFindings >= 2, "Should detect at least 2 IoC matches for .locked and .encrypted");
    }

    @Test
    @DisplayName("IoC scan detects ransom note files")
    void iocDetectsRansomNotes() {
        Snapshot withNote = snapshotManager.createFromMetadata("src", Map.of(
            "how.to.decrypt.txt", meta("how.to.decrypt.txt", "dead01", 2048, 3.5),
            "normal-file.txt",    meta("normal-file.txt",    "good01", 1024, 4.0)
        ));

        ThreatReport report = detector.analyze(withNote.snapshotId());
        assertFalse(report.isClean());
        assertTrue(report.overallSeverity().ordinal() >= Severity.HIGH.ordinal());
    }

    @Test
    @DisplayName("Anomaly detection flags mass file modification")
    void anomalyDetectsMassModification() {
        Instant t = Instant.now();
        // Baseline: 10 normal files
        Map<String, FileMetadata> baseline = new LinkedHashMap<>();
        for (int i = 0; i < 10; i++) {
            String name = "file-" + i + ".doc";
            baseline.put(name, new FileMetadata(name, "hash-" + i, 1000, 4.5, t));
        }

        // Attack: 8 out of 10 files changed with high entropy
        Map<String, FileMetadata> attacked = new LinkedHashMap<>(baseline);
        for (int i = 0; i < 8; i++) {
            String name = "file-" + i + ".doc";
            attacked.put(name, new FileMetadata(name, "evil-" + i, 1000, 7.98, t));
        }

        snapshotManager.createFromMetadata("src", baseline);
        Snapshot attackSnap = snapshotManager.createFromMetadata("src", attacked);

        ThreatReport report = detector.analyze(attackSnap.snapshotId());
        assertFalse(report.isClean());

        boolean hasMassModFinding = report.findings().stream()
                .anyMatch(f -> f.description().toLowerCase().contains("mass"));
        assertTrue(hasMassModFinding, "Should flag mass file modification");
    }

    @Test
    @DisplayName("Anomaly detection flags entropy spikes per file")
    void anomalyDetectsEntropySpike() {
        Instant t = Instant.now();
        Map<String, FileMetadata> before = Map.of(
            "secret.xlsx", new FileMetadata("secret.xlsx", "hash-orig", 5000, 4.2, t)
        );
        Map<String, FileMetadata> after = Map.of(
            "secret.xlsx", new FileMetadata("secret.xlsx", "hash-enc", 5000, 7.98, t)
        );

        snapshotManager.createFromMetadata("src", before);
        Snapshot afterSnap = snapshotManager.createFromMetadata("src", after);

        ThreatReport report = detector.analyze(afterSnap.snapshotId());

        boolean hasEntropyFinding = report.findings().stream()
                .anyMatch(f -> f.description().toLowerCase().contains("entropy"));
        assertTrue(hasEntropyFinding, "Should detect entropy spike");
    }

    @Test
    @DisplayName("Blast radius identifies correct last clean snapshot")
    void blastRadiusIdentifiesCleanSnapshot() {
        // Create clean → clean → compromised chain
        Snapshot s1 = snapshotManager.createFromMetadata("src", Map.of(
            "a.txt", meta("a.txt", "h1", 100, 4.0)
        ));
        Snapshot s2 = snapshotManager.createFromMetadata("src", Map.of(
            "a.txt", meta("a.txt", "h1", 100, 4.0)  // identical = clean
        ));
        Snapshot s3 = snapshotManager.createFromMetadata("src", Map.of(
            "a.txt", meta("a.txt", "h-enc", 100, 7.99)  // encrypted
        ));

        s3.markStatus(Snapshot.Status.COMPROMISED);

        BlastRadiusAnalyzer.BlastRadius radius = blastAnalyzer.analyze(s3.snapshotId());
        assertNotNull(radius.lastCleanSnapshot());
        assertEquals(1, radius.affectedFileCount());
    }

    @Test
    @DisplayName("Snapshot status transitions from CLEAN to COMPROMISED after threat detection")
    void snapshotStatusTransition() {
        snapshotManager.createFromMetadata("src", Map.of(
            "a.txt", meta("a.txt", "h1", 100, 4.0)
        ));
        Snapshot attack = snapshotManager.createFromMetadata("src", Map.of(
            "a.txt.locked", meta("a.txt.locked", "evil", 100, 7.99)
        ));

        assertEquals(Snapshot.Status.CLEAN, attack.status(), "Should start clean");

        detector.analyze(attack.snapshotId());

        assertNotEquals(Snapshot.Status.CLEAN, attack.status(),
                "Should transition away from CLEAN after threats detected");
    }

    // ── Helper ─────────────────────────────────────────────────────────

    private FileMetadata meta(String path, String hash, long size, double entropy) {
        return new FileMetadata(path, hash, size, entropy, Instant.now());
    }
}
