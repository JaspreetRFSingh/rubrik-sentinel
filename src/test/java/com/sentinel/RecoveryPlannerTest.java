package com.sentinel;

import com.sentinel.core.*;
import com.sentinel.recovery.RecoveryPlanner;
import com.sentinel.recovery.RecoveryPlanner.*;
import org.junit.jupiter.api.*;

import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Validates that the recovery planner picks the right snapshot to restore from
 * and generates a plan with clear, actionable steps.
 */
class RecoveryPlannerTest {

    private MetadataStore store;
    private SnapshotManager snapshotManager;
    private RecoveryPlanner planner;

    @BeforeEach
    void setUp() {
        store = new MetadataStore();
        snapshotManager = new SnapshotManager(store);
        planner = new RecoveryPlanner(store);
    }

    @Test
    @DisplayName("Finds most recent clean snapshot, skipping compromised ones")
    void findsCorrectRecoveryPoint() {
        Snapshot s1 = snapshotManager.createFromMetadata("src", Map.of(
            "a.txt", meta("a.txt", "h1", 100, 4.0)
        ));
        Snapshot s2 = snapshotManager.createFromMetadata("src", Map.of(
            "a.txt", meta("a.txt", "h2", 110, 4.1)
        ));
        Snapshot s3 = snapshotManager.createFromMetadata("src", Map.of(
            "a.txt", meta("a.txt", "h3", 100, 7.99)
        ));
        Snapshot s4 = snapshotManager.createFromMetadata("src", Map.of(
            "a.txt", meta("a.txt", "h4", 100, 7.98)
        ));

        // Mark attack snapshots
        s3.markStatus(Snapshot.Status.COMPROMISED);
        s4.markStatus(Snapshot.Status.COMPROMISED);

        Optional<RecoveryPoint> point = planner.findCleanRecoveryPoint("src");

        assertTrue(point.isPresent(), "Should find a clean recovery point");
        assertEquals(s2.snapshotId(), point.get().snapshot().snapshotId(),
                "Should pick s2 as the last clean snapshot");
        assertEquals(2, point.get().skippedSnapshots(),
                "Should have skipped 2 compromised snapshots");
    }

    @Test
    @DisplayName("Returns empty when all snapshots are compromised")
    void noRecoveryPointWhenAllCompromised() {
        Snapshot s1 = snapshotManager.createFromMetadata("src", Map.of(
            "a.txt", meta("a.txt", "h1", 100, 7.99)
        ));
        Snapshot s2 = snapshotManager.createFromMetadata("src", Map.of(
            "a.txt", meta("a.txt", "h2", 100, 7.98)
        ));

        s1.markStatus(Snapshot.Status.COMPROMISED);
        s2.markStatus(Snapshot.Status.COMPROMISED);

        Optional<RecoveryPoint> point = planner.findCleanRecoveryPoint("src");
        assertTrue(point.isEmpty(), "Should find no clean recovery point");
    }

    @Test
    @DisplayName("Recovery plan contains actionable steps")
    void recoveryPlanHasSteps() {
        Snapshot s1 = snapshotManager.createFromMetadata("src", Map.of(
            "a.txt", meta("a.txt", "h1", 100, 4.0)
        ));
        Snapshot s2 = snapshotManager.createFromMetadata("src", Map.of(
            "a.txt", meta("a.txt", "h2", 100, 7.99)
        ));
        s2.markStatus(Snapshot.Status.COMPROMISED);

        RecoveryPlan plan = planner.createRecoveryPlan("src");

        assertNotNull(plan.recoveryPoint(), "Plan should have a recovery point");
        assertFalse(plan.steps().isEmpty(), "Plan should contain recovery steps");
        assertTrue(plan.steps().stream().anyMatch(s -> s.contains("HALT")),
                "Plan should instruct halting writes");
        assertTrue(plan.steps().stream().anyMatch(s -> s.contains("RESTORE")),
                "Plan should instruct restoring files");
        assertTrue(plan.steps().stream().anyMatch(s -> s.contains("VALIDATE")),
                "Plan should instruct validation");
    }

    @Test
    @DisplayName("Recovery plan for non-existent source returns critical message")
    void recoveryPlanForUnknownSource() {
        RecoveryPlan plan = planner.createRecoveryPlan("non-existent");
        assertNull(plan.recoveryPoint());
        assertTrue(plan.summary().contains("CRITICAL"));
    }

    @Test
    @DisplayName("Single clean snapshot is a valid recovery target")
    void singleSnapshotRecovery() {
        Snapshot s1 = snapshotManager.createFromMetadata("src", Map.of(
            "a.txt", meta("a.txt", "h1", 100, 4.0)
        ));

        Optional<RecoveryPoint> point = planner.findCleanRecoveryPoint("src");
        assertTrue(point.isPresent());
        assertEquals(s1.snapshotId(), point.get().snapshot().snapshotId());
        assertEquals(0, point.get().skippedSnapshots());
    }

    private FileMetadata meta(String path, String hash, long size, double entropy) {
        return new FileMetadata(path, hash, size, entropy, Instant.now());
    }
}
