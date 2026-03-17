package com.sentinel.recovery;

import com.sentinel.core.MetadataStore;
import com.sentinel.core.Snapshot;
import com.sentinel.core.Snapshot.Status;

import java.util.*;

/**
 * Finds the best snapshot to restore from and generates a step-by-step plan
 * to actually do it.
 *
 * Picking the right snapshot matters: too recent and you restore the encrypted
 * data, too old and you throw away legitimate work. This planner walks the chain
 * backwards (newest first) and picks the first snapshot that wasn't flagged by
 * threat detection — giving you the most recent clean state available.
 */
public class RecoveryPlanner {

    private final MetadataStore store;

    public RecoveryPlanner(MetadataStore store) {
        this.store = Objects.requireNonNull(store);
    }

    /**
     * Walks the snapshot chain backwards and returns the most recent one still
     * marked CLEAN — that's the closest safe point before the attack hit.
     *
     * @param sourceId the workload to find a recovery point for
     * @return the recommended recovery point, or empty if every snapshot is compromised
     */
    public Optional<RecoveryPoint> findCleanRecoveryPoint(String sourceId) {
        List<Snapshot> chain = store.getBySource(sourceId);

        if (chain.isEmpty()) {
            return Optional.empty();
        }

        // Walk backwards from most recent to find the last clean snapshot
        Snapshot recoveryTarget = null;
        int skippedCount = 0;

        for (int i = chain.size() - 1; i >= 0; i--) {
            Snapshot snap = chain.get(i);
            if (snap.status() == Status.CLEAN) {
                recoveryTarget = snap;
                break;
            }
            skippedCount++;
        }

        if (recoveryTarget == null) {
            return Optional.empty();
        }

        // Calculate data loss window (time between clean snapshot and most recent)
        Snapshot latest = chain.get(chain.size() - 1);
        long dataLossSeconds = latest.createdAt().getEpochSecond() - recoveryTarget.createdAt().getEpochSecond();

        return Optional.of(new RecoveryPoint(
            recoveryTarget,
            skippedCount,
            dataLossSeconds,
            chain.size()
        ));
    }

    /**
     * Builds a step-by-step recovery plan based on the best available clean snapshot.
     * Returns a critical-status plan if no clean snapshot can be found.
     */
    public RecoveryPlan createRecoveryPlan(String sourceId) {
        Optional<RecoveryPoint> point = findCleanRecoveryPoint(sourceId);

        if (point.isEmpty()) {
            return new RecoveryPlan(sourceId, null, List.of(),
                    "CRITICAL: No clean recovery points available. Manual investigation required.");
        }

        Snapshot target = point.get().snapshot();
        List<String> steps = new ArrayList<>();
        steps.add(String.format("1. HALT all writes to source '%s' to prevent further damage.", sourceId));
        steps.add(String.format("2. VERIFY recovery target snapshot: %s (created at %s).",
                target.snapshotId(), target.createdAt()));
        steps.add(String.format("3. RESTORE %d files from snapshot to production environment.",
                target.fileCount()));
        steps.add(String.format("4. VALIDATE restored data integrity using content hashes."));
        steps.add(String.format("5. RE-ENABLE writes after validation passes."));
        steps.add(String.format("6. INVESTIGATE %d compromised snapshots for forensic analysis.",
                point.get().skippedSnapshots()));

        String summary = String.format(
            "Recovery Plan: Restore from '%s' (data loss window: %s). %d snapshots skipped as compromised.",
            target.snapshotId(), formatDuration(point.get().dataLossSeconds()), point.get().skippedSnapshots()
        );

        return new RecoveryPlan(sourceId, point.get(), steps, summary);
    }

    private String formatDuration(long seconds) {
        if (seconds < 60)   return seconds + " seconds";
        if (seconds < 3600) return (seconds / 60) + " minutes";
        if (seconds < 86400) return (seconds / 3600) + " hours";
        return (seconds / 86400) + " days";
    }

    // ─── Result Types ──────────────────────────────────────────────────

    public record RecoveryPoint(
        Snapshot snapshot,
        int      skippedSnapshots,
        long     dataLossSeconds,
        int      totalSnapshotsInChain
    ) {
        public String summary() {
            return String.format("RecoveryPoint{target='%s', skipped=%d, dataLoss=%ds}",
                    snapshot.snapshotId(), skippedSnapshots, dataLossSeconds);
        }
    }

    public record RecoveryPlan(
        String              sourceId,
        RecoveryPoint       recoveryPoint,
        List<String>        steps,
        String              summary
    ) {
        public String prettyPrint() {
            StringBuilder sb = new StringBuilder();
            sb.append("╔══════════════════════════════════════════════════╗\n");
            sb.append("║          CYBER RECOVERY PLAN                    ║\n");
            sb.append("╠══════════════════════════════════════════════════╣\n");
            sb.append(String.format("║  Source: %-40s║\n", sourceId));
            sb.append("╠══════════════════════════════════════════════════╣\n");
            for (String step : steps) {
                sb.append("║  ").append(step).append("\n");
            }
            sb.append("╠══════════════════════════════════════════════════╣\n");
            sb.append("║  ").append(summary).append("\n");
            sb.append("╚══════════════════════════════════════════════════╝\n");
            return sb.toString();
        }
    }
}
