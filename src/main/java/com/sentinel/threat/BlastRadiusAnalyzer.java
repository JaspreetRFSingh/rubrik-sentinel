package com.sentinel.threat;

import com.sentinel.core.FileMetadata;
import com.sentinel.core.MetadataStore;
import com.sentinel.core.Snapshot;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Figures out how far back the damage goes after a compromised snapshot is found.
 *
 * Walks the snapshot chain backwards from the point of compromise, using entropy
 * analysis at each step to distinguish attack-driven changes from normal ones.
 * Stops when it finds a snapshot where the changes look legitimate, and marks
 * that as the last clean point to recover from.
 *
 * The result tells you which files were touched, which snapshots are suspect,
 * and a per-directory breakdown of impact to help prioritize the recovery.
 */
public class BlastRadiusAnalyzer {

    private final MetadataStore store;

    public BlastRadiusAnalyzer(MetadataStore store) {
        this.store = Objects.requireNonNull(store);
    }

    /**
     * Walks backwards from the given snapshot to find the full scope of the attack.
     *
     * @param compromisedSnapshotId the snapshot where the threat was first detected
     * @return a BlastRadius with affected files, affected snapshots, and the last clean point
     */
    public BlastRadius analyze(String compromisedSnapshotId) {
        Snapshot compromised = store.get(compromisedSnapshotId)
                .orElseThrow(() -> new IllegalArgumentException("Snapshot not found: " + compromisedSnapshotId));

        List<Snapshot> chain = store.getBySource(compromised.sourceId());

        // Find the compromised snapshot's position in the chain
        int compromisedIndex = -1;
        for (int i = 0; i < chain.size(); i++) {
            if (chain.get(i).snapshotId().equals(compromisedSnapshotId)) {
                compromisedIndex = i;
                break;
            }
        }

        if (compromisedIndex <= 0) {
            // No previous snapshot to compare against — entire snapshot is suspect
            return new BlastRadius(
                compromised,
                null,
                compromised.files().keySet(),
                List.of(compromised),
                computeDirectoryBreakdown(compromised.files().keySet())
            );
        }

        // Walk backwards through the chain to find the last clean snapshot
        Set<String> allAffectedFiles = new LinkedHashSet<>();
        List<Snapshot> affectedSnapshots = new ArrayList<>();
        Snapshot lastClean = null;

        for (int i = compromisedIndex; i > 0; i--) {
            Snapshot current  = chain.get(i);
            Snapshot previous = chain.get(i - 1);

            Set<String> changed = current.diffFrom(previous);

            if (changed.isEmpty() || !hasHighEntropyChanges(current, previous, changed)) {
                lastClean = previous;
                break;
            }

            allAffectedFiles.addAll(changed);
            affectedSnapshots.add(current);
        }

        // If we walked the entire chain without finding a clean one
        if (lastClean == null && !chain.isEmpty()) {
            lastClean = chain.get(0); // first snapshot is our best bet
        }

        return new BlastRadius(
            compromised,
            lastClean,
            allAffectedFiles,
            affectedSnapshots,
            computeDirectoryBreakdown(allAffectedFiles)
        );
    }

    /**
     * Returns true if a meaningful portion of the changed files show entropy spikes
     * consistent with encryption — used to tell attack-driven changes from normal ones.
     */
    private boolean hasHighEntropyChanges(Snapshot current, Snapshot previous, Set<String> changed) {
        int highEntropyCount = 0;
        for (String path : changed) {
            Optional<FileMetadata> curr = current.getFile(path);
            Optional<FileMetadata> prev = previous.getFile(path);

            if (curr.isPresent() && prev.isPresent()) {
                double delta = curr.get().shannonEntropy() - prev.get().shannonEntropy();
                if (delta > 1.0 && curr.get().shannonEntropy() > 7.5) {
                    highEntropyCount++;
                }
            }
        }
        // If more than 30% of changes are high-entropy, likely still part of the attack
        return highEntropyCount > changed.size() * 0.3;
    }

    /** Groups affected files by their parent directory for impact prioritization. */
    private Map<String, Long> computeDirectoryBreakdown(Set<String> affectedFiles) {
        return affectedFiles.stream()
                .collect(Collectors.groupingBy(
                    path -> {
                        int lastSep = path.lastIndexOf('/');
                        return lastSep > 0 ? path.substring(0, lastSep) : "/";
                    },
                    Collectors.counting()
                ));
    }

    // ─── BlastRadius Result ────────────────────────────────────────────

    /**
     * Everything the blast radius walk found: which snapshot triggered it, how far
     * back the damage goes, and which files were hit across all affected snapshots.
     */
    public record BlastRadius(
        Snapshot              compromisedSnapshot,
        Snapshot              lastCleanSnapshot,
        Set<String>           affectedFiles,
        List<Snapshot>        affectedSnapshots,
        Map<String, Long>     directoryBreakdown
    ) {
        public int affectedFileCount() { return affectedFiles.size(); }

        public String summary() {
            StringBuilder sb = new StringBuilder();
            sb.append("── Blast Radius Analysis ──────────────────────\n");
            sb.append(String.format("  Compromised snapshot : %s\n", compromisedSnapshot.snapshotId()));
            sb.append(String.format("  Last clean snapshot  : %s\n",
                    lastCleanSnapshot != null ? lastCleanSnapshot.snapshotId() : "NONE (all compromised)"));
            sb.append(String.format("  Affected files       : %d\n", affectedFiles.size()));
            sb.append(String.format("  Affected snapshots   : %d\n", affectedSnapshots.size()));
            sb.append("  Directory breakdown:\n");
            directoryBreakdown.forEach((dir, count) ->
                sb.append(String.format("    %-30s : %d files\n", dir, count)));
            sb.append("───────────────────────────────────────────────\n");
            return sb.toString();
        }
    }
}
