package com.sentinel.threat;

import java.time.Instant;
import java.util.*;

/**
 * The output of a full threat analysis run — everything we found (or didn't)
 * in a snapshot.
 *
 * Holds a flat list of individual findings, a count of affected files, and an
 * overall severity derived from the worst individual finding. If findings is
 * empty, the snapshot is clean.
 */
public final class ThreatReport {

    public enum Severity { INFO, LOW, MEDIUM, HIGH, CRITICAL }

    private final String        snapshotId;
    private final Instant       analysisTime;
    private final List<Finding> findings;
    private final int           totalFilesScanned;
    private final int           affectedFileCount;  // blast radius
    private final Severity      overallSeverity;

    public ThreatReport(String snapshotId, Instant analysisTime, List<Finding> findings,
                        int totalFilesScanned, int affectedFileCount) {
        this.snapshotId       = snapshotId;
        this.analysisTime     = analysisTime;
        this.findings         = Collections.unmodifiableList(new ArrayList<>(findings));
        this.totalFilesScanned = totalFilesScanned;
        this.affectedFileCount = affectedFileCount;
        this.overallSeverity  = findings.stream()
                .map(Finding::severity)
                .max(Comparator.comparingInt(Enum::ordinal))
                .orElse(Severity.INFO);
    }

    public String        snapshotId()        { return snapshotId; }
    public Instant       analysisTime()      { return analysisTime; }
    public List<Finding> findings()          { return findings; }
    public int           totalFilesScanned() { return totalFilesScanned; }
    public int           affectedFileCount() { return affectedFileCount; }
    public Severity      overallSeverity()   { return overallSeverity; }
    public boolean       isClean()           { return findings.isEmpty(); }

    /** What percentage of scanned files had at least one finding. */
    public double blastRadiusPercent() {
        if (totalFilesScanned == 0) return 0.0;
        return (affectedFileCount * 100.0) / totalFilesScanned;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("╔══════════════════════════════════════════════════╗\n");
        sb.append("║           SENTINEL THREAT REPORT                ║\n");
        sb.append("╠══════════════════════════════════════════════════╣\n");
        sb.append(String.format("║  Snapshot     : %-32s║\n", snapshotId));
        sb.append(String.format("║  Scanned      : %-5d files                      ║\n", totalFilesScanned));
        sb.append(String.format("║  Affected     : %-5d files  (%.1f%% blast radius) ║\n",
                affectedFileCount, blastRadiusPercent()));
        sb.append(String.format("║  Severity     : %-10s                       ║\n", overallSeverity));
        sb.append(String.format("║  Findings     : %-5d                            ║\n", findings.size()));
        sb.append("╠══════════════════════════════════════════════════╣\n");

        for (Finding f : findings) {
            sb.append(String.format("║  [%s] %s\n", f.severity(), f.description()));
            sb.append(String.format("║    → File: %s\n", f.filePath()));
        }

        sb.append("╚══════════════════════════════════════════════════╝\n");
        return sb.toString();
    }

    // ─── Finding (inner record) ────────────────────────────────────────

    /** One thing we found: which file, what's wrong with it, how bad it is, and which detector caught it. */
    public record Finding(
        String   filePath,
        String   description,
        Severity severity,
        String   detectorName
    ) {
        public Finding {
            Objects.requireNonNull(filePath);
            Objects.requireNonNull(description);
            Objects.requireNonNull(severity);
            Objects.requireNonNull(detectorName);
        }
    }
}
