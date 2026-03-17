package com.sentinel.threat;

import com.sentinel.core.MetadataStore;
import com.sentinel.core.Snapshot;
import com.sentinel.threat.ThreatReport.Finding;

import java.time.Instant;
import java.util.*;

/**
 * Runs the full threat detection pipeline on a single snapshot and returns
 * a unified report.
 *
 * First checks the snapshot against known IoC signatures, then — if there's
 * a previous snapshot to compare against — runs behavioral anomaly detection.
 * Findings from both phases get merged into one ThreatReport, and the
 * snapshot's status gets updated to reflect the worst thing found.
 *
 * New detection engines can be plugged in here without touching the existing ones.
 */
public class ThreatDetector {

    private final IoCScanEngine       iocEngine;
    private final AnomalyDetector     anomalyDetector;
    private final MetadataStore       store;

    public ThreatDetector(MetadataStore store) {
        this.store           = Objects.requireNonNull(store);
        this.iocEngine       = new IoCScanEngine();
        this.anomalyDetector = new AnomalyDetector();
    }

    /** Exposes the IoC engine so callers can add custom rules before running analysis. */
    public IoCScanEngine iocEngine() {
        return iocEngine;
    }

    /**
     * Runs IoC scanning and anomaly detection on the given snapshot, then
     * returns a consolidated report with all findings and the updated status.
     *
     * @param snapshotId the snapshot to analyze
     * @return a ThreatReport with everything found across both detection phases
     */
    public ThreatReport analyze(String snapshotId) {
        Snapshot snapshot = store.get(snapshotId)
                .orElseThrow(() -> new IllegalArgumentException("Snapshot not found: " + snapshotId));

        List<Finding> allFindings = new ArrayList<>();

        // Phase 1: IoC Scan — known threat signatures
        allFindings.addAll(iocEngine.scan(snapshot));

        // Phase 2: Anomaly Detection — behavioral analysis against baseline
        Optional<Snapshot> baseline = findBaseline(snapshot);
        if (baseline.isPresent()) {
            allFindings.addAll(anomalyDetector.detect(snapshot, baseline.get()));
        }

        // Compute affected file count (unique files with findings)
        Set<String> affectedFiles = new LinkedHashSet<>();
        for (Finding f : allFindings) {
            if (!"/".equals(f.filePath())) {
                affectedFiles.add(f.filePath());
            }
        }

        // Update snapshot status based on findings
        ThreatReport report = new ThreatReport(
            snapshotId,
            Instant.now(),
            allFindings,
            snapshot.fileCount(),
            affectedFiles.size()
        );

        if (!report.isClean()) {
            snapshot.markStatus(
                report.overallSeverity().ordinal() >= ThreatReport.Severity.HIGH.ordinal()
                    ? Snapshot.Status.COMPROMISED
                    : Snapshot.Status.SUSPICIOUS
            );
        }

        return report;
    }

    /** Gets the parent snapshot to use as the baseline for anomaly comparison. Returns empty for the first snapshot in a chain. */
    private Optional<Snapshot> findBaseline(Snapshot snapshot) {
        if (snapshot.parentId() == null) {
            return Optional.empty();
        }
        return store.get(snapshot.parentId());
    }
}
