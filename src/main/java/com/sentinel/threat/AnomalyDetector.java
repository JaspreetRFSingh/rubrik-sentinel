package com.sentinel.threat;

import com.sentinel.core.FileMetadata;
import com.sentinel.core.Snapshot;
import com.sentinel.threat.ThreatReport.Finding;
import com.sentinel.threat.ThreatReport.Severity;

import java.util.*;

/**
 * Looks for signs of ransomware by comparing two consecutive snapshots —
 * no known signatures needed.
 *
 * Runs three checks:
 *   1. Did a large percentage of files change all at once? Ransomware encrypts
 *      everything in bulk; normal work touches a few files at a time.
 *
 *   2. Did any file's entropy jump dramatically? Encrypting a file makes it
 *      look like random noise — entropy spikes to near 8.0 bits/byte.
 *
 *   3. Did any files get a suspicious extension appended? (e.g., report.docx
 *      becoming report.docx.locked)
 *
 * Each check can fire on its own, but overlapping signals build much stronger
 * confidence that something is actually wrong.
 */
public class AnomalyDetector {

    // Thresholds (tunable per-environment in production)
    private static final double ENTROPY_SPIKE_THRESHOLD   = 1.5;   // bits/byte increase
    private static final double HIGH_ENTROPY_ABSOLUTE     = 7.8;   // near-random data
    private static final double MASS_MODIFICATION_PERCENT = 40.0;  // % of files changed
    private static final double SUSPICIOUS_MOD_PERCENT    = 15.0;  // lower threshold for warnings

    /**
     * Runs the three anomaly checks against the diff between two snapshots.
     *
     * @param current  the newer snapshot
     * @param previous the older snapshot used as the baseline
     * @return list of anomaly findings, empty if nothing suspicious was detected
     */
    public List<Finding> detect(Snapshot current, Snapshot previous) {
        List<Finding> findings = new ArrayList<>();

        Set<String> changedFiles = current.diffFrom(previous);

        // ── Check 1: Mass Modification ─────────────────────────────────
        double modPercent = (changedFiles.size() * 100.0) / Math.max(previous.fileCount(), 1);

        if (modPercent >= MASS_MODIFICATION_PERCENT) {
            findings.add(new Finding(
                "/",
                String.format("Mass file modification detected: %.1f%% of files changed (%d/%d). " +
                              "This pattern is consistent with ransomware encryption.",
                              modPercent, changedFiles.size(), previous.fileCount()),
                Severity.CRITICAL,
                "AnomalyDetector"
            ));
        } else if (modPercent >= SUSPICIOUS_MOD_PERCENT) {
            findings.add(new Finding(
                "/",
                String.format("Elevated file modification rate: %.1f%% of files changed (%d/%d).",
                              modPercent, changedFiles.size(), previous.fileCount()),
                Severity.MEDIUM,
                "AnomalyDetector"
            ));
        }

        // ── Check 2 & 3: Per-file entropy spike + extension mutation ───
        for (String path : changedFiles) {
            Optional<FileMetadata> currentMeta  = current.getFile(path);
            Optional<FileMetadata> previousMeta = previous.getFile(path);

            if (currentMeta.isPresent() && previousMeta.isPresent()) {
                FileMetadata curr = currentMeta.get();
                FileMetadata prev = previousMeta.get();

                // Entropy spike detection
                double entropyDelta = curr.shannonEntropy() - prev.shannonEntropy();
                if (entropyDelta >= ENTROPY_SPIKE_THRESHOLD && curr.shannonEntropy() >= HIGH_ENTROPY_ABSOLUTE) {
                    findings.add(new Finding(
                        path,
                        String.format("Entropy spike: %.2f → %.2f bits/byte (+%.2f). " +
                                      "File likely encrypted.",
                                      prev.shannonEntropy(), curr.shannonEntropy(), entropyDelta),
                        Severity.HIGH,
                        "AnomalyDetector"
                    ));
                }
            }

            // Extension mutation (file appeared with a suspicious double extension)
            if (currentMeta.isPresent() && looksLikeRenamedExtension(path)) {
                findings.add(new Finding(
                    path,
                    "Suspicious extension mutation detected — possible ransomware file rename.",
                    Severity.HIGH,
                    "AnomalyDetector"
                ));
            }
        }

        return findings;
    }

    /**
     * Returns true if the path looks like ransomware appended its extension on top
     * of an existing one — e.g., "report.docx.locked" or "data.xlsx.encrypted".
     */
    private boolean looksLikeRenamedExtension(String path) {
        String lower = path.toLowerCase();
        // Check for double extensions where the outer one is suspicious
        String[] suspiciousOuter = {".locked", ".encrypted", ".cry", ".enc", ".crypted", ".crypt"};
        for (String ext : suspiciousOuter) {
            if (lower.endsWith(ext)) {
                // Verify there's an original extension before the ransomware one
                String withoutSuspicious = lower.substring(0, lower.length() - ext.length());
                if (withoutSuspicious.contains(".")) {
                    return true;
                }
            }
        }
        return false;
    }
}
