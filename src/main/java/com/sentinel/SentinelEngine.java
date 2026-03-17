package com.sentinel;

import com.sentinel.core.*;
import com.sentinel.policy.SLAPolicy;
import com.sentinel.recovery.RecoveryPlanner;
import com.sentinel.threat.*;
import com.sentinel.threat.BlastRadiusAnalyzer.BlastRadius;

import java.time.Instant;
import java.util.*;

/**
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *  SENTINEL ENGINE — Snapshot-Based Data Protection & Threat Detection
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *
 *  Wires together all the subsystems and drives the simulation.
 *
 *  The project models how a data protection engine handles a ransomware
 *  attack end-to-end:
 *
 *  1. IMMUTABLE SNAPSHOTS — backups that can't be tampered with after the fact
 *  2. THREAT MONITORING   — flag files that match known malware signatures
 *  3. ANOMALY DETECTION   — catch zero-day attacks via entropy and behavioral signals
 *  4. BLAST RADIUS        — understand exactly which snapshots got hit
 *  5. CYBER RECOVERY      — pick the safest snapshot to restore from
 *
 *  Run main() to watch a simulated 4-day ransomware attack get detected
 *  and walked back to a clean recovery point.
 */
public class SentinelEngine {

    private final MetadataStore       store;
    private final SnapshotManager     snapshotManager;
    private final ThreatDetector      threatDetector;
    private final BlastRadiusAnalyzer blastAnalyzer;
    private final RecoveryPlanner     recoveryPlanner;

    public SentinelEngine() {
        this.store           = new MetadataStore();
        this.snapshotManager = new SnapshotManager(store);
        this.threatDetector  = new ThreatDetector(store);
        this.blastAnalyzer   = new BlastRadiusAnalyzer(store);
        this.recoveryPlanner = new RecoveryPlanner(store);
    }

    // ─── Accessors ─────────────────────────────────────────────────────

    public MetadataStore       store()           { return store; }
    public SnapshotManager     snapshotManager() { return snapshotManager; }
    public ThreatDetector      threatDetector()  { return threatDetector; }
    public BlastRadiusAnalyzer blastAnalyzer()   { return blastAnalyzer; }
    public RecoveryPlanner     recoveryPlanner() { return recoveryPlanner; }

    // ═══════════════════════════════════════════════════════════════════
    //  MAIN — Ransomware Attack Simulation
    // ═══════════════════════════════════════════════════════════════════

    public static void main(String[] args) {
        SentinelEngine engine = new SentinelEngine();
        engine.runSimulation();
    }

    /**
     * Plays out a 4-day ransomware attack scenario and runs the full detection
     * and recovery pipeline against it.
     *
     * Timeline:
     *   Day 1 — Initial clean backup (normal business files)
     *   Day 2 — Normal changes (a few files edited)
     *   Day 3 — ATTACK: ransomware encrypts most files, drops ransom note
     *   Day 4 — Post-attack snapshot (ransomware still spreading)
     *
     * After building the chain: Detection → Blast Radius → Recovery Plan
     */
    public void runSimulation() {
        printBanner();
        String sourceId = "production-fileserver";

        SLAPolicy policy = SLAPolicy.gold();
        System.out.println("SLA Policy: " + policy + "\n");

        // ── Day 1: Initial Clean Backup ────────────────────────────────
        printPhase("DAY 1 — Initial Clean Backup");
        Snapshot day1 = snapshotManager.createFromMetadata(sourceId, buildDay1Files());
        System.out.println("Created: " + day1);
        System.out.println("  Files: " + day1.fileCount() + " files captured\n");

        // ── Day 2: Normal Business Operations ──────────────────────────
        printPhase("DAY 2 — Normal Business Changes");
        Snapshot day2 = snapshotManager.createFromMetadata(sourceId, buildDay2Files());
        System.out.println("Created: " + day2);
        Set<String> day2Changes = day2.diffFrom(day1);
        System.out.println("  Changed files: " + day2Changes.size() + " " + day2Changes + "\n");

        // ── Day 3: RANSOMWARE ATTACK ───────────────────────────────────
        printPhase("DAY 3 — ⚠ RANSOMWARE ATTACK ⚠");
        Snapshot day3 = snapshotManager.createFromMetadata(sourceId, buildDay3AttackFiles());
        System.out.println("Created: " + day3);
        Set<String> day3Changes = day3.diffFrom(day2);
        System.out.println("  Changed files: " + day3Changes.size() + " — mass modification!\n");

        // ── Day 4: Post-Attack (ransomware still active) ───────────────
        printPhase("DAY 4 — Post-Attack (damage continues)");
        Snapshot day4 = snapshotManager.createFromMetadata(sourceId, buildDay4PostAttackFiles());
        System.out.println("Created: " + day4 + "\n");

        // ═══ THREAT DETECTION PIPELINE ═════════════════════════════════
        printPhase("RUNNING THREAT DETECTION PIPELINE");

        // Scan each snapshot
        System.out.println("Scanning Day 1...");
        ThreatReport report1 = threatDetector.analyze(day1.snapshotId());
        System.out.println("  Result: " + (report1.isClean() ? "✓ CLEAN" : "✗ THREATS FOUND") + "\n");

        System.out.println("Scanning Day 2...");
        ThreatReport report2 = threatDetector.analyze(day2.snapshotId());
        System.out.println("  Result: " + (report2.isClean() ? "✓ CLEAN" : "✗ THREATS FOUND") + "\n");

        System.out.println("Scanning Day 3 (attack day)...");
        ThreatReport report3 = threatDetector.analyze(day3.snapshotId());
        System.out.println("  Result: " + (report3.isClean() ? "✓ CLEAN" : "✗ THREATS FOUND"));
        System.out.println(report3);

        System.out.println("Scanning Day 4...");
        ThreatReport report4 = threatDetector.analyze(day4.snapshotId());
        System.out.println("  Result: " + (report4.isClean() ? "✓ CLEAN" : "✗ THREATS FOUND"));
        System.out.println(report4);

        // ═══ BLAST RADIUS ANALYSIS ═════════════════════════════════════
        printPhase("BLAST RADIUS ANALYSIS");
        BlastRadius blast = blastAnalyzer.analyze(day4.snapshotId());
        System.out.println(blast.summary());

        // ═══ CYBER RECOVERY PLAN ═══════════════════════════════════════
        printPhase("CYBER RECOVERY PLAN");
        RecoveryPlanner.RecoveryPlan plan = recoveryPlanner.createRecoveryPlan(sourceId);
        System.out.println(plan.prettyPrint());

        // ═══ FINAL STATUS ══════════════════════════════════════════════
        printPhase("SNAPSHOT CHAIN STATUS");
        for (Snapshot snap : store.getBySource(sourceId)) {
            String icon = switch (snap.status()) {
                case CLEAN       -> "✓";
                case SUSPICIOUS  -> "⚠";
                case COMPROMISED -> "✗";
            };
            System.out.printf("  %s [%s] %s — %d files%n",
                    icon, snap.status(), snap.snapshotId(), snap.fileCount());
        }
    }

    // ─── Simulation Data Builders ──────────────────────────────────────

    /** Day 1: Normal business files with typical entropy values. */
    private Map<String, FileMetadata> buildDay1Files() {
        Instant t = Instant.parse("2025-01-01T00:00:00Z");
        Map<String, FileMetadata> files = new LinkedHashMap<>();
        files.put("finance/q4-report.xlsx",    meta("finance/q4-report.xlsx",    "aabb1100", 52000,  4.2, t));
        files.put("finance/budget-2025.xlsx",   meta("finance/budget-2025.xlsx",   "aabb1101", 34000,  4.5, t));
        files.put("hr/employee-list.csv",       meta("hr/employee-list.csv",       "aabb1102", 15000,  3.8, t));
        files.put("hr/benefits-guide.pdf",      meta("hr/benefits-guide.pdf",      "aabb1103", 280000, 5.1, t));
        files.put("engineering/design-doc.md",  meta("engineering/design-doc.md",  "aabb1104", 8000,   4.0, t));
        files.put("engineering/arch-diagram.png",meta("engineering/arch-diagram.png","aabb1105",145000, 7.2, t));
        files.put("legal/contract-template.docx",meta("legal/contract-template.docx","aabb1106",44000, 4.3, t));
        files.put("legal/nda-signed.pdf",       meta("legal/nda-signed.pdf",       "aabb1107", 92000,  5.0, t));
        files.put("marketing/campaign-v2.pptx", meta("marketing/campaign-v2.pptx", "aabb1108", 380000, 5.5, t));
        files.put("marketing/brand-assets.zip", meta("marketing/brand-assets.zip", "aabb1109", 2200000,7.6, t));
        return files;
    }

    /** Day 2: A few normal edits — low change rate, no entropy anomalies. */
    private Map<String, FileMetadata> buildDay2Files() {
        Instant t = Instant.parse("2025-01-02T00:00:00Z");
        Map<String, FileMetadata> files = new LinkedHashMap<>(buildDay1Files());
        // Two files edited normally
        files.put("finance/q4-report.xlsx",    meta("finance/q4-report.xlsx",   "ccdd2200", 53000,  4.3, t));
        files.put("engineering/design-doc.md", meta("engineering/design-doc.md", "ccdd2201", 8500,   4.1, t));
        return files;
    }

    /** Day 3: RANSOMWARE — most files encrypted (high entropy), ransom note dropped. */
    private Map<String, FileMetadata> buildDay3AttackFiles() {
        Instant t = Instant.parse("2025-01-03T00:00:00Z");
        Map<String, FileMetadata> files = new LinkedHashMap<>();
        // Encrypted versions — entropy spikes to ~7.95+
        files.put("finance/q4-report.xlsx.locked",    meta("finance/q4-report.xlsx.locked",    "eeee0001", 52000, 7.98, t));
        files.put("finance/budget-2025.xlsx.locked",   meta("finance/budget-2025.xlsx.locked",   "eeee0002", 34000, 7.97, t));
        files.put("hr/employee-list.csv.locked",       meta("hr/employee-list.csv.locked",       "eeee0003", 15000, 7.99, t));
        files.put("hr/benefits-guide.pdf.locked",      meta("hr/benefits-guide.pdf.locked",      "eeee0004", 280000,7.96, t));
        files.put("engineering/design-doc.md.locked",  meta("engineering/design-doc.md.locked",  "eeee0005", 8500,  7.98, t));
        files.put("engineering/arch-diagram.png",      meta("engineering/arch-diagram.png",      "aabb1105", 145000,7.2,  t)); // unchanged
        files.put("legal/contract-template.docx.locked",meta("legal/contract-template.docx.locked","eeee0006",44000,7.97, t));
        files.put("legal/nda-signed.pdf.locked",       meta("legal/nda-signed.pdf.locked",       "eeee0007", 92000, 7.95, t));
        files.put("marketing/campaign-v2.pptx.locked", meta("marketing/campaign-v2.pptx.locked", "eeee0008", 380000,7.96, t));
        files.put("marketing/brand-assets.zip",        meta("marketing/brand-assets.zip",        "aabb1109", 2200000,7.6, t)); // unchanged
        // Ransom note dropped
        files.put("README-DECRYPT.txt",                meta("README-DECRYPT.txt",               "dead0001", 2048,   3.5, t));
        files.put("how.to.decrypt.html",               meta("how.to.decrypt.html",              "dead0002", 4096,   4.1, t));
        return files;
    }

    /** Day 4: Ransomware still active, remaining files encrypted. */
    private Map<String, FileMetadata> buildDay4PostAttackFiles() {
        Instant t = Instant.parse("2025-01-04T00:00:00Z");
        Map<String, FileMetadata> files = new LinkedHashMap<>(buildDay3AttackFiles());
        // Even the previously untouched files are now encrypted
        files.put("engineering/arch-diagram.png.encrypted",
                meta("engineering/arch-diagram.png.encrypted", "eeee0009", 145000, 7.99, t));
        files.remove("engineering/arch-diagram.png");
        files.put("marketing/brand-assets.zip.encrypted",
                meta("marketing/brand-assets.zip.encrypted", "eeee0010", 2200000, 7.99, t));
        files.remove("marketing/brand-assets.zip");
        return files;
    }

    private FileMetadata meta(String path, String hash, long size, double entropy, Instant t) {
        return new FileMetadata(path, hash, size, entropy, t);
    }

    // ─── Output Helpers ────────────────────────────────────────────────

    private void printBanner() {
        System.out.println("""
            
            ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
            ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
            ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
            ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
            ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
            ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
            
              Snapshot-Based Data Protection & Threat Detection Engine
              ─────────────────────────────────────────────────────────
              Simulating: Ransomware attack → Detection → Recovery
            
            """);
    }

    private void printPhase(String phase) {
        System.out.println("\n═══ " + phase + " " + "═".repeat(Math.max(1, 50 - phase.length())));
    }
}
