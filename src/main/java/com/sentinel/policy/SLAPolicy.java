package com.sentinel.policy;

import java.time.Duration;
import java.util.Objects;

/**
 * Defines the Service Level Agreement (SLA) policy for a protected workload.
 *
 * In Rubrik, SLA policies are the central governance mechanism. Instead of
 * configuring individual backup jobs, administrators define declarative SLA
 * policies that specify:
 *   - How frequently to snapshot (RPO — Recovery Point Objective)
 *   - How long to retain snapshots (retention)
 *   - What tier of threat scanning to apply
 *
 * The system then automatically schedules, executes, and manages the full
 * lifecycle. This policy-driven approach is one of Rubrik's key differentiators
 * over legacy backup systems that require manual job configuration.
 */
public final class SLAPolicy {

    public enum ThreatScanLevel {
        NONE,        // No threat scanning
        BASIC,       // IoC scan only
        FULL         // IoC scan + anomaly detection + blast radius
    }

    private final String         policyName;
    private final Duration       snapshotFrequency;   // RPO
    private final Duration       retentionPeriod;
    private final ThreatScanLevel scanLevel;

    public SLAPolicy(String policyName, Duration snapshotFrequency,
                     Duration retentionPeriod, ThreatScanLevel scanLevel) {
        this.policyName        = Objects.requireNonNull(policyName);
        this.snapshotFrequency = Objects.requireNonNull(snapshotFrequency);
        this.retentionPeriod   = Objects.requireNonNull(retentionPeriod);
        this.scanLevel         = Objects.requireNonNull(scanLevel);
    }

    public String          policyName()        { return policyName; }
    public Duration        snapshotFrequency() { return snapshotFrequency; }
    public Duration        retentionPeriod()   { return retentionPeriod; }
    public ThreatScanLevel scanLevel()         { return scanLevel; }

    /** Pre-built policies matching common enterprise tiers. */
    public static SLAPolicy gold() {
        return new SLAPolicy("Gold", Duration.ofHours(4), Duration.ofDays(30),
                ThreatScanLevel.FULL);
    }

    public static SLAPolicy silver() {
        return new SLAPolicy("Silver", Duration.ofHours(12), Duration.ofDays(14),
                ThreatScanLevel.BASIC);
    }

    public static SLAPolicy bronze() {
        return new SLAPolicy("Bronze", Duration.ofHours(24), Duration.ofDays(7),
                ThreatScanLevel.NONE);
    }

    @Override
    public String toString() {
        return String.format("SLAPolicy{name='%s', RPO=%s, retention=%s, scan=%s}",
                policyName, snapshotFrequency, retentionPeriod, scanLevel);
    }
}
