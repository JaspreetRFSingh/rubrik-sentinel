package com.sentinel.policy;

import java.time.Duration;
import java.util.Objects;

/**
 * Defines how aggressively we protect and monitor a workload.
 *
 * Rather than wiring up individual backup jobs, you pick a policy tier that
 * sets the snapshot frequency (RPO), how long to keep snapshots, and how
 * thorough the threat scanning should be. The three pre-built tiers
 * (Gold, Silver, Bronze) cover most cases out of the box.
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

    /** Pre-built tiers for common protection needs — use these instead of constructing a policy by hand. */
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
