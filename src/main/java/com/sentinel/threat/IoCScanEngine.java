package com.sentinel.threat;

import com.sentinel.core.FileMetadata;
import com.sentinel.core.Snapshot;
import com.sentinel.threat.ThreatReport.Finding;
import com.sentinel.threat.ThreatReport.Severity;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Scans snapshots for known Indicators of Compromise (IoCs).
 *
 * This models Rubrik's Threat Monitoring feature, which continuously scans
 * backup data for known malware signatures, ransomware artifacts, and other
 * IoCs. In Rubrik's production system, this uses YARA rules and hash-based
 * lookups against threat intelligence feeds.
 *
 * Our implementation supports three IoC types:
 *   1. File hash IoCs    — known malicious file hashes (like VirusTotal)
 *   2. File name IoCs    — ransomware-dropped artifacts (README.txt, .onion links)
 *   3. Extension IoCs    — known ransomware extensions (.locked, .encrypted, .cry)
 *
 * This is the core of what the DTA (Data Threat Analytics) team builds.
 */
public class IoCScanEngine {

    /** Represents a single Indicator of Compromise. */
    public record IoC(String id, String value, IoC.Type type, Severity severity, String description) {
        public enum Type { FILE_HASH, FILE_NAME_PATTERN, FILE_EXTENSION }
    }

    private final List<IoC> iocDatabase = new ArrayList<>();

    public IoCScanEngine() {
        loadDefaultIoCs();
    }

    /** Register a custom IoC (e.g., from a threat intelligence feed). */
    public void addIoC(IoC ioc) {
        iocDatabase.add(Objects.requireNonNull(ioc));
    }

    /**
     * Scans all files in a snapshot against the IoC database.
     * Returns a list of findings for any matches.
     */
    public List<Finding> scan(Snapshot snapshot) {
        List<Finding> findings = new ArrayList<>();

        for (FileMetadata file : snapshot.files().values()) {
            for (IoC ioc : iocDatabase) {
                if (matches(file, ioc)) {
                    findings.add(new Finding(
                        file.filePath(),
                        String.format("IoC match [%s]: %s", ioc.id(), ioc.description()),
                        ioc.severity(),
                        "IoCScanEngine"
                    ));
                }
            }
        }

        return findings;
    }

    private boolean matches(FileMetadata file, IoC ioc) {
        return switch (ioc.type()) {
            case FILE_HASH ->
                file.contentHash().equalsIgnoreCase(ioc.value());

            case FILE_NAME_PATTERN ->
                Pattern.compile(ioc.value(), Pattern.CASE_INSENSITIVE)
                       .matcher(file.filePath())
                       .find();

            case FILE_EXTENSION ->
                file.filePath().toLowerCase().endsWith(ioc.value().toLowerCase());
        };
    }

    /**
     * Loads a default set of well-known ransomware IoCs.
     * In production, this would be fed by Rubrik's threat intelligence pipeline.
     */
    private void loadDefaultIoCs() {
        // Ransomware ransom note patterns
        addIoC(new IoC("IOC-001", "readme.*\\.txt", IoC.Type.FILE_NAME_PATTERN,
                Severity.HIGH, "Potential ransomware note file detected"));
        addIoC(new IoC("IOC-002", "how.to.decrypt", IoC.Type.FILE_NAME_PATTERN,
                Severity.CRITICAL, "Ransomware decryption instructions detected"));
        addIoC(new IoC("IOC-003", "restore.*files", IoC.Type.FILE_NAME_PATTERN,
                Severity.HIGH, "Ransomware recovery instructions detected"));
        addIoC(new IoC("IOC-004", "decrypt.*instruction", IoC.Type.FILE_NAME_PATTERN,
                Severity.CRITICAL, "Ransomware decryption guide detected"));

        // Known ransomware file extensions
        addIoC(new IoC("IOC-010", ".locked", IoC.Type.FILE_EXTENSION,
                Severity.HIGH, "Known ransomware extension (.locked)"));
        addIoC(new IoC("IOC-011", ".encrypted", IoC.Type.FILE_EXTENSION,
                Severity.HIGH, "Known ransomware extension (.encrypted)"));
        addIoC(new IoC("IOC-012", ".cry", IoC.Type.FILE_EXTENSION,
                Severity.MEDIUM, "Known ransomware extension (.cry)"));
        addIoC(new IoC("IOC-013", ".wnry", IoC.Type.FILE_EXTENSION,
                Severity.CRITICAL, "WannaCry ransomware extension detected"));
        addIoC(new IoC("IOC-014", ".zepto", IoC.Type.FILE_EXTENSION,
                Severity.HIGH, "Zepto ransomware extension detected"));
        addIoC(new IoC("IOC-015", ".cerber", IoC.Type.FILE_EXTENSION,
                Severity.HIGH, "Cerber ransomware extension detected"));
    }

    public int iocCount() {
        return iocDatabase.size();
    }
}
