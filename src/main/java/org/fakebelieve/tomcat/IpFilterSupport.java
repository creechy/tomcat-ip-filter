package org.fakebelieve.tomcat;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

import org.apache.juli.logging.Log;

/**
 * Shared support class for IP and CIDR block filtering and file management.
 * Used by both FilteringNioEndpoint and FilteringValve.
 */
public class IpFilterSupport {
    private final Supplier<Log> logSupplier;

    private volatile Set<String> blockedIps = Set.of();
    private volatile List<CidrBlock> blockedCidrs = List.of();

    private volatile Set<String> allowedIps = Set.of();
    private volatile List<CidrBlock> allowedCidrs = List.of();

    private String blockedIpsFile;
    private String allowedIpsFile;

    private long blockedFileLastModified = 0L;
    private long allowedFileLastModified = 0L;
    private long lastCheckedTime = 0L;
    private static final long CHECK_INTERVAL_MS = 5000; // Throttle check to every 5 seconds

    public IpFilterSupport(Supplier<Log> logSupplier) {
        this.logSupplier = logSupplier;
    }

    public IpFilterSupport(Log staticLog) {
        this.logSupplier = () -> staticLog;
    }

    private Log getLog() {
        return logSupplier != null ? logSupplier.get() : null;
    }

    public boolean isBlocked(String ip) {
        if (ip == null) {
            return false;
        }
        if (blockedIps.contains(ip)) {
            return true;
        }
        for (CidrBlock block : blockedCidrs) {
            if (block.matches(ip)) {
                return true;
            }
        }
        return false;
    }

    public boolean isAllowed(String ip) {
        if (ip == null) {
            return false;
        }
        if (allowedIps.contains(ip)) {
            return true;
        }
        for (CidrBlock block : allowedCidrs) {
            if (block.matches(ip)) {
                return true;
            }
        }
        return false;
    }

    public void setBlockedIpsFile(String filePath) {
        this.blockedIpsFile = filePath;
        this.blockedFileLastModified = 0L;
        loadBlockedIpsFromFile(filePath);
    }

    public String getBlockedIpsFile() {
        return blockedIpsFile;
    }

    public void setAllowedIpsFile(String filePath) {
        this.allowedIpsFile = filePath;
        this.allowedFileLastModified = 0L;
        loadAllowedIpsFromFile(filePath);
    }

    public void setAllowedIpFile(String filePath) {
        setAllowedIpsFile(filePath);
    }

    public String getAllowedIpsFile() {
        return allowedIpsFile;
    }

    public String getAllowedIpFile() {
        return allowedIpsFile;
    }

    public File resolveFile(String filePath) {
        if (filePath == null || filePath.trim().isEmpty()) {
            return null;
        }
        File file = new File(filePath);
        if (!file.isAbsolute()) {
            String catalinaBase = System.getProperty("catalina.base");
            if (catalinaBase != null) {
                file = new File(catalinaBase, filePath);
            }
        }
        return file;
    }

    public static class IpLoadResult {
        public final Set<String> exactIps;
        public final List<CidrBlock> cidrBlocks;

        public IpLoadResult(Set<String> exactIps, List<CidrBlock> cidrBlocks) {
            this.exactIps = exactIps;
            this.cidrBlocks = cidrBlocks;
        }
    }

    public IpLoadResult loadIpsFromFile(String filePath) {
        File file = resolveFile(filePath);
        if (file == null) {
            return null;
        }

        if (!file.exists() || !file.isFile()) {
            return null;
        }

        Set<String> tempExact = new HashSet<>();
        List<CidrBlock> tempCidr = new ArrayList<>();

        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) {
                    continue;
                }

                int commentIdx = line.indexOf('#');
                if (commentIdx == 0) {
                    continue;
                }

                // Remove any characters after a comment character
                if (commentIdx != -1) {
                    line = line.substring(0, commentIdx).trim();
                }

                // Also remove any characters after the first whitespace
                int spaceIdx = -1;
                for (int i = 0; i < line.length(); i++) {
                    if (Character.isWhitespace(line.charAt(i))) {
                        spaceIdx = i;
                        break;
                    }
                }
                if (spaceIdx != -1) {
                    line = line.substring(0, spaceIdx).trim();
                }

                if (!line.isEmpty()) {
                    try {
                        if (line.contains("/")) {
                            CidrBlock block = new CidrBlock(line);
                            tempCidr.add(block);
                        } else {
                            try {
                                InetAddress addr = InetAddress.getByName(line);
                                tempExact.add(addr.getHostAddress());
                            } catch (Exception e) {
                                tempExact.add(line);
                            }
                        }
                    } catch (Exception e) {
                        Log l = getLog();
                        if (l != null) {
                            l.warn("Invalid IP or CIDR entry ignored: '" + line + "' in file " + file.getAbsolutePath());
                        }
                    }
                }
            }
            return new IpLoadResult(Set.copyOf(tempExact), List.copyOf(tempCidr));
        } catch (IOException e) {
            Log l = getLog();
            if (l != null) {
                l.error("Failed to read IPs file: " + file.getAbsolutePath(), e);
            }
            return null;
        }
    }

    public synchronized void loadBlockedIpsFromFile(String filePath) {
        this.blockedIpsFile = filePath;
        File file = resolveFile(filePath);
        if (file == null) {
            return;
        }

        Log l = getLog();
        if (l != null) {
            l.info("Loading blocked addresses from file: " + file.getAbsolutePath());
        }

        if (!file.exists() || !file.isFile()) {
            if (l != null) {
                l.warn("Blocked IPs file not found or not a valid file: " + file.getAbsolutePath());
            }
            return;
        }

        this.blockedFileLastModified = file.lastModified();
        IpLoadResult loaded = loadIpsFromFile(filePath);
        if (loaded != null) {
            this.blockedIps = loaded.exactIps;
            this.blockedCidrs = loaded.cidrBlocks;
            if (l != null) {
                l.info("Successfully loaded and replaced blocked addresses: " + loaded.exactIps.size() + " exact IP(s), " + loaded.cidrBlocks.size() + " CIDR block(s) from " + file.getAbsolutePath());
            }
        }
    }

    public synchronized void loadAllowedIpsFromFile(String filePath) {
        this.allowedIpsFile = filePath;
        File file = resolveFile(filePath);
        if (file == null) {
            return;
        }

        Log l = getLog();
        if (l != null) {
            l.info("Loading allowed addresses from file: " + file.getAbsolutePath());
        }

        if (!file.exists() || !file.isFile()) {
            if (l != null) {
                l.warn("Allowed IPs file not found or not a valid file: " + file.getAbsolutePath());
            }
            this.allowedIps = Set.of();
            this.allowedCidrs = List.of();
            return;
        }

        this.allowedFileLastModified = file.lastModified();
        IpLoadResult loaded = loadIpsFromFile(filePath);
        if (loaded != null) {
            this.allowedIps = loaded.exactIps;
            this.allowedCidrs = loaded.cidrBlocks;
            if (l != null) {
                l.info("Successfully loaded and replaced allowed addresses: " + loaded.exactIps.size() + " exact IP(s), " + loaded.cidrBlocks.size() + " CIDR block(s) from " + file.getAbsolutePath());
            }
        }
    }

    public void checkAndReloadFiles() {
        long now = System.currentTimeMillis();
        // Quick unsynchronized check to avoid lock contention on every request/connection
        if (now - lastCheckedTime < CHECK_INTERVAL_MS) {
            return;
        }

        synchronized (this) {
            // Re-check interval inside synchronization block
            long currentNow = System.currentTimeMillis();
            if (currentNow - lastCheckedTime < CHECK_INTERVAL_MS) {
                return;
            }
            lastCheckedTime = currentNow;

            if (blockedIpsFile != null && !blockedIpsFile.trim().isEmpty()) {
                File file = resolveFile(blockedIpsFile);
                if (file != null && file.exists() && file.isFile()) {
                    long currentModified = file.lastModified();
                    if (currentModified > blockedFileLastModified) {
                        Log l = getLog();
                        if (l != null) {
                            l.info("Blocked IPs file has changed. Reloading from: " + file.getAbsolutePath());
                        }
                        loadBlockedIpsFromFile(blockedIpsFile);
                    }
                }
            }

            if (allowedIpsFile != null && !allowedIpsFile.trim().isEmpty()) {
                File file = resolveFile(allowedIpsFile);
                if (file != null && file.exists() && file.isFile()) {
                    long currentModified = file.lastModified();
                    if (currentModified > allowedFileLastModified) {
                        Log l = getLog();
                        if (l != null) {
                            l.info("Allowed IPs file has changed. Reloading from: " + file.getAbsolutePath());
                        }
                        loadAllowedIpsFromFile(allowedIpsFile);
                    }
                }
            }
        }
    }
}
