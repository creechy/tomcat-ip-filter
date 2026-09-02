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
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import org.apache.juli.logging.Log;

/**
 * Shared support class for IP and CIDR block filtering and file management.
 * Used by both FilteringNioEndpoint and FilteringValve, sharing parsed rules
 * and file modification checks via a static cache keyed by absolute file path.
 */
public class IpFilterSupport {
    private final Log log;

    private String blockedIpsFile;
    private String allowedIpsFile;

    private static final long CHECK_INTERVAL_MS = 5000; // Throttle check to every 5 seconds

    private static class SharedRuleSet {
        private volatile Set<String> exactIps = Set.of();
        private volatile List<CidrBlock> cidrBlocks = List.of();
        private volatile long lastModified = -1L;
        private volatile long lastCheckedTime = 0L;

        public boolean matches(String ip) {
            if (exactIps.contains(ip)) {
                return true;
            }
            for (CidrBlock block : cidrBlocks) {
                if (block.matches(ip)) {
                    return true;
                }
            }
            return false;
        }
    }

    private static final ConcurrentHashMap<String, SharedRuleSet> RULE_CACHE = new ConcurrentHashMap<>();

    public IpFilterSupport(Log staticLog) {
        this.log = staticLog;
    }

    public boolean isBlocked(String ip) {
        if (ip == null) {
            return false;
        }
        checkAndReloadFiles();
        SharedRuleSet ruleSet = getCachedRuleSet(blockedIpsFile);
        return ruleSet != null && ruleSet.matches(ip);
    }

    public boolean isAllowed(String ip) {
        if (ip == null) {
            return false;
        }
        checkAndReloadFiles();
        SharedRuleSet ruleSet = getCachedRuleSet(allowedIpsFile);
        return ruleSet != null && ruleSet.matches(ip);
    }

    public void setBlockedIpsFile(String filePath) {
        this.blockedIpsFile = filePath;
        loadBlockedIpsFromFile(filePath);
    }

    public String getBlockedIpsFile() {
        return blockedIpsFile;
    }

    public void setAllowedIpsFile(String filePath) {
        this.allowedIpsFile = filePath;
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

    private String getFileCacheKey(String filePath) {
        File file = resolveFile(filePath);
        return file != null ? file.getAbsolutePath() : null;
    }

    private SharedRuleSet getCachedRuleSet(String filePath) {
        String key = getFileCacheKey(filePath);
        if (key == null) {
            return null;
        }
        return RULE_CACHE.get(key);
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
                        log.warn("Invalid IP or CIDR entry ignored: '" + line + "' in file "
                                    + file.getAbsolutePath());
                        }
                    }
                }
            }
            return new IpLoadResult(Set.copyOf(tempExact), List.copyOf(tempCidr));
        } catch (IOException e) {
            log.error("Failed to read IPs file: " + file.getAbsolutePath(), e);
            }
            return null;
        }
    }

    private void loadIpsForFile(String filePath, boolean isBlocked) {
        File file = resolveFile(filePath);
        if (file == null) {
            return;
        }

        String key = file.getAbsolutePath();
        SharedRuleSet ruleSet = RULE_CACHE.computeIfAbsent(key, k -> new SharedRuleSet());

        synchronized (ruleSet) {
            if (!file.exists() || !file.isFile()) {
                if (l != null) {
                    l.warn((isBlocked ? "Blocked" : "Allowed") + " IPs file not found or not a valid file: "
                            + file.getAbsolutePath());
                }
                ruleSet.exactIps = Set.of();
                ruleSet.cidrBlocks = List.of();
                ruleSet.lastModified = 0L;
                return;
            }

            long currentModified = file.lastModified();

            if (ruleSet.lastModified == currentModified) {
                if (l != null) {
                    l.info((isBlocked ? "Blocked" : "Allowed") + " addresses already loaded from "
                            + file.getAbsolutePath() + ", skipping redundant load.");
                }
                return;
            }

            if (l != null) {
                l.info("Loading " + (isBlocked ? "blocked" : "allowed") + " addresses from file: "
                        + file.getAbsolutePath());
            }

            ruleSet.lastModified = currentModified;
            IpLoadResult loaded = loadIpsFromFile(filePath);
            if (loaded != null) {
                ruleSet.exactIps = loaded.exactIps;
                ruleSet.cidrBlocks = loaded.cidrBlocks;
                if (l != null) {
                    l.info("Successfully loaded and replaced " + (isBlocked ? "blocked" : "allowed") + " addresses: "
                            + loaded.exactIps.size()
                            + " exact IP(s), " + loaded.cidrBlocks.size() + " CIDR block(s) from "
                            + file.getAbsolutePath());
                }
            }
        }
    }

    public void loadBlockedIpsFromFile(String filePath) {
        this.blockedIpsFile = filePath;
        loadIpsForFile(filePath, true);
    }

    public void loadAllowedIpsFromFile(String filePath) {
        this.allowedIpsFile = filePath;
        loadIpsForFile(filePath, false);
    }

    public void checkAndReloadFiles() {
        checkAndReloadFile(blockedIpsFile, true);
        checkAndReloadFile(allowedIpsFile, false);
    }

    private void checkAndReloadFile(String filePath, boolean isBlockedFile) {
        if (filePath == null || filePath.trim().isEmpty()) {
            return;
        }
        File file = resolveFile(filePath);
        if (file == null || !file.exists() || !file.isFile()) {
            return;
        }

        String key = file.getAbsolutePath();
        SharedRuleSet ruleSet = RULE_CACHE.computeIfAbsent(key, k -> new SharedRuleSet());

        long now = System.currentTimeMillis();
        if (now - ruleSet.lastCheckedTime < CHECK_INTERVAL_MS) {
            return;
        }

        synchronized (ruleSet) {
            long currentNow = System.currentTimeMillis();
            if (currentNow - ruleSet.lastCheckedTime < CHECK_INTERVAL_MS) {
                return;
            }
            ruleSet.lastCheckedTime = currentNow;

            long currentModified = file.lastModified();
            if (currentModified > ruleSet.lastModified) {
                log.info((isBlockedFile ? "Blocked" : "Allowed") + " IPs file has changed. Reloading from: "
                            + file.getAbsolutePath());
                }
                if (isBlockedFile) {
                    loadBlockedIpsFromFile(filePath);
                } else {
                    loadAllowedIpsFromFile(filePath);
                }
            }
        }
    }
}
