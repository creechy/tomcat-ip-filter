package org.fakebelieve.tomcat;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.tomcat.util.net.NioEndpoint;

/**
 * NioEndpoint that rejects connections from blocked IPs or non-allowed IPs at accept() time,
 * before any TLS handshake or HTTP parsing takes place. Supports both single IPs and CIDR blocks.
 *
 * Wired into Tomcat via FilteringHttp11NioProtocol and the connector's
 * "protocol" attribute in server.xml.
 */
public class FilteringNioEndpoint extends NioEndpoint {

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

    private File resolveFile(String filePath) {
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

    private static class IpLoadResult {
        final Set<String> exactIps;
        final List<CidrBlock> cidrBlocks;

        IpLoadResult(Set<String> exactIps, List<CidrBlock> cidrBlocks) {
            this.exactIps = exactIps;
            this.cidrBlocks = cidrBlocks;
        }
    }

    private IpLoadResult loadIpsFromFile(String filePath) {
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
                        CidrBlock block = new CidrBlock(line);
                        tempCidr.add(block);
                        // If it's a single IP (no slash) or full prefix, we can also record exact match
                        if (!line.contains("/")) {
                            // Normalize via InetAddress
                            try {
                                InetAddress addr = InetAddress.getByName(line);
                                tempExact.add(addr.getHostAddress());
                            } catch (Exception e) {
                                tempExact.add(line);
                            }
                        }
                    } catch (Exception e) {
                        getLog().warn("Invalid IP or CIDR entry ignored: '" + line + "' in file " + file.getAbsolutePath());
                    }
                }
            }
            return new IpLoadResult(Set.copyOf(tempExact), List.copyOf(tempCidr));
        } catch (IOException e) {
            getLog().error("Failed to read IPs file: " + file.getAbsolutePath(), e);
            return null;
        }
    }

    public synchronized void loadBlockedIpsFromFile(String filePath) {
        this.blockedIpsFile = filePath;
        File file = resolveFile(filePath);
        if (file == null) {
            return;
        }

        getLog().info("Loading blocked IPs/CIDRs from file: " + file.getAbsolutePath());

        if (!file.exists() || !file.isFile()) {
            getLog().warn("Blocked IPs file not found or not a valid file: " + file.getAbsolutePath());
            return;
        }

        this.blockedFileLastModified = file.lastModified();
        IpLoadResult loaded = loadIpsFromFile(filePath);
        if (loaded != null) {
            this.blockedIps = loaded.exactIps;
            this.blockedCidrs = loaded.cidrBlocks;
            getLog().info("Successfully loaded and replaced blocked IPs/CIDRs: " + loaded.exactIps.size() + " exact IP(s), " + loaded.cidrBlocks.size() + " CIDR block(s) from " + file.getAbsolutePath());
        }
    }

    public synchronized void loadAllowedIpsFromFile(String filePath) {
        this.allowedIpsFile = filePath;
        File file = resolveFile(filePath);
        if (file == null) {
            return;
        }

        getLog().info("Loading allowed IPs/CIDRs from file: " + file.getAbsolutePath());

        if (!file.exists() || !file.isFile()) {
            getLog().warn("Allowed IPs file not found or not a valid file: " + file.getAbsolutePath());
            this.allowedIps = Set.of();
            this.allowedCidrs = List.of();
            return;
        }

        this.allowedFileLastModified = file.lastModified();
        IpLoadResult loaded = loadIpsFromFile(filePath);
        if (loaded != null) {
            this.allowedIps = loaded.exactIps;
            this.allowedCidrs = loaded.cidrBlocks;
            getLog().info("Successfully loaded and replaced allowed IPs/CIDRs: " + loaded.exactIps.size() + " exact IP(s), " + loaded.cidrBlocks.size() + " CIDR block(s) from " + file.getAbsolutePath());
        }
    }

    private void checkAndReloadFiles() {
        long now = System.currentTimeMillis();
        // Quick unsynchronized check to avoid lock contention on every connection
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
                        getLog().info("Blocked IPs file has changed. Reloading from: " + file.getAbsolutePath());
                        loadBlockedIpsFromFile(blockedIpsFile);
                    }
                }
            }

            if (allowedIpsFile != null && !allowedIpsFile.trim().isEmpty()) {
                File file = resolveFile(allowedIpsFile);
                if (file != null && file.exists() && file.isFile()) {
                    long currentModified = file.lastModified();
                    if (currentModified > allowedFileLastModified) {
                        getLog().info("Allowed IPs file has changed. Reloading from: " + file.getAbsolutePath());
                        loadAllowedIpsFromFile(allowedIpsFile);
                    }
                }
            }
        }
    }

    @Override
    protected SocketChannel serverSocketAccept() throws Exception {
        while (true) {
            // Periodically check if the blocked or allowed IPs files have been modified
            checkAndReloadFiles();

            SocketChannel channel = super.serverSocketAccept();
            if (channel == null) {
                return null;
            }

            String remoteIp = null;
            if (channel.getRemoteAddress() instanceof InetSocketAddress addr) {
                remoteIp = addr.getAddress().getHostAddress();
            }

            getLog().warn("Checking connection IP: " + remoteIp);

            if (remoteIp != null) {
                // If an allow list is configured and the IP is on it, let it through without checking the block list
                if (isAllowed(remoteIp)) {
                    getLog().info("Accepted connection from allowed IP: " + remoteIp);
                    return channel;
                }

                if (isBlocked(remoteIp)) {
                    getLog().warn("Rejected connection from blocked IP: " + remoteIp);
                    try {
                        channel.close();
                    } catch (Exception ignored) {
                        // nothing to do
                    }
                    continue;
                }
            }

            return channel;
        }
    }
}
