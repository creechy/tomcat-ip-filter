package org.fakebelieve.tomcat;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SocketChannel;
import java.util.HashSet;
import java.util.Set;

import org.apache.tomcat.util.net.NioEndpoint;

/**
 * NioEndpoint that rejects connections from blocked IPs or non-allowed IPs at accept() time,
 * before any TLS handshake or HTTP parsing takes place.
 *
 * Wired into Tomcat via FilteringHttp11NioProtocol and the connector's
 * "protocol" attribute in server.xml.
 */
public class FilteringNioEndpoint extends NioEndpoint {

    private volatile Set<String> blockedIps = Set.of();
    private volatile Set<String> allowedIps = Set.of();

    private String blockedIpsFile;
    private String allowedIpsFile;

    private long blockedFileLastModified = 0L;
    private long allowedFileLastModified = 0L;
    private long lastCheckedTime = 0L;
    private static final long CHECK_INTERVAL_MS = 5000; // Throttle check to every 5 seconds

    public boolean isBlocked(String ip) {
        return blockedIps.contains(ip);
    }

    public boolean isAllowed(String ip) {
        return allowedIps.contains(ip);
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

    private Set<String> loadIpsFromFile(String filePath) {
        File file = resolveFile(filePath);
        if (file == null) {
            return null;
        }

        if (!file.exists() || !file.isFile()) {
            return null;
        }

        Set<String> tempSet = new HashSet<>();
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
                    tempSet.add(line);
                }
            }
            return Set.copyOf(tempSet);
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

        getLog().info("Loading blocked IPs from file: " + file.getAbsolutePath());

        if (!file.exists() || !file.isFile()) {
            getLog().warn("Blocked IPs file not found or not a valid file: " + file.getAbsolutePath());
            return;
        }

        this.blockedFileLastModified = file.lastModified();
        Set<String> loaded = loadIpsFromFile(filePath);
        if (loaded != null) {
            this.blockedIps = loaded;
            getLog().info("Successfully loaded and replaced blocked IPs with " + loaded.size() + " IP(s) from " + file.getAbsolutePath());
        }
    }

    public synchronized void loadAllowedIpsFromFile(String filePath) {
        this.allowedIpsFile = filePath;
        File file = resolveFile(filePath);
        if (file == null) {
            return;
        }

        getLog().info("Loading allowed IPs from file: " + file.getAbsolutePath());

        if (!file.exists() || !file.isFile()) {
            getLog().warn("Allowed IPs file not found or not a valid file: " + file.getAbsolutePath());
            this.allowedIps = Set.of();
            return;
        }

        this.allowedFileLastModified = file.lastModified();
        Set<String> loaded = loadIpsFromFile(filePath);
        if (loaded != null) {
            this.allowedIps = loaded;
            getLog().info("Successfully loaded and replaced allowed IPs with " + loaded.size() + " IP(s) from " + file.getAbsolutePath());
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
