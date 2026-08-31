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
 * NioEndpoint that rejects connections from blocked IPs at accept() time,
 * before any TLS handshake or HTTP parsing takes place.
 *
 * Wired into Tomcat via FilteringHttp11NioProtocol and the connector's
 * "protocol" attribute in server.xml.
 */
public class FilteringNioEndpoint extends NioEndpoint {

    private volatile Set<String> blockedIps = Set.of();

    private String blockedIpsFile;
    private long fileLastModified = 0L;
    private long lastCheckedTime = 0L;
    private static final long CHECK_INTERVAL_MS = 5000; // Throttle check to every 5 seconds

    public boolean isBlocked(String ip) {
        return blockedIps.contains(ip);
    }

    public void setBlockedIpsFile(String filePath) {
        this.blockedIpsFile = filePath;
	this.fileLastModified = 0L;
        loadBlockedIpsFromFile(filePath);
    }

    public String getBlockedIpsFile() {
        return blockedIpsFile;
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

    public synchronized void loadBlockedIpsFromFile(String filePath) {
        File file = resolveFile(filePath);
        if (file == null) {
            return;
        }

        getLog().info("Loading blocked IPs from file: " + file.getAbsolutePath());

        if (!file.exists() || !file.isFile()) {
            getLog().warn("Blocked IPs file not found or not a valid file: " + file.getAbsolutePath());
            return;
        }

        this.fileLastModified = file.lastModified();
        Set<String> tempSet = new HashSet<>();
        int count = 0;
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
                    count++;
                }
            }
            // Atomically swap in an immutable, read-only set
            this.blockedIps = Set.copyOf(tempSet);
            getLog().info("Successfully loaded and replaced blocked IPs with " + count + " IP(s) from " + file.getAbsolutePath());
        } catch (IOException e) {
            getLog().error("Failed to read blocked IPs file: " + file.getAbsolutePath(), e);
        }
    }

    private void checkAndReloadFile() {
        if (blockedIpsFile == null || blockedIpsFile.trim().isEmpty()) {
            return;
        }

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

            File file = resolveFile(blockedIpsFile);
            if (file != null && file.exists() && file.isFile()) {
                long currentModified = file.lastModified();
                if (currentModified > fileLastModified) {
                    getLog().info("Blocked IPs file has changed. Reloading from: " + file.getAbsolutePath());
                    loadBlockedIpsFromFile(blockedIpsFile);
                }
            }
        }
    }

    @Override
    protected SocketChannel serverSocketAccept() throws Exception {
        while (true) {
            // Periodically check if the blocked IPs file has been modified
            checkAndReloadFile();

            SocketChannel channel = super.serverSocketAccept();
            if (channel == null) {
                return null;
            }

            String remoteIp = null;
            if (channel.getRemoteAddress() instanceof InetSocketAddress addr) {
                remoteIp = addr.getAddress().getHostAddress();
            }

            getLog().warn("Checking connection IP: " + remoteIp);

            if (remoteIp != null && isBlocked(remoteIp)) {
                getLog().warn("Rejected connection from blocked IP: " + remoteIp);
                try {
                    channel.close();
                } catch (Exception ignored) {
                    // nothing to do
                }
                continue;
            }

            return channel;
        }
    }
}
