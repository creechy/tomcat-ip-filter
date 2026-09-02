package org.fakebelieve.tomcat;

import java.net.InetSocketAddress;
import java.nio.channels.SocketChannel;
import org.apache.tomcat.util.net.NioEndpoint;

/**
 * NioEndpoint that rejects connections from blocked IPs or non-allowed IPs at accept() time,
 * before any TLS handshake or HTTP parsing takes place. Supports both single IPs and CIDR blocks.
 *
 * Wired into Tomcat via FilteringHttp11NioProtocol and the connector's
 * "protocol" attribute in server.xml.
 */
public class FilteringNioEndpoint extends NioEndpoint {

    private final IpFilterSupport ipFilter = new IpFilterSupport(this::getLog);

    public boolean isBlocked(String ip) {
        return ipFilter.isBlocked(ip);
    }

    public boolean isAllowed(String ip) {
        return ipFilter.isAllowed(ip);
    }

    public void setBlockedIpsFile(String filePath) {
        ipFilter.setBlockedIpsFile(filePath);
    }

    public String getBlockedIpsFile() {
        return ipFilter.getBlockedIpsFile();
    }

    public void setAllowedIpsFile(String filePath) {
        ipFilter.setAllowedIpsFile(filePath);
    }

    public void setAllowedIpFile(String filePath) {
        ipFilter.setAllowedIpFile(filePath);
    }

    public String getAllowedIpsFile() {
        return ipFilter.getAllowedIpsFile();
    }

    public String getAllowedIpFile() {
        return ipFilter.getAllowedIpFile();
    }

    @Override
    protected SocketChannel serverSocketAccept() throws Exception {
        while (true) {
            // Periodically check if the blocked or allowed IPs files have been modified
            ipFilter.checkAndReloadFiles();

            SocketChannel channel = super.serverSocketAccept();
            if (channel == null) {
                return null;
            }

            String remoteIp = null;
            if (channel.getRemoteAddress() instanceof InetSocketAddress addr) {
                remoteIp = addr.getAddress().getHostAddress();
            }

            if (remoteIp != null) {
                // If an allow list is configured and the IP is on it, let it through without checking the block list
                if (isAllowed(remoteIp)) {
                    getLog().info("Accepted connection from allowed IP: " + remoteIp);
                    return channel;
                }

                if (isBlocked(remoteIp)) {
                    getLog().info("Rejected connection from blocked IP: " + remoteIp);
                    try {
                        channel.close();
                    } catch (Exception ignored) {
                        // nothing to do
                    }
                    continue;
                }
            }

            getLog().info("Passed through connection from IP: " + remoteIp);

            return channel;
        }
    }
}
