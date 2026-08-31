package org.fakebelieve.tomcat;

import org.apache.coyote.http11.Http11NioProtocol;

/**
 * Thin wrapper so server.xml can reference this protocol class directly:
 *
 *   <Connector port="8080"
 *              protocol="org.fakebelieve.tomcat.FilteringHttp11NioProtocol"
 *              connectionTimeout="20000"
 *              redirectPort="8443"
 *              blockedIpsFile="conf/blocked-ips.txt"
 *              allowedIpsFile="conf/allowed-ips.txt" />
 */
public class FilteringHttp11NioProtocol extends Http11NioProtocol {

    public FilteringHttp11NioProtocol() {
        super(new FilteringNioEndpoint());
    }

    /**
     * Sets the path to a file containing blocked IPs, one per line.
     * Comments starting with '#' and blank lines are ignored.
     * Tomcat calls this method automatically via reflection if the
     * "blockedIpsFile" attribute is present on the Connector in server.xml.
     *
     * @param filePath path to the blocked IPs file (absolute or relative to catalina.base)
     */
    public void setBlockedIpsFile(String filePath) {
        ((FilteringNioEndpoint) getEndpoint()).setBlockedIpsFile(filePath);
    }

    /**
     * Gets the configured path to the blocked IPs file.
     *
     * @return the file path string
     */
    public String getBlockedIpsFile() {
        return ((FilteringNioEndpoint) getEndpoint()).getBlockedIpsFile();
    }

    /**
     * Sets the path to a file containing allowed IPs, one per line.
     * Comments starting with '#' and blank lines are ignored.
     * Tomcat calls this method automatically via reflection if the
     * "allowedIpsFile" attribute is present on the Connector in server.xml.
     *
     * @param filePath path to the allowed IPs file (absolute or relative to catalina.base)
     */
    public void setAllowedIpsFile(String filePath) {
        ((FilteringNioEndpoint) getEndpoint()).setAllowedIpsFile(filePath);
    }

    /**
     * Alias for setAllowedIpsFile.
     *
     * @param filePath path to the allowed IPs file
     */
    public void setAllowedIpFile(String filePath) {
        ((FilteringNioEndpoint) getEndpoint()).setAllowedIpFile(filePath);
    }

    /**
     * Gets the configured path to the allowed IPs file.
     *
     * @return the file path string
     */
    public String getAllowedIpsFile() {
        return ((FilteringNioEndpoint) getEndpoint()).getAllowedIpsFile();
    }

    /**
     * Alias for getAllowedIpsFile.
     *
     * @return the file path string
     */
    public String getAllowedIpFile() {
        return ((FilteringNioEndpoint) getEndpoint()).getAllowedIpFile();
    }
}
