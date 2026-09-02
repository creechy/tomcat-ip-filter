package org.fakebelieve.tomcat;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;

/**
 * Tomcat Valve that filters requests based on blocked IPs/CIDRs and allowed IPs/CIDRs
 * loaded from files. Rejects unauthorized requests with a configurable HTTP error code (e.g. 404, 444, 403).
 * Uses request.getRemoteAddr() which should contain the most appropriate address based on other filters like RemoteIpValve.
 */
public class FilteringValve extends ValveBase {

    private final IpFilterSupport ipFilter = new IpFilterSupport(() -> containerLog);
    private int errorCode = HttpServletResponse.SC_FORBIDDEN; // Default to 403 Forbidden

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
        return ipFilter.getAllowedIpsFile();
    }

    public void setErrorCode(int errorCode) {
        this.errorCode = errorCode;
    }

    public int getErrorCode() {
        return errorCode;
    }

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        // Periodically check if the blocked or allowed IPs files have been modified
        ipFilter.checkAndReloadFiles();

        String remoteAddr = request.getRemoteAddr();

        if (remoteAddr != null && !remoteAddr.trim().isEmpty()) {
            String ip = remoteAddr.trim();

            // If an allow list is configured, check if the IP is allowed
            if (isAllowed(ip)) {
                if (containerLog.isDebugEnabled()) {
                    containerLog.debug("Allowed request from IP: " + ip);
                }
                getNext().invoke(request, response);
                return;
            }

            // Check if the IP is blocked
            if (isBlocked(ip)) {
                containerLog.info("Rejected request due to blocked IP: " + ip + " with error code: " + errorCode);
                try {
                    response.sendError(errorCode);
                } catch (Exception e) {
                    // Fallback in case sendError fails or code is non-standard (like 444)
                    try {
                        response.setStatus(errorCode);
                        response.flushBuffer();
                    } catch (Exception ignored) {
                    }
                }
                return;
            }
        }

        // Pass through if neither explicitly allowed nor blocked
        getNext().invoke(request, response);
    }
}
