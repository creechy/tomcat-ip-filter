package org.fakebelieve.tomcat;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;

/**
 * Tomcat Valve that filters requests based on blocked IPs/CIDRs and allowed IPs/CIDRs
 * loaded from files. Rejects unauthorized requests with a configurable HTTP error code (e.g. 404, 444, 403).
 * Checks X-Forwarded-For (or a configurable remote IP header) which can be a comma-separated list of IPs.
 */
public class FilteringValve extends ValveBase {

    private final IpFilterSupport ipFilter = new IpFilterSupport(() -> containerLog);
    private int errorCode = HttpServletResponse.SC_FORBIDDEN; // Default to 403 Forbidden
    private String remoteIpHeader = "X-Forwarded-For";

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

    public void setRemoteIpHeader(String remoteIpHeader) {
        this.remoteIpHeader = remoteIpHeader;
    }

    public String getRemoteIpHeader() {
        return remoteIpHeader;
    }

    /**
     * Extracts all IP addresses from the configured header (supporting comma-separated lists like X-Forwarded-For),
     * and falls back to request.getRemoteAddr() if the header is absent or empty.
     */
    private List<String> getClientIps(Request request) {
        List<String> ips = new ArrayList<>();
        if (remoteIpHeader != null && !remoteIpHeader.trim().isEmpty()) {
            String headerValue = request.getHeader(remoteIpHeader);
            if (headerValue != null && !headerValue.trim().isEmpty()) {
                String[] parts = headerValue.split(",");
                for (String part : parts) {
                    String ip = part.trim();
                    if (!ip.isEmpty()) {
                        ips.add(ip);
                    }
                }
            }
        }

        if (ips.isEmpty()) {
            String remoteAddr = request.getRemoteAddr();
            if (remoteAddr != null && !remoteAddr.trim().isEmpty()) {
                ips.add(remoteAddr.trim());
            }
        }

        return ips;
    }

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        // Periodically check if the blocked or allowed IPs files have been modified
        ipFilter.checkAndReloadFiles();

        List<String> clientIps = getClientIps(request);

        // If an allow list is configured, check if any IP in the chain is allowed
        if (!clientIps.isEmpty()) {
            boolean allowed = false;
            String matchedAllowedIp = null;
            for (String ip : clientIps) {
                if (isAllowed(ip)) {
                    allowed = true;
                    matchedAllowedIp = ip;
                    break;
                }
            }

            if (allowed) {
                if (containerLog.isDebugEnabled()) {
                    containerLog.debug("Allowed request from IP in chain: " + matchedAllowedIp);
                }
                getNext().invoke(request, response);
                return;
            }

            // Check if any IP in the chain is blocked
	    boolean blocked = false;
	    String matchedBlockedIp = null;
            for (String ip : clientIps) {
                if (isBlocked(ip)) {
		    blocked = true;
		    matchedBlockedIp = ip;
		    break;
		}
	    }

	    if (blocked) {
		containerLog.info("Rejected request due to blocked IP in chain: " + matchedBlockedIp + " with error code: " + errorCode);
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
