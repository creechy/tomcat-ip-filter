package org.fakebelieve.tomcat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

public class FilteringNioEndpointTest {

    @Test
    public void testCidrBlockIpv4Exact() {
        CidrBlock block = new CidrBlock("192.168.1.10");
        assertTrue(block.matches("192.168.1.10"));
        assertFalse(block.matches("192.168.1.11"));
    }

    @Test
    public void testCidrBlockIpv4Range() {
        CidrBlock block = new CidrBlock("192.168.1.0/24");
        assertTrue(block.matches("192.168.1.0"));
        assertTrue(block.matches("192.168.1.1"));
        assertTrue(block.matches("192.168.1.255"));
        assertFalse(block.matches("192.168.2.1"));
        assertFalse(block.matches("10.0.0.1"));
    }

    @Test
    public void testCidrBlockIpv4Subnet() {
        CidrBlock block = new CidrBlock("192.168.1.128/25");
        assertTrue(block.matches("192.168.1.128"));
        assertTrue(block.matches("192.168.1.255"));
        assertFalse(block.matches("192.168.1.127"));
        assertFalse(block.matches("192.168.1.0"));
    }

    @Test
    public void testCidrBlockIpv6Range() {
        CidrBlock block = new CidrBlock("2001:db8::/32");
        assertTrue(block.matches("2001:db8:0:0:0:0:0:1"));
        assertTrue(block.matches("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"));
        assertFalse(block.matches("2001:db9::1"));
    }

    @Test
    public void testInvalidCidr() {
        assertThrows(IllegalArgumentException.class, () -> {
            new CidrBlock("999.999.999.999/24");
        });
        assertThrows(IllegalArgumentException.class, () -> {
            new CidrBlock("192.168.1.1/33");
        });
    }

    @Test
    public void testEndpointFileLoadingAndMatching(@TempDir Path tempDir) throws IOException {
        File blockedFile = tempDir.resolve("blocked-ips.txt").toFile();
        try (FileWriter writer = new FileWriter(blockedFile)) {
            writer.write("# Comment line\n");
            writer.write("10.0.0.5\n");
            writer.write("192.168.100.0/24  # subnet block\n");
            writer.write("invalid_ip_here\n");
            writer.write("2001:db9::/64\n");
        }

        File allowedFile = tempDir.resolve("allowed-ips.txt").toFile();
        try (FileWriter writer = new FileWriter(allowedFile)) {
            writer.write("192.168.100.50\n");
            writer.write("10.1.1.0/28\n");
        }

        FilteringNioEndpoint endpoint = new FilteringNioEndpoint();
        endpoint.setBlockedIpsFile(blockedFile.getAbsolutePath());
        endpoint.setAllowedIpsFile(allowedFile.getAbsolutePath());

        // Test blocked exact and CIDR
        assertTrue(endpoint.isBlocked("10.0.0.5"));
        assertTrue(endpoint.isBlocked("192.168.100.42"));
        assertTrue(endpoint.isBlocked("2001:db9::1234"));
        assertFalse(endpoint.isBlocked("10.0.0.6"));

        // Test allowed exact and CIDR
        assertTrue(endpoint.isAllowed("192.168.100.50"));
        assertTrue(endpoint.isAllowed("10.1.1.5"));
        assertFalse(endpoint.isAllowed("10.1.1.20"));
    }
}
