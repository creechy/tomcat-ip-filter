package org.fakebelieve.tomcat;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class FilteringValveTest {

    @Test
    public void testValveFileLoadingAndMatching(@TempDir Path tempDir) throws IOException {
        File blockedFile = tempDir.resolve("blocked-ips.txt").toFile();
        try (FileWriter writer = new FileWriter(blockedFile)) {
            writer.write("10.0.0.5\n");
            writer.write("192.168.100.0/24\n");
        }

        File allowedFile = tempDir.resolve("allowed-ips.txt").toFile();
        try (FileWriter writer = new FileWriter(allowedFile)) {
            writer.write("192.168.100.50\n");
        }

        FilteringValve valve = new FilteringValve();
        valve.setBlockedIpsFile(blockedFile.getAbsolutePath());
        valve.setAllowedIpsFile(allowedFile.getAbsolutePath());
        valve.setErrorCode(444);

        assertEquals(444, valve.getErrorCode());
        assertTrue(valve.isBlocked("10.0.0.5"));
        assertTrue(valve.isBlocked("192.168.100.10"));
        assertFalse(valve.isBlocked("10.0.0.6"));

        assertTrue(valve.isAllowed("192.168.100.50"));
        assertFalse(valve.isAllowed("192.168.100.10"));
    }
}
