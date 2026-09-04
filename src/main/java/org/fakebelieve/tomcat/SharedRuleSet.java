package org.fakebelieve.tomcat;

import java.util.List;
import java.util.Set;

class SharedRuleSet {
    volatile Set<String> exactIps = Set.of();
    volatile List<CidrBlock> cidrBlocks = List.of();
    volatile long lastModified = -1L;
    volatile long lastCheckedTime = 0L;

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
