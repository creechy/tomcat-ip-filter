package org.fakebelieve.tomcat;

import java.util.concurrent.ConcurrentHashMap;

class RuleSetCache {

    private static final ConcurrentHashMap<String, SharedRuleSet> RULE_CACHE = new ConcurrentHashMap<>();

    public static SharedRuleSet get(String key) {
        return RULE_CACHE.computeIfAbsent(key, k -> new SharedRuleSet());
    }
}
