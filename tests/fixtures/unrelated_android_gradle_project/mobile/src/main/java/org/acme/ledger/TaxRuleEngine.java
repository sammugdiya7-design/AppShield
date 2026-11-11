package org.acme.ledger;

public class TaxRuleEngine {
    public int resolveBasisPoints(String regionCode) {
        if ("EU".equals(regionCode)) {
            return 2000;
        }
        if ("UK".equals(regionCode)) {
            return 2000;
        }
        return 750;
    }
}
