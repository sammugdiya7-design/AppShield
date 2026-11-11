package org.acme.ledger;

public class InvoiceCalculator {
    private final TaxRuleEngine taxRuleEngine;

    public InvoiceCalculator(TaxRuleEngine taxRuleEngine) {
        this.taxRuleEngine = taxRuleEngine;
    }

    public long computeTotalCents(long subtotalCents, String regionCode) {
        int rateBasisPoints = taxRuleEngine.resolveBasisPoints(regionCode);
        long tax = (subtotalCents * rateBasisPoints) / 10000L;
        return subtotalCents + tax;
    }
}
