# ProGuard and R8 Rules for Acme Ledger Regression Fixture

-keep public class org.acme.ledger.LedgerHomeActivity extends android.app.Activity {
    public void onCreate(android.os.Bundle);
}

-keep,allowobfuscation class org.acme.ledger.InvoiceCalculator {
    public <methods>;
}

-keep,allowobfuscation class org.acme.ledger.TaxRuleEngine {
    public <methods>;
}
