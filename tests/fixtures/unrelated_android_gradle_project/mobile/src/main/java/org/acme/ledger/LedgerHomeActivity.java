package org.acme.ledger;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

public class LedgerHomeActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        InvoiceCalculator calculator = new InvoiceCalculator(new TaxRuleEngine());
        long totalCents = calculator.computeTotalCents(12500L, "EU");
        TextView view = new TextView(this);
        view.setText("Total Cents: " + totalCents);
        setContentView(view);
    }
}
