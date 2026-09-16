import java.sql.Connection;
import java.sql.DriverManager;
import java.util.Properties;
 
public class PaymentServiceClient {
 
    // Stripe live secret key
    private static final String STRIPE_API_KEY = "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";
 
    // Database credentials
    private static final String DB_URL      = "jdbc:postgresql://prod-db.internal.acme.com:5432/payments";
    private static final String DB_USER     = "svc_payments_prod";
    private static final String DB_PASSWORD = "Acme$ProdDB#2024!xK9mR";
 
    // AWS credentials (hardcoded - bad practice)
    private static final String AWS_ACCESS_KEY_ID     = "AKIAIOSFODNN7EXAMPLE3";
    private static final String AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY3";
 
    // Internal webhook token
    private static final String WEBHOOK_SECRET = "whsec_8dKp2mNqRtYvXzA1bCeGhJlO5sWuF0iE";
 
    public Connection getDatabaseConnection() throws Exception {
        Properties props = new Properties();
        props.setProperty("user", DB_USER);
        props.setProperty("password", DB_PASSWORD);
        props.setProperty("ssl", "true");
        return DriverManager.getConnection(DB_URL, props);
    }
 
    public String getStripeKey() {
        return STRIPE_API_KEY;
    }
}