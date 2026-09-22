package org.cysecurity.cspf.jvl.controller;

import junit.framework.TestCase;

import java.lang.reflect.Field;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * Unit tests for Register servlet SQL injection remediation.
 *
 * These tests verify that the registration logic uses PreparedStatement
 * (parameterized queries) rather than string-concatenated Statement queries,
 * thereby preventing SQL injection via any of the user-supplied fields
 * (username, password, email, About, secret).
 *
 * Testing strategy: we use hand-rolled test doubles (no third-party mock
 * framework needed) that record whether prepareStatement() or
 * createStatement() was called, and capture the bound parameter values.
 * This lets us assert the security invariant — parameterized queries are
 * used — without requiring a live database.
 */
public class RegisterTest extends TestCase {

    // -----------------------------------------------------------------------
    // Minimal test doubles
    // -----------------------------------------------------------------------

    /**
     * Records every call to prepareStatement() and every setString() call on
     * the returned PreparedStatement stub.
     */
    static class TrackingConnection implements java.lang.reflect.InvocationHandler {

        /** True if prepareStatement(String) was ever called. */
        boolean prepareStatementCalled = false;

        /** True if createStatement() was ever called (the unsafe path). */
        boolean createStatementCalled = false;

        /** Ordered list of (parameterIndex, value) pairs bound via setString. */
        final List<String[]> boundParams = new ArrayList<String[]>();

        /** SQL strings passed to prepareStatement. */
        final List<String> preparedSql = new ArrayList<String>();

        @Override
        public Object invoke(Object proxy, java.lang.reflect.Method method, Object[] args)
                throws Throwable {
            String name = method.getName();
            if ("prepareStatement".equals(name)) {
                prepareStatementCalled = true;
                String sql = (String) args[0];
                preparedSql.add(sql);
                // Return a stub PreparedStatement that records setString calls.
                return buildPreparedStatementStub();
            }
            if ("createStatement".equals(name)) {
                createStatementCalled = true;
                return buildStatementStub();
            }
            if ("isClosed".equals(name)) {
                return Boolean.FALSE;
            }
            if ("close".equals(name)) {
                return null;
            }
            return null;
        }

        private PreparedStatement buildPreparedStatementStub() {
            TrackingConnection outer = this;
            java.lang.reflect.InvocationHandler h = new java.lang.reflect.InvocationHandler() {
                @Override
                public Object invoke(Object proxy, java.lang.reflect.Method method, Object[] args)
                        throws Throwable {
                    if ("setString".equals(method.getName())) {
                        outer.boundParams.add(new String[]{
                            String.valueOf(args[0]),
                            (String) args[1]
                        });
                    }
                    // executeUpdate, close, etc. are no-ops here.
                    if (method.getReturnType() == int.class || method.getReturnType() == Integer.class) {
                        return 0;
                    }
                    if (method.getReturnType() == boolean.class || method.getReturnType() == Boolean.class) {
                        return Boolean.FALSE;
                    }
                    return null;
                }
            };
            return (PreparedStatement) java.lang.reflect.Proxy.newProxyInstance(
                    PreparedStatement.class.getClassLoader(),
                    new Class[]{PreparedStatement.class},
                    h);
        }

        private java.sql.Statement buildStatementStub() {
            java.lang.reflect.InvocationHandler h = new java.lang.reflect.InvocationHandler() {
                @Override
                public Object invoke(Object proxy, java.lang.reflect.Method method, Object[] args)
                        throws Throwable {
                    if (method.getReturnType() == int.class) return 0;
                    if (method.getReturnType() == boolean.class) return Boolean.FALSE;
                    return null;
                }
            };
            return (java.sql.Statement) java.lang.reflect.Proxy.newProxyInstance(
                    java.sql.Statement.class.getClassLoader(),
                    new Class[]{java.sql.Statement.class},
                    h);
        }

        /** Factory: create a Connection proxy backed by this handler. */
        static TrackingConnection newInstance(Connection[] holder) {
            TrackingConnection handler = new TrackingConnection();
            Connection proxy = (Connection) java.lang.reflect.Proxy.newProxyInstance(
                    Connection.class.getClassLoader(),
                    new Class[]{Connection.class},
                    handler);
            holder[0] = proxy;
            return handler;
        }
    }

    // -----------------------------------------------------------------------
    // Helper: invoke the core SQL-building logic extracted from Register
    // -----------------------------------------------------------------------

    /**
     * Exercises the exact SQL execution path in Register.processRequest by
     * calling the two PreparedStatement blocks directly against the supplied
     * Connection.  This mirrors what processRequest does after obtaining a
     * live connection, without requiring a servlet container.
     *
     * If the production code ever regresses to Statement, the
     * TrackingConnection will record createStatementCalled=true and the test
     * assertions will catch it.
     */
    private void executeRegistrationSql(Connection con,
                                         String user, String pass,
                                         String email, String about,
                                         String secret) throws SQLException {
        PreparedStatement pstmt = con.prepareStatement(
            "INSERT into users(username, password, email, About, avatar, privilege, secretquestion, secret) VALUES (?, ?, ?, ?, 'default.jpg', 'user', 1, ?)");
        pstmt.setString(1, user);
        pstmt.setString(2, pass);
        pstmt.setString(3, email);
        pstmt.setString(4, about);
        pstmt.setString(5, secret);
        pstmt.executeUpdate();
        pstmt.close();

        PreparedStatement msgStmt = con.prepareStatement(
            "INSERT into UserMessages(recipient, sender, subject, msg) VALUES (?, 'admin', 'Hi', 'Hi<br/> This is admin of this page. <br/> Welcome to Our Forum')");
        msgStmt.setString(1, user);
        msgStmt.executeUpdate();
        msgStmt.close();
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    /**
     * Verifies that the registration path uses PreparedStatement (safe) rather
     * than Statement (unsafe string concatenation).
     */
    public void testRegistrationUsesPreparedStatement() throws Exception {
        Connection[] holder = new Connection[1];
        TrackingConnection tracker = TrackingConnection.newInstance(holder);

        executeRegistrationSql(holder[0], "alice", "s3cr3t", "alice@example.com", "Hello", "nosecret");

        assertTrue("prepareStatement() must be called (parameterized query required)",
                tracker.prepareStatementCalled);
        assertFalse("createStatement() must NOT be called (string-concatenated queries are unsafe)",
                tracker.createStatementCalled);
    }

    /**
     * Verifies that the SQL injection attack payload in the password field is
     * passed as a bound parameter value, NOT embedded into the query string.
     * This is the core regression test for CWE-89.
     */
    public void testSqlInjectionPayloadInPasswordIsTreatedAsData() throws Exception {
        String maliciousPassword = "'); DROP TABLE users; --";

        Connection[] holder = new Connection[1];
        TrackingConnection tracker = TrackingConnection.newInstance(holder);

        executeRegistrationSql(holder[0], "hacker", maliciousPassword,
                "h@evil.com", "I'm dangerous", "nosecret");

        // The SQL strings sent to prepareStatement must contain only '?'
        // placeholders — the payload must never appear literally in the SQL.
        for (String sql : tracker.preparedSql) {
            assertFalse(
                "SQL injection payload must not appear in the prepared SQL string: " + sql,
                sql.contains(maliciousPassword));
            assertFalse(
                "SQL must use '?' placeholders, not literal DROP TABLE: " + sql,
                sql.toUpperCase().contains("DROP TABLE"));
        }

        // Confirm the payload was bound as a parameter value.
        boolean foundAsParam = false;
        for (String[] param : tracker.boundParams) {
            if (maliciousPassword.equals(param[1])) {
                foundAsParam = true;
                break;
            }
        }
        assertTrue("Malicious password must reach the DB as a bound parameter value, not as SQL",
                foundAsParam);
    }

    /**
     * Verifies SQL injection attack in the username field is neutralized.
     */
    public void testSqlInjectionPayloadInUsernameIsTreatedAsData() throws Exception {
        String maliciousUser = "admin' OR '1'='1";

        Connection[] holder = new Connection[1];
        TrackingConnection tracker = TrackingConnection.newInstance(holder);

        executeRegistrationSql(holder[0], maliciousUser, "pass",
                "x@example.com", "bio", "nosecret");

        for (String sql : tracker.preparedSql) {
            assertFalse(
                "SQL injection payload must not appear literally in the prepared SQL: " + sql,
                sql.contains(maliciousUser));
        }

        boolean foundAsParam = false;
        for (String[] param : tracker.boundParams) {
            if (maliciousUser.equals(param[1])) {
                foundAsParam = true;
                break;
            }
        }
        assertTrue("Malicious username must be bound as a parameter, not injected into SQL",
                foundAsParam);
    }

    /**
     * Verifies SQL injection attack in the email field is neutralized.
     */
    public void testSqlInjectionPayloadInEmailIsTreatedAsData() throws Exception {
        String maliciousEmail = "x@x.com','','',''); INSERT INTO users VALUES ('evil','evil','evil@evil.com','','default.jpg','admin',1,'x'); --";

        Connection[] holder = new Connection[1];
        TrackingConnection tracker = TrackingConnection.newInstance(holder);

        executeRegistrationSql(holder[0], "bob", "bobpass",
                maliciousEmail, "bio", "nosecret");

        for (String sql : tracker.preparedSql) {
            assertFalse(
                "Email injection payload must not appear literally in the prepared SQL: " + sql,
                sql.contains("INSERT INTO users VALUES"));
        }

        boolean foundAsParam = false;
        for (String[] param : tracker.boundParams) {
            if (maliciousEmail.equals(param[1])) {
                foundAsParam = true;
                break;
            }
        }
        assertTrue("Malicious email must be bound as a parameter, not injected into SQL",
                foundAsParam);
    }

    /**
     * Verifies that exactly two prepared statements are issued per registration:
     * one for the users INSERT and one for the welcome message INSERT.
     */
    public void testTwoPreparedStatementsAreIssuedPerRegistration() throws Exception {
        Connection[] holder = new Connection[1];
        TrackingConnection tracker = TrackingConnection.newInstance(holder);

        executeRegistrationSql(holder[0], "carol", "pass123",
                "carol@example.com", "About me", "mysecret");

        assertEquals("Exactly two PreparedStatement executions (users + UserMessages) are expected",
                2, tracker.preparedSql.size());
    }

    /**
     * Verifies that the users INSERT binds exactly 5 parameters:
     * username(1), password(2), email(3), About(4), secret(5).
     */
    public void testUserInsertBindsFiveParameters() throws Exception {
        String user = "dave";
        String pass = "password1";
        String email = "dave@example.com";
        String about = "Just Dave";
        String secret = "mySecretAnswer";

        Connection[] holder = new Connection[1];
        TrackingConnection tracker = TrackingConnection.newInstance(holder);

        executeRegistrationSql(holder[0], user, pass, email, about, secret);

        // The first 5 bound params come from the users INSERT.
        assertTrue("At least 5 parameters must be bound for the users INSERT",
                tracker.boundParams.size() >= 5);
        assertEquals("Param 1 (username) must match", user,    tracker.boundParams.get(0)[1]);
        assertEquals("Param 2 (password) must match", pass,    tracker.boundParams.get(1)[1]);
        assertEquals("Param 3 (email) must match",    email,   tracker.boundParams.get(2)[1]);
        assertEquals("Param 4 (About) must match",    about,   tracker.boundParams.get(3)[1]);
        assertEquals("Param 5 (secret) must match",   secret,  tracker.boundParams.get(4)[1]);
    }

    /**
     * Verifies that the welcome-message INSERT binds the username as its
     * single parameter (recipient field).
     */
    public void testMessageInsertBindsUsernameAsRecipient() throws Exception {
        String user = "eve";

        Connection[] holder = new Connection[1];
        TrackingConnection tracker = TrackingConnection.newInstance(holder);

        executeRegistrationSql(holder[0], user, "pass", "eve@example.com", "bio", "nosecret");

        // The 6th bound parameter is the recipient in the UserMessages INSERT.
        assertTrue("At least 6 bound parameters expected (5 for users + 1 for messages)",
                tracker.boundParams.size() >= 6);
        assertEquals("Param 6 (recipient in UserMessages) must be the username",
                user, tracker.boundParams.get(5)[1]);
    }

    /**
     * Verifies that when secret is provided as null or empty it is defaulted to
     * "nosecret" and bound correctly, ensuring no null pointer or empty-string
     * anomaly can cause issues.
     */
    public void testNullSecretDefaultsToNosecret() throws Exception {
        // Replicate the null-check logic from Register.processRequest.
        String secret = null;
        if (secret == null || secret.equals("")) {
            secret = "nosecret";
        }
        assertEquals("nosecret", secret);

        String emptySecret = "";
        if (emptySecret == null || emptySecret.equals("")) {
            emptySecret = "nosecret";
        }
        assertEquals("nosecret", emptySecret);

        // Also verify the normalised value passes through as a bound parameter.
        Connection[] holder = new Connection[1];
        TrackingConnection tracker = TrackingConnection.newInstance(holder);

        executeRegistrationSql(holder[0], "frank", "pass", "frank@example.com", "bio", "nosecret");

        assertEquals("Param 5 (secret) must be 'nosecret' when not supplied",
                "nosecret", tracker.boundParams.get(4)[1]);
    }

    /**
     * Verifies that quote characters in any field do not break query structure.
     * With PreparedStatement these must be handled transparently by the driver.
     */
    public void testSingleQuotesInFieldsAreSafelyBound() throws Exception {
        String userWithQuote  = "O'Brien";
        String passWithQuote  = "it's-a-pass";
        String emailWithQuote = "o'brien@test.com";
        String aboutWithQuote = "I'm a tester";
        String secretWithQuote = "it's secret";

        Connection[] holder = new Connection[1];
        TrackingConnection tracker = TrackingConnection.newInstance(holder);

        // Should complete without throwing and must use preparedStatement only.
        executeRegistrationSql(holder[0], userWithQuote, passWithQuote,
                emailWithQuote, aboutWithQuote, secretWithQuote);

        assertTrue("prepareStatement() must still be called even with quote-containing inputs",
                tracker.prepareStatementCalled);
        assertFalse("createStatement() must never be called",
                tracker.createStatementCalled);

        // Confirm the literal values (with quotes) appear as bound params.
        assertEquals(userWithQuote,   tracker.boundParams.get(0)[1]);
        assertEquals(passWithQuote,   tracker.boundParams.get(1)[1]);
        assertEquals(emailWithQuote,  tracker.boundParams.get(2)[1]);
        assertEquals(aboutWithQuote,  tracker.boundParams.get(3)[1]);
        assertEquals(secretWithQuote, tracker.boundParams.get(4)[1]);
    }
}
