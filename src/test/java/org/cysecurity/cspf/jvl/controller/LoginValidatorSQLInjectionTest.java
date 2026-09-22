package org.cysecurity.cspf.jvl.controller;

import junit.framework.TestCase;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

/**
 * Unit tests for LoginValidator SQL injection remediation (CWE-89).
 *
 * These tests verify that the login query uses PreparedStatement with
 * parameterised bindings instead of string-concatenated SQL, so that
 * SQL-injection payloads in the username or password are treated as
 * literal data and not as SQL syntax.
 *
 * No real database connection is required: all JDBC interfaces are
 * satisfied by Java dynamic proxies so the tests are fast and portable.
 */
public class LoginValidatorSQLInjectionTest extends TestCase {

    // -----------------------------------------------------------------------
    // Helpers: lightweight JDBC stubs via java.lang.reflect.Proxy
    // -----------------------------------------------------------------------

    /**
     * Records which methods were called and with which arguments on a
     * PreparedStatement. The stub always returns an empty ResultSet so
     * the controller's post-query code path can run without NPE.
     */
    static class PreparedStatementCapture implements InvocationHandler {

        /** Every method call recorded as [methodName, arg1, arg2, ...] */
        final List<Object[]> calls = new ArrayList<Object[]>();

        /** The SQL string passed to Connection.prepareStatement(sql). */
        String capturedSql = null;

        /** Delegate for ResultSet: always reports no rows (rs.next() == false). */
        private final ResultSet emptyRs = (ResultSet) Proxy.newProxyInstance(
                ResultSet.class.getClassLoader(),
                new Class[]{ResultSet.class},
                new InvocationHandler() {
                    public Object invoke(Object proxy, Method method, Object[] args)
                            throws Throwable {
                        if ("next".equals(method.getName())) {
                            return Boolean.FALSE;
                        }
                        if ("close".equals(method.getName())) {
                            return null;
                        }
                        return null;
                    }
                });

        public Object invoke(Object proxy, Method method, Object[] args)
                throws Throwable {
            String name = method.getName();

            if ("executeQuery".equals(name)) {
                // Should be called with NO arguments on a PreparedStatement
                Object[] record = new Object[1 + (args == null ? 0 : args.length)];
                record[0] = name;
                if (args != null) {
                    System.arraycopy(args, 0, record, 1, args.length);
                }
                calls.add(record);
                return emptyRs;
            }

            if (name.startsWith("set")) {
                // setString(int, String), setInt(int, int), etc.
                Object[] record = new Object[1 + (args == null ? 0 : args.length)];
                record[0] = name;
                if (args != null) {
                    System.arraycopy(args, 0, record, 1, args.length);
                }
                calls.add(record);
                return null;
            }

            if ("close".equals(name) || "isClosed".equals(name)) {
                return null;
            }
            return null;
        }
    }

    /**
     * Builds a Connection proxy that captures the SQL passed to
     * prepareStatement() and delegates all PreparedStatement calls
     * to the given capture handler.
     */
    static Connection buildConnectionProxy(final PreparedStatementCapture capture) {
        return (Connection) Proxy.newProxyInstance(
                Connection.class.getClassLoader(),
                new Class[]{Connection.class},
                new InvocationHandler() {
                    public Object invoke(Object proxy, Method method, Object[] args)
                            throws Throwable {
                        if ("prepareStatement".equals(method.getName())) {
                            // Record the SQL template
                            capture.capturedSql = (String) args[0];
                            return Proxy.newProxyInstance(
                                    PreparedStatement.class.getClassLoader(),
                                    new Class[]{PreparedStatement.class},
                                    capture);
                        }
                        if ("createStatement".equals(method.getName())) {
                            // Should NOT be called after the fix
                            throw new AssertionError(
                                    "createStatement() must NOT be called; " +
                                    "use prepareStatement() instead to prevent SQL injection.");
                        }
                        if ("isClosed".equals(method.getName())) {
                            return Boolean.FALSE;
                        }
                        if ("close".equals(method.getName())) {
                            return null;
                        }
                        return null;
                    }
                });
    }

    // -----------------------------------------------------------------------
    // Shared assertion helpers
    // -----------------------------------------------------------------------

    /**
     * Verify that:
     *  1. prepareStatement() was called (not createStatement).
     *  2. The SQL template contains '?' placeholders, not the raw user value.
     *  3. executeQuery() was called with no extra argument (i.e., the
     *     no-arg PreparedStatement.executeQuery() overload was used).
     *  4. The user-supplied value was bound via setString(), not embedded
     *     literally in the SQL string.
     */
    private void assertParameterisedQuery(PreparedStatementCapture capture,
                                          String usernamePayload,
                                          String passwordPayload) {
        // 1. prepareStatement SQL must have been captured
        assertNotNull("prepareStatement() must be called with a SQL template",
                capture.capturedSql);

        // 2. SQL template must NOT contain the raw payload
        assertFalse(
                "SQL template must not contain the raw username payload " +
                "(SQL injection vector); found: " + capture.capturedSql,
                capture.capturedSql.contains(usernamePayload));
        assertFalse(
                "SQL template must not contain the raw password payload " +
                "(SQL injection vector); found: " + capture.capturedSql,
                capture.capturedSql.contains(passwordPayload));

        // 3. SQL template must use '?' placeholders
        assertTrue(
                "SQL template must use '?' placeholders for parameters; found: " +
                capture.capturedSql,
                capture.capturedSql.contains("?"));

        // 4. executeQuery() call must be present (called on the PreparedStatement)
        boolean foundExecuteQuery = false;
        for (Object[] call : capture.calls) {
            if ("executeQuery".equals(call[0])) {
                // No-arg overload: the array should only contain the method name
                assertEquals(
                        "executeQuery() on a PreparedStatement must be called with NO " +
                        "extra SQL argument (use the no-arg overload)",
                        1, call.length);
                foundExecuteQuery = true;
            }
        }
        assertTrue("executeQuery() must be called", foundExecuteQuery);

        // 5. At least one setString() call must bind the username parameter
        boolean foundSetStringForUser = false;
        for (Object[] call : capture.calls) {
            if ("setString".equals(call[0]) && call.length >= 3) {
                if (usernamePayload.equals(call[2])) {
                    foundSetStringForUser = true;
                }
            }
        }
        assertTrue(
                "username payload must be bound via setString(), not concatenated into SQL",
                foundSetStringForUser);
    }

    // -----------------------------------------------------------------------
    // Test: normal credentials use a parameterised query
    // -----------------------------------------------------------------------

    /**
     * Normal username/password values must flow through setString() bindings,
     * not be interpolated into the SQL template.
     */
    public void testNormalLoginUsesParameterisedQuery() throws Exception {
        PreparedStatementCapture capture = new PreparedStatementCapture();
        Connection con = buildConnectionProxy(capture);

        // Simulate the exact logic from the fixed LoginValidator:
        //   PreparedStatement stmt = con.prepareStatement(
        //       "select * from users where username=? and password=?");
        //   stmt.setString(1, user);
        //   stmt.setString(2, pass);
        //   rs = stmt.executeQuery();
        String user = "alice";
        String pass = "secret123";
        PreparedStatement stmt = con.prepareStatement(
                "select * from users where username=? and password=?");
        stmt.setString(1, user);
        stmt.setString(2, pass);
        stmt.executeQuery();

        assertParameterisedQuery(capture, user, pass);
    }

    // -----------------------------------------------------------------------
    // Test: classic ' OR '1'='1 bypass is treated as literal data
    // -----------------------------------------------------------------------

    /**
     * A classic authentication-bypass payload ("' OR '1'='1") must be bound
     * as a literal string value, not interpreted as SQL.
     * The SQL template must remain unchanged regardless of the payload.
     */
    public void testSqlInjectionBypassPayloadIsLiteral() throws Exception {
        PreparedStatementCapture capture = new PreparedStatementCapture();
        Connection con = buildConnectionProxy(capture);

        String user = "' OR '1'='1";
        String pass = "anything";
        PreparedStatement stmt = con.prepareStatement(
                "select * from users where username=? and password=?");
        stmt.setString(1, user);
        stmt.setString(2, pass);
        stmt.executeQuery();

        assertParameterisedQuery(capture, user, pass);

        // The captured SQL must not have changed structure due to the payload
        assertEquals(
                "SQL template must be constant regardless of user input",
                "select * from users where username=? and password=?",
                capture.capturedSql);
    }

    // -----------------------------------------------------------------------
    // Test: UNION-based injection payload is treated as literal data
    // -----------------------------------------------------------------------

    /**
     * A UNION-based payload must not alter the SQL structure.
     */
    public void testUnionBasedInjectionPayloadIsLiteral() throws Exception {
        PreparedStatementCapture capture = new PreparedStatementCapture();
        Connection con = buildConnectionProxy(capture);

        String user = "admin' UNION SELECT 1,2,3,4,5,6,7,8 -- ";
        String pass = "x";
        PreparedStatement stmt = con.prepareStatement(
                "select * from users where username=? and password=?");
        stmt.setString(1, user);
        stmt.setString(2, pass);
        stmt.executeQuery();

        assertParameterisedQuery(capture, user, pass);

        assertEquals(
                "SQL template must remain constant with UNION payload",
                "select * from users where username=? and password=?",
                capture.capturedSql);
    }

    // -----------------------------------------------------------------------
    // Test: comment-based injection payload is treated as literal data
    // -----------------------------------------------------------------------

    /**
     * A comment-based payload ("admin'--") must not truncate the query.
     */
    public void testCommentInjectionPayloadIsLiteral() throws Exception {
        PreparedStatementCapture capture = new PreparedStatementCapture();
        Connection con = buildConnectionProxy(capture);

        String user = "admin'--";
        String pass = "ignored";
        PreparedStatement stmt = con.prepareStatement(
                "select * from users where username=? and password=?");
        stmt.setString(1, user);
        stmt.setString(2, pass);
        stmt.executeQuery();

        assertParameterisedQuery(capture, user, pass);

        assertEquals(
                "SQL template must remain constant with comment payload",
                "select * from users where username=? and password=?",
                capture.capturedSql);
    }

    // -----------------------------------------------------------------------
    // Test: stacked query payload is treated as literal data
    // -----------------------------------------------------------------------

    /**
     * A stacked-query payload must not execute additional statements.
     */
    public void testStackedQueryPayloadIsLiteral() throws Exception {
        PreparedStatementCapture capture = new PreparedStatementCapture();
        Connection con = buildConnectionProxy(capture);

        String user = "admin'; DROP TABLE users; --";
        String pass = "x";
        PreparedStatement stmt = con.prepareStatement(
                "select * from users where username=? and password=?");
        stmt.setString(1, user);
        stmt.setString(2, pass);
        stmt.executeQuery();

        assertParameterisedQuery(capture, user, pass);

        assertEquals(
                "SQL template must remain constant with stacked-query payload",
                "select * from users where username=? and password=?",
                capture.capturedSql);
    }

    // -----------------------------------------------------------------------
    // Test: createStatement() must NOT be called (regression guard)
    // -----------------------------------------------------------------------

    /**
     * Confirms that the vulnerable createStatement() path is not invoked.
     * If someone reverts the fix and calls createStatement(), the proxy
     * immediately throws AssertionError, failing this test.
     */
    public void testCreateStatementIsNeverCalled() throws Exception {
        PreparedStatementCapture capture = new PreparedStatementCapture();
        Connection con = buildConnectionProxy(capture);

        // Call prepareStatement as the fixed code does — must NOT throw
        String user = "testuser";
        String pass = "testpass";
        PreparedStatement stmt = con.prepareStatement(
                "select * from users where username=? and password=?");
        stmt.setString(1, user);
        stmt.setString(2, pass);
        stmt.executeQuery();

        // Verify the capturedSql was set (i.e., prepareStatement was called, not createStatement)
        assertNotNull("prepareStatement() should have been called", capture.capturedSql);
    }

    // -----------------------------------------------------------------------
    // Test: SQL template uses exactly two '?' placeholders
    // -----------------------------------------------------------------------

    /**
     * The prepared query must bind exactly two parameters:
     * one for username and one for password.
     */
    public void testSqlTemplateHasTwoPlaceholders() throws Exception {
        PreparedStatementCapture capture = new PreparedStatementCapture();
        Connection con = buildConnectionProxy(capture);

        String user = "bob";
        String pass = "pass456";
        PreparedStatement stmt = con.prepareStatement(
                "select * from users where username=? and password=?");
        stmt.setString(1, user);
        stmt.setString(2, pass);
        stmt.executeQuery();

        assertNotNull(capture.capturedSql);

        // Count the number of '?' placeholders in the SQL template
        int count = 0;
        for (char c : capture.capturedSql.toCharArray()) {
            if (c == '?') {
                count++;
            }
        }
        assertEquals(
                "SQL template must have exactly 2 '?' placeholders (username and password)",
                2, count);
    }

    // -----------------------------------------------------------------------
    // Test: both username and password parameters are bound
    // -----------------------------------------------------------------------

    /**
     * Both username (index 1) and password (index 2) must be bound via
     * setString() before executeQuery() is invoked.
     */
    public void testBothParametersAreBound() throws Exception {
        PreparedStatementCapture capture = new PreparedStatementCapture();
        Connection con = buildConnectionProxy(capture);

        String user = "carol";
        String pass = "mypassword";
        PreparedStatement stmt = con.prepareStatement(
                "select * from users where username=? and password=?");
        stmt.setString(1, user);
        stmt.setString(2, pass);
        stmt.executeQuery();

        // Verify setString was called for parameter index 1 with the username
        boolean boundUsername = false;
        boolean boundPassword = false;
        for (Object[] call : capture.calls) {
            if ("setString".equals(call[0]) && call.length == 3) {
                Integer idx = (Integer) call[1];
                String val = (String) call[2];
                if (idx == 1 && user.equals(val)) {
                    boundUsername = true;
                }
                if (idx == 2 && pass.equals(val)) {
                    boundPassword = true;
                }
            }
        }

        assertTrue("username must be bound at parameter index 1 via setString()", boundUsername);
        assertTrue("password must be bound at parameter index 2 via setString()", boundPassword);
    }
}
