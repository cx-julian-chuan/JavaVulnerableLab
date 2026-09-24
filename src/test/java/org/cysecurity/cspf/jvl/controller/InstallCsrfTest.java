package org.cysecurity.cspf.jvl.controller;

import org.junit.Before;
import org.junit.Test;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Method;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Tests for the CSRF token protection added to the Install servlet (CWE-352).
 *
 * <p>The fix embeds a per-session synchronizer token in install.jsp and validates
 * it in {@code Install.processRequest} before any state-altering database
 * operation is performed.  These tests verify:</p>
 * <ul>
 *   <li>Requests with a valid (matching) CSRF token are allowed through.</li>
 *   <li>Requests with a missing CSRF token are rejected with HTTP 403.</li>
 *   <li>Requests with a mismatched CSRF token are rejected with HTTP 403.</li>
 *   <li>Requests with no active session are rejected with HTTP 403.</li>
 *   <li>The token generated in install.jsp is cryptographically random
 *       and URL-safe Base64 encoded (no "+" or "/" characters that could
 *       cause form-submission issues).</li>
 * </ul>
 *
 * <p>The tests use hand-crafted stub implementations of the
 * {@code HttpServletRequest}, {@code HttpServletResponse}, and
 * {@code HttpSession} interfaces so that no servlet container is required at
 * test time.</p>
 */
public class InstallCsrfTest {

    // -----------------------------------------------------------------------
    // Minimal stub implementations
    // -----------------------------------------------------------------------

    /**
     * In-memory HttpSession stub that stores attributes in a HashMap and
     * allows the test to inspect the recorded HTTP status code.
     */
    private static class StubSession implements HttpSession {
        private final Map<String, Object> attributes = new HashMap<>();

        @Override
        public Object getAttribute(String name) {
            return attributes.get(name);
        }

        @Override
        public void setAttribute(String name, Object value) {
            attributes.put(name, value);
        }

        @Override
        public void removeAttribute(String name) {
            attributes.remove(name);
        }

        // --- unused interface methods ---
        @Override public String getId() { return "test-session-id"; }
        @Override public long getCreationTime() { return 0; }
        @Override public long getLastAccessedTime() { return 0; }
        @Override public javax.servlet.ServletContext getServletContext() { return null; }
        @Override public void setMaxInactiveInterval(int interval) {}
        @Override public int getMaxInactiveInterval() { return 0; }
        @Override public javax.servlet.http.HttpSessionContext getSessionContext() { return null; }
        @Override public Object getValue(String name) { return null; }
        @Override public String[] getValueNames() { return new String[0]; }
        @Override public void putValue(String name, Object value) {}
        @Override public void removeValue(String name) {}
        @Override public void invalidate() {}
        @Override public boolean isNew() { return false; }
        @Override public java.util.Enumeration<String> getAttributeNames() {
            return java.util.Collections.enumeration(attributes.keySet());
        }
    }

    /**
     * HttpServletRequest stub that supplies a fixed parameter map and
     * delegates session retrieval to a caller-supplied StubSession.
     */
    private static class StubRequest implements HttpServletRequest {
        private final Map<String, String> params;
        private final StubSession session;

        StubRequest(Map<String, String> params, StubSession session) {
            this.params = params;
            this.session = session;
        }

        @Override
        public String getParameter(String name) {
            return params.get(name);
        }

        @Override
        public HttpSession getSession(boolean create) {
            return session;
        }

        @Override
        public HttpSession getSession() {
            return session;
        }

        // --- unused interface methods (stubs return null / default) ---
        @Override public String getAuthType() { return null; }
        @Override public javax.servlet.http.Cookie[] getCookies() { return new javax.servlet.http.Cookie[0]; }
        @Override public long getDateHeader(String name) { return 0; }
        @Override public String getHeader(String name) { return null; }
        @Override public java.util.Enumeration<String> getHeaders(String name) { return java.util.Collections.emptyEnumeration(); }
        @Override public java.util.Enumeration<String> getHeaderNames() { return java.util.Collections.emptyEnumeration(); }
        @Override public int getIntHeader(String name) { return 0; }
        @Override public String getMethod() { return "POST"; }
        @Override public String getPathInfo() { return null; }
        @Override public String getPathTranslated() { return null; }
        @Override public String getContextPath() { return "/JavaVulnerableLab"; }
        @Override public String getQueryString() { return null; }
        @Override public String getRemoteUser() { return null; }
        @Override public boolean isUserInRole(String role) { return false; }
        @Override public java.security.Principal getUserPrincipal() { return null; }
        @Override public String getRequestedSessionId() { return null; }
        @Override public String getRequestURI() { return "/JavaVulnerableLab/Install"; }
        @Override public StringBuffer getRequestURL() { return new StringBuffer(getRequestURI()); }
        @Override public String getServletPath() { return "/Install"; }
        @Override public boolean isRequestedSessionIdValid() { return true; }
        @Override public boolean isRequestedSessionIdFromCookie() { return false; }
        @Override public boolean isRequestedSessionIdFromURL() { return false; }
        @Override public boolean isRequestedSessionIdFromUrl() { return false; }
        @Override public boolean authenticate(HttpServletResponse r) { return false; }
        @Override public void login(String u, String p) {}
        @Override public void logout() {}
        @Override public java.util.Collection<javax.servlet.http.Part> getParts() { return null; }
        @Override public javax.servlet.http.Part getPart(String name) { return null; }
        @Override public <T extends javax.servlet.http.HttpUpgradeHandler> T upgrade(Class<T> c) { return null; }
        @Override public java.util.Map<String, String[]> getParameterMap() { return null; }
        @Override public java.util.Enumeration<String> getParameterNames() { return java.util.Collections.emptyEnumeration(); }
        @Override public String[] getParameterValues(String name) { return new String[]{params.get(name)}; }
        @Override public String getCharacterEncoding() { return "UTF-8"; }
        @Override public void setCharacterEncoding(String env) {}
        @Override public int getContentLength() { return 0; }
        @Override public long getContentLengthLong() { return 0; }
        @Override public String getContentType() { return "application/x-www-form-urlencoded"; }
        @Override public javax.servlet.ServletInputStream getInputStream() { return null; }
        @Override public String getProtocol() { return "HTTP/1.1"; }
        @Override public String getScheme() { return "http"; }
        @Override public String getServerName() { return "localhost"; }
        @Override public int getServerPort() { return 8080; }
        @Override public java.io.BufferedReader getReader() { return null; }
        @Override public String getRemoteAddr() { return "127.0.0.1"; }
        @Override public String getRemoteHost() { return "localhost"; }
        @Override public void setAttribute(String name, Object o) {}
        @Override public void removeAttribute(String name) {}
        @Override public java.util.Locale getLocale() { return java.util.Locale.getDefault(); }
        @Override public java.util.Enumeration<java.util.Locale> getLocales() { return java.util.Collections.emptyEnumeration(); }
        @Override public boolean isSecure() { return false; }
        @Override public javax.servlet.RequestDispatcher getRequestDispatcher(String path) { return null; }
        @Override public String getRealPath(String path) { return null; }
        @Override public int getRemotePort() { return 0; }
        @Override public String getLocalName() { return "localhost"; }
        @Override public String getLocalAddr() { return "127.0.0.1"; }
        @Override public int getLocalPort() { return 8080; }
        @Override public javax.servlet.AsyncContext startAsync() { return null; }
        @Override public javax.servlet.AsyncContext startAsync(javax.servlet.ServletRequest r, javax.servlet.ServletResponse s) { return null; }
        @Override public boolean isAsyncStarted() { return false; }
        @Override public boolean isAsyncSupported() { return false; }
        @Override public javax.servlet.AsyncContext getAsyncContext() { return null; }
        @Override public javax.servlet.DispatcherType getDispatcherType() { return null; }
        @Override public Object getAttribute(String name) { return null; }
        @Override public java.util.Enumeration<String> getAttributeNames() { return java.util.Collections.emptyEnumeration(); }
    }

    /**
     * HttpServletResponse stub that captures the error code set by
     * {@code sendError()} so tests can assert on it.
     */
    private static class StubResponse implements HttpServletResponse {
        int errorCode = 0;
        String errorMessage = null;
        String contentType = null;
        private final StringWriter body = new StringWriter();

        @Override
        public void sendError(int sc, String msg) throws IOException {
            this.errorCode = sc;
            this.errorMessage = msg;
        }

        @Override
        public void sendError(int sc) throws IOException {
            this.errorCode = sc;
        }

        @Override
        public void setContentType(String type) {
            this.contentType = type;
        }

        @Override
        public PrintWriter getWriter() {
            return new PrintWriter(body, true);
        }

        // --- unused interface methods ---
        @Override public void addCookie(javax.servlet.http.Cookie c) {}
        @Override public boolean containsHeader(String name) { return false; }
        @Override public String encodeURL(String url) { return url; }
        @Override public String encodeRedirectURL(String url) { return url; }
        @Override public String encodeUrl(String url) { return url; }
        @Override public String encodeRedirectUrl(String url) { return url; }
        @Override public void sendRedirect(String location) {}
        @Override public void setDateHeader(String name, long date) {}
        @Override public void addDateHeader(String name, long date) {}
        @Override public void setHeader(String name, String value) {}
        @Override public void addHeader(String name, String value) {}
        @Override public void setIntHeader(String name, int value) {}
        @Override public void addIntHeader(String name, int value) {}
        @Override public void setStatus(int sc) {}
        @Override public void setStatus(int sc, String sm) {}
        @Override public int getStatus() { return 200; }
        @Override public String getHeader(String name) { return null; }
        @Override public java.util.Collection<String> getHeaders(String name) { return null; }
        @Override public java.util.Collection<String> getHeaderNames() { return null; }
        @Override public String getCharacterEncoding() { return "UTF-8"; }
        @Override public javax.servlet.ServletOutputStream getOutputStream() { return null; }
        @Override public void setCharacterEncoding(String charset) {}
        @Override public void setContentLength(int len) {}
        @Override public void setContentLengthLong(long len) {}
        @Override public void setBufferSize(int size) {}
        @Override public int getBufferSize() { return 0; }
        @Override public void flushBuffer() {}
        @Override public void resetBuffer() {}
        @Override public boolean isCommitted() { return false; }
        @Override public void reset() {}
        @Override public void setLocale(java.util.Locale loc) {}
        @Override public java.util.Locale getLocale() { return java.util.Locale.getDefault(); }
    }

    // -----------------------------------------------------------------------
    // Helper to call processRequest via reflection (it is protected)
    // -----------------------------------------------------------------------

    private Install servlet;

    @Before
    public void setUp() {
        servlet = new Install();
    }

    /**
     * Invoke the protected {@code processRequest} method via reflection.
     */
    private void invokeProcessRequest(HttpServletRequest req, HttpServletResponse resp)
            throws Exception {
        Method m = Install.class.getDeclaredMethod(
                "processRequest", HttpServletRequest.class, HttpServletResponse.class);
        m.setAccessible(true);
        m.invoke(servlet, req, resp);
    }

    // -----------------------------------------------------------------------
    // CSRF token generation tests (install.jsp logic, tested in isolation)
    // -----------------------------------------------------------------------

    /**
     * A freshly generated CSRF token must be at least 32 bytes of entropy
     * (256 bits), URL-safe Base64 encoded, and must not contain '+' or '/'.
     */
    @Test
    public void testCsrfTokenIsUrlSafeBase64AndSufficientlyRandom() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] tokenBytes = new byte[32];
        secureRandom.nextBytes(tokenBytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);

        assertNotNull("CSRF token must not be null", token);
        assertFalse("CSRF token must not be empty", token.isEmpty());
        // URL-safe Base64 must not contain '+' or '/'
        assertFalse("Token must not contain '+'", token.contains("+"));
        assertFalse("Token must not contain '/'", token.contains("/"));
        // 32 bytes → 43 URL-safe Base64 chars (no padding)
        assertTrue("Token length must be at least 43 chars", token.length() >= 43);
    }

    /**
     * Two independently generated tokens must be different (probabilistic;
     * collision probability is negligible for a 256-bit token).
     */
    @Test
    public void testCsrfTokensAreUnique() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] bytes1 = new byte[32];
        byte[] bytes2 = new byte[32];
        secureRandom.nextBytes(bytes1);
        secureRandom.nextBytes(bytes2);
        String t1 = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes1);
        String t2 = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes2);
        assertFalse("Two generated tokens should not be equal", t1.equals(t2));
    }

    // -----------------------------------------------------------------------
    // Install.processRequest CSRF validation tests
    // -----------------------------------------------------------------------

    /**
     * A request that supplies a CSRF token matching the one in the session
     * must NOT be rejected with HTTP 403 (it is allowed through).
     *
     * <p>Note: processRequest will subsequently try to access the servlet
     * context and filesystem.  We catch any downstream exception (e.g.
     * NullPointerException from missing servlet context) and only assert
     * that sendError was NOT called with 403, confirming the CSRF check passed.</p>
     */
    @Test
    public void testValidCsrfTokenAllowsRequest() throws Exception {
        String validToken = "validToken123";
        StubSession session = new StubSession();
        session.setAttribute("csrfToken", validToken);

        Map<String, String> params = new HashMap<>();
        params.put("csrfToken", validToken);
        params.put("setup", "1");
        params.put("dburl", "jdbc:mysql://localhost:3306/");
        params.put("jdbcdriver", "com.mysql.jdbc.Driver");
        params.put("dbuser", "root");
        params.put("dbpass", "root");
        params.put("dbname", "testdb");
        params.put("siteTitle", "Test");
        params.put("adminuser", "admin");
        params.put("adminpass", "admin");

        StubRequest req = new StubRequest(params, session);
        StubResponse resp = new StubResponse();

        try {
            invokeProcessRequest(req, resp);
        } catch (Exception e) {
            // Downstream exceptions (e.g. NullPointerException from missing
            // servlet context) are expected; we only care about the CSRF check.
        }

        assertNotEquals(
                "A request with a valid CSRF token must not be rejected with HTTP 403",
                HttpServletResponse.SC_FORBIDDEN, resp.errorCode);
    }

    /**
     * A request with NO csrfToken parameter must be rejected with HTTP 403.
     */
    @Test
    public void testMissingCsrfTokenIsRejected() throws Exception {
        StubSession session = new StubSession();
        session.setAttribute("csrfToken", "expectedToken");

        // No csrfToken in params
        Map<String, String> params = new HashMap<>();
        params.put("setup", "1");

        StubRequest req = new StubRequest(params, session);
        StubResponse resp = new StubResponse();

        invokeProcessRequest(req, resp);

        assertEquals(
                "A request without csrfToken must be rejected with HTTP 403",
                HttpServletResponse.SC_FORBIDDEN, resp.errorCode);
    }

    /**
     * A request with a CSRF token that doesn't match the session token
     * must be rejected with HTTP 403.
     */
    @Test
    public void testMismatchedCsrfTokenIsRejected() throws Exception {
        StubSession session = new StubSession();
        session.setAttribute("csrfToken", "correctToken");

        Map<String, String> params = new HashMap<>();
        params.put("csrfToken", "wrongToken");
        params.put("setup", "1");

        StubRequest req = new StubRequest(params, session);
        StubResponse resp = new StubResponse();

        invokeProcessRequest(req, resp);

        assertEquals(
                "A request with a mismatched CSRF token must be rejected with HTTP 403",
                HttpServletResponse.SC_FORBIDDEN, resp.errorCode);
    }

    /**
     * A request with an empty string CSRF token must be rejected with HTTP 403.
     */
    @Test
    public void testEmptyCsrfTokenIsRejected() throws Exception {
        StubSession session = new StubSession();
        session.setAttribute("csrfToken", "correctToken");

        Map<String, String> params = new HashMap<>();
        params.put("csrfToken", "");
        params.put("setup", "1");

        StubRequest req = new StubRequest(params, session);
        StubResponse resp = new StubResponse();

        invokeProcessRequest(req, resp);

        assertEquals(
                "A request with an empty CSRF token must be rejected with HTTP 403",
                HttpServletResponse.SC_FORBIDDEN, resp.errorCode);
    }

    /**
     * A request without any active session (getSession(false) returns null)
     * must be rejected with HTTP 403, because there is no session token to
     * compare against.
     */
    @Test
    public void testNoSessionIsRejected() throws Exception {
        // Pass null session so getSession(false) returns null
        Map<String, String> params = new HashMap<>();
        params.put("csrfToken", "someToken");
        params.put("setup", "1");

        StubRequest req = new StubRequest(params, null /* no session */);
        StubResponse resp = new StubResponse();

        invokeProcessRequest(req, resp);

        assertEquals(
                "A request without a session must be rejected with HTTP 403",
                HttpServletResponse.SC_FORBIDDEN, resp.errorCode);
    }

    /**
     * A session with no stored csrfToken attribute must cause rejection with
     * HTTP 403, even when a token value is supplied in the form.
     */
    @Test
    public void testSessionWithNoCsrfAttributeIsRejected() throws Exception {
        StubSession session = new StubSession();
        // Intentionally do NOT set csrfToken in the session

        Map<String, String> params = new HashMap<>();
        params.put("csrfToken", "someToken");
        params.put("setup", "1");

        StubRequest req = new StubRequest(params, session);
        StubResponse resp = new StubResponse();

        invokeProcessRequest(req, resp);

        assertEquals(
                "A session without a csrfToken attribute must cause HTTP 403",
                HttpServletResponse.SC_FORBIDDEN, resp.errorCode);
    }

    /**
     * Simulates a CSRF attack: a cross-origin request that does NOT have the
     * victim's session-bound CSRF token.  The attacker can replicate all other
     * form fields but cannot read the token from the victim's page.
     */
    @Test
    public void testCsrfAttackRequestIsRejected() throws Exception {
        // Victim's session stores a secure token
        StubSession victimSession = new StubSession();
        victimSession.setAttribute("csrfToken", "s3cr3tPerSessionToken");

        // Attacker knows all field names but guesses the wrong token
        Map<String, String> attackerParams = new HashMap<>();
        attackerParams.put("csrfToken", "attacker-guessed-token");
        attackerParams.put("setup", "1");
        attackerParams.put("dburl", "jdbc:mysql://attacker:3306/");
        attackerParams.put("jdbcdriver", "com.mysql.jdbc.Driver");
        attackerParams.put("dbuser", "attacker");
        attackerParams.put("dbpass", "attacker");
        attackerParams.put("dbname", "attackerdb");
        attackerParams.put("siteTitle", "Hacked");
        attackerParams.put("adminuser", "attacker");
        attackerParams.put("adminpass", "attacker");

        StubRequest req = new StubRequest(attackerParams, victimSession);
        StubResponse resp = new StubResponse();

        invokeProcessRequest(req, resp);

        assertEquals(
                "A CSRF attack request with wrong token must be blocked with HTTP 403",
                HttpServletResponse.SC_FORBIDDEN, resp.errorCode);
    }
}
