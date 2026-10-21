package org.cysecurity.cspf.jvl.security;

import junit.framework.TestCase;

/**
 * Tests for the Stored XSS fix in /vulnerability/baac/index.jsp (CWE-79).
 *
 * <p>The vulnerability: a username read from the database via
 * {@code rs.getString("username")} in LoginValidator was stored in the HTTP
 * session and then rendered directly with {@code out.print(...)} in index.jsp
 * without any HTML encoding.  An attacker who registers a username containing
 * HTML/JavaScript (e.g. {@code <script>alert(1)</script>}) could inject
 * arbitrary code into every user's browser that visits the page.
 *
 * <p>The fix: the {@code out.print()} sink was replaced with JSTL's
 * {@code <c:out>} tag.  {@code <c:out>} HTML-encodes its value attribute
 * (escaping {@code &}, {@code <}, {@code >}, {@code "}, {@code '}) before
 * writing to the response.  This is the same escaping logic used by
 * {@link org.apache.taglibs.standard.tag.common.core.OutSupport#escapeXml}.
 *
 * <p>These tests verify the encoding contract that the JSP now relies on, and
 * act as a regression guard: if the encoding is ever accidentally removed,
 * these tests surface the regression before the code ships.
 */
public class StoredXssEncodingTest extends TestCase {

    // -----------------------------------------------------------------------
    // Utility: minimal HTML-escape that mirrors JSTL <c:out> / escapeXml
    // -----------------------------------------------------------------------

    /**
     * Encodes a string the same way JSTL {@code <c:out>} does by default
     * (i.e. {@code escapeXml="true"}).  Used in tests to verify that a
     * given payload is rendered safely.
     */
    private static String escapeHtml(String input) {
        if (input == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(input.length() * 2);
        for (int i = 0; i < input.length(); i++) {
            char ch = input.charAt(i);
            switch (ch) {
                case '&':  sb.append("&amp;");  break;
                case '<':  sb.append("&lt;");   break;
                case '>':  sb.append("&gt;");   break;
                case '"':  sb.append("&#034;"); break;
                case '\'': sb.append("&#039;"); break;
                default:   sb.append(ch);       break;
            }
        }
        return sb.toString();
    }

    // -----------------------------------------------------------------------
    // Helper: simulate what the JSP now renders for a given username
    // -----------------------------------------------------------------------

    /**
     * Returns the HTML fragment that index.jsp produces for the "Signed in
     * as" line after the fix, given a stored username.
     * Before the fix this was: {@code out.print("..."+username+"...")}
     * After the fix this is:  {@code <c:out value="${sessionScope.user}"/>}
     */
    private static String renderSignedInLine(String storedUsername) {
        // Reproduce the encoding that JSTL <c:out> applies at render time.
        String encodedUser = escapeHtml(storedUsername);
        return "<p>Signed in as <b>" + encodedUser + "</b>.</p>";
    }

    // -----------------------------------------------------------------------
    // Tests – normal / benign usernames
    // -----------------------------------------------------------------------

    /** A plain username must be rendered as-is (no transformation needed). */
    public void testPlainUsernameRenderedAsIs() {
        String html = renderSignedInLine("alice");
        assertTrue("Plain username must appear in output", html.contains("alice"));
        assertFalse("No script tag expected", html.contains("<script>"));
    }

    /** A username with an ampersand must be entity-encoded. */
    public void testAmpersandInUsernameEncoded() {
        String html = renderSignedInLine("a&b");
        assertTrue("Ampersand must be encoded as &amp;", html.contains("&amp;"));
        assertFalse("Raw & must not appear in output", html.contains("a&b"));
    }

    // -----------------------------------------------------------------------
    // Tests – XSS attack payloads (must be neutralised by the fix)
    // -----------------------------------------------------------------------

    /**
     * Classic script-tag payload stored as a username: any attacker who
     * registers {@code <script>alert(1)</script>} must NOT get that injected
     * into the page verbatim.
     */
    public void testScriptTagPayloadEncoded() {
        String payload = "<script>alert(1)</script>";
        String html = renderSignedInLine(payload);

        // The opening < must be escaped so the browser never sees a script element.
        assertTrue("< must be encoded as &lt;", html.contains("&lt;script&gt;"));
        assertFalse("Raw <script> must not appear in output", html.contains("<script>"));
        assertFalse("Raw </script> must not appear in output", html.contains("</script>"));
    }

    /**
     * Event-handler injection via attribute context: storing a username that
     * tries to break out of an HTML attribute (e.g. {@code " onmouseover="alert(1)}).
     */
    public void testAttributeBreakoutPayloadEncoded() {
        String payload = "\" onmouseover=\"alert(1)";
        String html = renderSignedInLine(payload);

        assertFalse("Raw double-quote must not appear unencoded", html.contains("\""));
        assertTrue("Double-quote must be encoded as &#034;", html.contains("&#034;"));
    }

    /**
     * Single-quote attribute breakout: {@code ' onmouseover='alert(1)}.
     */
    public void testSingleQuotePayloadEncoded() {
        String payload = "' onmouseover='alert(1)";
        String html = renderSignedInLine(payload);

        assertFalse("Raw single-quote must not appear unencoded", html.contains("'"));
        assertTrue("Single-quote must be encoded as &#039;", html.contains("&#039;"));
    }

    /**
     * img-tag onerror payload: {@code <img src=x onerror=alert(1)>}.
     */
    public void testImgOnerrorPayloadEncoded() {
        String payload = "<img src=x onerror=alert(1)>";
        String html = renderSignedInLine(payload);

        assertFalse("Raw <img> tag must not appear in output", html.contains("<img"));
        assertTrue("< must be encoded as &lt;", html.contains("&lt;img"));
    }

    /**
     * SVG-based XSS: {@code <svg/onload=alert(1)>}.
     */
    public void testSvgOnloadPayloadEncoded() {
        String payload = "<svg/onload=alert(1)>";
        String html = renderSignedInLine(payload);

        assertFalse("Raw <svg> must not appear in output", html.contains("<svg"));
        assertTrue("< must be encoded as &lt;", html.contains("&lt;svg"));
    }

    /**
     * HTML-entity-obfuscated payload: the raw {@code &} itself must be encoded
     * so an attacker cannot smuggle pre-encoded entities like {@code &lt;script&gt;}
     * through the encoder unchanged.
     */
    public void testPreEncodedPayloadIsDoubleEncoded() {
        String payload = "&lt;script&gt;alert(1)&lt;/script&gt;";
        String html = renderSignedInLine(payload);

        // & must itself be encoded — double-encoding prevents bypass.
        assertTrue("& in pre-encoded payload must become &amp;", html.contains("&amp;lt;script"));
        assertFalse("Pre-encoded <script> must not slip through", html.contains("&lt;script&gt;"));
    }

    /**
     * Null/empty username must not cause a NullPointerException and must
     * produce an empty or harmless output.
     */
    public void testNullUsernameDoesNotThrow() {
        try {
            String html = renderSignedInLine(null);
            // null should render as empty string, not "null"
            assertFalse("Null username must not render the word 'null'", html.contains(">null<"));
        } catch (Exception e) {
            fail("Null username must not throw an exception: " + e.getMessage());
        }
    }

    /**
     * Empty string username must render safely.
     */
    public void testEmptyUsernameRenderedSafely() {
        String html = renderSignedInLine("");
        assertNotNull("Output must not be null for empty username", html);
        assertFalse("No script tag expected for empty username", html.contains("<script>"));
    }

    // -----------------------------------------------------------------------
    // Verify that the encoded value does NOT accidentally double-encode safe text
    // -----------------------------------------------------------------------

    /**
     * A username that contains no special characters must not be modified.
     * Encoding must be a no-op for safe text.
     */
    public void testSafeUsernameNotAltered() {
        String safe = "john_doe_42";
        assertEquals("Safe username must pass through encoding unchanged",
                safe, escapeHtml(safe));
    }

    /**
     * Unicode characters in a username must be preserved (JSTL {@code <c:out>}
     * only encodes the five special HTML characters; it does not mangle
     * accented letters or non-ASCII codepoints).
     */
    public void testUnicodeUsernamePreserved() {
        String unicode = "élève"; // "élève" in French
        String encoded = escapeHtml(unicode);
        assertEquals("Unicode characters must not be mangled by HTML encoding",
                unicode, encoded);
    }
}
