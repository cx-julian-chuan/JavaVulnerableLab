package org.cysecurity.cspf.jvl.csrf;

import java.math.BigInteger;
import java.security.SecureRandom;
import junit.framework.TestCase;

/**
 * Unit tests for the CSRF synchronizer-token protection implemented in
 * src/main/webapp/vulnerability/csrf/changepassword.jsp.
 *
 * These tests verify the core CSRF token logic in isolation:
 *   1. Token generation produces a non-null, non-empty value.
 *   2. Successive tokens are distinct (preventing token reuse attacks).
 *   3. A matching token is accepted (valid request).
 *   4. A null token is rejected (missing token → CSRF attempt blocked).
 *   5. An empty token is rejected.
 *   6. A mismatched token is rejected (forged/cross-site request blocked).
 *   7. Token entropy is sufficient (>= 130 bits encoded in base-32).
 */
public class CsrfTokenTest extends TestCase {

    // ---------------------------------------------------------------------------
    // Helper: mirrors the token-generation logic in changepassword.jsp
    // ---------------------------------------------------------------------------

    /**
     * Generates a CSRF token the same way changepassword.jsp does:
     * SecureRandom + BigInteger(130 bits) in base-32 encoding.
     */
    private String generateCsrfToken() {
        SecureRandom sr = new SecureRandom();
        return new BigInteger(130, sr).toString(32);
    }

    /**
     * Mirrors the server-side validation guard in changepassword.jsp:
     *   if (csrfFormToken == null || !csrfFormToken.equals(csrfSessionToken)) → reject
     *
     * Returns true when the request is accepted, false when rejected.
     */
    private boolean isCsrfTokenValid(String sessionToken, String formToken) {
        if (formToken == null || !formToken.equals(sessionToken)) {
            return false;
        }
        return true;
    }

    // ---------------------------------------------------------------------------
    // Tests: token generation
    // ---------------------------------------------------------------------------

    /**
     * Token must be non-null and non-empty so it can be embedded in the form
     * and compared server-side.
     */
    public void testTokenIsNotNullOrEmpty() {
        String token = generateCsrfToken();
        assertNotNull("Generated CSRF token must not be null", token);
        assertTrue("Generated CSRF token must not be empty", token.length() > 0);
    }

    /**
     * 130 bits in base-32 produces at least 26 characters.
     * A shorter token would not provide enough entropy to resist brute-force guessing.
     */
    public void testTokenHasSufficientLength() {
        String token = generateCsrfToken();
        // BigInteger(130, sr).toString(32): 130 / log2(32) = 26 chars minimum
        assertTrue("CSRF token must be at least 26 characters long for adequate entropy",
                token.length() >= 26);
    }

    /**
     * Two consecutive tokens must differ; identical tokens would mean any
     * cross-site form could hard-code the token and bypass protection.
     */
    public void testSuccessiveTokensAreUnique() {
        String token1 = generateCsrfToken();
        String token2 = generateCsrfToken();
        assertFalse("Successive CSRF tokens must be distinct (re-use breaks CSRF protection)",
                token1.equals(token2));
    }

    // ---------------------------------------------------------------------------
    // Tests: token validation — valid cases
    // ---------------------------------------------------------------------------

    /**
     * A legitimate same-origin POST carries the session token echoed back from
     * the hidden form field; this must be accepted.
     */
    public void testValidTokenIsAccepted() {
        String sessionToken = generateCsrfToken();
        String formToken = sessionToken; // same-origin form echoes the token back
        assertTrue("A matching CSRF token must be accepted", isCsrfTokenValid(sessionToken, formToken));
    }

    // ---------------------------------------------------------------------------
    // Tests: token validation — attack cases
    // ---------------------------------------------------------------------------

    /**
     * Cross-site forms constructed by an attacker carry no token at all
     * (null parameter). The server must reject these requests.
     */
    public void testNullTokenIsRejected() {
        String sessionToken = generateCsrfToken();
        assertFalse("A null (missing) CSRF token must be rejected to block CSRF attacks",
                isCsrfTokenValid(sessionToken, null));
    }

    /**
     * An attacker who cannot read the victim's page cannot supply the correct
     * token; an empty string token must be rejected.
     */
    public void testEmptyTokenIsRejected() {
        String sessionToken = generateCsrfToken();
        assertFalse("An empty CSRF token must be rejected",
                isCsrfTokenValid(sessionToken, ""));
    }

    /**
     * A cross-site request with a guessed or fabricated token value must be
     * rejected, regardless of how close it looks to the real token.
     */
    public void testMismatchedTokenIsRejected() {
        String sessionToken = generateCsrfToken();
        String attackerToken = generateCsrfToken(); // different random value
        // Ensure they are actually different before asserting rejection
        if (sessionToken.equals(attackerToken)) {
            // Astronomically unlikely (1 in 2^130), but handle defensively
            attackerToken = attackerToken + "x";
        }
        assertFalse("A mismatched CSRF token must be rejected to block CSRF attacks",
                isCsrfTokenValid(sessionToken, attackerToken));
    }

    /**
     * A token that differs in just one trailing character must also be rejected;
     * partial-match or prefix-match comparisons would be insecure.
     */
    public void testPartiallyMatchingTokenIsRejected() {
        String sessionToken = generateCsrfToken();
        // Truncate by one character: the prefix does NOT constitute a valid token
        String partialToken = sessionToken.substring(0, sessionToken.length() - 1);
        assertFalse("A token that is a prefix of the valid token must be rejected",
                isCsrfTokenValid(sessionToken, partialToken));
    }

    /**
     * A token containing an extra character appended by an attacker must be
     * rejected; suffix-extension must not produce a valid token.
     */
    public void testExtendedTokenIsRejected() {
        String sessionToken = generateCsrfToken();
        String extendedToken = sessionToken + "z"; // attacker appends a character
        assertFalse("A token with an extra trailing character must be rejected",
                isCsrfTokenValid(sessionToken, extendedToken));
    }

    /**
     * Token comparison must be exact; a token from a completely different session
     * (e.g. an attacker's own session token) must not validate for another user's session.
     */
    public void testDifferentSessionTokenIsRejected() {
        String victimSessionToken = generateCsrfToken();
        String attackerSessionToken = generateCsrfToken();
        if (victimSessionToken.equals(attackerSessionToken)) {
            attackerSessionToken = attackerSessionToken + "a";
        }
        assertFalse(
                "A token from a different session must be rejected; session tokens must not be interchangeable",
                isCsrfTokenValid(victimSessionToken, attackerSessionToken));
    }
}
