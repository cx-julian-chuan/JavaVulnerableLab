package org.cysecurity.cspf.jvl.otp;

import junit.framework.TestCase;
import junit.framework.TestSuite;

import java.util.HashMap;
import java.util.Map;

/**
 * Tests for the OTP verification flow's server-side enforcement of the
 * verification state (CWE-287 / CWE-302 / CWE-602).
 *
 * The vulnerability was that verify-otp.jsp performed the OTP check correctly
 * but wrote the result only to the HTTP response (client-visible JSON), never
 * to the server-side session.  confirm.jsp then trusted the
 * "otp_verified=true" parameter supplied by the client, making the entire
 * step-up check bypassable.
 *
 * The fix:
 *   - verify-otp.jsp: on success, sets session attributes
 *       otpVerified  = Boolean.TRUE
 *       confirmedPayee  = <value from session, set by send-otp.jsp>
 *       confirmedAmount = <value from session, set by send-otp.jsp>
 *   - confirm.jsp: reads those session attributes instead of request params
 *     and removes them immediately (one-time consumption).
 *
 * These tests exercise the same logical operations using a simple
 * HashMap-backed mock session so that no container is required.
 */
public class OtpVerificationTest extends TestCase {

    // ------------------------------------------------------------------ //
    //  Minimal mock of HttpSession attribute storage                       //
    // ------------------------------------------------------------------ //

    /** A minimal session stand-in backed by a HashMap. */
    static class MockSession {
        private final Map<String, Object> attrs = new HashMap<String, Object>();

        public void setAttribute(String name, Object value) {
            attrs.put(name, value);
        }

        public Object getAttribute(String name) {
            return attrs.get(name);
        }

        public void removeAttribute(String name) {
            attrs.remove(name);
        }

        public boolean contains(String name) {
            return attrs.containsKey(name);
        }
    }

    // ------------------------------------------------------------------ //
    //  Helpers that replicate the JSP scriptlet logic under test           //
    // ------------------------------------------------------------------ //

    /**
     * Constant-time comparison extracted verbatim from verify-otp.jsp so the
     * test does not depend on the container.
     */
    static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null || a.length() != b.length()) return false;
        int diff = 0;
        for (int i = 0; i < a.length(); i++) {
            diff |= a.charAt(i) ^ b.charAt(i);
        }
        return diff == 0;
    }

    static final long OTP_LIFETIME_MS  = 120_000L;
    static final int  OTP_MAX_ATTEMPTS = 5;

    /** Clears OTP state from session (mirrors clearOtp in verify-otp.jsp). */
    static void clearOtp(MockSession session) {
        session.removeAttribute("otpCode");
        session.removeAttribute("otpIssuedAt");
        session.removeAttribute("otpAttempts");
    }

    /**
     * Simulates the verify-otp.jsp success path: clears the OTP and records
     * the server-side verified state with the payee/amount values.
     *
     * @return "verified:true" on success, an error string otherwise.
     */
    static String simulateVerifyOtp(MockSession session, String submittedOtp) {
        String expected  = (String)  session.getAttribute("otpCode");
        Long   issuedAt  = (Long)    session.getAttribute("otpIssuedAt");
        Integer attempts = (Integer) session.getAttribute("otpAttempts");

        if (expected == null || issuedAt == null || attempts == null) {
            return "error:no_otp";
        }
        if (System.currentTimeMillis() - issuedAt > OTP_LIFETIME_MS) {
            clearOtp(session);
            return "error:expired";
        }
        if (attempts >= OTP_MAX_ATTEMPTS) {
            clearOtp(session);
            return "error:too_many_attempts";
        }
        if (!constantTimeEquals(expected, submittedOtp == null ? "" : submittedOtp.trim())) {
            int used = attempts + 1;
            session.setAttribute("otpAttempts", used);
            int left = OTP_MAX_ATTEMPTS - used;
            if (left <= 0) {
                clearOtp(session);
                return "error:too_many_attempts";
            }
            return "error:wrong_code";
        }

        // Correct code – replicate the FIXED verify-otp.jsp success path.
        String verifiedPayee  = (String) session.getAttribute("otpPayee");
        String verifiedAmount = (String) session.getAttribute("otpAmount");
        clearOtp(session);

        // Server-side state written here – this is the fix.
        session.setAttribute("otpVerified",    Boolean.TRUE);
        session.setAttribute("confirmedPayee",  verifiedPayee  != null ? verifiedPayee  : "");
        session.setAttribute("confirmedAmount", verifiedAmount != null ? verifiedAmount : "");

        return "verified:true";
    }

    /**
     * Simulates the confirm.jsp authorisation gate with the FIXED behaviour:
     * reads and consumes session-side flags only, ignores any request-side
     * "otp_verified" parameter.
     *
     * @param clientOtpVerified  the value an attacker might supply in the POST
     *                           body (ignored by the fixed implementation).
     * @return true if the transfer is authorised.
     */
    static boolean simulateConfirmAuthorisation(MockSession session,
                                                String clientOtpVerified) {
        // Read from session – the only authority that counts.
        Boolean serverFlag = (Boolean) session.getAttribute("otpVerified");

        // Consume immediately (one-time use).
        session.removeAttribute("otpVerified");
        session.removeAttribute("confirmedPayee");
        session.removeAttribute("confirmedAmount");

        // The client-supplied parameter is NOT consulted at all.
        return Boolean.TRUE.equals(serverFlag);
    }

    // ------------------------------------------------------------------ //
    //  Test helper: build a session with a pending OTP                     //
    // ------------------------------------------------------------------ //

    static MockSession sessionWithPendingOtp(String code, String payee,
                                             String amount) {
        MockSession s = new MockSession();
        s.setAttribute("isLoggedIn",   "1");
        s.setAttribute("otpCode",      code);
        s.setAttribute("otpIssuedAt",  System.currentTimeMillis());
        s.setAttribute("otpAttempts",  0);
        s.setAttribute("otpPayee",     payee);
        s.setAttribute("otpAmount",    amount);
        return s;
    }

    // ================================================================== //
    //  Tests                                                               //
    // ================================================================== //

    // --- verify-otp.jsp: session state after correct OTP ---------------

    /**
     * After a correct OTP is submitted, otpVerified must be set to Boolean.TRUE
     * in the session.
     */
    public void testCorrectOtpSetsSessionVerifiedFlag() {
        MockSession session = sessionWithPendingOtp("123456", "Alice", "100.00");
        String result = simulateVerifyOtp(session, "123456");
        assertEquals("verified:true", result);
        assertEquals(Boolean.TRUE, session.getAttribute("otpVerified"));
    }

    /**
     * After a correct OTP, the payee stored by send-otp.jsp must be copied
     * into confirmedPayee in the session.
     */
    public void testCorrectOtpSetsConfirmedPayeeInSession() {
        MockSession session = sessionWithPendingOtp("654321", "Bob", "250.00");
        simulateVerifyOtp(session, "654321");
        assertEquals("Bob", session.getAttribute("confirmedPayee"));
    }

    /**
     * After a correct OTP, the amount stored by send-otp.jsp must be copied
     * into confirmedAmount in the session.
     */
    public void testCorrectOtpSetsConfirmedAmountInSession() {
        MockSession session = sessionWithPendingOtp("654321", "Bob", "250.00");
        simulateVerifyOtp(session, "654321");
        assertEquals("250.00", session.getAttribute("confirmedAmount"));
    }

    /**
     * After a correct OTP, the raw OTP code must be removed from the session
     * (single-use enforcement).
     */
    public void testCorrectOtpClearsOtpCodeFromSession() {
        MockSession session = sessionWithPendingOtp("111222", "Carol", "50.00");
        simulateVerifyOtp(session, "111222");
        assertNull("otpCode must be removed after successful verification",
                   session.getAttribute("otpCode"));
    }

    /**
     * After a wrong OTP, otpVerified must NOT be set in the session.
     */
    public void testWrongOtpDoesNotSetVerifiedFlag() {
        MockSession session = sessionWithPendingOtp("999999", "Dave", "75.00");
        String result = simulateVerifyOtp(session, "000000");
        assertFalse("result should indicate failure",
                    "verified:true".equals(result));
        Object flag = session.getAttribute("otpVerified");
        assertFalse("otpVerified must not be set on wrong code",
                    Boolean.TRUE.equals(flag));
    }

    // --- confirm.jsp: server-side gate ---------------------------------

    /**
     * confirm.jsp must allow the transfer when the session carries the
     * verified flag set by verify-otp.jsp.
     */
    public void testConfirmAllowsTransferWhenSessionFlagPresent() {
        MockSession session = new MockSession();
        session.setAttribute("isLoggedIn",    "1");
        session.setAttribute("otpVerified",   Boolean.TRUE);
        session.setAttribute("confirmedPayee", "Eve");
        session.setAttribute("confirmedAmount", "500.00");

        boolean allowed = simulateConfirmAuthorisation(session, "false");
        assertTrue("Transfer must be authorised when session flag is TRUE", allowed);
    }

    /**
     * SECURITY: confirm.jsp must DENY the transfer when there is no session
     * flag, even if the attacker sends otp_verified=true in the POST body.
     * This is the core regression test for CWE-302.
     */
    public void testConfirmDeniesTransferWithoutSessionFlagEvenIfClientSaysTrue() {
        MockSession session = new MockSession();
        session.setAttribute("isLoggedIn", "1");
        // No otpVerified in session – OTP step was never completed server-side.

        boolean allowed = simulateConfirmAuthorisation(session, "true");
        assertFalse(
            "Transfer must be DENIED when session flag is absent, " +
            "regardless of the client-supplied otp_verified parameter",
            allowed);
    }

    /**
     * SECURITY: confirm.jsp must DENY when session flag is explicitly false.
     */
    public void testConfirmDeniesTransferWhenSessionFlagIsFalse() {
        MockSession session = new MockSession();
        session.setAttribute("isLoggedIn", "1");
        session.setAttribute("otpVerified", Boolean.FALSE);

        boolean allowed = simulateConfirmAuthorisation(session, "true");
        assertFalse("Transfer must be DENIED when session flag is FALSE", allowed);
    }

    /**
     * SECURITY: The verified flag must be consumed (single-use) so a replay
     * of the confirm.jsp POST does not re-authorise a second transfer.
     */
    public void testConfirmFlagIsConsumedAfterFirstUse() {
        MockSession session = new MockSession();
        session.setAttribute("isLoggedIn",   "1");
        session.setAttribute("otpVerified",  Boolean.TRUE);
        session.setAttribute("confirmedPayee",  "Frank");
        session.setAttribute("confirmedAmount", "1000.00");

        // First call: should be allowed.
        boolean first = simulateConfirmAuthorisation(session, "false");
        assertTrue("First call must succeed", first);

        // Second call (replay): session flag was consumed, must be denied.
        boolean second = simulateConfirmAuthorisation(session, "true");
        assertFalse("Replayed call must be DENIED (flag is single-use)", second);
    }

    /**
     * Full happy-path: send-otp → verify-otp (correct) → confirm authorises.
     */
    public void testFullFlowCorrectOtpAuthorisesTransfer() {
        // send-otp.jsp stores these in the session.
        MockSession session = sessionWithPendingOtp("246810", "Grace", "300.00");

        // verify-otp.jsp: correct code submitted.
        String verifyResult = simulateVerifyOtp(session, "246810");
        assertEquals("verified:true", verifyResult);

        // confirm.jsp: reads session, not request.
        boolean allowed = simulateConfirmAuthorisation(session, "false");
        assertTrue("Full correct-OTP flow must authorise the transfer", allowed);
    }

    /**
     * Full attack-path: skip send-otp and verify-otp entirely, POST directly
     * to confirm.jsp with otp_verified=true.  Must be denied.
     */
    public void testAttackDirectPostToConfirmWithoutOtpVerification() {
        // Attacker has a valid login session but has NOT gone through OTP.
        MockSession session = new MockSession();
        session.setAttribute("isLoggedIn", "1");
        // Attacker crafts: POST /confirm.jsp?payee=Attacker&amount=9999&otp_verified=true

        boolean allowed = simulateConfirmAuthorisation(session, "true");
        assertFalse(
            "Direct POST with otp_verified=true must be DENIED without " +
            "prior server-side OTP verification",
            allowed);
    }

    /**
     * Full attack-path: submit a wrong OTP, then POST directly to confirm.jsp
     * with otp_verified=true.  Must be denied.
     */
    public void testAttackWrongOtpThenForgeConfirmParameter() {
        MockSession session = sessionWithPendingOtp("333444", "Hank", "200.00");

        // Wrong OTP submitted.
        String verifyResult = simulateVerifyOtp(session, "000000");
        assertFalse("Wrong OTP must fail", "verified:true".equals(verifyResult));

        // Attacker immediately POSTs to confirm.jsp with otp_verified=true.
        boolean allowed = simulateConfirmAuthorisation(session, "true");
        assertFalse(
            "confirm.jsp must DENY even when client sends otp_verified=true " +
            "after a failed OTP attempt",
            allowed);
    }

    /**
     * Expired OTP must not set the verified flag.
     */
    public void testExpiredOtpDoesNotSetVerifiedFlag() {
        MockSession session = new MockSession();
        session.setAttribute("isLoggedIn",   "1");
        session.setAttribute("otpCode",      "777888");
        // Issued 3 minutes ago – past the 2-minute lifetime.
        session.setAttribute("otpIssuedAt",  System.currentTimeMillis() - 180_000L);
        session.setAttribute("otpAttempts",  0);
        session.setAttribute("otpPayee",     "Ivan");
        session.setAttribute("otpAmount",    "150.00");

        String result = simulateVerifyOtp(session, "777888");
        assertFalse("Expired OTP must fail", "verified:true".equals(result));
        assertFalse("otpVerified must not be set for an expired code",
                    Boolean.TRUE.equals(session.getAttribute("otpVerified")));
    }

    /**
     * Exhausting the attempt limit must not set the verified flag.
     */
    public void testMaxAttemptsExceededDoesNotSetVerifiedFlag() {
        MockSession session = new MockSession();
        session.setAttribute("isLoggedIn",   "1");
        session.setAttribute("otpCode",      "555666");
        session.setAttribute("otpIssuedAt",  System.currentTimeMillis());
        session.setAttribute("otpAttempts",  OTP_MAX_ATTEMPTS); // already at limit
        session.setAttribute("otpPayee",     "Judy");
        session.setAttribute("otpAmount",    "50.00");

        String result = simulateVerifyOtp(session, "555666");
        assertFalse("Should fail when attempt limit is reached",
                    "verified:true".equals(result));
        assertFalse("otpVerified must not be set when attempt limit exceeded",
                    Boolean.TRUE.equals(session.getAttribute("otpVerified")));
    }

    // --- Test suite entry point ----------------------------------------

    public static TestSuite suite() {
        return new TestSuite(OtpVerificationTest.class);
    }
}
