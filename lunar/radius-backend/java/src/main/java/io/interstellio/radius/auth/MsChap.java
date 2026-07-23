/*
 * MS-CHAPv1 authentication (RFC 2433).
 *
 * The NAS sends two Microsoft vendor attributes:
 *
 *   - MS-CHAP-Challenge - the 8-byte challenge.
 *   - MS-CHAP-Response  - 50 bytes: Ident (1), Flags (1), LM-Response (24) and
 *                         NT-Response (24).
 *
 * We verify the NT-Response only (the LM-Response is obsolete and often zero):
 * the 24-byte DES response over the challenge, keyed by the NT hash of the
 * password. lunar forwards both attributes as raw bytes ("0x" hex).
 */
package io.interstellio.radius.auth;

import java.security.MessageDigest;
import java.util.Arrays;

public final class MsChap {

    private MsChap() {
    }

    /**
     * Return true when the MS-CHAPv1 NT-Response matches.
     *
     * challenge is the 8-byte MS-CHAP-Challenge and response is the 50-byte
     * MS-CHAP-Response.
     */
    public static boolean verify(String expectedPassword, byte[] challenge, byte[] response) {
        if (challenge == null || response == null) {
            return false;
        }
        if (challenge.length != 8 || response.length != 50) {
            return false;
        }

        byte[] ntResponse = Arrays.copyOfRange(response, 26, 50);
        byte[] expected = Nt.ntChallengeResponse(challenge, Nt.ntHash(expectedPassword));
        return MessageDigest.isEqual(expected, ntResponse);
    }
}
