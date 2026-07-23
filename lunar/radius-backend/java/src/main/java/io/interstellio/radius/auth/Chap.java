/*
 * CHAP authentication (RFC 2865, section 2.2).
 *
 * CHAP never sends the password. The NAS sends:
 *
 *   - CHAP-Password  - 1 byte CHAP Identifier followed by a 16-byte MD5 hash.
 *   - CHAP-Challenge - the challenge the hash was computed over. When this
 *                      attribute is absent, the challenge is the packet's
 *                      Request Authenticator (the "authenticator" field of the
 *                      forwarded packet).
 *
 * To verify, we recompute MD5(chap_id + password + challenge) from the password
 * we hold and compare it to the hash the NAS sent. Both are forwarded by lunar
 * as raw bytes ("0x" hex in the packet JSON).
 */
package io.interstellio.radius.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

public final class Chap {

    private Chap() {
    }

    /**
     * Return true when the CHAP response matches expectedPassword.
     *
     * chapPassword is the 17-byte CHAP-Password value (id + hash) and challenge
     * is the CHAP-Challenge (or the Request Authenticator when no CHAP-Challenge
     * was sent).
     */
    public static boolean verify(String expectedPassword, byte[] chapPassword, byte[] challenge) {
        if (chapPassword == null || challenge == null) {
            return false;
        }
        if (chapPassword.length != 17) {
            return false;
        }

        byte[] chapId = Arrays.copyOfRange(chapPassword, 0, 1);
        byte[] sentHash = Arrays.copyOfRange(chapPassword, 1, 17);

        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            digest.update(chapId);
            digest.update(expectedPassword.getBytes(StandardCharsets.UTF_8));
            digest.update(challenge);
            byte[] expectedHash = digest.digest();
            return MessageDigest.isEqual(expectedHash, sentHash);
        } catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }
}
