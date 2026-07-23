/*
 * MS-CHAPv2 authentication (RFC 2759).
 *
 * The NAS sends two Microsoft vendor attributes:
 *
 *   - MS-CHAP-Challenge  - the 16-byte Authenticator Challenge.
 *   - MS-CHAP2-Response  - 50 bytes: Ident (1), Flags (1), Peer-Challenge (16),
 *                          Reserved (8) and NT-Response (24).
 *
 * MS-CHAPv2 first derives an 8-byte "Challenge Hash" from the peer and
 * authenticator challenges and the user name, then computes the NT-Response over
 * that hash (keyed by the NT hash of the password) exactly as MS-CHAPv1 does. We
 * recompute it and compare. All values are forwarded by lunar as raw bytes
 * ("0x" hex in the packet JSON); the user name is a normal text attribute.
 *
 * On success, successAndKeys also returns what a server normally adds to the
 * Access-Accept: the MS-CHAP2-Success value (so the client can verify the
 * server - MS-CHAPv2 is mutual authentication) and the MPPE link-encryption
 * keys. This class only computes the bytes; the caller sets the reply
 * attributes.
 */
package io.interstellio.radius.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Locale;

public final class MsChapV2 {

    private MsChapV2() {
    }

    /**
     * The MS-CHAP2-Success value and the two MPPE keys returned on accept. The
     * caller turns these bytes into reply attributes.
     */
    public record SuccessKeys(byte[] success, byte[] sendKey, byte[] recvKey) {
    }

    // Magic constants, byte-for-byte, from RFC 2759 (success) and RFC 3079 (MPPE).
    private static final byte[] MAGIC_SIGN =
            "Magic server to client signing constant".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] MAGIC_PAD =
            "Pad to make it do more than one iteration".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] MAGIC_MASTER =
            "This is the MPPE Master Key".getBytes(StandardCharsets.US_ASCII);
    // On the SERVER, the send key uses this constant and the receive key the other.
    private static final byte[] MAGIC_SERVER_SEND = (
            "On the client side, this is the receive key; "
            + "on the server side, it is the send key.").getBytes(StandardCharsets.US_ASCII);
    private static final byte[] MAGIC_SERVER_RECV = (
            "On the client side, this is the send key; "
            + "on the server side, it is the receive key.").getBytes(StandardCharsets.US_ASCII);

    private static byte[] sha1(byte[]... chunks) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            for (byte[] chunk : chunks) {
                digest.update(chunk);
            }
            return digest.digest();
        } catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }

    /** Return the 8-byte Challenge Hash (RFC 2759, GenerateNTResponse). */
    private static byte[] challengeHash(byte[] peerChallenge, byte[] authenticatorChallenge,
            String username) {
        byte[] digest = sha1(peerChallenge, authenticatorChallenge,
                username.getBytes(StandardCharsets.US_ASCII));
        return Arrays.copyOfRange(digest, 0, 8);
    }

    /**
     * Return true when the MS-CHAPv2 NT-Response matches.
     *
     * challenge is the 16-byte MS-CHAP-Challenge (Authenticator Challenge) and
     * response is the 50-byte MS-CHAP2-Response.
     */
    public static boolean verify(String expectedPassword, String username, byte[] challenge,
            byte[] response) {
        if (username == null || challenge == null || response == null) {
            return false;
        }
        if (challenge.length != 16 || response.length != 50) {
            return false;
        }

        byte[] peerChallenge = Arrays.copyOfRange(response, 2, 18);
        byte[] ntResponse = Arrays.copyOfRange(response, 26, 50);

        byte[] hash = challengeHash(peerChallenge, challenge, username);
        byte[] expected = Nt.ntChallengeResponse(hash, Nt.ntHash(expectedPassword));
        return MessageDigest.isEqual(expected, ntResponse);
    }

    // --- MS-CHAP2-Success and MPPE keys (RFC 2759 + RFC 3079) ----------------
    //
    // On a successful MS-CHAPv2 auth a server normally adds three Microsoft
    // attributes to the Access-Accept, and this backend does the same:
    //
    //   - MS-CHAP2-Success  - lets the CLIENT verify the server (mutual auth). It
    //                         is the response Ident byte followed by an "S=<hex>"
    //                         string.
    //   - MS-MPPE-Send-Key   - the MPPE session keys that encrypt the PPP link
    //   - MS-MPPE-Recv-Key     (PPTP, some L2TP), derived from the password hash.
    //
    // This class only COMPUTES the raw bytes; the controller sets the reply
    // attributes. The MPPE keys are sent as PLAINTEXT 0x hex - lunar
    // salt-encrypts them on the wire with the shared secret (they are marked
    // encrypt=2 in the RADIUS dictionary), so this backend never needs the
    // Request Authenticator.

    /** Return the "S=<hex>" server authenticator response (RFC 2759). */
    private static byte[] authenticatorResponse(String password, String username,
            byte[] peerChallenge, byte[] authenticatorChallenge, byte[] ntResponse) {
        byte[] passwordHashHash = Nt.ntHashHash(password);
        byte[] hash = challengeHash(peerChallenge, authenticatorChallenge, username);

        byte[] digest = sha1(passwordHashHash, ntResponse, MAGIC_SIGN);
        byte[] response = sha1(digest, hash, MAGIC_PAD);
        String text = "S=" + toHex(response).toUpperCase(Locale.ROOT);
        return text.getBytes(StandardCharsets.US_ASCII);
    }

    /** Derive one 16-byte MPPE session key from the master key (RFC 3079). */
    private static byte[] mppeSessionKey(byte[] masterKey, byte[] magic) {
        byte[] zeros = new byte[40];
        byte[] pad = new byte[40];
        Arrays.fill(pad, (byte) 0xF2);
        byte[] digest = sha1(masterKey, zeros, magic, pad);
        return Arrays.copyOfRange(digest, 0, 16);
    }

    /**
     * Return the raw MS-CHAP2-Success value and the two MPPE keys.
     *
     * challenge is the 16-byte MS-CHAP-Challenge and response the 50-byte
     * MS-CHAP2-Response.
     */
    public static SuccessKeys successAndKeys(String password, String username, byte[] challenge,
            byte[] response) {
        byte[] ident = Arrays.copyOfRange(response, 0, 1);
        byte[] peerChallenge = Arrays.copyOfRange(response, 2, 18);
        byte[] ntResponse = Arrays.copyOfRange(response, 26, 50);

        // MS-CHAP2-Success: the response Ident byte, then the "S=<hex>" string.
        byte[] auth = authenticatorResponse(password, username, peerChallenge, challenge,
                ntResponse);
        byte[] success = new byte[ident.length + auth.length];
        System.arraycopy(ident, 0, success, 0, ident.length);
        System.arraycopy(auth, 0, success, ident.length, auth.length);

        // MPPE keys: one 16-byte master key, then a send and a receive session key.
        byte[] masterKey = Arrays.copyOfRange(
                sha1(Nt.ntHashHash(password), ntResponse, MAGIC_MASTER), 0, 16);
        byte[] sendKey = mppeSessionKey(masterKey, MAGIC_SERVER_SEND);
        byte[] recvKey = mppeSessionKey(masterKey, MAGIC_SERVER_RECV);
        return new SuccessKeys(success, sendKey, recvKey);
    }

    private static String toHex(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            builder.append(Character.forDigit((value >> 4) & 0xF, 16));
            builder.append(Character.forDigit(value & 0xF, 16));
        }
        return builder.toString();
    }
}
