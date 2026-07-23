/*
 * Shared NT-hash, MD4 and DES primitives for the MS-CHAP family.
 *
 * MS-CHAPv1 and MS-CHAPv2 both authenticate by encrypting a challenge with a
 * key derived from the "NT hash" of the user's password. This class provides
 * the low-level pieces they share, so MsChap and MsChapV2 do not duplicate the
 * crypto:
 *
 *   - ntHash                - the NT hash of a password (MD4 of the UTF-16LE
 *                             password).
 *   - ntChallengeResponse   - the 24-byte DES response over an 8-byte
 *                             challenge, as defined by RFC 2433 (MS-CHAPv1) and
 *                             RFC 2759 (MS-CHAPv2).
 *
 * MD4 is legacy and the JDK's MessageDigest does not provide it, so - like the
 * other examples - this backend ships its own small implementation and drives
 * javax.crypto's DES directly, depending on nothing outside the JDK.
 *
 * This is EXAMPLE code, favouring clarity over completeness; a production
 * backend would look the user up in a real store and handle more edge cases.
 */
package io.interstellio.radius.auth;

import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public final class Nt {

    private Nt() {
    }

    /** Return the 16-byte MD4 digest of message (RFC 1320). */
    static byte[] md4(byte[] message) {
        int a = 0x67452301;
        int b = 0xEFCDAB89;
        int c = 0x98BADCFE;
        int d = 0x10325476;

        // Pad the message to a multiple of 64 bytes (MD4 padding).
        int length = message.length;
        int padded = length + 1;
        while (padded % 64 != 56) {
            padded++;
        }
        byte[] msg = new byte[padded + 8];
        System.arraycopy(message, 0, msg, 0, length);
        msg[length] = (byte) 0x80;
        long bits = (long) length * 8;
        for (int i = 0; i < 8; i++) {
            msg[padded + i] = (byte) (bits >>> (8 * i));
        }

        for (int offset = 0; offset < msg.length; offset += 64) {
            int[] x = new int[16];
            for (int i = 0; i < 16; i++) {
                int j = offset + i * 4;
                x[i] = (msg[j] & 0xFF)
                        | ((msg[j + 1] & 0xFF) << 8)
                        | ((msg[j + 2] & 0xFF) << 16)
                        | ((msg[j + 3] & 0xFF) << 24);
            }
            int aa = a;
            int bb = b;
            int cc = c;
            int dd = d;

            // Round 1
            for (int i = 0; i < 16; i += 4) {
                a = rol(a + f(b, c, d) + x[i], 3);
                d = rol(d + f(a, b, c) + x[i + 1], 7);
                c = rol(c + f(d, a, b) + x[i + 2], 11);
                b = rol(b + f(c, d, a) + x[i + 3], 19);
            }

            // Round 2
            for (int i = 0; i < 4; i++) {
                a = rol(a + g(b, c, d) + x[i] + 0x5A827999, 3);
                d = rol(d + g(a, b, c) + x[i + 4] + 0x5A827999, 5);
                c = rol(c + g(d, a, b) + x[i + 8] + 0x5A827999, 9);
                b = rol(b + g(c, d, a) + x[i + 12] + 0x5A827999, 13);
            }

            // Round 3
            for (int i : new int[] {0, 2, 1, 3}) {
                a = rol(a + h(b, c, d) + x[i] + 0x6ED9EBA1, 3);
                d = rol(d + h(a, b, c) + x[i + 8] + 0x6ED9EBA1, 9);
                c = rol(c + h(d, a, b) + x[i + 4] + 0x6ED9EBA1, 11);
                b = rol(b + h(c, d, a) + x[i + 12] + 0x6ED9EBA1, 15);
            }

            a += aa;
            b += bb;
            c += cc;
            d += dd;
        }

        byte[] out = new byte[16];
        writeLittleEndian(out, 0, a);
        writeLittleEndian(out, 4, b);
        writeLittleEndian(out, 8, c);
        writeLittleEndian(out, 12, d);
        return out;
    }

    private static int rol(int x, int c) {
        return (x << c) | (x >>> (32 - c));
    }

    private static int f(int x, int y, int z) {
        return (x & y) | (~x & z);
    }

    private static int g(int x, int y, int z) {
        return (x & y) | (x & z) | (y & z);
    }

    private static int h(int x, int y, int z) {
        return x ^ y ^ z;
    }

    private static void writeLittleEndian(byte[] out, int offset, int value) {
        out[offset] = (byte) value;
        out[offset + 1] = (byte) (value >>> 8);
        out[offset + 2] = (byte) (value >>> 16);
        out[offset + 3] = (byte) (value >>> 24);
    }

    /** Return the 16-byte NT hash of password (MD4 of the UTF-16LE bytes). */
    public static byte[] ntHash(String password) {
        return md4(password.getBytes(StandardCharsets.UTF_16LE));
    }

    /**
     * Return MD4 of the NT hash.
     *
     * MS-CHAPv2 uses this "password-hash-hash" both for the server
     * authenticator response (MS-CHAP2-Success) and to derive the MPPE session
     * keys.
     */
    public static byte[] ntHashHash(String password) {
        return md4(ntHash(password));
    }

    /**
     * Expand a 7-byte key into the 8-byte form DES expects.
     *
     * DES keys are 64 bits with one parity bit per byte, so 56 bits of real key
     * material are spread across 8 bytes. This is the standard MS-CHAP key
     * expansion (the parity bits themselves are ignored by DES).
     */
    private static byte[] expandDesKey(byte[] key7) {
        byte[] key = new byte[8];
        key[0] = (byte) ((key7[0] & 0xFF) >> 1);
        key[1] = (byte) (((key7[0] & 0x01) << 6) | ((key7[1] & 0xFF) >> 2));
        key[2] = (byte) (((key7[1] & 0x03) << 5) | ((key7[2] & 0xFF) >> 3));
        key[3] = (byte) (((key7[2] & 0x07) << 4) | ((key7[3] & 0xFF) >> 4));
        key[4] = (byte) (((key7[3] & 0x0F) << 3) | ((key7[4] & 0xFF) >> 5));
        key[5] = (byte) (((key7[4] & 0x1F) << 2) | ((key7[5] & 0xFF) >> 6));
        key[6] = (byte) (((key7[5] & 0x3F) << 1) | ((key7[6] & 0xFF) >> 7));
        key[7] = (byte) (key7[6] & 0x7F);
        for (int i = 0; i < 8; i++) {
            key[i] = (byte) ((key[i] << 1) & 0xFF);
        }
        return key;
    }

    /** DES-ECB encrypt one 8-byte block8 with a 7-byte key. */
    private static byte[] desEncrypt(byte[] key7, byte[] block8) {
        try {
            Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
            SecretKeySpec key = new SecretKeySpec(expandDesKey(key7), "DES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(block8);
        } catch (Exception exception) {
            // The key is always 8 bytes and the block always 8 bytes here, so
            // this cannot happen in practice.
            throw new IllegalStateException(exception);
        }
    }

    /**
     * Return the 24-byte NT response over an 8-byte challenge.
     *
     * The 16-byte NT hash is padded to 21 bytes and split into three 7-byte DES
     * keys; each encrypts the same 8-byte challenge, and the three 8-byte
     * results are concatenated into the 24-byte response.
     */
    public static byte[] ntChallengeResponse(byte[] challenge8, byte[] passwordNtHash) {
        byte[] padded = new byte[21];
        System.arraycopy(passwordNtHash, 0, padded, 0, passwordNtHash.length);
        byte[] out = new byte[24];
        for (int i = 0; i < 3; i++) {
            byte[] key7 = new byte[7];
            System.arraycopy(padded, i * 7, key7, 0, 7);
            byte[] block = desEncrypt(key7, challenge8);
            System.arraycopy(block, 0, out, i * 8, 8);
        }
        return out;
    }
}
