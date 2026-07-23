// Shared NT-hash and DES primitives for the MS-CHAP family.
//
// MS-CHAPv1 and MS-CHAPv2 both authenticate by encrypting a challenge with a
// key derived from the "NT hash" of the user's password. This file provides the
// low-level pieces they share, so MsChap.cs and MsChapV2.cs do not duplicate the
// crypto:
//
//   * NtHash               - the NT hash of a password (MD4 of the UTF-16LE
//                            password bytes).
//   * NtHashHash           - MD4 of the NT hash (MS-CHAPv2 server response and
//                            MPPE key derivation).
//   * NtChallengeResponse  - the 24-byte DES response over an 8-byte challenge
//                            (RFC 2433 / RFC 2759).
//
// .NET's base class library ships MD5, SHA1 and DES but NOT MD4, so MD4 is
// implemented here as a compact, self-contained function (RFC 1320). That keeps
// the whole example dependency-free.
//
// This is EXAMPLE code, favouring clarity over completeness; a production
// backend would look the user up in a real store and handle more edge cases.

using System.Security.Cryptography;
using System.Text;

namespace RadiusBackend.Auth;

public static class Nt
{
    /// <summary>16-byte NT hash of a password: MD4 of the UTF-16LE bytes.</summary>
    public static byte[] NtHash(string password)
    {
        // Encoding.Unicode is UTF-16 little-endian, exactly what the NT hash
        // is defined over.
        return Md4(Encoding.Unicode.GetBytes(password));
    }

    /// <summary>
    /// MD4 of the NT hash. MS-CHAPv2 uses this "password-hash-hash" both for the
    /// server authenticator response (MS-CHAP2-Success) and to derive the MPPE
    /// session keys.
    /// </summary>
    public static byte[] NtHashHash(string password)
    {
        return Md4(NtHash(password));
    }

    /// <summary>
    /// The 24-byte NT response over an 8-byte challenge. The 16-byte NT hash is
    /// padded to 21 bytes and split into three 7-byte DES keys; each encrypts
    /// the same 8-byte challenge, and the three 8-byte results are concatenated.
    /// </summary>
    public static byte[] NtChallengeResponse(byte[] challenge8, byte[] passwordNtHash)
    {
        var padded = new byte[21];
        Array.Copy(passwordNtHash, padded, passwordNtHash.Length);

        var response = new byte[24];
        for (var i = 0; i < 3; i++)
        {
            var key7 = padded.AsSpan(i * 7, 7).ToArray();
            var block = DesEncrypt(key7, challenge8);
            Array.Copy(block, 0, response, i * 8, 8);
        }
        return response;
    }

    // --- DES ---------------------------------------------------------------

    /// <summary>
    /// Expand a 7-byte key into the 8-byte form DES expects. DES keys are 64
    /// bits with one parity bit per byte, so 56 bits of real key material are
    /// spread across 8 bytes. This is the standard MS-CHAP key expansion (the
    /// parity bits themselves are ignored by DES).
    /// </summary>
    private static byte[] ExpandDesKey(byte[] key7)
    {
        var key = new byte[8];
        key[0] = (byte)(key7[0] >> 1);
        key[1] = (byte)(((key7[0] & 0x01) << 6) | (key7[1] >> 2));
        key[2] = (byte)(((key7[1] & 0x03) << 5) | (key7[2] >> 3));
        key[3] = (byte)(((key7[2] & 0x07) << 4) | (key7[3] >> 4));
        key[4] = (byte)(((key7[3] & 0x0F) << 3) | (key7[4] >> 5));
        key[5] = (byte)(((key7[4] & 0x1F) << 2) | (key7[5] >> 6));
        key[6] = (byte)(((key7[5] & 0x3F) << 1) | (key7[6] >> 7));
        key[7] = (byte)(key7[6] & 0x7F);
        for (var i = 0; i < 8; i++)
        {
            key[i] = (byte)((key[i] << 1) & 0xFF);
        }
        return key;
    }

    /// <summary>DES-ECB encrypt one 8-byte block with a 7-byte key.</summary>
    private static byte[] DesEncrypt(byte[] key7, byte[] block8)
    {
        using var des = DES.Create();
        des.Mode = CipherMode.ECB;
        des.Padding = PaddingMode.None;
        // NOTE: DES.Key rejects the handful of known "weak" keys. The MS-CHAP
        // key expansion can in theory produce one, but the odds for a real
        // password hash are ~16 in 2^56 (effectively never). A production
        // implementation that must be bullet-proof would use a DES that skips
        // that check; for a readable example the BCL DES is the right choice.
        des.Key = ExpandDesKey(key7);
        using var encryptor = des.CreateEncryptor();
        return encryptor.TransformFinalBlock(block8, 0, 8);
    }

    // --- MD4 (RFC 1320) ----------------------------------------------------

    /// <summary>A compact, self-contained MD4 (the BCL does not provide one).</summary>
    private static byte[] Md4(byte[] message)
    {
        uint a = 0x67452301, b = 0xEFCDAB89, c = 0x98BADCFE, d = 0x10325476;

        // Pad the message to a multiple of 64 bytes (MD4 padding): a 0x80 byte,
        // then zeros, then the original length in bits as a 64-bit LE integer.
        var length = (ulong)message.Length * 8;
        var padded = new List<byte>(message) { 0x80 };
        while (padded.Count % 64 != 56)
        {
            padded.Add(0x00);
        }
        for (var i = 0; i < 8; i++)
        {
            padded.Add((byte)(length >> (8 * i)));
        }
        var data = padded.ToArray();

        for (var offset = 0; offset < data.Length; offset += 64)
        {
            var x = new uint[16];
            for (var i = 0; i < 16; i++)
            {
                x[i] = ReadLittleEndian(data, offset + i * 4);
            }

            uint aa = a, bb = b, cc = c, dd = d;

            // Round 1
            for (var i = 0; i < 16; i += 4)
            {
                a = Rol(a + F(b, c, d) + x[i], 3);
                d = Rol(d + F(a, b, c) + x[i + 1], 7);
                c = Rol(c + F(d, a, b) + x[i + 2], 11);
                b = Rol(b + F(c, d, a) + x[i + 3], 19);
            }

            // Round 2
            for (var i = 0; i < 4; i++)
            {
                a = Rol(a + G(b, c, d) + x[i] + 0x5A827999, 3);
                d = Rol(d + G(a, b, c) + x[i + 4] + 0x5A827999, 5);
                c = Rol(c + G(d, a, b) + x[i + 8] + 0x5A827999, 9);
                b = Rol(b + G(c, d, a) + x[i + 12] + 0x5A827999, 13);
            }

            // Round 3
            foreach (var i in new[] { 0, 2, 1, 3 })
            {
                a = Rol(a + H(b, c, d) + x[i] + 0x6ED9EBA1, 3);
                d = Rol(d + H(a, b, c) + x[i + 8] + 0x6ED9EBA1, 9);
                c = Rol(c + H(d, a, b) + x[i + 4] + 0x6ED9EBA1, 11);
                b = Rol(b + H(c, d, a) + x[i + 12] + 0x6ED9EBA1, 15);
            }

            a += aa;
            b += bb;
            c += cc;
            d += dd;
        }

        var result = new byte[16];
        WriteLittleEndian(result, 0, a);
        WriteLittleEndian(result, 4, b);
        WriteLittleEndian(result, 8, c);
        WriteLittleEndian(result, 12, d);
        return result;
    }

    private static uint F(uint x, uint y, uint z) => (x & y) | (~x & z);
    private static uint G(uint x, uint y, uint z) => (x & y) | (x & z) | (y & z);
    private static uint H(uint x, uint y, uint z) => x ^ y ^ z;
    private static uint Rol(uint value, int count) => (value << count) | (value >> (32 - count));

    private static uint ReadLittleEndian(byte[] buffer, int offset)
    {
        return (uint)(buffer[offset]
                      | buffer[offset + 1] << 8
                      | buffer[offset + 2] << 16
                      | buffer[offset + 3] << 24);
    }

    private static void WriteLittleEndian(byte[] buffer, int offset, uint value)
    {
        buffer[offset] = (byte)value;
        buffer[offset + 1] = (byte)(value >> 8);
        buffer[offset + 2] = (byte)(value >> 16);
        buffer[offset + 3] = (byte)(value >> 24);
    }
}
