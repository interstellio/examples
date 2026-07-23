// CHAP authentication (RFC 2865, section 2.2).
//
// CHAP never sends the password. The NAS sends:
//
//   * CHAP-Password  - 1 byte CHAP Identifier followed by a 16-byte MD5 hash.
//   * CHAP-Challenge - the challenge the hash was computed over. When this
//                      attribute is absent, the challenge is the packet's
//                      Request Authenticator (the "authenticator" field).
//
// To verify, we recompute MD5(chap_id + password + challenge) from the password
// we hold and compare it to the hash the NAS sent. Both are forwarded by lunar
// as raw bytes ("0x" hex in the packet JSON).

using System.Security.Cryptography;
using System.Text;

namespace RadiusBackend.Auth;

public static class Chap
{
    /// <summary>
    /// Return true when the CHAP response matches <paramref name="expectedPassword"/>.
    /// <paramref name="chapPassword"/> is the 17-byte CHAP-Password value
    /// (id + hash) and <paramref name="challenge"/> is the CHAP-Challenge (or
    /// the Request Authenticator when no CHAP-Challenge was sent).
    /// </summary>
    public static bool Verify(string expectedPassword, byte[] chapPassword, byte[] challenge)
    {
        if (chapPassword.Length != 17)
        {
            return false;
        }

        var chapId = chapPassword[0];
        var sentHash = chapPassword.AsSpan(1, 16).ToArray();

        var input = new List<byte> { chapId };
        input.AddRange(Encoding.UTF8.GetBytes(expectedPassword));
        input.AddRange(challenge);
        var expectedHash = MD5.HashData(input.ToArray());

        return CryptographicOperations.FixedTimeEquals(expectedHash, sentHash);
    }
}
