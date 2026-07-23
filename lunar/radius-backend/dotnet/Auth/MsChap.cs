// MS-CHAPv1 authentication (RFC 2433).
//
// The NAS sends two Microsoft vendor attributes:
//
//   * MS-CHAP-Challenge - the 8-byte challenge.
//   * MS-CHAP-Response  - 50 bytes: Ident (1), Flags (1), LM-Response (24) and
//                         NT-Response (24).
//
// We verify the NT-Response only (the LM-Response is obsolete and often zero):
// the 24-byte DES response over the challenge, keyed by the NT hash of the
// password. lunar forwards both attributes as raw bytes ("0x" hex).

using System.Security.Cryptography;

namespace RadiusBackend.Auth;

public static class MsChap
{
    /// <summary>
    /// Return true when the MS-CHAPv1 NT-Response matches.
    /// <paramref name="challenge"/> is the 8-byte MS-CHAP-Challenge and
    /// <paramref name="response"/> is the 50-byte MS-CHAP-Response.
    /// </summary>
    public static bool Verify(string expectedPassword, byte[] challenge, byte[] response)
    {
        if (challenge.Length != 8 || response.Length != 50)
        {
            return false;
        }

        var ntResponse = response.AsSpan(26, 24).ToArray();
        var expected = Nt.NtChallengeResponse(challenge, Nt.NtHash(expectedPassword));
        return CryptographicOperations.FixedTimeEquals(expected, ntResponse);
    }
}
