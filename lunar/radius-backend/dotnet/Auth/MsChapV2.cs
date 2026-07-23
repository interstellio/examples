// MS-CHAPv2 authentication (RFC 2759).
//
// The NAS sends two Microsoft vendor attributes:
//
//   * MS-CHAP-Challenge  - the 16-byte Authenticator Challenge.
//   * MS-CHAP2-Response  - 50 bytes: Ident (1), Flags (1), Peer-Challenge (16),
//                          Reserved (8) and NT-Response (24).
//
// MS-CHAPv2 first derives an 8-byte "Challenge Hash" from the peer and
// authenticator challenges and the user name, then computes the NT-Response over
// that hash (keyed by the NT hash of the password) exactly as MS-CHAPv1 does. We
// recompute it and compare.
//
// On success, SuccessAndKeys also returns what a server normally adds to the
// Access-Accept: the MS-CHAP2-Success value (so the client can verify the
// server - MS-CHAPv2 is mutual authentication) and the MPPE link-encryption
// keys (RFC 3079). This class only computes the bytes; the caller sets the
// reply attributes. The MPPE keys are sent as PLAINTEXT "0x" hex - lunar
// salt-encrypts them on the wire with the shared secret (they are encrypt=2
// attributes), so this backend never needs the Request Authenticator.

using System.Security.Cryptography;
using System.Text;

namespace RadiusBackend.Auth;

public static class MsChapV2
{
    // Magic constants, byte-for-byte, from RFC 2759 (success) and RFC 3079 (MPPE).
    private static readonly byte[] MagicSign =
        Encoding.ASCII.GetBytes("Magic server to client signing constant");
    private static readonly byte[] MagicPad =
        Encoding.ASCII.GetBytes("Pad to make it do more than one iteration");
    private static readonly byte[] MagicMaster =
        Encoding.ASCII.GetBytes("This is the MPPE Master Key");
    // On the SERVER, the send key uses this constant and the receive key the other.
    private static readonly byte[] MagicServerSend = Encoding.ASCII.GetBytes(
        "On the client side, this is the receive key; " +
        "on the server side, it is the send key.");
    private static readonly byte[] MagicServerRecv = Encoding.ASCII.GetBytes(
        "On the client side, this is the send key; " +
        "on the server side, it is the receive key.");

    /// <summary>
    /// Return true when the MS-CHAPv2 NT-Response matches.
    /// <paramref name="challenge"/> is the 16-byte MS-CHAP-Challenge
    /// (Authenticator Challenge) and <paramref name="response"/> is the 50-byte
    /// MS-CHAP2-Response.
    /// </summary>
    public static bool Verify(string expectedPassword, string username,
        byte[] challenge, byte[] response)
    {
        if (challenge.Length != 16 || response.Length != 50)
        {
            return false;
        }

        var peerChallenge = response.AsSpan(2, 16).ToArray();
        var ntResponse = response.AsSpan(26, 24).ToArray();

        var challengeHash = ChallengeHash(peerChallenge, challenge, username);
        var expected = Nt.NtChallengeResponse(challengeHash, Nt.NtHash(expectedPassword));
        return CryptographicOperations.FixedTimeEquals(expected, ntResponse);
    }

    /// <summary>
    /// Return the raw MS-CHAP2-Success value and the two MPPE keys.
    /// <paramref name="challenge"/> is the 16-byte MS-CHAP-Challenge and
    /// <paramref name="response"/> the 50-byte MS-CHAP2-Response.
    /// </summary>
    public static (byte[] Success, byte[] SendKey, byte[] RecvKey) SuccessAndKeys(
        string password, string username, byte[] challenge, byte[] response)
    {
        var ident = response[0];
        var peerChallenge = response.AsSpan(2, 16).ToArray();
        var ntResponse = response.AsSpan(26, 24).ToArray();

        // MS-CHAP2-Success: the response Ident byte, then the "S=<hex>" string.
        var authenticatorResponse =
            AuthenticatorResponse(password, username, peerChallenge, challenge, ntResponse);
        var success = new List<byte> { ident };
        success.AddRange(Encoding.ASCII.GetBytes(authenticatorResponse));

        // MPPE keys: one 16-byte master key, then a send and a receive session key.
        var masterInput = new List<byte>();
        masterInput.AddRange(Nt.NtHashHash(password));
        masterInput.AddRange(ntResponse);
        masterInput.AddRange(MagicMaster);
        var masterKey = SHA1.HashData(masterInput.ToArray()).AsSpan(0, 16).ToArray();

        var sendKey = MppeSessionKey(masterKey, MagicServerSend);
        var recvKey = MppeSessionKey(masterKey, MagicServerRecv);

        return (success.ToArray(), sendKey, recvKey);
    }

    /// <summary>The 8-byte Challenge Hash (RFC 2759, GenerateNTResponse).</summary>
    private static byte[] ChallengeHash(byte[] peerChallenge,
        byte[] authenticatorChallenge, string username)
    {
        var input = new List<byte>();
        input.AddRange(peerChallenge);
        input.AddRange(authenticatorChallenge);
        input.AddRange(Encoding.ASCII.GetBytes(username));
        return SHA1.HashData(input.ToArray()).AsSpan(0, 8).ToArray();
    }

    /// <summary>The "S=&lt;hex&gt;" server authenticator response (RFC 2759).</summary>
    private static string AuthenticatorResponse(string password, string username,
        byte[] peerChallenge, byte[] authenticatorChallenge, byte[] ntResponse)
    {
        var passwordHashHash = Nt.NtHashHash(password);
        var challengeHash = ChallengeHash(peerChallenge, authenticatorChallenge, username);

        var first = new List<byte>();
        first.AddRange(passwordHashHash);
        first.AddRange(ntResponse);
        first.AddRange(MagicSign);
        var digest = SHA1.HashData(first.ToArray());

        var second = new List<byte>();
        second.AddRange(digest);
        second.AddRange(challengeHash);
        second.AddRange(MagicPad);
        var responseHash = SHA1.HashData(second.ToArray());

        return "S=" + Convert.ToHexString(responseHash); // ToHexString is uppercase
    }

    /// <summary>Derive one 16-byte MPPE session key from the master key (RFC 3079).</summary>
    private static byte[] MppeSessionKey(byte[] masterKey, byte[] magic)
    {
        var input = new List<byte>();
        input.AddRange(masterKey);
        input.AddRange(Enumerable.Repeat((byte)0x00, 40));
        input.AddRange(magic);
        input.AddRange(Enumerable.Repeat((byte)0xF2, 40));
        return SHA1.HashData(input.ToArray()).AsSpan(0, 16).ToArray();
    }
}
