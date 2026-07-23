<?php
/**
 * MS-CHAPv2 authentication (RFC 2759).
 *
 * The NAS sends two Microsoft vendor attributes:
 *
 *  - MS-CHAP-Challenge  - the 16-byte Authenticator Challenge.
 *  - MS-CHAP2-Response  - 50 bytes: Ident (1), Flags (1), Peer-Challenge (16),
 *    Reserved (8) and NT-Response (24).
 *
 * MS-CHAPv2 first derives an 8-byte "Challenge Hash" from the peer and
 * authenticator challenges and the user name, then computes the NT-Response
 * over that hash exactly as MS-CHAPv1 does. We recompute it and compare.
 *
 * On success, mschapv2_success_and_keys() also returns what a server normally
 * adds to the Access-Accept: the MS-CHAP2-Success value (mutual auth) and the
 * MPPE link-encryption keys. This file only computes the bytes; the caller
 * sets the reply attributes.
 */

declare(strict_types=1);

require_once __DIR__ . '/nt.php';

// Magic constants, byte-for-byte, from RFC 2759 (success) and RFC 3079 (MPPE).
const MSCHAPV2_MAGIC_SIGN = 'Magic server to client signing constant';
const MSCHAPV2_MAGIC_PAD = 'Pad to make it do more than one iteration';
const MSCHAPV2_MAGIC_MASTER = 'This is the MPPE Master Key';
const MSCHAPV2_MAGIC_SERVER_SEND =
    'On the client side, this is the receive key; '
    . 'on the server side, it is the send key.';
const MSCHAPV2_MAGIC_SERVER_RECV =
    'On the client side, this is the send key; '
    . 'on the server side, it is the receive key.';

/** Return the 8-byte Challenge Hash (RFC 2759, GenerateNTResponse). */
function mschapv2_challenge_hash(string $peer_challenge, string $authenticator_challenge, string $username): string
{
    $digest = sha1($peer_challenge . $authenticator_challenge . $username, true);
    return substr($digest, 0, 8);
}

/**
 * Return true when the MS-CHAPv2 NT-Response matches.
 *
 * $challenge is the 16-byte MS-CHAP-Challenge (Authenticator Challenge) and
 * $response is the 50-byte MS-CHAP2-Response.
 */
function mschapv2_verify(string $expected_password, string $username, string $challenge, string $response): bool
{
    if (strlen($challenge) !== 16 || strlen($response) !== 50) {
        return false;
    }

    $peer_challenge = substr($response, 2, 16);
    $nt_response = substr($response, 26, 24);

    $challenge_hash = mschapv2_challenge_hash($peer_challenge, $challenge, $username);
    $expected = nt_challenge_response($challenge_hash, nt_hash($expected_password));
    return hash_equals($expected, $nt_response);
}

/** Return the "S=<hex>" server authenticator response (RFC 2759). */
function mschapv2_authenticator_response(string $password, string $username, string $peer_challenge, string $authenticator_challenge, string $nt_response): string
{
    $password_hash_hash = nt_hash_hash($password);
    $challenge_hash = mschapv2_challenge_hash($peer_challenge, $authenticator_challenge, $username);
    $digest = sha1($password_hash_hash . $nt_response . MSCHAPV2_MAGIC_SIGN, true);
    $response = sha1($digest . $challenge_hash . MSCHAPV2_MAGIC_PAD, true);
    return 'S=' . strtoupper(bin2hex($response));
}

/** Derive one 16-byte MPPE session key from the master key (RFC 3079). */
function mschapv2_mppe_session_key(string $master_key, string $magic): string
{
    $digest = sha1(
        $master_key . str_repeat("\x00", 40) . $magic . str_repeat("\xf2", 40),
        true
    );
    return substr($digest, 0, 16);
}

/**
 * Return [success, send_key, recv_key] as raw bytes.
 *
 * $challenge is the 16-byte MS-CHAP-Challenge and $response the 50-byte
 * MS-CHAP2-Response. The caller turns them into reply attributes.
 */
function mschapv2_success_and_keys(string $password, string $username, string $challenge, string $response): array
{
    $ident = $response[0];
    $peer_challenge = substr($response, 2, 16);
    $nt_response = substr($response, 26, 24);

    // MS-CHAP2-Success: the response Ident byte, then the "S=<hex>" string.
    $success = $ident . mschapv2_authenticator_response(
        $password,
        $username,
        $peer_challenge,
        $challenge,
        $nt_response
    );

    // MPPE keys: one 16-byte master key, then a send and a receive key.
    $master_key = substr(
        sha1(nt_hash_hash($password) . $nt_response . MSCHAPV2_MAGIC_MASTER, true),
        0,
        16
    );
    $send_key = mschapv2_mppe_session_key($master_key, MSCHAPV2_MAGIC_SERVER_SEND);
    $recv_key = mschapv2_mppe_session_key($master_key, MSCHAPV2_MAGIC_SERVER_RECV);

    return [$success, $send_key, $recv_key];
}
