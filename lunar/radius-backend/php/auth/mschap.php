<?php
/**
 * MS-CHAPv1 authentication (RFC 2433).
 *
 * The NAS sends two Microsoft vendor attributes:
 *
 *  - MS-CHAP-Challenge - the 8-byte challenge.
 *  - MS-CHAP-Response  - 50 bytes: Ident (1), Flags (1), LM-Response (24) and
 *    NT-Response (24).
 *
 * We verify the NT-Response only (the LM-Response is obsolete and often zero):
 * the 24-byte DES response over the challenge, keyed by the NT hash of the
 * password. lunar forwards both attributes as raw bytes ("0x" hex).
 */

declare(strict_types=1);

require_once __DIR__ . '/nt.php';

/**
 * Return true when the MS-CHAPv1 NT-Response matches.
 *
 * $challenge is the 8-byte MS-CHAP-Challenge and $response the 50-byte
 * MS-CHAP-Response.
 */
function mschap_verify(string $expected_password, string $challenge, string $response): bool
{
    if (strlen($challenge) !== 8 || strlen($response) !== 50) {
        return false;
    }

    $nt_response = substr($response, 26, 24);
    $expected = nt_challenge_response($challenge, nt_hash($expected_password));
    return hash_equals($expected, $nt_response);
}
