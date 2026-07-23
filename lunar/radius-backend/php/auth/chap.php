<?php
/**
 * CHAP authentication (RFC 2865, section 2.2).
 *
 * CHAP never sends the password. The NAS sends:
 *
 *  - CHAP-Password  - 1 byte CHAP Identifier followed by a 16-byte MD5 hash.
 *  - CHAP-Challenge - the challenge the hash was computed over. When this
 *    attribute is absent, the challenge is the packet's Request Authenticator.
 *
 * To verify, we recompute MD5(chap_id + password + challenge) from the
 * password we hold and compare it to the hash the NAS sent. Both are forwarded
 * by lunar as raw bytes ("0x" hex in the packet JSON).
 */

declare(strict_types=1);

/**
 * Return true when the CHAP response matches $expected_password.
 *
 * $chap_password is the 17-byte CHAP-Password value (id + hash) and $challenge
 * is the CHAP-Challenge (or the Request Authenticator when none was sent).
 */
function chap_verify(string $expected_password, string $chap_password, string $challenge): bool
{
    if (strlen($chap_password) !== 17) {
        return false;
    }

    $chap_id = $chap_password[0];
    $sent_hash = substr($chap_password, 1, 16);

    $expected_hash = md5($chap_id . $expected_password . $challenge, true);
    return hash_equals($expected_hash, $sent_hash);
}
