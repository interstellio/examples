<?php
/**
 * Shared NT-hash and DES primitives for the MS-CHAP family.
 *
 * MS-CHAPv1 and MS-CHAPv2 both authenticate by encrypting a challenge with a
 * key derived from the "NT hash" of the user's password. This file provides
 * the low-level pieces they share, so mschap.php and mschapv2.php do not
 * duplicate the crypto:
 *
 *  - nt_hash()               - the NT hash of a password (MD4 of UTF-16LE).
 *  - nt_challenge_response() - the 24-byte DES response over an 8-byte
 *                              challenge (RFC 2433 / RFC 2759).
 *
 * MD4 is provided by ext-hash and single DES by ext-openssl (DES-ECB).
 *
 * This is EXAMPLE code, favouring clarity over completeness.
 */

declare(strict_types=1);

/** Return the 16-byte NT hash of a password (MD4 of the UTF-16LE bytes). */
function nt_hash(string $password): string
{
    return hash('md4', iconv('UTF-8', 'UTF-16LE', $password), true);
}

/**
 * Return MD4 of the NT hash. MS-CHAPv2 uses this "password-hash-hash" both for
 * the server authenticator response (MS-CHAP2-Success) and the MPPE keys.
 */
function nt_hash_hash(string $password): string
{
    return hash('md4', nt_hash($password), true);
}

/**
 * Expand a 7-byte key into the 8-byte form DES expects.
 *
 * DES keys are 64 bits with one parity bit per byte, so 56 bits of real key
 * material are spread across 8 bytes. This is the standard MS-CHAP key
 * expansion (the parity bits themselves are ignored by DES).
 */
function nt_expand_des_key(string $key7): string
{
    $k = array_values(unpack('C7', $key7));
    $key = [];
    $key[0] = $k[0] >> 1;
    $key[1] = (($k[0] & 0x01) << 6) | ($k[1] >> 2);
    $key[2] = (($k[1] & 0x03) << 5) | ($k[2] >> 3);
    $key[3] = (($k[2] & 0x07) << 4) | ($k[3] >> 4);
    $key[4] = (($k[3] & 0x0F) << 3) | ($k[4] >> 5);
    $key[5] = (($k[4] & 0x1F) << 2) | ($k[5] >> 6);
    $key[6] = (($k[5] & 0x3F) << 1) | ($k[6] >> 7);
    $key[7] = $k[6] & 0x7F;

    $out = '';
    foreach ($key as $byte) {
        $out .= chr(($byte << 1) & 0xFF);
    }
    return $out;
}

/** DES-ECB encrypt one 8-byte block with a 7-byte key. */
function nt_des_encrypt(string $key7, string $block8): string
{
    $key8 = nt_expand_des_key($key7);
    return openssl_encrypt(
        $block8,
        'DES-ECB',
        $key8,
        OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING
    );
}

/**
 * Return the 24-byte NT response over an 8-byte challenge.
 *
 * The 16-byte NT hash is padded to 21 bytes and split into three 7-byte DES
 * keys; each encrypts the same 8-byte challenge, and the three 8-byte results
 * are concatenated into the 24-byte response.
 */
function nt_challenge_response(string $challenge8, string $password_nt_hash): string
{
    $padded = str_pad($password_nt_hash, 21, "\x00");
    $response = '';
    for ($i = 0; $i < 21; $i += 7) {
        $response .= nt_des_encrypt(substr($padded, $i, 7), $challenge8);
    }
    return $response;
}
