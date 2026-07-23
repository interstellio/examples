<?php
/**
 * An example RADIUS backend for lunar, built with plain PHP.
 *
 * This implements the lunar backend API (the same endpoints
 * lunar_backend_sim serves), but instead of mirroring attributes back it
 * performs REAL authentication and returns a single Framed-IP-Address.
 * Point lunar's subscriber.endpoint at this server and lunar will:
 *
 *   1. fetch the TEST virtual (one NAS client, secret "testing123"),
 *   2. forward each Access-Request here, where we authenticate test / test
 *      over PAP, CHAP, MS-CHAPv1 or MS-CHAPv2,
 *   3. reply Access-Accept with Framed-IP-Address = 192.168.50.50 (or reject).
 *
 * Accounting and CoA are acknowledged; the log and health endpoints are
 * accepted. It is a front controller: run it with PHP's built-in server
 * (php -S 127.0.0.1:5555 index.php) and every request is routed through here.
 * See README.rst for the full walk-through.
 *
 * This is EXAMPLE code - a starting point to adapt, not a production backend.
 */

declare(strict_types=1);

require_once __DIR__ . '/auth/chap.php';
require_once __DIR__ . '/auth/mschap.php';
require_once __DIR__ . '/auth/mschapv2.php';

// The only account this example knows about, and the static IP it hands out.
const USERNAME = 'test';
const PASSWORD = 'test';
const FRAMED_IP_ADDRESS = '192.168.50.50';

// The one virtual RADIUS server this example serves to lunar: a "TEST" virtual
// on 127.0.0.1 with a single NAS client whose shared secret is "testing123".
// lunar fetches this at start-up and starts a RADIUS server from it.
const TEST_VIRTUAL = [
    'id' => 'TEST',
    'domain' => 'test.local',
    'name' => 'test-virtual',
    'ip4_address' => '127.0.0.1',
    'radius_auth_port' => 1812,
    'radius_acct_port' => 1813,
    'radius_coa_port' => 3799,
    'clients' => [
        [
            'id' => 'client-test',
            'name' => 'test-client',
            'type' => 'nas',
            'ip4_address' => '127.0.0.1',
            'secret' => 'testing123',
            'profile' => 'default',
            'coa_port' => 3799,
            'req_message_auth' => false,
            'message_auth_reply' => true,
        ],
    ],
];

/**
 * Log an inbound packet and our reply as a readable, multi-line block.
 *
 * $client_ip is the real source the packet arrived from (lunar's x-client-ip
 * header); the NAS source IP is what the NAS reports in its NAS-IP-Address
 * attribute. Every attribute is shown as "name = value".
 */
function log_exchange(string $kind, string $server_id, string $virtual_id, ?string $client_ip, array $request, array $reply): void
{
    $render = function (array $attributes): string {
        if (!$attributes) {
            return '    (no attributes)';
        }
        ksort($attributes);
        $lines = [];
        foreach ($attributes as $name => $field) {
            $values = $field['values'] ?? [];
            $value = $values ? implode(', ', $values) : '(empty)';
            $lines[] = "    $name = $value";
        }
        return implode("\n", $lines);
    };

    $request_attributes = $request['attributes'] ?? [];
    $nas_ip = $request_attributes['nas-ip-address']['values'][0] ?? '-';

    error_log(sprintf(
        "%s %s/%s\n"
        . "  client source ip: %s\n"
        . "  nas source ip:    %s\n"
        . "  in  (%s):\n%s\n"
        . "  out (%s):\n%s",
        $kind,
        $server_id,
        $virtual_id,
        $client_ip ?? '-',
        $nas_ip,
        $request['code'] ?? '-',
        $render($request_attributes),
        $reply['code'] ?? '-',
        $render($reply['attributes'] ?? [])
    ));
}

/** GET /v1/lunar/ping - the health probe lunar's /v1/status hits. */
function ping(array $params): void
{
    http_response_code(200);
}

/** GET /v1/lunar/{server_id}/virtuals - list virtuals for a server. */
function virtuals(array $params): void
{
    header('Content-Type: application/json');
    echo json_encode([TEST_VIRTUAL]);
}

/** GET /v1/lunar/{server_id}/virtual/{virtual_id} - one virtual by id. */
function virtual(array $params): void
{
    header('Content-Type: application/json');
    echo json_encode(TEST_VIRTUAL);
}

/**
 * POST /v1/lunar/{server_id}/auth/{virtual_id} - an Access-Request.
 *
 * Answering a request happens in four steps, numbered below: (1) read the
 * forwarded packet, (2) find the user name, (3) detect the credential method
 * and verify it to build the reply, (4) answer lunar and log it. Each method
 * has its own block so it is obvious what happens for it.
 */
function auth(array $params): void
{
    // 1. Read the forwarded packet. lunar decodes the RADIUS packet off the
    //    wire and POSTs it to us as JSON in the request body.
    $packet = json_decode(file_get_contents('php://input'), true) ?? [];

    // 2. Find the user name. Every attribute arrives as {"values": [...]};
    //    we take the first User-Name value (null if it was not sent).
    $attributes = $packet['attributes'] ?? [];
    $username = $attributes['user-name']['values'][0] ?? null;

    // 3. Decide the reply. Which credential attribute is present tells us the
    //    method; each branch verifies that one method and sets $reply to an
    //    accept (with a Framed-IP-Address) or a reject.

    // No username: there is nobody to look up.
    if ($username === null) {
        $reply = [
            'code' => 'access-reject',
            'attributes' => [
                'Reply-Message' => ['values' => ['user not found']],
            ],
        ];

    // PAP: lunar has already decrypted User-Password, so just compare it.
    } elseif (isset($attributes['user-password'])) {
        $supplied = $attributes['user-password']['values'][0];
        if ($username !== USERNAME) {
            $reply = [
                'code' => 'access-reject',
                'attributes' => [
                    'Reply-Message' => ['values' => ['user not found']],
                ],
            ];
        } elseif ($supplied === PASSWORD) {
            $reply = [
                'code' => 'access-accept',
                'attributes' => [
                    'Framed-IP-Address' => ['values' => [FRAMED_IP_ADDRESS]],
                ],
            ];
        } else {
            $reply = [
                'code' => 'access-reject',
                'attributes' => [
                    'Reply-Message' => ['values' => ['invalid password']],
                ],
            ];
        }

    // CHAP: the challenge is CHAP-Challenge, or the Request Authenticator when
    // that attribute is absent. Binary values arrive as "0x" hex, so every
    // value is sliced with substr(..., 2) to drop the leading "0x" - hex2bin()
    // accepts only the hex digits, not the "0x" marker.
    } elseif (isset($attributes['chap-password'])) {
        $chap_password = hex2bin(substr($attributes['chap-password']['values'][0], 2));
        if (isset($attributes['chap-challenge'])) {
            $challenge = hex2bin(substr($attributes['chap-challenge']['values'][0], 2));
        } else {
            $challenge = hex2bin(substr($packet['authenticator'], 2));
        }
        $valid = chap_verify(PASSWORD, $chap_password, $challenge);
        if ($username !== USERNAME) {
            $reply = [
                'code' => 'access-reject',
                'attributes' => [
                    'Reply-Message' => ['values' => ['user not found']],
                ],
            ];
        } elseif ($valid) {
            $reply = [
                'code' => 'access-accept',
                'attributes' => [
                    'Framed-IP-Address' => ['values' => [FRAMED_IP_ADDRESS]],
                ],
            ];
        } else {
            $reply = [
                'code' => 'access-reject',
                'attributes' => [
                    'Reply-Message' => ['values' => ['invalid password']],
                ],
            ];
        }

    // MS-CHAPv1: 8-byte challenge + 50-byte response. As with CHAP, substr(2)
    // drops the "0x" prefix so hex2bin() sees only the hex digits.
    } elseif (isset($attributes['ms-chap-response'])) {
        $challenge = hex2bin(substr($attributes['ms-chap-challenge']['values'][0], 2));
        $response = hex2bin(substr($attributes['ms-chap-response']['values'][0], 2));
        $valid = mschap_verify(PASSWORD, $challenge, $response);
        if ($username !== USERNAME) {
            $reply = [
                'code' => 'access-reject',
                'attributes' => [
                    'Reply-Message' => ['values' => ['user not found']],
                ],
            ];
        } elseif ($valid) {
            $reply = [
                'code' => 'access-accept',
                'attributes' => [
                    'Framed-IP-Address' => ['values' => [FRAMED_IP_ADDRESS]],
                ],
            ];
        } else {
            $reply = [
                'code' => 'access-reject',
                'attributes' => [
                    'Reply-Message' => ['values' => ['invalid password']],
                ],
            ];
        }

    // MS-CHAPv2: 16-byte challenge + 50-byte response. As above, substr(2)
    // strips the "0x" prefix before hex2bin(). On success we also return
    // MS-CHAP2-Success (mutual auth) and the MPPE keys.
    } elseif (isset($attributes['ms-chap2-response'])) {
        $challenge = hex2bin(substr($attributes['ms-chap-challenge']['values'][0], 2));
        $response = hex2bin(substr($attributes['ms-chap2-response']['values'][0], 2));
        $valid = mschapv2_verify(PASSWORD, $username, $challenge, $response);
        if ($username !== USERNAME) {
            $reply = [
                'code' => 'access-reject',
                'attributes' => [
                    'Reply-Message' => ['values' => ['user not found']],
                ],
            ];
        } elseif ($valid) {
            // The helper gives us the raw bytes; we set the attributes here.
            // lunar salt-encrypts the MPPE keys on the wire.
            [$success, $send_key, $recv_key] = mschapv2_success_and_keys(
                PASSWORD,
                $username,
                $challenge,
                $response
            );
            $reply = [
                'code' => 'access-accept',
                'attributes' => [
                    'Framed-IP-Address' => ['values' => [FRAMED_IP_ADDRESS]],
                    'MS-CHAP2-Success' => ['values' => ['0x' . bin2hex($success)]],
                    'MS-MPPE-Send-Key' => ['values' => ['0x' . bin2hex($send_key)]],
                    'MS-MPPE-Recv-Key' => ['values' => ['0x' . bin2hex($recv_key)]],
                ],
            ];
        } else {
            $reply = [
                'code' => 'access-reject',
                'attributes' => [
                    'Reply-Message' => ['values' => ['invalid password']],
                ],
            ];
        }

    // No credential attribute we support.
    } else {
        $reply = ['code' => 'access-reject'];
    }

    // 4. Answer lunar: serialise the reply as JSON in the response body, then
    //    log the request and reply for the demo.
    log_exchange('auth', $params['server_id'], $params['virtual_id'], $_SERVER['HTTP_X_CLIENT_IP'] ?? null, $packet, $reply);
    header('Content-Type: application/json');
    echo json_encode($reply);
}

/**
 * POST /v1/lunar/{server_id}/acct/{virtual_id} - an Accounting-Request.
 *
 * lunar fast-ACKs accounting to the NAS itself, so we just acknowledge it.
 */
function acct(array $params): void
{
    $packet = json_decode(file_get_contents('php://input'), true) ?? [];
    $reply = ['code' => 'accounting-response', 'attributes' => []];
    log_exchange('acct', $params['server_id'], $params['virtual_id'], $_SERVER['HTTP_X_CLIENT_IP'] ?? null, $packet, $reply);
    header('Content-Type: application/json');
    echo json_encode($reply);
}

/**
 * POST /v1/lunar/{server_id}/coa/{virtual_id} - CoA / Disconnect.
 *
 * Acknowledge with the reply that matches the request.
 */
function coa(array $params): void
{
    $packet = json_decode(file_get_contents('php://input'), true) ?? [];
    if (($packet['code'] ?? null) === 'disconnect-request') {
        $reply = ['code' => 'disconnect-ack', 'attributes' => []];
    } else {
        $reply = ['code' => 'coa-ack', 'attributes' => []];
    }
    log_exchange('coa', $params['server_id'], $params['virtual_id'], $_SERVER['HTTP_X_CLIENT_IP'] ?? null, $packet, $reply);
    header('Content-Type: application/json');
    echo json_encode($reply);
}

/** POST /v1/lunar/{server_id}/log - remote log lines (accepted). */
function remote_log(array $params): void
{
    // lunar ships its subscriber log lines here as a JSON object; print them
    // in a readable form, then accept.
    $line = json_decode(file_get_contents('php://input'), true) ?? [];
    $level = strtoupper((string) ($line['level'] ?? 'info'));
    $message = $line['message'] ?? '';
    $when = isset($line['time']) ? date('Y-m-d H:i:s', (int) $line['time']) : '-';

    // Show any extra top-level fields lunar attached (virtual_id, client_ip,
    // ...) apart from the reserved ones we print above.
    $details = '';
    foreach ($line as $key => $value) {
        if (!in_array($key, ['level', 'message', 'time'], true)) {
            $details .= "\n    $key = " . (is_scalar($value) ? $value : json_encode($value));
        }
    }

    error_log(sprintf("log %s [%s] %s%s\n    %s", $params['server_id'], $level, $when, $details, $message));
    http_response_code(201);
}

// The routes lunar calls: [method, path regex with named params, handler].
$routes = [
    ['GET',  '#^/v1/lunar/ping$#', 'ping'],
    ['GET',  '#^/v1/lunar/(?P<server_id>[^/]+)/virtuals$#', 'virtuals'],
    ['GET',  '#^/v1/lunar/(?P<server_id>[^/]+)/virtual/(?P<virtual_id>[^/]+)$#', 'virtual'],
    ['POST', '#^/v1/lunar/(?P<server_id>[^/]+)/auth/(?P<virtual_id>[^/]+)$#', 'auth'],
    ['POST', '#^/v1/lunar/(?P<server_id>[^/]+)/acct/(?P<virtual_id>[^/]+)$#', 'acct'],
    ['POST', '#^/v1/lunar/(?P<server_id>[^/]+)/coa/(?P<virtual_id>[^/]+)$#', 'coa'],
    ['POST', '#^/v1/lunar/(?P<server_id>[^/]+)/log$#', 'remote_log'],
];

$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

foreach ($routes as [$route_method, $pattern, $handler]) {
    if ($route_method === $method && preg_match($pattern, $path, $params)) {
        $handler($params);
        return;
    }
}

http_response_code(404);
header('Content-Type: application/json');
echo json_encode(['error' => 'not found']);
