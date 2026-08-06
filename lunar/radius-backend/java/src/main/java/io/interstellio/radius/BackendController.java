/*
 * The Spring MVC controller for the example RADIUS backend, plus the hard-coded
 * TEST virtual returned to lunar.
 *
 * Endpoints (see docs/subscriber/radius/api.rst):
 *
 *   GET  /v1/lunar/radius/{server_id}/virtuals            -> [ TEST virtual ]
 *   GET  /v1/lunar/radius/{server_id}/virtual/{id}        -> TEST virtual
 *   POST /v1/lunar/radius/{server_id}/auth/{virtual_id}   -> access-accept / reject
 *   POST /v1/lunar/radius/{server_id}/acct/{virtual_id}   -> accounting-response
 *   POST /v1/lunar/radius/{server_id}/coa/{virtual_id}    -> coa-ack / disconnect-ack
 *   POST /v1/lunar/radius/{server_id}/log                 -> 201 (accept + log)
 *   GET  /v1/lunar/radius/ping                            -> 200 (health probe)
 */
package io.interstellio.radius;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.interstellio.radius.auth.Chap;
import io.interstellio.radius.auth.MsChap;
import io.interstellio.radius.auth.MsChapV2;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class BackendController {

    // The only account this example knows about, and the static IP it hands out.
    private static final String USERNAME = "test";
    private static final String PASSWORD = "test";
    private static final String FRAMED_IP_ADDRESS = "192.168.50.50";

    // Set from Application.main by --nodebug / RADIUS_BACKEND_NODEBUG.
    static boolean debug = true;

    private static final Logger LOG = LoggerFactory.getLogger("radius-backend");
    private static final DateTimeFormatter TIME_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * The one virtual RADIUS server this example serves to lunar: a "TEST"
     * virtual on 127.0.0.1 with a single NAS client whose shared secret is
     * "testing123". lunar fetches this at start-up and starts a RADIUS server
     * from it.
     */
    private static Map<String, Object> testVirtual() {
        Map<String, Object> client = new LinkedHashMap<>();
        client.put("id", "client-test");
        client.put("name", "test-client");
        client.put("type", "nas");
        client.put("ip4_address", "127.0.0.1");
        client.put("secret", "testing123");
        client.put("profile", "default");
        client.put("coa_port", 3799);
        client.put("req_message_auth", false);
        client.put("message_auth_reply", true);

        Map<String, Object> virtual = new LinkedHashMap<>();
        virtual.put("id", "TEST");
        virtual.put("domain", "test.local");
        virtual.put("name", "test-virtual");
        virtual.put("ip4_address", "127.0.0.1");
        virtual.put("radius_auth_port", 1812);
        virtual.put("radius_acct_port", 1813);
        virtual.put("radius_coa_port", 3799);
        virtual.put("clients", List.of(client));
        return virtual;
    }

    // --- reply builders ------------------------------------------------------

    /** One RADIUS attribute as lunar encodes it: {"values": [...]}. */
    private static Map<String, Object> attribute(Object... values) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("values", List.of(values));
        return map;
    }

    /** An Access-Accept carrying the static Framed-IP-Address. */
    private static Map<String, Object> accept() {
        Map<String, Object> attributes = new LinkedHashMap<>();
        attributes.put("Framed-IP-Address", attribute(FRAMED_IP_ADDRESS));
        return packet("access-accept", attributes);
    }

    /** An Access-Reject carrying a Reply-Message. */
    private static Map<String, Object> reject(String message) {
        Map<String, Object> attributes = new LinkedHashMap<>();
        attributes.put("Reply-Message", attribute(message));
        return packet("access-reject", attributes);
    }

    /**
     * Turn a verified/failed check into the matching reply: a user-not-found
     * reject for an unknown user, otherwise accept or reject.
     */
    private static Map<String, Object> passwordReply(String user, boolean valid) {
        if (!USERNAME.equals(user)) {
            return reject("user not found");
        }
        if (valid) {
            return accept();
        }
        return reject("invalid password");
    }

    private static Map<String, Object> packet(String code, Map<String, Object> attributes) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("code", code);
        map.put("attributes", attributes);
        return map;
    }

    // --- packet helpers ------------------------------------------------------

    /**
     * Decode the forwarded packet from the request body. Bad or empty JSON
     * becomes an empty packet here, never a 500.
     */
    private Map<String, Object> readPacket(String body) {
        if (body == null || body.isEmpty()) {
            return new LinkedHashMap<>();
        }
        try {
            return mapper.readValue(body, LinkedHashMap.class);
        } catch (Exception exception) {
            return new LinkedHashMap<>();
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> attributes(Map<String, Object> packet) {
        Object value = packet.get("attributes");
        if (value instanceof Map) {
            return (Map<String, Object>) value;
        }
        return new LinkedHashMap<>();
    }

    private static boolean hasAttr(Map<String, Object> attributes, String name) {
        return attributes.containsKey(name);
    }

    /** Return the first value of an attribute as a string, or null. */
    @SuppressWarnings("unchecked")
    private static String firstValue(Map<String, Object> attributes, String name) {
        Object attribute = attributes.get(name);
        if (!(attribute instanceof Map)) {
            return null;
        }
        Object values = ((Map<String, Object>) attribute).get("values");
        if (!(values instanceof List) || ((List<Object>) values).isEmpty()) {
            return null;
        }
        Object first = ((List<Object>) values).get(0);
        return first == null ? null : first.toString();
    }

    /**
     * Decode a "0x"-prefixed hex string into raw bytes. Binary attributes
     * arrive as "0x" hex, so the prefix is dropped before decoding.
     */
    private static byte[] hexValue(String value) {
        if (value == null) {
            return new byte[0];
        }
        String hex = value.startsWith("0x") ? value.substring(2) : value;
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    /** Encode raw bytes as a "0x"-prefixed lowercase hex string. */
    private static String hexPrefixed(byte[] bytes) {
        StringBuilder builder = new StringBuilder("0x");
        for (byte value : bytes) {
            builder.append(Character.forDigit((value >> 4) & 0xF, 16));
            builder.append(Character.forDigit(value & 0xF, 16));
        }
        return builder.toString();
    }

    // --- logging -------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private static String renderAttributes(Map<String, Object> attributes) {
        if (attributes == null || attributes.isEmpty()) {
            return "    (no attributes)";
        }
        List<String> lines = new ArrayList<>();
        for (Map.Entry<String, Object> entry : new TreeMap<>(attributes).entrySet()) {
            List<String> parts = new ArrayList<>();
            Object attribute = entry.getValue();
            if (attribute instanceof Map) {
                Object values = ((Map<String, Object>) attribute).get("values");
                if (values instanceof List) {
                    for (Object value : (List<Object>) values) {
                        parts.add(String.valueOf(value));
                    }
                }
            }
            String value = parts.isEmpty() ? "(empty)" : String.join(", ", parts);
            lines.add("    " + entry.getKey() + " = " + value);
        }
        return String.join("\n", lines);
    }

    /**
     * Log an inbound packet and our reply as a readable, multi-line block.
     * clientIp is the real source the packet arrived from (lunar's x-client-ip
     * header); the NAS source IP is what the NAS reports in its NAS-IP-Address
     * attribute.
     */
    private static void logExchange(String kind, String serverId, String virtualId,
            String clientIp, Map<String, Object> request, Map<String, Object> reply) {
        if (!debug) {
            return;
        }
        Map<String, Object> requestAttributes = attributes(request);
        String nasIp = firstValue(requestAttributes, "nas-ip-address");
        String requestCode = request.get("code") == null ? "-" : request.get("code").toString();
        String replyCode = reply.get("code") == null ? "-" : reply.get("code").toString();

        LOG.info("{} {}/{}\n"
                + "  client source ip: {}\n"
                + "  nas source ip:    {}\n"
                + "  in  ({}):\n{}\n"
                + "  out ({}):\n{}",
                kind, serverId, virtualId,
                clientIp == null ? "-" : clientIp,
                nasIp == null ? "-" : nasIp,
                requestCode, renderAttributes(requestAttributes),
                replyCode, renderAttributes(attributes(reply)));
    }

    // --- endpoints -----------------------------------------------------------

    /** GET /v1/lunar/radius/{server_id}/virtuals - list virtuals for a server. */
    @GetMapping(value = "/v1/lunar/radius/{serverId}/virtuals", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<Map<String, Object>> virtuals(@PathVariable String serverId) {
        return List.of(testVirtual());
    }

    /** GET /v1/lunar/radius/{server_id}/virtual/{virtual_id} - one virtual by id. */
    @GetMapping(value = "/v1/lunar/radius/{serverId}/virtual/{virtualId}",
            produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> virtual(@PathVariable String serverId,
            @PathVariable String virtualId) {
        return testVirtual();
    }

    /**
     * POST /v1/lunar/radius/{server_id}/auth/{virtual_id} - an Access-Request.
     *
     * Answering a request happens in four steps, numbered below: (1) read the
     * forwarded packet, (2) find the user name, (3) detect the credential
     * method and verify it to build the reply, (4) answer lunar and log it.
     * Each method has its own block so it is obvious what happens for it.
     */
    @PostMapping(value = "/v1/lunar/radius/{serverId}/auth/{virtualId}",
            produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> auth(@PathVariable String serverId, @PathVariable String virtualId,
            @RequestBody(required = false) String body,
            @RequestHeader(value = "x-client-ip", required = false) String clientIp) {
        // 1. Read the forwarded packet. lunar decodes the RADIUS packet off the
        //    wire and POSTs it to us as JSON in the request body.
        Map<String, Object> packet = readPacket(body);

        // 2. Find the user name. Every attribute arrives as {"values": [...]};
        //    we take the first User-Name value (null if it was not sent).
        Map<String, Object> attributes = attributes(packet);
        String username = firstValue(attributes, "user-name");

        // 3. Decide the reply. Which credential attribute is present tells us
        //    the method; each branch below verifies that one method and sets
        //    reply to an accept (with a Framed-IP-Address) or a reject.
        Map<String, Object> reply;

        // No username: there is nobody to look up.
        if (username == null) {
            reply = reject("user not found");

        // PAP: lunar has already decrypted User-Password, so just compare it.
        } else if (hasAttr(attributes, "user-password")) {
            String supplied = firstValue(attributes, "user-password");
            reply = passwordReply(username, PASSWORD.equals(supplied));

        // CHAP: the challenge is CHAP-Challenge, or the Request Authenticator
        // when that attribute is absent.
        } else if (hasAttr(attributes, "chap-password")) {
            byte[] chapPassword = hexValue(firstValue(attributes, "chap-password"));
            byte[] challenge;
            if (hasAttr(attributes, "chap-challenge")) {
                challenge = hexValue(firstValue(attributes, "chap-challenge"));
            } else {
                challenge = hexValue((String) packet.get("authenticator"));
            }
            boolean valid = Chap.verify(PASSWORD, chapPassword, challenge);
            reply = passwordReply(username, valid);

        // MS-CHAPv1: 8-byte challenge + 50-byte response.
        } else if (hasAttr(attributes, "ms-chap-response")) {
            byte[] challenge = hexValue(firstValue(attributes, "ms-chap-challenge"));
            byte[] response = hexValue(firstValue(attributes, "ms-chap-response"));
            boolean valid = MsChap.verify(PASSWORD, challenge, response);
            reply = passwordReply(username, valid);

        // MS-CHAPv2: 16-byte challenge + 50-byte response. On success we also
        // return MS-CHAP2-Success (mutual auth) and the MPPE keys.
        } else if (hasAttr(attributes, "ms-chap2-response")) {
            byte[] challenge = hexValue(firstValue(attributes, "ms-chap-challenge"));
            byte[] response = hexValue(firstValue(attributes, "ms-chap2-response"));
            boolean valid = MsChapV2.verify(PASSWORD, username, challenge, response);
            if (!USERNAME.equals(username)) {
                reply = reject("user not found");
            } else if (valid) {
                // The module gives us the raw bytes; we set the attributes
                // here. lunar salt-encrypts the MPPE keys on the wire.
                MsChapV2.SuccessKeys keys =
                        MsChapV2.successAndKeys(PASSWORD, username, challenge, response);
                Map<String, Object> acceptAttributes = new LinkedHashMap<>();
                acceptAttributes.put("Framed-IP-Address", attribute(FRAMED_IP_ADDRESS));
                acceptAttributes.put("MS-CHAP2-Success", attribute(hexPrefixed(keys.success())));
                acceptAttributes.put("MS-MPPE-Send-Key", attribute(hexPrefixed(keys.sendKey())));
                acceptAttributes.put("MS-MPPE-Recv-Key", attribute(hexPrefixed(keys.recvKey())));
                reply = packet("access-accept", acceptAttributes);
            } else {
                reply = reject("invalid password");
            }

        // No credential attribute we support.
        } else {
            reply = packet("access-reject", new LinkedHashMap<>());
        }

        // 4. Answer lunar: return the reply as JSON, then log it for the demo.
        logExchange("auth", serverId, virtualId, clientIp, packet, reply);
        return reply;
    }

    /**
     * POST /v1/lunar/radius/{server_id}/acct/{virtual_id} - an Accounting-Request.
     * lunar fast-ACKs accounting to the NAS itself, so we just acknowledge it.
     */
    @PostMapping(value = "/v1/lunar/radius/{serverId}/acct/{virtualId}",
            produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> acct(@PathVariable String serverId, @PathVariable String virtualId,
            @RequestBody(required = false) String body,
            @RequestHeader(value = "x-client-ip", required = false) String clientIp) {
        Map<String, Object> packet = readPacket(body);
        Map<String, Object> reply = packet("accounting-response", new LinkedHashMap<>());
        logExchange("acct", serverId, virtualId, clientIp, packet, reply);
        return reply;
    }

    /**
     * POST /v1/lunar/radius/{server_id}/coa/{virtual_id} - CoA / Disconnect.
     * Acknowledge with the reply that matches the request.
     */
    @PostMapping(value = "/v1/lunar/radius/{serverId}/coa/{virtualId}",
            produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> coa(@PathVariable String serverId, @PathVariable String virtualId,
            @RequestBody(required = false) String body,
            @RequestHeader(value = "x-client-ip", required = false) String clientIp) {
        Map<String, Object> packet = readPacket(body);
        Map<String, Object> reply;
        if ("disconnect-request".equals(packet.get("code"))) {
            reply = packet("disconnect-ack", new LinkedHashMap<>());
        } else {
            reply = packet("coa-ack", new LinkedHashMap<>());
        }
        logExchange("coa", serverId, virtualId, clientIp, packet, reply);
        return reply;
    }

    /** POST /v1/lunar/radius/{server_id}/log - remote log lines (accepted). */
    @PostMapping("/v1/lunar/radius/{serverId}/log")
    public ResponseEntity<Void> remoteLog(@PathVariable String serverId,
            @RequestBody(required = false) String body) {
        // lunar ships its subscriber log lines here as a JSON object; print
        // them in a readable form, then accept.
        Map<String, Object> line = readPacket(body);

        String level = line.get("level") == null ? "INFO"
                : line.get("level").toString().toUpperCase(java.util.Locale.ROOT);
        String message = line.get("message") == null
                ? (body == null ? "" : body.strip()) : line.get("message").toString();
        String when = "-";
        Object time = line.get("time");
        if (time instanceof Number) {
            when = TIME_FORMAT.format(Instant.ofEpochSecond(((Number) time).longValue()));
        }

        // Show any extra top-level fields lunar attached (virtual_id, client_ip,
        // ...) apart from the reserved ones we print above.
        StringBuilder details = new StringBuilder();
        for (Map.Entry<String, Object> entry : new TreeMap<>(line).entrySet()) {
            String key = entry.getKey();
            if (key.equals("level") || key.equals("message") || key.equals("time")) {
                continue;
            }
            details.append("\n    ").append(key).append(" = ").append(entry.getValue());
        }

        if (debug) {
            LOG.info("log {} [{}] {}{}\n    {}", serverId, level, when, details.toString(), message);
        }
        return ResponseEntity.status(201).build();
    }

    /** GET /v1/lunar/radius/ping - the health probe lunar's /v1/status hits. */
    @GetMapping("/v1/lunar/radius/ping")
    public ResponseEntity<Void> ping() {
        return ResponseEntity.ok().build();
    }
}
