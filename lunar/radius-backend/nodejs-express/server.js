// An example RADIUS backend for lunar, built with Node.js and Express.
//
// This implements the lunar backend API (the same endpoints lunar_backend_sim
// serves), but instead of mirroring attributes back it performs REAL
// authentication and returns a single Framed-IP-Address. Point lunar's
// subscriber.endpoint at this server and lunar will:
//
//   1. fetch the TEST virtual (one NAS client, secret "testing123"),
//   2. forward each Access-Request here, where we authenticate "test" / "test"
//      over PAP, CHAP, MS-CHAPv1 or MS-CHAPv2,
//   3. reply Access-Accept with Framed-IP-Address = 192.168.50.50 (or reject).
//
// Accounting and CoA are acknowledged; the log and health endpoints are accepted.
//
// Endpoints (see docs/subscriber/radius/api.rst):
//
//   GET  /v1/lunar/{server_id}/virtuals            -> [ TEST virtual ]
//   GET  /v1/lunar/{server_id}/virtual/{id}        -> TEST virtual
//   POST /v1/lunar/{server_id}/auth/{virtual_id}   -> access-accept / reject
//   POST /v1/lunar/{server_id}/acct/{virtual_id}   -> accounting-response
//   POST /v1/lunar/{server_id}/coa/{virtual_id}    -> coa-ack / disconnect-ack
//   POST /v1/lunar/{server_id}/log                 -> 201 (accept + log)
//   GET  /v1/lunar/ping                            -> 200 (health probe)
//
// Run it (from this directory) with `npm start` (or `node server.js`); it listens
// on 127.0.0.1:5555. Pass `--nodebug` to quiet the per-exchange logging. See
// README.rst for the full walk-through.
//
// This is EXAMPLE code - a starting point to adapt, not a production backend.

"use strict";

const express = require("express");
const chap = require("./auth/chap");
const msChap = require("./auth/mschap");
const msChapV2 = require("./auth/mschapv2");

// The only account this example knows about, and the static IP it hands out.
const USERNAME = "test";
const PASSWORD = "test";
const FRAMED_IP = "192.168.50.50";

// The one virtual RADIUS server this example serves to lunar: a "TEST" virtual
// on 127.0.0.1 with a single NAS client whose shared secret is "testing123".
// lunar fetches this at start-up and starts a RADIUS server from it. The field
// names are the exact server-side snake_case keys lunar expects.
const TEST_VIRTUAL = {
  id: "TEST",
  domain: "test.local",
  name: "test-virtual",
  ip4_address: "127.0.0.1",
  radius_auth_port: 1812,
  radius_acct_port: 1813,
  radius_coa_port: 3799,
  clients: [
    {
      id: "client-test",
      name: "test-client",
      type: "nas",
      ip4_address: "127.0.0.1",
      secret: "testing123",
      profile: "default",
      coa_port: 3799,
      req_message_auth: false,
      message_auth_reply: true,
    },
  ],
};

// `node server.js --nodebug` (or the RADIUS_BACKEND_NODEBUG env var) turns off
// the per-exchange, human-formatted logging - the slowest thing this example
// does. On by default so you can watch exactly what lunar sends.
const debug = !(
  process.argv.includes("--nodebug") || process.env.RADIUS_BACKEND_NODEBUG
);

const app = express();
// Read every body as raw text (any content type). We parse the JSON ourselves
// in readJson so an empty or malformed body becomes a reject, never a 500 -
// express.json() would instead reject a bad body with its own 400.
app.use(express.text({ type: "*/*", limit: "1mb" }));

// --- Configuration endpoints (what lunar fetches at start-up) --------------

// GET /v1/lunar/{server_id}/virtuals - list virtuals for a server.
app.get("/v1/lunar/:serverId/virtuals", (req, res) => {
  res.json([TEST_VIRTUAL]);
});

// GET /v1/lunar/{server_id}/virtual/{virtual_id} - one virtual by id.
app.get("/v1/lunar/:serverId/virtual/:virtualId", (req, res) => {
  res.json(TEST_VIRTUAL);
});

// --- Authentication ---------------------------------------------------------

// POST /v1/lunar/{server_id}/auth/{virtual_id} - an Access-Request.
//
// Answering a request happens in four steps: (1) read the forwarded packet,
// (2) find the user name, (3) detect the credential method and verify it to
// build the reply, (4) answer lunar and log it.
app.post("/v1/lunar/:serverId/auth/:virtualId", (req, res) => {
  // 1. Read the forwarded packet. lunar decodes the RADIUS packet off the wire
  //    and POSTs it to us as JSON. Bad or empty JSON becomes a reject here,
  //    never a 500.
  const packet = readJson(req);
  const attributes = packet.attributes || {};

  // 2. Find the user name (the first User-Name value, or null).
  const username = firstValue(attributes, "user-name");

  // 3. Decide the reply. Which credential attribute is present tells us the
  //    method; each branch verifies that one method.
  let reply;
  if (username === null) {
    // No username: there is nobody to look up.
    reply = accessReject("user not found");
  } else if (has(attributes, "user-password")) {
    // PAP: lunar has already decrypted User-Password, so just compare it.
    const supplied = firstValue(attributes, "user-password");
    reply = decision(username, supplied === PASSWORD);
  } else if (has(attributes, "chap-password")) {
    // CHAP: the challenge is CHAP-Challenge, or the Request Authenticator when
    // that attribute is absent.
    const chapPassword = fromHex(firstValue(attributes, "chap-password"));
    const challenge = has(attributes, "chap-challenge")
      ? fromHex(firstValue(attributes, "chap-challenge"))
      : fromHex(packet.authenticator);
    reply = decision(username, chap.verify(PASSWORD, chapPassword, challenge));
  } else if (has(attributes, "ms-chap-response")) {
    // MS-CHAPv1: 8-byte challenge + 50-byte response.
    const challenge = fromHex(firstValue(attributes, "ms-chap-challenge"));
    const response = fromHex(firstValue(attributes, "ms-chap-response"));
    reply = decision(username, msChap.verify(PASSWORD, challenge, response));
  } else if (has(attributes, "ms-chap2-response")) {
    // MS-CHAPv2: 16-byte challenge + 50-byte response. On success we also
    // return MS-CHAP2-Success (mutual auth) and the MPPE keys.
    const challenge = fromHex(firstValue(attributes, "ms-chap-challenge"));
    const response = fromHex(firstValue(attributes, "ms-chap2-response"));
    const valid = msChapV2.verify(PASSWORD, username, challenge, response);
    if (username !== USERNAME) {
      reply = accessReject("user not found");
    } else if (valid) {
      const { success, sendKey, recvKey } = msChapV2.successAndKeys(
        PASSWORD,
        username,
        challenge,
        response
      );
      reply = {
        code: "access-accept",
        attributes: {
          "Framed-IP-Address": values(FRAMED_IP),
          "MS-CHAP2-Success": values("0x" + toHex(success)),
          "MS-MPPE-Send-Key": values("0x" + toHex(sendKey)),
          "MS-MPPE-Recv-Key": values("0x" + toHex(recvKey)),
        },
      };
    } else {
      reply = accessReject("invalid password");
    }
  } else {
    // No credential attribute we support.
    reply = { code: "access-reject" };
  }

  // 4. Answer lunar, and log the exchange for the demo.
  logExchange("auth", req.params.serverId, req.params.virtualId, req.get("x-client-ip"), packet, reply);
  res.json(reply);
});

// --- Accounting, CoA, log, health ------------------------------------------

// POST /v1/lunar/{server_id}/acct/{virtual_id} - an Accounting-Request.
// lunar fast-ACKs accounting to the NAS itself, so we just acknowledge it.
app.post("/v1/lunar/:serverId/acct/:virtualId", (req, res) => {
  const packet = readJson(req);
  const reply = { code: "accounting-response", attributes: {} };
  logExchange("acct", req.params.serverId, req.params.virtualId, req.get("x-client-ip"), packet, reply);
  res.json(reply);
});

// POST /v1/lunar/{server_id}/coa/{virtual_id} - CoA / Disconnect.
// Acknowledge with the reply that matches the request.
app.post("/v1/lunar/:serverId/coa/:virtualId", (req, res) => {
  const packet = readJson(req);
  const code = packet.code === "disconnect-request" ? "disconnect-ack" : "coa-ack";
  const reply = { code, attributes: {} };
  logExchange("coa", req.params.serverId, req.params.virtualId, req.get("x-client-ip"), packet, reply);
  res.json(reply);
});

// POST /v1/lunar/{server_id}/log - remote log lines (accepted).
app.post("/v1/lunar/:serverId/log", (req, res) => {
  const line = readJson(req);
  if (debug) {
    const level = (line.level || "info").toUpperCase();
    const message = line.message || "";
    console.log(`log ${req.params.serverId} [${level}] ${message}`);
  }
  res.sendStatus(201);
});

// GET /v1/lunar/ping - the health probe lunar's /v1/status hits.
app.get("/v1/lunar/ping", (req, res) => {
  res.sendStatus(200);
});

console.log("RADIUS backend listening on http://127.0.0.1:5555");
app.listen(5555, "127.0.0.1");

// --- Helpers ----------------------------------------------------------------

// Parse the request body as a JSON object; empty or malformed bodies become an
// empty object so a bad packet is a reject, never a 500.
function readJson(req) {
  const body = req.body;
  if (typeof body !== "string" || body.trim() === "") {
    return {};
  }
  try {
    const parsed = JSON.parse(body);
    return parsed !== null && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

// True when the attribute is present. Every attribute arrives as
// {"values": [...]}; presence alone tells us which credential method was used.
function has(attributes, name) {
  return attributes[name] != null;
}

// The first value of an attribute (null if absent). Values are always strings
// in the packet JSON (binary values are "0x" hex).
function firstValue(attributes, name) {
  const attribute = attributes[name];
  if (attribute && Array.isArray(attribute.values) && attribute.values.length > 0) {
    return attribute.values[0];
  }
  return null;
}

// Build an attribute value object: {"values": ["a", "b"]}.
function values(...items) {
  return { values: items };
}

// The shared accept/reject verdict used by PAP, CHAP and MS-CHAPv1: an unknown
// user is "user not found", a bad credential "invalid password", success an
// Access-Accept carrying the static Framed-IP-Address.
function decision(username, valid) {
  if (username !== USERNAME) {
    return accessReject("user not found");
  }
  return valid
    ? {
        code: "access-accept",
        attributes: { "Framed-IP-Address": values(FRAMED_IP) },
      }
    : accessReject("invalid password");
}

function accessReject(message) {
  return {
    code: "access-reject",
    attributes: { "Reply-Message": values(message) },
  };
}

// Decode a "0x"-prefixed hex string to bytes (empty for null/empty input).
function fromHex(value) {
  if (!value) {
    return Buffer.alloc(0);
  }
  if (value.startsWith("0x") || value.startsWith("0X")) {
    value = value.slice(2);
  }
  return Buffer.from(value, "hex");
}

// Encode bytes as lower-case hex (to match the packet JSON convention).
function toHex(buffer) {
  return buffer.toString("hex");
}

// Log an inbound packet and our reply as a readable, multi-line block.
// clientIp is the real source the packet arrived from (lunar's x-client-ip
// header); the NAS source IP is what the NAS reports in NAS-IP-Address.
function logExchange(kind, serverId, virtualId, clientIp, request, reply) {
  if (!debug) {
    return;
  }

  const requestAttributes = request.attributes || {};
  const nasIp = firstValue(requestAttributes, "nas-ip-address") || "-";

  console.log(
    `${kind} ${serverId}/${virtualId}\n` +
      `  client source ip: ${clientIp || "-"}\n` +
      `  nas source ip:    ${nasIp}\n` +
      `  in  (${request.code || "-"}):\n${render(requestAttributes)}\n` +
      `  out (${reply.code || "-"}):\n${render(reply.attributes)}`
  );
}

// Render every attribute as "    name = v1, v2", sorted by name.
function render(attributes) {
  if (!attributes || Object.keys(attributes).length === 0) {
    return "    (no attributes)";
  }

  const lines = Object.keys(attributes)
    .sort()
    .map((name) => {
      const attribute = attributes[name];
      const rendered =
        attribute && Array.isArray(attribute.values) && attribute.values.length > 0
          ? attribute.values.join(", ")
          : "(empty)";
      return `    ${name} = ${rendered}`;
    });
  return lines.join("\n");
}
