"""An example RADIUS backend for lunar, built with Falcon.

This implements the lunar backend API (the same endpoints
``lunar_backend_sim`` serves), but instead of mirroring attributes back it
performs REAL authentication and returns a single ``Framed-IP-Address``.
Point lunar's ``subscriber.endpoint`` at this server and lunar will:

1. fetch the ``TEST`` virtual (one NAS client, secret ``testing123``),
2. forward each Access-Request here, where we authenticate ``test`` /
   ``test`` over PAP, CHAP, MS-CHAPv1 or MS-CHAPv2,
3. reply Access-Accept with ``Framed-IP-Address = 192.168.50.50`` (or
   reject).

Accounting and CoA are acknowledged; the log and health endpoints are accepted.

Endpoints (see ``docs/subscriber/radius/api.rst``):

    GET  /v1/lunar/radius/{server_id}/virtuals          -> [ TEST virtual ]
    GET  /v1/lunar/radius/{server_id}/virtual/{id}      -> TEST virtual
    POST /v1/lunar/radius/{server_id}/auth/{virtual_id} -> accept / reject
    POST /v1/lunar/radius/{server_id}/acct/{virtual_id} -> accounting-response
    POST /v1/lunar/radius/{server_id}/coa/{virtual_id}  -> coa/disconnect-ack
    POST /v1/lunar/radius/{server_id}/log               -> 201 (accept + log)
    GET  /v1/lunar/radius/ping                          -> 200 (health probe)

Run it (from this directory) with ``python app.py`` and it listens on
127.0.0.1:5555. See README.rst for the full walk-through.

This is EXAMPLE code - a starting point to adapt, not a production backend.
"""

import json
import logging
import os
from datetime import datetime

import falcon

from auth import chap, mschap, mschapv2

# The only account this example knows about, and the static IP it hands out.
USERNAME = "test"
PASSWORD = "test"
FRAMED_IP_ADDRESS = "192.168.50.50"

# The one virtual RADIUS server this example serves to lunar: a "TEST" virtual
# on 127.0.0.1 with a single NAS client whose shared secret is "testing123".
# lunar fetches this at start-up and starts a RADIUS server from it.
TEST_VIRTUAL = {
    "id": "TEST",
    "domain": "test.local",
    "name": "test-virtual",
    "ip4_address": "127.0.0.1",
    "radius_auth_port": 1812,
    "radius_acct_port": 1813,
    "radius_coa_port": 3799,
    "clients": [
        {
            "id": "client-test",
            "name": "test-client",
            "type": "nas",
            "ip4_address": "127.0.0.1",
            "secret": "testing123",
            "profile": "default",
            "coa_port": 3799,
            "req_message_auth": False,
            "message_auth_reply": True,
        }
    ],
}

# run.py's --nodebug sets RADIUS_BACKEND_NODEBUG so we log only errors and
# above (ERROR, CRITICAL); otherwise we log everything from INFO up.
_LOG_LEVEL = (
    logging.ERROR if os.environ.get("RADIUS_BACKEND_NODEBUG")
    else logging.INFO
)
logging.basicConfig(level=_LOG_LEVEL, format="%(asctime)s %(message)s")
log = logging.getLogger("radius-backend")


def log_exchange(kind, server_id, virtual_id, client_ip, request, reply):
    """Log an inbound packet and our reply as a readable, multi-line block.

    ``client_ip`` is the real source the packet arrived from (lunar's
    ``x-client-ip`` header); the NAS source IP is what the NAS reports in its
    ``NAS-IP-Address`` attribute. Every attribute is shown as "name = value".
    """
    def render(attributes):
        if not attributes:
            return "    (no attributes)"
        lines = []
        for name in sorted(attributes):
            values = (attributes[name] or {}).get("values") or []
            value = ", ".join(str(v) for v in values) or "(empty)"
            lines.append(f"    {name} = {value}")
        return "\n".join(lines)

    request_attributes = request.get("attributes") or {}
    nas = request_attributes.get("nas-ip-address") or {}
    nas_ip = (nas.get("values") or ["-"])[0]

    log.info(
        "%s %s/%s\n"
        "  client source ip: %s\n"
        "  nas source ip:    %s\n"
        "  in  (%s):\n%s\n"
        "  out (%s):\n%s",
        kind,
        server_id,
        virtual_id,
        client_ip or "-",
        nas_ip,
        request.get("code", "-"),
        render(request_attributes),
        reply.get("code", "-"),
        render(reply.get("attributes") or {}),
    )


class VirtualsResource:
    """GET /v1/lunar/radius/{server_id}/virtuals - virtuals for a server."""

    def on_get(self, req, resp, server_id):
        resp.text = json.dumps([TEST_VIRTUAL])


class VirtualResource:
    """GET /v1/lunar/radius/{server_id}/virtual/{virtual_id} - one virtual."""

    def on_get(self, req, resp, server_id, virtual_id):
        resp.text = json.dumps(TEST_VIRTUAL)


class AuthResource:
    """POST /v1/lunar/radius/{server_id}/auth/{virtual_id} - an Access-Request.

    Answering a request happens in four steps, numbered in ``on_post`` below:
    (1) read the forwarded packet, (2) find the user name, (3) detect the
    credential method and verify it to build the reply, (4) answer lunar and
    log it. Each method has its own block so it is obvious what happens for it.
    """

    def on_post(self, req, resp, server_id, virtual_id):
        # 1. Read the forwarded packet. lunar decodes the RADIUS packet off
        #    the wire and POSTs it to us as JSON in the request body. Bad or
        #    empty JSON becomes a reject here, never a 500.
        try:
            packet = json.loads(req.bounded_stream.read() or b"{}")
        except ValueError:
            packet = {}

        # 2. Find the user name. Every attribute arrives as {"values": [...]};
        #    we take the first User-Name value (None if it was not sent).
        attributes = packet.get("attributes") or {}
        user_name = attributes.get("user-name") or {}
        user_values = user_name.get("values") or []
        username = user_values[0] if user_values else None

        # 3. Decide the reply. Which credential attribute is present tells us
        #    the method; each branch below verifies that one method and sets
        #    `reply` to an accept (with a Framed-IP-Address) or a reject.

        # No username: there is nobody to look up.
        if username is None:
            reply = {
                "code": "access-reject",
                "attributes": {
                    "Reply-Message": {"values": ["user not found"]},
                },
            }

        # PAP: lunar has already decrypted User-Password, so just compare it.
        elif "user-password" in attributes:
            supplied = attributes["user-password"]["values"][0]
            if username != USERNAME:
                reply = {
                    "code": "access-reject",
                    "attributes": {
                        "Reply-Message": {"values": ["user not found"]},
                    },
                }
            elif supplied == PASSWORD:
                reply = {
                    "code": "access-accept",
                    "attributes": {
                        "Framed-IP-Address": {"values": [FRAMED_IP_ADDRESS]},
                    },
                }
            else:
                reply = {
                    "code": "access-reject",
                    "attributes": {
                        "Reply-Message": {"values": ["invalid password"]},
                    },
                }

        # CHAP: the challenge is CHAP-Challenge, or the Request Authenticator
        # when that attribute is absent. Binary values arrive as "0x" hex, so
        # every value is sliced with [2:] to drop the leading "0x" -
        # bytes.fromhex() accepts only the hex digits, not the "0x" marker.
        elif "chap-password" in attributes:
            chap_password = bytes.fromhex(
                attributes["chap-password"]["values"][0][2:])
            if "chap-challenge" in attributes:
                challenge = bytes.fromhex(
                    attributes["chap-challenge"]["values"][0][2:])
            else:
                challenge = bytes.fromhex(packet["authenticator"][2:])
            valid = chap.verify(PASSWORD, chap_password, challenge)
            if username != USERNAME:
                reply = {
                    "code": "access-reject",
                    "attributes": {
                        "Reply-Message": {"values": ["user not found"]},
                    },
                }
            elif valid:
                reply = {
                    "code": "access-accept",
                    "attributes": {
                        "Framed-IP-Address": {"values": [FRAMED_IP_ADDRESS]},
                    },
                }
            else:
                reply = {
                    "code": "access-reject",
                    "attributes": {
                        "Reply-Message": {"values": ["invalid password"]},
                    },
                }

        # MS-CHAPv1: 8-byte challenge + 50-byte response. As with CHAP, [2:]
        # drops the "0x" prefix so bytes.fromhex() sees only the hex digits.
        elif "ms-chap-response" in attributes:
            challenge = bytes.fromhex(
                attributes["ms-chap-challenge"]["values"][0][2:])
            response = bytes.fromhex(
                attributes["ms-chap-response"]["values"][0][2:])
            valid = mschap.verify(PASSWORD, challenge, response)
            if username != USERNAME:
                reply = {
                    "code": "access-reject",
                    "attributes": {
                        "Reply-Message": {"values": ["user not found"]},
                    },
                }
            elif valid:
                reply = {
                    "code": "access-accept",
                    "attributes": {
                        "Framed-IP-Address": {"values": [FRAMED_IP_ADDRESS]},
                    },
                }
            else:
                reply = {
                    "code": "access-reject",
                    "attributes": {
                        "Reply-Message": {"values": ["invalid password"]},
                    },
                }

        # MS-CHAPv2: 16-byte challenge + 50-byte response. As above, [2:]
        # strips the "0x" prefix before bytes.fromhex(). On success we also
        # return MS-CHAP2-Success (mutual auth) and the MPPE keys.
        elif "ms-chap2-response" in attributes:
            challenge = bytes.fromhex(
                attributes["ms-chap-challenge"]["values"][0][2:])
            response = bytes.fromhex(
                attributes["ms-chap2-response"]["values"][0][2:])
            valid = mschapv2.verify(PASSWORD, username, challenge, response)
            if username != USERNAME:
                reply = {
                    "code": "access-reject",
                    "attributes": {
                        "Reply-Message": {"values": ["user not found"]},
                    },
                }
            elif valid:
                # The module gives us the raw bytes; we set the attributes
                # here. lunar salt-encrypts the MPPE keys on the wire.
                success, send_key, recv_key = mschapv2.success_and_keys(
                    PASSWORD, username, challenge, response)
                reply = {
                    "code": "access-accept",
                    "attributes": {
                        "Framed-IP-Address": {"values": [FRAMED_IP_ADDRESS]},
                        "MS-CHAP2-Success": {
                            "values": ["0x" + success.hex()]},
                        "MS-MPPE-Send-Key": {
                            "values": ["0x" + send_key.hex()]},
                        "MS-MPPE-Recv-Key": {
                            "values": ["0x" + recv_key.hex()]},
                    },
                }
            else:
                reply = {
                    "code": "access-reject",
                    "attributes": {
                        "Reply-Message": {"values": ["invalid password"]},
                    },
                }

        # No credential attribute we support.
        else:
            reply = {"code": "access-reject"}

        # 4. Answer lunar: serialise the reply as JSON in the response body,
        #    then log the request and reply for the demo.
        resp.text = json.dumps(reply)
        log_exchange("auth", server_id, virtual_id,
                     req.get_header("x-client-ip"), packet, reply)


class AcctResource:
    """POST /v1/lunar/radius/{server_id}/acct/{virtual_id} - an acct request.

    lunar fast-ACKs accounting to the NAS itself, so we just acknowledge it.
    """

    def on_post(self, req, resp, server_id, virtual_id):
        try:
            packet = json.loads(req.bounded_stream.read() or b"{}")
        except ValueError:
            packet = {}
        reply = {"code": "accounting-response", "attributes": {}}
        resp.text = json.dumps(reply)
        log_exchange("acct", server_id, virtual_id,
                     req.get_header("x-client-ip"), packet, reply)


class CoaResource:
    """POST /v1/lunar/radius/{server_id}/coa/{virtual_id} - CoA / Disconnect.

    Acknowledge with the reply that matches the request.
    """

    def on_post(self, req, resp, server_id, virtual_id):
        try:
            request_packet = json.loads(req.bounded_stream.read() or b"{}")
        except ValueError:
            request_packet = {}
        if request_packet.get("code") == "disconnect-request":
            reply = {"code": "disconnect-ack", "attributes": {}}
        else:
            reply = {"code": "coa-ack", "attributes": {}}
        resp.text = json.dumps(reply)
        log_exchange("coa", server_id, virtual_id,
                     req.get_header("x-client-ip"), request_packet, reply)


class LogResource:
    """POST /v1/lunar/radius/{server_id}/log - remote log lines (accepted)."""

    def on_post(self, req, resp, server_id):
        # lunar ships its subscriber log lines here as a JSON object; print
        # them in a readable form, then accept.
        body = req.bounded_stream.read()
        try:
            line = json.loads(body or b"{}")
        except ValueError:
            line = {}

        level = str(line.get("level", "info")).upper()
        message = line.get("message", body.decode("utf-8", "replace").strip())
        when = line.get("time")
        if isinstance(when, (int, float)):
            when = datetime.fromtimestamp(when).strftime("%Y-%m-%d %H:%M:%S")
        else:
            when = "-"

        # Show any extra top-level fields lunar attached (virtual_id,
        # client_ip, ...) apart from the reserved ones we print above.
        extra = {
            key: value
            for key, value in line.items()
            if key not in ("level", "message", "time")
        }
        details = "".join(f"\n    {key} = {value}"
                          for key, value in extra.items())

        log.info(
            "log %s [%s] %s%s\n    %s",
            server_id,
            level,
            when,
            details,
            message,
        )
        resp.status = falcon.HTTP_201


class PingResource:
    """GET /v1/lunar/radius/ping - the health probe lunar's /v1/status hits."""

    def on_get(self, req, resp):
        resp.status = falcon.HTTP_200


def create_app():
    """Build and return the Falcon WSGI application."""
    application = falcon.App()
    application.add_route(
        "/v1/lunar/radius/{server_id}/virtuals", VirtualsResource())
    application.add_route(
        "/v1/lunar/radius/{server_id}/virtual/{virtual_id}", VirtualResource())
    application.add_route(
        "/v1/lunar/radius/{server_id}/auth/{virtual_id}", AuthResource())
    application.add_route(
        "/v1/lunar/radius/{server_id}/acct/{virtual_id}", AcctResource())
    application.add_route(
        "/v1/lunar/radius/{server_id}/coa/{virtual_id}", CoaResource())
    application.add_route("/v1/lunar/radius/{server_id}/log", LogResource())
    application.add_route("/v1/lunar/radius/ping", PingResource())
    return application


# WSGI entry point (for gunicorn: ``gunicorn app:application``).
application = create_app()


if __name__ == "__main__":
    from wsgiref.simple_server import make_server

    host, port = "127.0.0.1", 5555
    log.info("RADIUS backend listening on http://%s:%d", host, port)
    with make_server(host, port, application) as httpd:
        httpd.serve_forever()
