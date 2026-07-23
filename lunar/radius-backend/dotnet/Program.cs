// An example RADIUS backend for lunar, built with ASP.NET Core minimal APIs.
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
// Run it (from this directory) with `dotnet run`; it listens on 127.0.0.1:5555.
// Pass `--nodebug` to quiet the per-exchange logging. See README.rst for the
// full walk-through.
//
// This is EXAMPLE code - a starting point to adapt, not a production backend.

using System.Text.Json.Nodes;
using RadiusBackend.Auth;

// The only account this example knows about, and the static IP it hands out.
const string Username = "test";
const string Password = "test";
const string FramedIp = "192.168.50.50";

// The one virtual RADIUS server this example serves to lunar: a "TEST" virtual
// on 127.0.0.1 with a single NAS client whose shared secret is "testing123".
// lunar fetches this at start-up and starts a RADIUS server from it. It is kept
// as a verbatim JSON string so the exact field names (server-side snake_case)
// are guaranteed regardless of C# naming conventions.
const string TestVirtualJson = """
{
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
      "req_message_auth": false,
      "message_auth_reply": true
    }
  ]
}
""";

// `dotnet run -- --nodebug` (or the RADIUS_BACKEND_NODEBUG env var) turns off
// the per-exchange, human-formatted logging - the slowest thing this example
// does. On by default so you can watch exactly what lunar sends.
var debug = !(args.Contains("--nodebug")
              || Environment.GetEnvironmentVariable("RADIUS_BACKEND_NODEBUG") != null);

var builder = WebApplication.CreateBuilder(args);
// We do our own readable Console logging below, so silence the framework's.
builder.Logging.ClearProviders();
var app = builder.Build();

// --- Configuration endpoints (what lunar fetches at start-up) --------------

// GET /v1/lunar/{server_id}/virtuals - list virtuals for a server.
app.MapGet("/v1/lunar/{serverId}/virtuals",
    (string serverId) => Results.Text("[" + TestVirtualJson + "]", "application/json"));

// GET /v1/lunar/{server_id}/virtual/{virtual_id} - one virtual by id.
app.MapGet("/v1/lunar/{serverId}/virtual/{virtualId}",
    (string serverId, string virtualId) => Results.Text(TestVirtualJson, "application/json"));

// --- Authentication ---------------------------------------------------------

// POST /v1/lunar/{server_id}/auth/{virtual_id} - an Access-Request.
//
// Answering a request happens in four steps: (1) read the forwarded packet,
// (2) find the user name, (3) detect the credential method and verify it to
// build the reply, (4) answer lunar and log it.
app.MapPost("/v1/lunar/{serverId}/auth/{virtualId}",
    async (string serverId, string virtualId, HttpRequest request) =>
{
    // 1. Read the forwarded packet. lunar decodes the RADIUS packet off the
    //    wire and POSTs it to us as JSON. Bad or empty JSON becomes a reject
    //    here, never a 500.
    var packet = await ReadJson(request);
    var attributes = packet["attributes"] as JsonObject;

    // 2. Find the user name (the first User-Name value, or null).
    var username = FirstValue(attributes, "user-name");

    // 3. Decide the reply. Which credential attribute is present tells us the
    //    method; each branch verifies that one method.
    JsonObject reply;
    if (username is null)
    {
        // No username: there is nobody to look up.
        reply = AccessReject("user not found");
    }
    else if (Has(attributes, "user-password"))
    {
        // PAP: lunar has already decrypted User-Password, so just compare it.
        var supplied = FirstValue(attributes, "user-password");
        reply = Decision(username, supplied == Password);
    }
    else if (Has(attributes, "chap-password"))
    {
        // CHAP: the challenge is CHAP-Challenge, or the Request Authenticator
        // when that attribute is absent.
        var chapPassword = FromHex(FirstValue(attributes, "chap-password"));
        var challenge = Has(attributes, "chap-challenge")
            ? FromHex(FirstValue(attributes, "chap-challenge"))
            : FromHex(packet["authenticator"]?.GetValue<string>());
        reply = Decision(username, Chap.Verify(Password, chapPassword, challenge));
    }
    else if (Has(attributes, "ms-chap-response"))
    {
        // MS-CHAPv1: 8-byte challenge + 50-byte response.
        var challenge = FromHex(FirstValue(attributes, "ms-chap-challenge"));
        var response = FromHex(FirstValue(attributes, "ms-chap-response"));
        reply = Decision(username, MsChap.Verify(Password, challenge, response));
    }
    else if (Has(attributes, "ms-chap2-response"))
    {
        // MS-CHAPv2: 16-byte challenge + 50-byte response. On success we also
        // return MS-CHAP2-Success (mutual auth) and the MPPE keys.
        var challenge = FromHex(FirstValue(attributes, "ms-chap-challenge"));
        var response = FromHex(FirstValue(attributes, "ms-chap2-response"));
        var valid = MsChapV2.Verify(Password, username, challenge, response);
        if (username != Username)
        {
            reply = AccessReject("user not found");
        }
        else if (valid)
        {
            var (success, sendKey, recvKey) =
                MsChapV2.SuccessAndKeys(Password, username, challenge, response);
            reply = new JsonObject
            {
                ["code"] = "access-accept",
                ["attributes"] = new JsonObject
                {
                    ["Framed-IP-Address"] = Values(FramedIp),
                    ["MS-CHAP2-Success"] = Values("0x" + ToHex(success)),
                    ["MS-MPPE-Send-Key"] = Values("0x" + ToHex(sendKey)),
                    ["MS-MPPE-Recv-Key"] = Values("0x" + ToHex(recvKey)),
                },
            };
        }
        else
        {
            reply = AccessReject("invalid password");
        }
    }
    else
    {
        // No credential attribute we support.
        reply = new JsonObject { ["code"] = "access-reject" };
    }

    // 4. Answer lunar, and log the exchange for the demo.
    LogExchange("auth", serverId, virtualId, request.Headers["x-client-ip"], packet, reply);
    return Results.Text(reply.ToJsonString(), "application/json");
});

// --- Accounting, CoA, log, health ------------------------------------------

// POST /v1/lunar/{server_id}/acct/{virtual_id} - an Accounting-Request.
// lunar fast-ACKs accounting to the NAS itself, so we just acknowledge it.
app.MapPost("/v1/lunar/{serverId}/acct/{virtualId}",
    async (string serverId, string virtualId, HttpRequest request) =>
{
    var packet = await ReadJson(request);
    var reply = new JsonObject { ["code"] = "accounting-response", ["attributes"] = new JsonObject() };
    LogExchange("acct", serverId, virtualId, request.Headers["x-client-ip"], packet, reply);
    return Results.Text(reply.ToJsonString(), "application/json");
});

// POST /v1/lunar/{server_id}/coa/{virtual_id} - CoA / Disconnect.
// Acknowledge with the reply that matches the request.
app.MapPost("/v1/lunar/{serverId}/coa/{virtualId}",
    async (string serverId, string virtualId, HttpRequest request) =>
{
    var packet = await ReadJson(request);
    var code = packet["code"]?.GetValue<string>() == "disconnect-request"
        ? "disconnect-ack"
        : "coa-ack";
    var reply = new JsonObject { ["code"] = code, ["attributes"] = new JsonObject() };
    LogExchange("coa", serverId, virtualId, request.Headers["x-client-ip"], packet, reply);
    return Results.Text(reply.ToJsonString(), "application/json");
});

// POST /v1/lunar/{server_id}/log - remote log lines (accepted).
app.MapPost("/v1/lunar/{serverId}/log",
    async (string serverId, HttpRequest request) =>
{
    var line = await ReadJson(request);
    if (debug)
    {
        var level = (line["level"]?.GetValue<string>() ?? "info").ToUpperInvariant();
        var message = line["message"]?.GetValue<string>() ?? "";
        Console.WriteLine($"log {serverId} [{level}] {message}");
    }
    return Results.StatusCode(201);
});

// GET /v1/lunar/ping - the health probe lunar's /v1/status hits.
app.MapGet("/v1/lunar/ping", () => Results.StatusCode(200));

Console.WriteLine("RADIUS backend listening on http://127.0.0.1:5555");
app.Run("http://127.0.0.1:5555");

// --- Helpers ----------------------------------------------------------------

// Read the request body as a JSON object; empty or malformed bodies become an
// empty object so a bad packet is a reject, never a 500.
async Task<JsonObject> ReadJson(HttpRequest request)
{
    using var reader = new StreamReader(request.Body);
    var body = await reader.ReadToEndAsync();
    if (string.IsNullOrWhiteSpace(body))
    {
        return new JsonObject();
    }
    try
    {
        return JsonNode.Parse(body) as JsonObject ?? new JsonObject();
    }
    catch (System.Text.Json.JsonException)
    {
        return new JsonObject();
    }
}

// True when the attribute is present. Every attribute arrives as
// {"values": [...]}; presence alone tells us which credential method was used.
static bool Has(JsonObject? attributes, string name) => attributes?[name] is not null;

// The first value of an attribute (null if absent). Values are always strings
// in the packet JSON (binary values are "0x" hex).
static string? FirstValue(JsonObject? attributes, string name)
{
    if (attributes?[name]?["values"] is JsonArray values && values.Count > 0)
    {
        return values[0]?.GetValue<string>();
    }
    return null;
}

// Build an attribute value object: {"values": ["a", "b"]}.
static JsonObject Values(params string[] items)
{
    var array = new JsonArray();
    foreach (var item in items)
    {
        array.Add(item);
    }
    return new JsonObject { ["values"] = array };
}

// The shared accept/reject verdict used by PAP, CHAP and MS-CHAPv1: an unknown
// user is "user not found", a bad credential "invalid password", success an
// Access-Accept carrying the static Framed-IP-Address.
JsonObject Decision(string username, bool valid)
{
    if (username != Username)
    {
        return AccessReject("user not found");
    }
    return valid
        ? new JsonObject
        {
            ["code"] = "access-accept",
            ["attributes"] = new JsonObject { ["Framed-IP-Address"] = Values(FramedIp) },
        }
        : AccessReject("invalid password");
}

static JsonObject AccessReject(string message) => new()
{
    ["code"] = "access-reject",
    ["attributes"] = new JsonObject { ["Reply-Message"] = Values(message) },
};

// Decode a "0x"-prefixed hex string to bytes (empty for null/empty input).
static byte[] FromHex(string? value)
{
    if (string.IsNullOrEmpty(value))
    {
        return Array.Empty<byte>();
    }
    if (value.StartsWith("0x") || value.StartsWith("0X"))
    {
        value = value[2..];
    }
    return Convert.FromHexString(value);
}

// Encode bytes as lower-case hex (to match the packet JSON convention).
static string ToHex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

// Log an inbound packet and our reply as a readable, multi-line block.
// client_ip is the real source the packet arrived from (lunar's x-client-ip
// header); the NAS source IP is what the NAS reports in NAS-IP-Address.
void LogExchange(string kind, string serverId, string virtualId,
    string? clientIp, JsonObject request, JsonObject reply)
{
    if (!debug)
    {
        return;
    }

    var requestAttributes = request["attributes"] as JsonObject;
    var nasIp = FirstValue(requestAttributes, "nas-ip-address") ?? "-";

    Console.WriteLine(
        $"{kind} {serverId}/{virtualId}\n" +
        $"  client source ip: {(string.IsNullOrEmpty(clientIp) ? "-" : clientIp)}\n" +
        $"  nas source ip:    {nasIp}\n" +
        $"  in  ({request["code"]?.GetValue<string>() ?? "-"}):\n{Render(requestAttributes)}\n" +
        $"  out ({reply["code"]?.GetValue<string>() ?? "-"}):\n{Render(reply["attributes"] as JsonObject)}");
}

// Render every attribute as "    name = v1, v2", sorted by name.
static string Render(JsonObject? attributes)
{
    if (attributes is null || attributes.Count == 0)
    {
        return "    (no attributes)";
    }

    var lines = new List<string>();
    foreach (var name in attributes.Select(pair => pair.Key).OrderBy(name => name))
    {
        var values = attributes[name]?["values"] as JsonArray;
        var rendered = values is { Count: > 0 }
            ? string.Join(", ", values.Select(value => value?.ToString()))
            : "(empty)";
        lines.Add($"    {name} = {rendered}");
    }
    return string.Join("\n", lines);
}
