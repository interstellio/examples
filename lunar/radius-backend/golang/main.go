// An example RADIUS backend for lunar, built with Go's standard net/http.
//
// This implements the lunar backend API (the same endpoints lunar_backend_sim
// serves), but instead of mirroring attributes back it performs REAL
// authentication and returns a single Framed-IP-Address. Point lunar's
// subscriber.endpoint at this server and lunar will:
//
//  1. fetch the TEST virtual (one NAS client, secret "testing123"),
//  2. forward each Access-Request here, where we authenticate test / test over
//     PAP, CHAP, MS-CHAPv1 or MS-CHAPv2,
//  3. reply Access-Accept with Framed-IP-Address = 192.168.50.50 (or reject).
//
// Accounting and CoA are acknowledged; the log and health endpoints are
// accepted.
//
// Endpoints (see docs/subscriber/radius/api.rst):
//
//	GET  /v1/lunar/radius/{server_id}/virtuals            -> [ TEST virtual ]
//	GET  /v1/lunar/radius/{server_id}/virtual/{id}        -> TEST virtual
//	POST /v1/lunar/radius/{server_id}/auth/{virtual_id}   -> access-accept / reject
//	POST /v1/lunar/radius/{server_id}/acct/{virtual_id}   -> accounting-response
//	POST /v1/lunar/radius/{server_id}/coa/{virtual_id}    -> coa-ack / disconnect-ack
//	POST /v1/lunar/radius/{server_id}/log                 -> 201 (accept + log)
//	GET  /v1/lunar/radius/ping                            -> 200 (health probe)
//
// Run it (from this directory) with "go run ." and it listens on
// 127.0.0.1:5555. See README.rst for the full walk-through.
//
// This is EXAMPLE code - a starting point to adapt, not a production backend.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"radius-backend/auth"
)

// The only account this example knows about, and the static IP it hands out.
const (
	username        = "test"
	password        = "test"
	framedIPAddress = "192.168.50.50"
)

// Attribute is one RADIUS attribute as lunar encodes it: a list of values.
type Attribute struct {
	Values []any `json:"values"`
}

// Packet is a forwarded RADIUS packet (and the shape of our JSON replies).
type Packet struct {
	Code          string               `json:"code"`
	Authenticator string               `json:"authenticator,omitempty"`
	Attributes    map[string]Attribute `json:"attributes"`
}

// Client is one NAS client inside a virtual.
type Client struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Type             string `json:"type"`
	IP4Address       string `json:"ip4_address"`
	Secret           string `json:"secret"`
	Profile          string `json:"profile"`
	CoaPort          int    `json:"coa_port"`
	ReqMessageAuth   bool   `json:"req_message_auth"`
	MessageAuthReply bool   `json:"message_auth_reply"`
}

// Virtual is one virtual RADIUS server lunar starts from our configuration.
type Virtual struct {
	ID             string   `json:"id"`
	Domain         string   `json:"domain"`
	Name           string   `json:"name"`
	IP4Address     string   `json:"ip4_address"`
	RadiusAuthPort int      `json:"radius_auth_port"`
	RadiusAcctPort int      `json:"radius_acct_port"`
	RadiusCoaPort  int      `json:"radius_coa_port"`
	Clients        []Client `json:"clients"`
}

// The one virtual RADIUS server this example serves to lunar: a "TEST" virtual
// on 127.0.0.1 with a single NAS client whose shared secret is "testing123".
// lunar fetches this at start-up and starts a RADIUS server from it.
var testVirtual = Virtual{
	ID:             "TEST",
	Domain:         "test.local",
	Name:           "test-virtual",
	IP4Address:     "127.0.0.1",
	RadiusAuthPort: 1812,
	RadiusAcctPort: 1813,
	RadiusCoaPort:  3799,
	Clients: []Client{
		{
			ID:               "client-test",
			Name:             "test-client",
			Type:             "nas",
			IP4Address:       "127.0.0.1",
			Secret:           "testing123",
			Profile:          "default",
			CoaPort:          3799,
			ReqMessageAuth:   false,
			MessageAuthReply: true,
		},
	},
}

// --nodebug (or RADIUS_BACKEND_NODEBUG) turns the per-exchange logging off so
// only the startup line is printed; otherwise every exchange is logged in full.
var debug = true

// logf writes a log line only when debug logging is on.
func logf(format string, args ...any) {
	if debug {
		log.Printf(format, args...)
	}
}

// accept builds an Access-Accept carrying the static Framed-IP-Address.
func accept() Packet {
	return Packet{
		Code: "access-accept",
		Attributes: map[string]Attribute{
			"Framed-IP-Address": {Values: []any{framedIPAddress}},
		},
	}
}

// reject builds an Access-Reject carrying a Reply-Message.
func reject(message string) Packet {
	return Packet{
		Code: "access-reject",
		Attributes: map[string]Attribute{
			"Reply-Message": {Values: []any{message}},
		},
	}
}

// passwordReply turns a verified/failed check into the matching reply: a
// user-not-found reject for an unknown user, otherwise accept or reject.
func passwordReply(user string, valid bool) Packet {
	switch {
	case user != username:
		return reject("user not found")
	case valid:
		return accept()
	default:
		return reject("invalid password")
	}
}

// readPacket decodes the forwarded packet from the request body. Bad or empty
// JSON becomes an empty packet here, never a 500.
func readPacket(r *http.Request) Packet {
	var packet Packet
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 {
		return Packet{}
	}
	if err := json.Unmarshal(body, &packet); err != nil {
		return Packet{}
	}
	return packet
}

// hasAttr reports whether attributes carries an attribute by name.
func hasAttr(attributes map[string]Attribute, name string) bool {
	_, ok := attributes[name]
	return ok
}

// firstValue returns the first value of an attribute as a string.
func firstValue(attributes map[string]Attribute, name string) (string, bool) {
	attribute, ok := attributes[name]
	if !ok || len(attribute.Values) == 0 {
		return "", false
	}
	value, ok := attribute.Values[0].(string)
	return value, ok
}

// hexValue decodes a "0x"-prefixed hex string into raw bytes. Binary attributes
// arrive as "0x" hex, so the prefix is dropped before decoding.
func hexValue(value string) []byte {
	raw, _ := hex.DecodeString(strings.TrimPrefix(value, "0x"))
	return raw
}

// writeJSON serialises v as the JSON response body.
func writeJSON(w http.ResponseWriter, v any) {
	body, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// renderAttributes formats attributes as sorted "name = value" lines for logs.
func renderAttributes(attributes map[string]Attribute) string {
	if len(attributes) == 0 {
		return "    (no attributes)"
	}
	names := make([]string, 0, len(attributes))
	for name := range attributes {
		names = append(names, name)
	}
	sort.Strings(names)

	lines := make([]string, 0, len(names))
	for _, name := range names {
		parts := make([]string, 0, len(attributes[name].Values))
		for _, value := range attributes[name].Values {
			parts = append(parts, fmt.Sprintf("%v", value))
		}
		value := strings.Join(parts, ", ")
		if value == "" {
			value = "(empty)"
		}
		lines = append(lines, fmt.Sprintf("    %s = %s", name, value))
	}
	return strings.Join(lines, "\n")
}

// logExchange logs an inbound packet and our reply as a readable, multi-line
// block. clientIP is the real source the packet arrived from (lunar's
// x-client-ip header); the NAS source IP is what the NAS reports in its
// NAS-IP-Address attribute.
func logExchange(kind, serverID, virtualID, clientIP string, request, reply Packet) {
	nasIP := "-"
	if value, ok := firstValue(request.Attributes, "nas-ip-address"); ok {
		nasIP = value
	}
	if clientIP == "" {
		clientIP = "-"
	}
	requestCode := request.Code
	if requestCode == "" {
		requestCode = "-"
	}
	replyCode := reply.Code
	if replyCode == "" {
		replyCode = "-"
	}

	logf(
		"%s %s/%s\n"+
			"  client source ip: %s\n"+
			"  nas source ip:    %s\n"+
			"  in  (%s):\n%s\n"+
			"  out (%s):\n%s",
		kind, serverID, virtualID, clientIP, nasIP,
		requestCode, renderAttributes(request.Attributes),
		replyCode, renderAttributes(reply.Attributes),
	)
}

// handleVirtuals answers GET /v1/lunar/radius/{server_id}/virtuals.
func handleVirtuals(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, []Virtual{testVirtual})
}

// handleVirtual answers GET /v1/lunar/radius/{server_id}/virtual/{virtual_id}.
func handleVirtual(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, testVirtual)
}

// handleAuth answers POST /v1/lunar/radius/{server_id}/auth/{virtual_id}, an
// Access-Request.
//
// Answering a request happens in four steps, numbered below: (1) read the
// forwarded packet, (2) find the user name, (3) detect the credential method
// and verify it to build the reply, (4) answer lunar and log it. Each method
// has its own block so it is obvious what happens for it.
func handleAuth(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	virtualID := r.PathValue("virtual_id")

	// 1. Read the forwarded packet. lunar decodes the RADIUS packet off the
	//    wire and POSTs it to us as JSON in the request body.
	packet := readPacket(r)

	// 2. Find the user name. Every attribute arrives as {"values": [...]}; we
	//    take the first User-Name value (missing if it was not sent).
	attributes := packet.Attributes
	user, hasUser := firstValue(attributes, "user-name")

	// 3. Decide the reply. Which credential attribute is present tells us the
	//    method; each branch below verifies that one method and sets reply to
	//    an accept (with a Framed-IP-Address) or a reject.
	var reply Packet
	switch {
	// No username: there is nobody to look up.
	case !hasUser:
		reply = reject("user not found")

	// PAP: lunar has already decrypted User-Password, so just compare it.
	case hasAttr(attributes, "user-password"):
		supplied, _ := firstValue(attributes, "user-password")
		reply = passwordReply(user, supplied == password)

	// CHAP: the challenge is CHAP-Challenge, or the Request Authenticator when
	// that attribute is absent.
	case hasAttr(attributes, "chap-password"):
		chapPasswordValue, _ := firstValue(attributes, "chap-password")
		chapPassword := hexValue(chapPasswordValue)
		var challenge []byte
		if hasAttr(attributes, "chap-challenge") {
			challengeValue, _ := firstValue(attributes, "chap-challenge")
			challenge = hexValue(challengeValue)
		} else {
			challenge = hexValue(packet.Authenticator)
		}
		valid := auth.VerifyCHAP(password, chapPassword, challenge)
		reply = passwordReply(user, valid)

	// MS-CHAPv1: 8-byte challenge + 50-byte response.
	case hasAttr(attributes, "ms-chap-response"):
		challengeValue, _ := firstValue(attributes, "ms-chap-challenge")
		responseValue, _ := firstValue(attributes, "ms-chap-response")
		valid := auth.VerifyMSCHAP(password, hexValue(challengeValue), hexValue(responseValue))
		reply = passwordReply(user, valid)

	// MS-CHAPv2: 16-byte challenge + 50-byte response. On success we also
	// return MS-CHAP2-Success (mutual auth) and the MPPE keys.
	case hasAttr(attributes, "ms-chap2-response"):
		challengeValue, _ := firstValue(attributes, "ms-chap-challenge")
		responseValue, _ := firstValue(attributes, "ms-chap2-response")
		challenge := hexValue(challengeValue)
		response := hexValue(responseValue)
		valid := auth.VerifyMSCHAPv2(password, user, challenge, response)
		switch {
		case user != username:
			reply = reject("user not found")
		case valid:
			// The module gives us the raw bytes; we set the attributes here.
			// lunar salt-encrypts the MPPE keys on the wire.
			success, sendKey, recvKey := auth.SuccessAndKeys(password, user, challenge, response)
			reply = Packet{
				Code: "access-accept",
				Attributes: map[string]Attribute{
					"Framed-IP-Address": {Values: []any{framedIPAddress}},
					"MS-CHAP2-Success":  {Values: []any{"0x" + hex.EncodeToString(success)}},
					"MS-MPPE-Send-Key":  {Values: []any{"0x" + hex.EncodeToString(sendKey)}},
					"MS-MPPE-Recv-Key":  {Values: []any{"0x" + hex.EncodeToString(recvKey)}},
				},
			}
		default:
			reply = reject("invalid password")
		}

	// No credential attribute we support.
	default:
		reply = Packet{Code: "access-reject", Attributes: map[string]Attribute{}}
	}

	// 4. Answer lunar: serialise the reply as JSON in the response body, then
	//    log the request and reply for the demo.
	logExchange("auth", serverID, virtualID, r.Header.Get("x-client-ip"), packet, reply)
	writeJSON(w, reply)
}

// handleAcct answers POST /v1/lunar/radius/{server_id}/acct/{virtual_id}, an
// Accounting-Request. lunar fast-ACKs accounting to the NAS itself, so we just
// acknowledge it.
func handleAcct(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	virtualID := r.PathValue("virtual_id")
	packet := readPacket(r)
	reply := Packet{Code: "accounting-response", Attributes: map[string]Attribute{}}
	logExchange("acct", serverID, virtualID, r.Header.Get("x-client-ip"), packet, reply)
	writeJSON(w, reply)
}

// handleCoa answers POST /v1/lunar/radius/{server_id}/coa/{virtual_id}, a CoA or
// Disconnect. Acknowledge with the reply that matches the request.
func handleCoa(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	virtualID := r.PathValue("virtual_id")
	packet := readPacket(r)
	var reply Packet
	if packet.Code == "disconnect-request" {
		reply = Packet{Code: "disconnect-ack", Attributes: map[string]Attribute{}}
	} else {
		reply = Packet{Code: "coa-ack", Attributes: map[string]Attribute{}}
	}
	logExchange("coa", serverID, virtualID, r.Header.Get("x-client-ip"), packet, reply)
	writeJSON(w, reply)
}

// handleLog answers POST /v1/lunar/radius/{server_id}/log, remote log lines (accepted).
func handleLog(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")

	// lunar ships its subscriber log lines here as a JSON object; print them in
	// a readable form, then accept.
	body, _ := io.ReadAll(r.Body)
	var line map[string]any
	if err := json.Unmarshal(body, &line); err != nil {
		line = map[string]any{}
	}

	level := "INFO"
	if value, ok := line["level"]; ok {
		level = strings.ToUpper(fmt.Sprintf("%v", value))
	}
	message := strings.TrimSpace(string(body))
	if value, ok := line["message"]; ok {
		message = fmt.Sprintf("%v", value)
	}
	when := "-"
	if value, ok := line["time"].(float64); ok {
		when = time.Unix(int64(value), 0).Format("2006-01-02 15:04:05")
	}

	// Show any extra top-level fields lunar attached (virtual_id, client_ip,
	// ...) apart from the reserved ones we print above.
	keys := make([]string, 0, len(line))
	for key := range line {
		if key == "level" || key == "message" || key == "time" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var details strings.Builder
	for _, key := range keys {
		fmt.Fprintf(&details, "\n    %s = %v", key, line[key])
	}

	logf("log %s [%s] %s%s\n    %s", serverID, level, when, details.String(), message)
	w.WriteHeader(http.StatusCreated)
}

// handlePing answers GET /v1/lunar/radius/ping, the health probe lunar's /v1/status
// hits.
func handlePing(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// hasFlag reports whether the process was started with the given argument.
func hasFlag(name string) bool {
	for _, arg := range os.Args[1:] {
		if arg == name {
			return true
		}
	}
	return false
}

func main() {
	if hasFlag("--nodebug") || os.Getenv("RADIUS_BACKEND_NODEBUG") != "" {
		debug = false
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/lunar/radius/{server_id}/virtuals", handleVirtuals)
	mux.HandleFunc("GET /v1/lunar/radius/{server_id}/virtual/{virtual_id}", handleVirtual)
	mux.HandleFunc("POST /v1/lunar/radius/{server_id}/auth/{virtual_id}", handleAuth)
	mux.HandleFunc("POST /v1/lunar/radius/{server_id}/acct/{virtual_id}", handleAcct)
	mux.HandleFunc("POST /v1/lunar/radius/{server_id}/coa/{virtual_id}", handleCoa)
	mux.HandleFunc("POST /v1/lunar/radius/{server_id}/log", handleLog)
	mux.HandleFunc("GET /v1/lunar/radius/ping", handlePing)

	addr := "127.0.0.1:5555"

	// Use an explicit http.Server so we can set timeouts. Leaving them unset
	// (as http.ListenAndServe does) lets a slow or idle client hold a
	// connection open indefinitely; these bounds guard against that.
	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	fmt.Printf("RADIUS backend listening on http://%s\n", addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
