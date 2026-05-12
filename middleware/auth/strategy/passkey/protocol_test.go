package passkey

import (
	"strings"
	"testing"
)

// TestVerifyClientData_TolerantOfUnknownFields locks in WebAuthn §5.8.1
// compliance: the RP MUST ignore unrecognized members of clientDataJSON
// so the format can be extended without breaking existing servers.
// The spec even seeds the structure with a placeholder key named
// "other_keys_can_be_added_here" precisely as a trap for implementers
// who reach for strict template matching — a previous version of this
// file used json.Decoder.DisallowUnknownFields() and rejected real
// authenticator output that included this literal key, plus legacy
// "tokenBinding" members.
//
// We assert two things here:
//  1. A clientDataJSON containing the spec's literal placeholder
//     decodes successfully (no "unknown field" error).
//  2. A clientDataJSON containing the legacy tokenBinding member
//     decodes successfully too.
//
// Both inputs pass the type/challenge/origin checks so the only thing
// being exercised is the leniency of the JSON parse step.
func TestVerifyClientData_TolerantOfUnknownFields(t *testing.T) {
	challenge := []byte("test-challenge-bytes")
	challengeB64 := encodeBase64URL(challenge)
	origin := "http://localhost"

	cases := []struct {
		name string
		raw  string
	}{
		{
			// The literal field name the W3C example clientDataJSON uses
			// as a trap. Some real-world authenticators (notably some
			// mobile password managers and virtual-authenticator browser
			// extensions) emit this verbatim. Strict template matching
			// blows up here; the spec mandates we ignore it.
			name: "spec placeholder other_keys_can_be_added_here",
			raw: `{"type":"webauthn.create","challenge":"` + challengeB64 +
				`","origin":"` + origin + `","other_keys_can_be_added_here":` +
				`"do not compare clientDataJSON against a template"}`,
		},
		{
			// Legacy member that older Chrome / Edge builds emit. Removed
			// in modern browsers but still legal on the wire.
			name: "legacy tokenBinding member",
			raw: `{"type":"webauthn.create","challenge":"` + challengeB64 +
				`","origin":"` + origin + `","tokenBinding":{"status":"supported"}}`,
		},
		{
			// Forward-compat smoke test: arbitrary nested member should
			// not break parsing.
			name: "arbitrary future nested member",
			raw: `{"type":"webauthn.create","challenge":"` + challengeB64 +
				`","origin":"` + origin + `","futureExtension":{"a":[1,2,3]}}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := verifyClientData([]byte(tc.raw), clientDataTypeCreate, challenge, []string{origin})
			if err != nil {
				t.Fatalf("expected unknown fields to be ignored; got error: %v", err)
			}
		})
	}
}

// TestVerifyClientData_RejectsMalformedJSON makes sure removing the
// strict-mode guard didn't accidentally turn the decoder into a no-op.
// Genuinely malformed input must still error out with the
// "client data: parse json" prefix the caller relies on.
func TestVerifyClientData_RejectsMalformedJSON(t *testing.T) {
	_, err := verifyClientData([]byte(`{not json`), clientDataTypeCreate, []byte("c"), []string{"http://localhost"})
	if err == nil {
		t.Fatal("expected error on malformed JSON, got nil")
	}
	if !strings.HasPrefix(err.Error(), "client data: parse json") {
		t.Fatalf("expected parse-json error prefix, got %q", err.Error())
	}
}

// TestVerifyClientData_RejectsTrailingContent locks the
// dec.More() check: a clientDataJSON blob is a single JSON value,
// any trailing tokens are suspicious (could indicate smuggled
// content) and must be rejected.
func TestVerifyClientData_RejectsTrailingContent(t *testing.T) {
	challenge := []byte("test-challenge-bytes")
	challengeB64 := encodeBase64URL(challenge)
	raw := `{"type":"webauthn.create","challenge":"` + challengeB64 +
		`","origin":"http://localhost"}{"extra":true}`

	_, err := verifyClientData([]byte(raw), clientDataTypeCreate, challenge, []string{"http://localhost"})
	if err == nil {
		t.Fatal("expected error on trailing content, got nil")
	}
	if !strings.Contains(err.Error(), "trailing content") {
		t.Fatalf("expected trailing-content error, got %q", err.Error())
	}
}
