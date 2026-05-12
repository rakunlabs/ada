package passkey

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
)

// attestationObject is the CBOR-encoded blob the authenticator returns
// at the end of a registration ceremony. Layout (WebAuthn §6.5.4):
//
//	{
//	  "fmt":      tstr,          // attestation format identifier
//	  "authData": bstr,          // raw authenticator data
//	  "attStmt":  map { ... }    // format-specific signature/cert bundle
//	}
type attestationObject struct {
	Fmt      string
	AuthData []byte
	AttStmt  map[any]any
}

// parseAttestationObject decodes the top-level CBOR shape. Errors at
// this level mean the authenticator produced garbage; we surface a
// generic message because no useful client-side action depends on
// the detail.
func parseAttestationObject(blob []byte) (*attestationObject, error) {
	v, n, err := decodeCBOR(blob)
	if err != nil {
		return nil, fmt.Errorf("attestation object: cbor: %w", err)
	}
	if n != len(blob) {
		return nil, errors.New("attestation object: trailing bytes")
	}
	m, ok := cborMap(v)
	if !ok {
		return nil, errors.New("attestation object: not a map")
	}

	fmtStr, err := mapStringField(m, "fmt")
	if err != nil {
		return nil, fmt.Errorf("attestation object: %w", err)
	}
	authData, err := mapBytesField(m, "authData")
	if err != nil {
		return nil, fmt.Errorf("attestation object: %w", err)
	}
	attRaw, ok := m["attStmt"]
	if !ok {
		return nil, errors.New("attestation object: missing attStmt")
	}
	attStmt, ok := cborMap(attRaw)
	if !ok {
		return nil, errors.New("attestation object: attStmt not a map")
	}

	return &attestationObject{Fmt: fmtStr, AuthData: authData, AttStmt: attStmt}, nil
}

// mapStringField / mapBytesField are small typed helpers for the
// string-keyed top-level attestation map. (cose.go's mapInt/mapBytes
// work on int-keyed COSE maps; the keys are different so we have
// dedicated helpers here to keep things obvious.)
func mapStringField(m map[any]any, key string) (string, error) {
	v, ok := m[key]
	if !ok {
		return "", fmt.Errorf("missing %q", key)
	}
	s, ok := cborString(v)
	if !ok {
		return "", fmt.Errorf("%q is not a string", key)
	}
	return s, nil
}

func mapBytesField(m map[any]any, key string) ([]byte, error) {
	v, ok := m[key]
	if !ok {
		return nil, fmt.Errorf("missing %q", key)
	}
	b, ok := cborBytes(v)
	if !ok {
		return nil, fmt.Errorf("%q is not a byte string", key)
	}
	return b, nil
}

// AttestationResult summarizes what the verifier learned about the
// attestation. AttestationType describes the trust model the
// authenticator claims:
//
//   - "none": no attestation; the authenticator declined to identify
//     itself. This is what platform authenticators (Windows Hello,
//     iCloud Keychain, Android Keystore) emit in practice and is
//     perfectly fine for passkey use cases.
//   - "self": the credential public key signs the attestation
//     statement itself; common for older YubiKeys in "packed" format
//     when no attestation certificate is included.
//   - "basic": a manufacturer-supplied certificate chain signs the
//     statement; lets the RP verify the device model via AAGUID.
//
// Callers that want to enforce attestation policy (e.g. "only allow
// FIDO-certified hardware keys") branch on these values. Pika does
// not enforce any policy today.
type AttestationResult struct {
	Format          string
	AttestationType string
}

// verifyAttestation dispatches to the format-specific verifier. The
// clientDataHash is the SHA-256 of the raw clientDataJSON computed
// by verifyClientData. The signed message format varies per
// attestation type — none/packed concatenate authData and
// clientDataHash, but other formats (tpm, android-key, ...) use
// different constructions.
//
// Returns the parsed authenticator data (so the caller doesn't have
// to re-parse it) and the trust summary. An unknown attestation
// format yields an error; we deliberately do NOT fall through to
// "treat as none" — silently accepting an unrecognized attStmt
// shape could let a malicious authenticator smuggle data past
// verification.
func verifyAttestation(obj *attestationObject, clientDataHash [32]byte) (*authenticatorData, *AttestationResult, error) {
	ad, err := parseAuthenticatorData(obj.AuthData)
	if err != nil {
		return nil, nil, err
	}
	if ad.AttestedCredential == nil {
		// Registration response MUST carry attested credential data.
		// Its absence is a protocol violation, not a corner case.
		return nil, nil, errors.New("attestation: authenticator data lacks attested credential data")
	}

	switch obj.Fmt {
	case "none":
		res, err := verifyNone(obj.AttStmt)
		return ad, res, err
	case "packed":
		res, err := verifyPacked(obj, ad, clientDataHash)
		return ad, res, err
	default:
		// Listing the supported formats makes operator debugging
		// faster — they immediately know whether to file a feature
		// request or chase a transport bug.
		return nil, nil, fmt.Errorf("attestation: format %q not supported (supported: none, packed)", obj.Fmt)
	}
}

// verifyNone handles the trivial "no attestation" format. The
// authenticator MUST send an empty attStmt map; anything else is a
// protocol violation worth rejecting because some clients used to
// stuff extension data into attStmt by mistake.
func verifyNone(attStmt map[any]any) (*AttestationResult, error) {
	if len(attStmt) != 0 {
		return nil, errors.New("attestation 'none': attStmt must be empty")
	}
	return &AttestationResult{Format: "none", AttestationType: "none"}, nil
}

// verifyPacked implements the packed attestation format (WebAuthn
// §8.2). attStmt shape:
//
//	{
//	  "alg":  int,            // COSE alg used to sign
//	  "sig":  bstr,           // signature over authData || clientDataHash
//	  "x5c":  [bstr+]?,       // optional X.509 cert chain
//	  "ecdaaKeyId": bstr?     // optional ECDAA key id (rare, we reject)
//	}
//
// We handle two of the three sub-cases:
//
//   - With x5c: "basic" attestation. The first certificate's public
//     key verifies the signature. We do NOT validate the chain
//     against a trust anchor today — adding MDS support is a
//     follow-up.
//   - Without x5c, without ecdaaKeyId: "self" attestation. The
//     credential's own public key (from authData.attestedCredentialData)
//     verifies the signature.
//   - With ecdaaKeyId: ECDAA, deprecated and never deployed at scale.
//     Rejected.
func verifyPacked(obj *attestationObject, ad *authenticatorData, clientDataHash [32]byte) (*AttestationResult, error) {
	algRaw, ok := obj.AttStmt["alg"]
	if !ok {
		return nil, errors.New("attestation 'packed': missing alg")
	}
	algBig, ok := cborInt(algRaw)
	if !ok {
		return nil, errors.New("attestation 'packed': alg not an integer")
	}
	alg := int(algBig)

	sig, err := mapBytesField(obj.AttStmt, "sig")
	if err != nil {
		return nil, fmt.Errorf("attestation 'packed': %w", err)
	}

	if _, present := obj.AttStmt["ecdaaKeyId"]; present {
		return nil, errors.New("attestation 'packed': ECDAA not supported")
	}

	// The signed message is authData ‖ clientDataHash. The
	// authenticator data already lives on the object as a verbatim
	// blob, so we just concatenate.
	signedMessage := make([]byte, 0, len(obj.AuthData)+len(clientDataHash))
	signedMessage = append(signedMessage, obj.AuthData...)
	signedMessage = append(signedMessage, clientDataHash[:]...)

	// Decide between "basic" (x5c present) and "self" (absent).
	if x5cRaw, hasX5c := obj.AttStmt["x5c"]; hasX5c {
		return verifyPackedBasic(alg, x5cRaw, signedMessage, sig)
	}
	return verifyPackedSelf(alg, signedMessage, sig, ad)
}

// verifyPackedBasic handles the x5c branch. The first cert in the
// chain signs the attestation; subsequent certs (if any) are
// intermediates leading to a root we don't currently verify.
//
// Constraints we DO enforce (WebAuthn §8.2):
//
//   - alg in the attStmt must match what the cert's key supports.
//   - Cert version 3.
//   - Basic Constraints CA == false.
//   - If the cert has the OID id-fido-gen-ce-aaguid extension, it
//     SHOULD match the AAGUID in authData. We skip this check until
//     we ship an MDS provider — without one we have no way to confirm
//     a certificate-supplied AAGUID is trustworthy.
func verifyPackedBasic(alg int, x5cRaw any, signedMessage, sig []byte) (*AttestationResult, error) {
	chainRaw, ok := x5cRaw.([]any)
	if !ok || len(chainRaw) == 0 {
		return nil, errors.New("attestation 'packed': x5c must be a non-empty array")
	}

	derLeaf, ok := cborBytes(chainRaw[0])
	if !ok {
		return nil, errors.New("attestation 'packed': x5c[0] not bytes")
	}
	leaf, err := x509.ParseCertificate(derLeaf)
	if err != nil {
		return nil, fmt.Errorf("attestation 'packed': leaf parse: %w", err)
	}
	if leaf.Version != 3 {
		return nil, errors.New("attestation 'packed': leaf cert must be v3")
	}
	if leaf.IsCA {
		return nil, errors.New("attestation 'packed': leaf cert is marked CA")
	}

	// Lift the cert's public key into our internal type so we can
	// reuse the same signature primitive used elsewhere in the
	// package. We require the cert key type to match the declared
	// COSE alg family — otherwise an attacker could submit an
	// ECDSA-cert with an RSA alg and bypass curve checks.
	pk, err := publicKeyFromCert(leaf, alg)
	if err != nil {
		return nil, fmt.Errorf("attestation 'packed': cert key: %w", err)
	}

	if err := verifySignature(pk, signedMessage, sig); err != nil {
		return nil, fmt.Errorf("attestation 'packed': %w", err)
	}

	return &AttestationResult{Format: "packed", AttestationType: "basic"}, nil
}

// verifyPackedSelf handles the no-x5c branch where the credential
// signs its own attestation. The alg in attStmt MUST match the alg
// in the credential public key — otherwise an attacker could submit
// a credential under one alg and a signature under another.
func verifyPackedSelf(alg int, signedMessage, sig []byte, ad *authenticatorData) (*AttestationResult, error) {
	pk, err := parseCOSEPublicKey(ad.AttestedCredential.PublicKeyCBOR)
	if err != nil {
		return nil, fmt.Errorf("attestation 'packed' self: cose: %w", err)
	}
	if pk.Algorithm != alg {
		return nil, errors.New("attestation 'packed' self: alg/credential mismatch")
	}
	if err := verifySignature(pk, signedMessage, sig); err != nil {
		return nil, fmt.Errorf("attestation 'packed' self: %w", err)
	}
	return &AttestationResult{Format: "packed", AttestationType: "self"}, nil
}

// publicKeyFromCert lifts an x509.Certificate's public key into the
// internal publicKey shape. We accept only ECDSA and RSA — Ed25519
// in attestation certs is exceedingly rare and would slot in as a
// follow-up.
//
// We cross-check the cert's key type against the declared alg
// family to defeat substitution attacks (e.g. ECDSA cert + RSA alg).
func publicKeyFromCert(cert *x509.Certificate, alg int) (*publicKey, error) {
	switch k := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if alg != algES256 && alg != algES384 && alg != algES512 {
			return nil, fmt.Errorf("alg %s not compatible with ECDSA cert", algorithmName(alg))
		}
		return &publicKey{Algorithm: alg, EC2: k}, nil
	case *rsa.PublicKey:
		switch alg {
		case algRS256, algRS384, algRS512, algPS256, algPS384, algPS512:
			return &publicKey{Algorithm: alg, RSA: k}, nil
		}
		return nil, fmt.Errorf("alg %s not compatible with RSA cert", algorithmName(alg))
	default:
		return nil, fmt.Errorf("attestation cert: unsupported key type %T", cert.PublicKey)
	}
}
