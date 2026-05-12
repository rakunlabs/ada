/**
 * Zero-dependency WebAuthn helpers for the ada login UI.
 *
 * The W3C navigator.credentials API works with ArrayBuffers, while
 * the ada/passkey wire format uses URL-safe base64 (RFC 4648 §5, no
 * padding) — matching what passkey.Base64URLEncode emits on the
 * server side. We do the conversion inline so there's no third-party
 * dependency to track.
 *
 * All ceremony functions throw on protocol violations (NotAllowedError,
 * etc.) — callers wrap them in user-facing error messages.
 */

// --- base64url plumbing ---

/**
 * Encode an ArrayBuffer / Uint8Array as URL-safe base64 (no padding).
 *
 * Implemented via btoa + char-class swaps because that's the most
 * portable browser path. The intermediate "binary string" stage is
 * fine for the small blobs WebAuthn returns (challenge ≈ 32 B,
 * credentialId ≤ 1023 B, attestationObject few KiB at most).
 */
export function bufferToBase64URL(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * Decode a URL-safe base64 (with or without padding) string into a
 * Uint8Array backed by a non-shared ArrayBuffer.
 *
 * The narrow `Uint8Array<ArrayBuffer>` return type matters: WebAuthn
 * DOM types (BufferSource, PublicKeyCredentialDescriptor.id) reject
 * SharedArrayBuffer-backed views, so pinning the backing buffer here
 * lets the result flow into navigator.credentials.* without a cast
 * at every call site.
 */
export function base64URLToBuffer(s: string): Uint8Array<ArrayBuffer> {
  const padded = s
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(s.length + ((4 - (s.length % 4)) % 4), "=");
  const bin = atob(padded);
  const buf = new ArrayBuffer(bin.length);
  const out = new Uint8Array(buf);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// --- feature detection ---

/**
 * Feature-detect WebAuthn. Returns true on browsers that expose the
 * PublicKeyCredential global; false on every other environment
 * (older browsers, SSR, hard-blocked enterprise policies).
 */
export function isWebAuthnSupported(): boolean {
  return (
    typeof window !== "undefined"
    && typeof window.PublicKeyCredential !== "undefined"
  );
}

/**
 * Feature-detect conditional mediation (a.k.a. "autofill UI"). When
 * supported, the browser surfaces enrolled passkeys inline with the
 * username field's autocomplete dropdown — picking one resolves the
 * conditional get() promise without a click on a passkey button.
 *
 * The static method may be missing (older Firefox) or throw on
 * exotic profiles; either path resolves false so callers can simply
 * gate "should we even try" on this boolean.
 *
 * Spec: https://w3c.github.io/webauthn/#sctn-conditional-ui
 */
export async function isConditionalMediationAvailable(): Promise<boolean> {
  if (!isWebAuthnSupported()) return false;
  const PKC = window.PublicKeyCredential as unknown as {
    isConditionalMediationAvailable?: () => Promise<boolean>;
  };
  if (typeof PKC.isConditionalMediationAvailable !== "function") return false;
  try {
    return await PKC.isConditionalMediationAvailable();
  } catch {
    return false;
  }
}

// --- wire shapes ---

/**
 * Server-issued CredentialRequestOptions for a login (assertion)
 * ceremony. Matches ada/passkey.CredentialRequestOptions byte-for-byte;
 * every BufferSource arrives as a base64url string.
 */
export interface ServerRequestOptions {
  challenge: string;
  timeout?: number;
  rpId: string;
  allowCredentials?: Array<{
    type: "public-key";
    id: string;
    transports?: string[];
  }>;
  userVerification?: UserVerificationRequirement;
}

/**
 * Browser → server response shape after a successful get(). Mirrors
 * ada/passkey.AssertionResponseJSON. UserHandle is populated only on
 * discoverable-login flows.
 */
export interface AssertionResponseJSON {
  id: string;
  rawId: string;
  type: "public-key";
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle?: string;
  };
  authenticatorAttachment?: string;
}

/**
 * Optional extras for startAuthentication. mediation drives the
 * conditional UI flow; signal lets a long-running conditional get()
 * be aborted (e.g. when the user clicks a manual sign-in button
 * instead of picking from the autofill dropdown).
 */
export interface StartAuthenticationExtra {
  mediation?: CredentialMediationRequirement;
  signal?: AbortSignal;
}

// --- ceremony ---

/**
 * Run the login (assertion) ceremony.
 *
 * Translates the server-issued (base64url-stringy) options into the
 * WebIDL (ArrayBuffer-y) shape navigator.credentials.get wants,
 * invokes it, and translates the response back into the wire shape
 * the ada strategy expects.
 *
 * Pass `{ mediation: "conditional", signal }` to drive the inline
 * autofill flow: the call returns when the user picks a passkey
 * from the username field's autocomplete dropdown, or when the
 * abort signal fires (then it returns null instead of throwing —
 * callers use null to mean "no credential was selected").
 *
 * Throws:
 *  - DOMException(NotAllowedError) when the user cancels or the
 *    authenticator times out.
 *  - Error("webauthn not supported") in non-browser environments.
 */
export async function startAuthentication(
  opts: ServerRequestOptions,
  extra?: StartAuthenticationExtra,
): Promise<AssertionResponseJSON | null> {
  if (!isWebAuthnSupported()) throw new Error("webauthn not supported");

  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge: base64URLToBuffer(opts.challenge),
    timeout: opts.timeout,
    rpId: opts.rpId,
    allowCredentials: (opts.allowCredentials ?? []).map((c) => ({
      type: c.type,
      id: base64URLToBuffer(c.id),
      transports: c.transports as AuthenticatorTransport[] | undefined,
    })),
    userVerification: opts.userVerification,
  };

  try {
    const cred = (await navigator.credentials.get({
      publicKey,
      mediation: extra?.mediation,
      signal: extra?.signal,
    })) as PublicKeyCredential | null;
    if (!cred) return null;

    const asn = cred.response as AuthenticatorAssertionResponse;
    return {
      id: cred.id,
      rawId: bufferToBase64URL(cred.rawId),
      type: "public-key",
      response: {
        clientDataJSON: bufferToBase64URL(asn.clientDataJSON),
        authenticatorData: bufferToBase64URL(asn.authenticatorData),
        signature: bufferToBase64URL(asn.signature),
        userHandle: asn.userHandle ? bufferToBase64URL(asn.userHandle) : undefined,
      },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      authenticatorAttachment: (cred as any).authenticatorAttachment,
    };
  } catch (err: unknown) {
    // AbortError is the expected outcome when a caller cancels the
    // conditional get() to start a manual flow. Surface it as null
    // so callers don't have to special-case the error type.
    if (err && typeof err === "object" && (err as { name?: string }).name === "AbortError") {
      return null;
    }
    throw err;
  }
}
