/**
 * Two small pieces of cryptography:
 *
 *  1. The MyFitnessPal identity service authenticates a password sign-in with
 *     a JWT: `{ username, password }` signed HS512 using a key the service
 *     itself hands out (`GET /clientKeys`, keyed by `kid`). WebCrypto HMAC
 *     covers that; no JWT library needed.
 *
 *  2. Sealing for our own KV cache. Tokens and diary days are bearer
 *     credentials / health data, so nothing goes into KV in the clear: values
 *     are AES-256-GCM encrypted with a key derived from SESSION_ENCRYPTION_KEY.
 */

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64.replace(/\s+/g, ""));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export function base64UrlEncode(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64UrlDecode(text: string): Uint8Array {
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/");
  return base64ToBytes(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
}

/** Compact JWS, HS512, with the given `kid` in the header. */
export async function signHs512Jwt(payload: Record<string, unknown>, key: Uint8Array, kid: string): Promise<string> {
  const header = { alg: "HS512", typ: "JWT", kid };
  const signingInput = `${base64UrlEncode(encoder.encode(JSON.stringify(header)))}.${base64UrlEncode(encoder.encode(JSON.stringify(payload)))}`;
  const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-512" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, encoder.encode(signingInput)));
  return `${signingInput}.${base64UrlEncode(sig)}`;
}

/** Decode a JWT payload without verifying (used to read `sub` from an id_token). */
export function decodeJwtPayload(jwt: string): Record<string, unknown> {
  const parts = jwt.split(".");
  if (parts.length !== 3) throw new Error("Not a JWT");
  return JSON.parse(decoder.decode(base64UrlDecode(parts[1]))) as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// KV sealing (AES-256-GCM)
// ---------------------------------------------------------------------------

/** Derive a non-extractable AES-GCM key from an arbitrary secret string. */
export async function deriveSealKey(secret: string): Promise<CryptoKey> {
  const raw = await crypto.subtle.digest("SHA-256", encoder.encode(secret));
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

/** Encrypt text → base64(iv || ciphertext+tag). */
export async function seal(key: CryptoKey, text: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(text)));
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv, 0);
  out.set(ct, iv.length);
  return bytesToBase64(out);
}

/** Inverse of `seal`. Throws if the payload was tampered with or the key differs. */
export async function open(key: CryptoKey, sealed: string): Promise<string> {
  const bytes = base64ToBytes(sealed);
  if (bytes.length < 13) throw new Error("Sealed payload too short");
  const iv = bytes.subarray(0, 12);
  const ct = bytes.subarray(12);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return decoder.decode(plain);
}

/** Lower-case hex SHA-256 of a string. Used to namespace cache keys per user. */
export async function sha256Hex(text: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(text)));
  return Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("");
}
