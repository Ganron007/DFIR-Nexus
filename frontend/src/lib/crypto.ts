/**
 * Browser Web Crypto PBKDF2 + HMAC-SHA256 for DFIR-Nexus finding approval.
 *
 * Replaces manual HMAC hex input with automated client-side derivation
 * from the examiner's password, matching the backend's post_commit verification.
 */

export async function pbkdf2(
  password: string,
  salt: string,
  iterations: number = 600000
): Promise<string> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: enc.encode(salt),
      iterations,
      hash: "SHA-256",
    },
    keyMaterial,
    256
  );
  return Array.from(new Uint8Array(bits))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function hmacSha256(keyHex: string, data: string): Promise<string> {
  const match = keyHex.match(/.{1,2}/g);
  if (!match) throw new Error("Invalid keyHex");
  const keyBytes = new Uint8Array(match.map((b) => parseInt(b, 16)));
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(data)
  );
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function computeApprovalResponse(
  password: string,
  salt: string,
  iterations: number,
  nonce: string
): Promise<string> {
  const keyHex = await pbkdf2(password, salt, iterations);
  return hmacSha256(keyHex, nonce);
}
