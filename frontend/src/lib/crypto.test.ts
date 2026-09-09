import { describe, it, expect } from "vitest";
import { pbkdf2, hmacSha256, computeApprovalResponse } from "./crypto";

describe("Web Crypto approval helpers", () => {
  it("derives PBKDF2 matching hashlib.pbkdf2_hmac SHA-256", async () => {
    // PBKDF2-HMAC-SHA256 (password="password", salt="salt", c=1)
    const result1 = await pbkdf2("password", "salt", 1);
    expect(result1).toBe("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");

    // PBKDF2-HMAC-SHA256 (password="password", salt="salt", c=2)
    const result2 = await pbkdf2("password", "salt", 2);
    expect(result2).toBe("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43");
  });

  it("computes HMAC-SHA256 matching Python hmac.new", async () => {
    // Key = "Jefe" (hex 4a656665)
    // Data = "what do ya want for nothing?"
    const keyHex = "4a656665";
    const data = "what do ya want for nothing?";
    const result = await hmacSha256(keyHex, data);
    expect(result).toBe("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
  });

  it("computes end-to-end approval response format", async () => {
    const password = "OperatorSecretPassword";
    const salt = "cadre-salt-01";
    const iterations = 50;
    const nonce = "nonce-abc-12345";

    const response = await computeApprovalResponse(password, salt, iterations, nonce);
    expect(response).toMatch(/^[0-9a-f]{64}$/);

    // Deriving step-by-step should yield the identical value
    const derivedKey = await pbkdf2(password, salt, iterations);
    const expected = await hmacSha256(derivedKey, nonce);
    expect(response).toBe(expected);
  });
});
