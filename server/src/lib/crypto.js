// Chiffrement AES-256-GCM des tokens stockés en base.

import crypto from "node:crypto";
import { TOKEN_ENCRYPTION_KEY, ENC_PREFIX } from "../config/index.js";

export function encryptSecret(value) {
  if (!value) return value ?? null;
  if (!TOKEN_ENCRYPTION_KEY) return value;
  if (String(value).startsWith(ENC_PREFIX)) return value;

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", TOKEN_ENCRYPTION_KEY, iv);
  const encrypted = Buffer.concat([
    cipher.update(String(value), "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  return ENC_PREFIX + Buffer.concat([iv, tag, encrypted]).toString("base64url");
}

export function decryptSecret(value) {
  if (!value) return value ?? null;
  if (!String(value).startsWith(ENC_PREFIX)) return value; // ancien token en clair

  if (!TOKEN_ENCRYPTION_KEY) {
    throw new Error("TOKEN_ENCRYPTION_KEY is required to read encrypted tokens");
  }

  const raw = Buffer.from(String(value).slice(ENC_PREFIX.length), "base64url");
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(12, 28);
  const data = raw.subarray(28);

  const decipher = crypto.createDecipheriv("aes-256-gcm", TOKEN_ENCRYPTION_KEY, iv);
  decipher.setAuthTag(tag);

  return Buffer.concat([decipher.update(data), decipher.final()]).toString("utf8");
}

export function decryptTokenRow(row) {
  if (!row) return null;

  try {
    return {
      ...row,
      access_token: decryptSecret(row.access_token),
      refresh_token: decryptSecret(row.refresh_token),
    };
  } catch (error) {
    console.error("Token decryption failed:", error.message);
    // L'utilisateur devra reconnecter son compte.
    return { ...row, access_token: null, refresh_token: null };
  }
}
