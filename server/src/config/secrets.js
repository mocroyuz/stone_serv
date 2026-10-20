// Secrets : signature du state OAuth + clé de chiffrement des tokens.

import crypto from "node:crypto";
import { env, IS_PRODUCTION } from "./env.js";
import { TIKTOK_CLIENT_SECRET } from "./tiktok.js";
import { PINTEREST_APP_SECRET } from "./pinterest.js";
import { YOUTUBE_CLIENT_SECRET } from "./youtube.js";
import { CANVA_CLIENT_SECRET } from "./canva.js";

export let OAUTH_STATE_SECRET =
  env("OAUTH_STATE_SECRET") ||
  TIKTOK_CLIENT_SECRET ||
  PINTEREST_APP_SECRET ||
  YOUTUBE_CLIENT_SECRET ||
  CANVA_CLIENT_SECRET;

if (!OAUTH_STATE_SECRET && !IS_PRODUCTION) {
  // Dev uniquement : secret éphémère (les states ne survivent pas au redémarrage).
  OAUTH_STATE_SECRET = crypto.randomBytes(32).toString("hex");
  console.warn(
    "⚠️  OAUTH_STATE_SECRET manquant — secret éphémère généré (dev uniquement)."
  );
}

export const TOKEN_ENCRYPTION_KEY = env("TOKEN_ENCRYPTION_KEY")
  ? crypto.createHash("sha256").update(env("TOKEN_ENCRYPTION_KEY")).digest()
  : null;

export const ENC_PREFIX = "enc:v1:";
