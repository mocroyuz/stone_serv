// ============================================================
// STONE — API SERVER
// ============================================================
//
// Variables d'environnement
//   Obligatoires : SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY
//   Production   : NODE_ENV=production, APP_URL, OAUTH_REDIRECT_URL,
//                  OAUTH_STATE_SECRET (32+ caractères aléatoires)
//   Recommandé   : TOKEN_ENCRYPTION_KEY (32+ caractères aléatoires) →
//                  chiffre les tokens TikTok / Pinterest / YouTube / Canva /
//                  Dropbox / Google Drive / Google Photos en base
//                  (AES-256-GCM). Les anciens tokens en clair restent lisibles.
//   Mot de passe oublié :
//                  PASSWORD_RESET_REDIRECT_URL (optionnel, défaut :
//                  ${APP_URL}/#/reset-password).
//   Photos TikTok: URL publique de CE serveur :
//                  PUBLIC_API_URL → VITE_API_BASE_URL → RAILWAY_PUBLIC_DOMAIN
//                  → RENDER_EXTERNAL_URL
//   TikTok       : TIKTOK_AUDITED=1 une fois l'app auditée par TikTok.
//   Pinterest    : PINTEREST_APP_ID, PINTEREST_APP_SECRET.
//   YouTube      : YOUTUBE_CLIENT_ID, YOUTUBE_CLIENT_SECRET.
//   Google Drive : GOOGLE_DRIVE_CLIENT_ID, GOOGLE_DRIVE_CLIENT_SECRET
//                  (fallback sur les identifiants YouTube si absents).
//   Google Photos: GOOGLE_PHOTOS_CLIENT_ID, GOOGLE_PHOTOS_CLIENT_SECRET
//                  (fallback sur Google Drive / YouTube si absents).
//                  GOOGLE_PHOTOS_REDIRECT_URI
//                  (défaut : ${APP_URL}/googlephotos/callback).
//   Canva        : CANVA_CLIENT_ID, CANVA_CLIENT_SECRET.
//   Dropbox      : DROPBOX_APP_KEY, DROPBOX_APP_SECRET.
//   Stripe       : STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, STRIPE_PRICE_*
//   MFA (2FA)    : TOUT passe par le backend :
//                    - RECOVERY_CODE_PEPPER (32+ caractères aléatoires)
//                    - MFA_VERIFIED_SESSION_TTL_MINUTES (défaut : 15)
//                    - WEBAUTHN_RP_ID, WEBAUTHN_RP_NAME, WEBAUTHN_ORIGIN
//                      (défauts : stone-prod.vercel.app / Stone /
//                      https://stone-prod.vercel.app)
//                    - le frontend n'embarque PAS @supabase/supabase-js
//                    - le backend proxifie /auth/v1/factors* de Supabase Auth
//                    - ⚠️ Supabase Auth n'expose PAS `GET /auth/v1/factors` :
//                      la liste des facteurs est lue dans `user.factors`
//                    - après un verify, Supabase renvoie une session AAL2
//                      que le backend transmet au frontend pour qu'il la
//                      stocke (remplace la session AAL1)
//                    - les opérations sensibles exigent AAL2 via requireAal2()
//                    - un code de secours valide vérifie le session_id du JWT
//                      pendant la fenêtre configurée
//   Tags         : MAX_TAGS_PER_USER (défaut : 100)
//   Saved replies: MAX_SAVED_REPLIES_PER_USER (défaut : 100)
// ============================================================

import { fileURLToPath } from "node:url";
import path from "node:path";
import { createServer } from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import { createClient } from "@supabase/supabase-js";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import busboy from "busboy";
import Stripe from "stripe";

// ============================================================
// CHEMIN DU DOSSIER SERVER
// ============================================================

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const envPath = path.join(__dirname, ".env");

// ============================================================
// CHARGEMENT DU .env (robuste)
// ============================================================

function loadEnvFile(filePath) {
  if (!fs.existsSync(filePath)) return;

  try {
    const lines = fs.readFileSync(filePath, "utf-8").split(/\r?\n/);

    for (const line of lines) {
      const trimmed = line.trim();

      if (!trimmed || trimmed.startsWith("#")) continue;

      const idx = trimmed.indexOf("=");
      if (idx === -1) continue;

      const key = trimmed.slice(0, idx).trim();
      let value = trimmed.slice(idx + 1).trim();

      value = value.replace(/^(['"])(.*)\1$/, "$2");

      if (key && !(key in process.env)) {
        process.env[key] = value;
      }
    }
  } catch (error) {
    console.error(`Erreur lors du chargement de ${filePath}:`, error.message);
  }
}

loadEnvFile(envPath);

function env(name) {
  const value = process.env[name];
  return typeof value === "string" ? value.trim() : undefined;
}

const IS_PRODUCTION = env("NODE_ENV") === "production";

// ============================================================
// UTILITAIRES GÉNÉRIQUES
// ============================================================

class HttpError extends Error {
  constructor(status, message, code, headers, retryAfter) {
    super(message);
    this.name = "HttpError";
    this.status = status;
    this.code = code;
    this.headers = headers;
    this.retryAfter = retryAfter;
  }
}

const sha256 = (value) =>
  crypto.createHash("sha256").update(String(value)).digest("hex");

const normalizeEmail = (value) => String(value ?? "").trim().toLowerCase();

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const toBool = (v) => v === true || v === "true" || v === "1";

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const inflight = new Map();

function withLock(key, fn) {
  const existing = inflight.get(key);
  if (existing) return existing;

  const promise = Promise.resolve()
    .then(fn)
    .finally(() => inflight.delete(key));

  inflight.set(key, promise);
  return promise;
}

const serialChains = new Map();

function runSerial(key, fn) {
  const previous = serialChains.get(key) || Promise.resolve();
  const result = previous.catch(() => {}).then(fn);
  const tail = result.catch(() => {});

  serialChains.set(key, tail);
  tail.then(() => {
    if (serialChains.get(key) === tail) serialChains.delete(key);
  });

  return result;
}

function createSeenCache(maxEntries, ttlMs) {
  const entries = new Map();

  return {
    has(key) {
      const expires = entries.get(key);
      if (!expires) return false;

      if (expires <= Date.now()) {
        entries.delete(key);
        return false;
      }

      return true;
    },
    add(key) {
      if (entries.size >= maxEntries) {
        entries.delete(entries.keys().next().value);
      }

      entries.set(key, Date.now() + ttlMs);
    },
  };
}

const callbackCache = new Map();
const CALLBACK_TTL_MS = 60_000;

function dedupeCallback(key, fn) {
  const cached = callbackCache.get(key);
  if (cached && cached.expires > Date.now()) return cached.promise;

  const promise = fn();
  callbackCache.set(key, { promise, expires: Date.now() + CALLBACK_TTL_MS });
  promise.catch(() => callbackCache.delete(key));

  return promise;
}

setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of callbackCache) {
    if (entry.expires <= now) callbackCache.delete(key);
  }
}, 60_000).unref?.();

async function fetchJson(resource, options = {}, timeoutMs = 15_000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(resource, {
      ...options,
      signal: controller.signal,
    });
    const data = await response.json().catch(() => ({}));
    return { response, data };
  } catch (error) {
    if (error?.name === "AbortError") {
      throw new HttpError(504, "Upstream service timed out", "UPSTREAM_TIMEOUT");
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

function upstreamError(name, error) {
  if (error instanceof HttpError) return error;
  console.error(`[upstream:${name}]`, error?.message || error);
  return new HttpError(502, `${name} is unreachable`, "UPSTREAM_UNREACHABLE");
}

function upstreamStatus(status) {
  if (status === 429) return 429;
  return status >= 500 ? 502 : 400;
}

const reconnectError = (name, code) =>
  new HttpError(409, `${name} session expired, please reconnect`, code);

function dbError(context, error) {
  console.error(`[db] ${context}:`, error?.message || error);
  return new HttpError(500, "Database error", "DB_ERROR");
}

// ============================================================
// DÉTECTION DES OBJETS POSTGRES ABSENTS (migration manquante)
// ============================================================

function isSchemaCacheMissingError(error) {
  const msg = String(error?.message || "");
  return (
    /could not find the (table|function)/i.test(msg) ||
    /in the schema cache/i.test(msg)
  );
}

// ============================================================
// CONFIGURATION
// ============================================================

const PORT = Number(
  env("PORT") || (IS_PRODUCTION ? 10000 : 3002)
);

const SUPABASE_URL = env("SUPABASE_URL");
const SUPABASE_ANON_KEY = env("SUPABASE_ANON_KEY");
const SUPABASE_SERVICE_ROLE_KEY = env("SUPABASE_SERVICE_ROLE_KEY");
const RECOVERY_CODE_PEPPER = env("RECOVERY_CODE_PEPPER");
const WEBAUTHN_RP_ID = env("WEBAUTHN_RP_ID") || "stone-prod.vercel.app";
const WEBAUTHN_RP_NAME = env("WEBAUTHN_RP_NAME") || "Stone";
const WEBAUTHN_ORIGIN = (
  env("WEBAUTHN_ORIGIN") || "https://stone-prod.vercel.app"
).replace(/\/+$/, "");
const MFA_VERIFIED_SESSION_TTL_MINUTES = Number(
  env("MFA_VERIFIED_SESSION_TTL_MINUTES") || 15
);

if (
  !Number.isSafeInteger(MFA_VERIFIED_SESSION_TTL_MINUTES) ||
  MFA_VERIFIED_SESSION_TTL_MINUTES < 1 ||
  MFA_VERIFIED_SESSION_TTL_MINUTES > 1440
) {
  throw new Error("MFA_VERIFIED_SESSION_TTL_MINUTES must be an integer between 1 and 1440");
}

const WEBAUTHN_ORIGIN_URL = new URL(WEBAUTHN_ORIGIN);
if (
  !WEBAUTHN_RP_ID ||
  WEBAUTHN_RP_ID.length > 253 ||
  WEBAUTHN_RP_ID.includes("/") ||
  WEBAUTHN_RP_NAME.length === 0 ||
  WEBAUTHN_RP_NAME.length > 64 ||
  WEBAUTHN_ORIGIN_URL.origin !== WEBAUTHN_ORIGIN ||
  WEBAUTHN_ORIGIN_URL.hostname !== WEBAUTHN_RP_ID ||
  (WEBAUTHN_ORIGIN_URL.protocol !== "https:" &&
    !["localhost", "127.0.0.1"].includes(WEBAUTHN_ORIGIN_URL.hostname))
) {
  throw new Error("Invalid WebAuthn RP or origin configuration");
}

const DEFAULT_OAUTH_REDIRECT =
  env("OAUTH_REDIRECT_URL") || "http://localhost:5173/";

const AVATAR_BUCKET = "avatars";
const MAX_AVATAR_SIZE = 2 * 1024 * 1024;

// ============================================================
// CONFIGURATION STRIPE
// ============================================================

const STRIPE_SECRET_KEY = env("STRIPE_SECRET_KEY");
const STRIPE_WEBHOOK_SECRET = env("STRIPE_WEBHOOK_SECRET");

const APP_URL = (env("APP_URL") || "http://localhost:5173").replace(/\/+$/, "");

const PASSWORD_RESET_REDIRECT_URL =
  env("PASSWORD_RESET_REDIRECT_URL") || `${APP_URL}/#/reset-password`;

const RECOVERY_TOKEN_MAX_AGE_SEC = 60 * 60;

const STRIPE_PRICES = {
  starter: {
    monthly: env("STRIPE_PRICE_STARTER_MONTHLY"),
    annual: env("STRIPE_PRICE_STARTER_ANNUAL"),
  },
  pro: {
    monthly: env("STRIPE_PRICE_PRO_MONTHLY"),
    annual: env("STRIPE_PRICE_PRO_ANNUAL"),
  },
  enterprise: {
    monthly: env("STRIPE_PRICE_ENTERPRISE_MONTHLY"),
    annual: env("STRIPE_PRICE_ENTERPRISE_ANNUAL"),
  },
};

const PLAN_NAMES = {
  starter: "Starter",
  pro: "Professional",
  enterprise: "Enterprise",
};

const PRICE_TO_PLAN = new Map();

for (const [planKey, periods] of Object.entries(STRIPE_PRICES)) {
  for (const priceId of Object.values(periods)) {
    if (priceId) PRICE_TO_PLAN.set(priceId, planKey);
  }
}

function planDetails(priceId, metadataPlan) {
  let key = priceId ? PRICE_TO_PLAN.get(priceId) : undefined;

  if (!key) {
    const fromMetadata = String(metadataPlan || "").toLowerCase();
    if (Object.hasOwn(PLAN_NAMES, fromMetadata)) key = fromMetadata;
  }

  return {
    plan: key || null,
    plan_key: key || null,
    plan_name: key ? PLAN_NAMES[key] : null,
  };
}

const STRIPE_SUCCESS_URL = `${APP_URL}/#/account?checkout=success&session_id={CHECKOUT_SESSION_ID}`;
const STRIPE_CANCEL_URL = `${APP_URL}/#/pricing?checkout=cancel`;
const STRIPE_PORTAL_RETURN_URL = `${APP_URL}/#/account`;

const stripe = STRIPE_SECRET_KEY
  ? new Stripe(STRIPE_SECRET_KEY, {
      apiVersion: "2024-06-20",
      maxNetworkRetries: 2,
      timeout: 20_000,
    })
  : null;

// ============================================================
// CONFIGURATION TIKTOK
// ============================================================

const TIKTOK_CLIENT_KEY = env("TIKTOK_CLIENT_KEY");
const TIKTOK_CLIENT_SECRET = env("TIKTOK_CLIENT_SECRET");
const TIKTOK_REDIRECT_URI =
  env("TIKTOK_REDIRECT_URI") || `${APP_URL}/tiktok/callback`;

const TIKTOK_SCOPES = "user.info.basic,video.publish,video.upload";
const TIKTOK_API = "https://open.tiktokapis.com";
const MAX_VIDEO_SIZE = 100 * 1024 * 1024;
const TIKTOK_PRIVACY_LEVELS = new Set([
  "PUBLIC_TO_EVERYONE",
  "MUTUAL_FOLLOW_FRIENDS",
  "FOLLOWER_OF_CREATOR",
  "SELF_ONLY",
]);

const TIKTOK_AUDITED = env("TIKTOK_AUDITED") === "1";
const TIKTOK_SANDBOX = !TIKTOK_AUDITED;
const TIKTOK_FORCE_DRAFT = env("TIKTOK_FORCE_DRAFT") === "1";

const tiktokEnabled = Boolean(TIKTOK_CLIENT_KEY && TIKTOK_CLIENT_SECRET);

function tiktokCapabilities() {
  return {
    audited: TIKTOK_AUDITED,
    sandbox: TIKTOK_SANDBOX,
    force_draft: TIKTOK_FORCE_DRAFT,
    can_direct_post: TIKTOK_AUDITED && !TIKTOK_FORCE_DRAFT,
    forced_privacy_level:
      TIKTOK_AUDITED && !TIKTOK_FORCE_DRAFT ? null : "SELF_ONLY",
    photos_mode:
      TIKTOK_AUDITED && !TIKTOK_FORCE_DRAFT ? "direct_or_draft" : "draft_only",
    testers_only_auth: TIKTOK_SANDBOX,
  };
}

const TIKTOK_WEBHOOK_TOLERANCE_SEC = (() => {
  const raw = env("TIKTOK_WEBHOOK_TOLERANCE_SEC");
  const value = raw ? Number(raw) : Number.NaN;
  return Number.isFinite(value) && value >= 0 ? value : 300;
})();

const TIKTOK_VERIFICATION_NAME = (
  env("TIKTOK_VERIFICATION_FILE") ||
  "tiktok-developers-site-verification=mRJN1EDyG6GdEuRBeOe9A5VyNF5FZTlU"
).replace(/\.txt$/i, "");

function resolvePublicApiUrl() {
  const candidates = [
    ["PUBLIC_API_URL", env("PUBLIC_API_URL")],
    ["VITE_API_BASE_URL", env("VITE_API_BASE_URL")],
    [
      "RAILWAY_PUBLIC_DOMAIN",
      env("RAILWAY_PUBLIC_DOMAIN")
        ? `https://${env("RAILWAY_PUBLIC_DOMAIN")}`
        : undefined,
    ],
    ["RENDER_EXTERNAL_URL", env("RENDER_EXTERNAL_URL")],
  ];

  for (const [source, raw] of candidates) {
    if (!raw) continue;

    const value = raw
      .replace(/\/+$/, "")
      .replace(/\/api$/i, "")
      .replace(/\/+$/, "");

    try {
      const parsed = new URL(value);

      if (parsed.protocol === "https:" || parsed.protocol === "http:") {
        return { url: value, source };
      }
    } catch {
      // ignore
    }
  }

  return { url: "", source: null };
}

const { url: PUBLIC_API_URL, source: PUBLIC_API_URL_SOURCE } =
  resolvePublicApiUrl();
const TIKTOK_MEDIA_BUCKET = "tiktok-media";
const TIKTOK_MEDIA_TTL_MS = 2 * 60 * 60 * 1000;
const MAX_TIKTOK_PHOTOS = 35;
const MAX_PHOTO_SIZE = 10 * 1024 * 1024;
const MAX_PHOTOS_TOTAL = 80 * 1024 * 1024;

// ============================================================
// ✅ NOUVEAU — CONFIGURATION POST MEDIA (intégration /api/posts)
// ============================================================

const POST_MEDIA_BUCKET = "post-media";
const MAX_POST_FILES = 60;
const MAX_POST_FILE_SIZE = 100 * 1024 * 1024;
const MAX_POST_UPLOAD_TOTAL = 500 * 1024 * 1024;
const POSTS_PUBLISH_INTERVAL_MS = 30_000;

function publicApiLooksLikeFrontend() {
  if (!PUBLIC_API_URL) return false;

  try {
    const apiHost = new URL(PUBLIC_API_URL).host;
    const appHost = new URL(APP_URL).host;

    return apiHost === appHost || apiHost.endsWith(".vercel.app");
  } catch {
    return false;
  }
}

function publicApiSourceLabel(source) {
  return source || "URL publique";
}

// ============================================================
// CONFIGURATION PINTEREST
// ============================================================

const PINTEREST_APP_ID = env("PINTEREST_APP_ID");
const PINTEREST_APP_SECRET = env("PINTEREST_APP_SECRET");
const PINTEREST_REDIRECT_URI =
  env("PINTEREST_REDIRECT_URI") || `${APP_URL}/pinterest/callback`;

const PINTEREST_SCOPES =
  env("PINTEREST_SCOPES") ||
  "user_accounts:read,boards:read,boards:write,pins:read,pins:write";

const PINTEREST_PROD_API_BASE = "https://api.pinterest.com/v5";
const PINTEREST_SANDBOX_API_BASE = "https://api-sandbox.pinterest.com/v5";

const trimSlashes = (value) => String(value).trim().replace(/\/+$/, "");
const isSandboxUrl = (value) => /sandbox/i.test(String(value));

const PINTEREST_AUTH_URL =
  env("PINTEREST_AUTH_URL") || "https://www.pinterest.com/oauth/";

const PINTEREST_API_BASE = trimSlashes(
  env("PINTEREST_API_BASE") || PINTEREST_SANDBOX_API_BASE
);

const PINTEREST_ENVIRONMENT = isSandboxUrl(PINTEREST_API_BASE)
  ? "sandbox"
  : "production";

const PINTEREST_OAUTH_BASE = trimSlashes(
  env("PINTEREST_OAUTH_BASE") ||
    (PINTEREST_ENVIRONMENT === "sandbox"
      ? PINTEREST_SANDBOX_API_BASE
      : PINTEREST_PROD_API_BASE)
);

const pinterestEnabled = Boolean(PINTEREST_APP_ID && PINTEREST_APP_SECRET);

const pinterestConfigError = (() => {
  for (const [label, value] of [
    ["PINTEREST_API_BASE", PINTEREST_API_BASE],
    ["PINTEREST_OAUTH_BASE", PINTEREST_OAUTH_BASE],
    ["PINTEREST_AUTH_URL", PINTEREST_AUTH_URL],
  ]) {
    try {
      const parsed = new URL(value);

      if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
        return `${label} invalide`;
      }
    } catch {
      return `${label} invalide`;
    }
  }

  if (isSandboxUrl(PINTEREST_OAUTH_BASE) !== isSandboxUrl(PINTEREST_API_BASE)) {
    return "PINTEREST_API_BASE et PINTEREST_OAUTH_BASE ne sont pas du même environnement (sandbox / production)";
  }

  return null;
})();

const pinterestUsable = pinterestEnabled && !pinterestConfigError;

// ============================================================
// CONFIGURATION YOUTUBE
// ============================================================

const YOUTUBE_CLIENT_ID = env("YOUTUBE_CLIENT_ID");
const YOUTUBE_CLIENT_SECRET = env("YOUTUBE_CLIENT_SECRET");
const YOUTUBE_REDIRECT_URI =
  env("YOUTUBE_REDIRECT_URI") || `${APP_URL}/youtube/callback`;

// ✅ force-ssl est désormais demandé par défaut : il est requis pour
// répondre aux commentaires et pour toute opération d'écriture
// (insert/update/delete de commentThreads).
const YOUTUBE_SCOPES = (
  env("YOUTUBE_SCOPES") ||
  "https://www.googleapis.com/auth/youtube.readonly https://www.googleapis.com/auth/youtube.upload https://www.googleapis.com/auth/youtube.force-ssl"
)
  .split(/[\s,]+/)
  .filter(Boolean)
  .join(" ");

const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke";
const YOUTUBE_API_BASE = "https://www.googleapis.com/youtube/v3";

const youtubeEnabled = Boolean(YOUTUBE_CLIENT_ID && YOUTUBE_CLIENT_SECRET);

const YOUTUBE_UPLOAD_URL = "https://www.googleapis.com/upload/youtube/v3/videos";
const YOUTUBE_CHUNK_SIZE = 8 * 1024 * 1024;
const YOUTUBE_PRIVACY_LEVELS = new Set(["public", "unlisted", "private"]);
const YOUTUBE_TITLE_MAX = 100;
const YOUTUBE_DESCRIPTION_MAX_BYTES = 5000;
const YOUTUBE_UPLOAD_SCOPE = "https://www.googleapis.com/auth/youtube.upload";

// ✅ NOUVEAU — lecture YouTube (vidéos + commentaires)
const YOUTUBE_READ_SCOPES = [
  "https://www.googleapis.com/auth/youtube.readonly",
  "https://www.googleapis.com/auth/youtube.force-ssl",
];
const YOUTUBE_FORCE_SSL_SCOPE =
  "https://www.googleapis.com/auth/youtube.force-ssl";
const YOUTUBE_ID_PATTERN = /^[\w-]{1,64}$/;
const YOUTUBE_COMMENT_FILTERS = new Set(["all", "unanswered", "answered"]);

// ============================================================
// CONFIGURATION GOOGLE DRIVE
// ============================================================

const GDRIVE_CLIENT_ID = env("GOOGLE_DRIVE_CLIENT_ID") || YOUTUBE_CLIENT_ID;
const GDRIVE_CLIENT_SECRET = env("GOOGLE_DRIVE_CLIENT_SECRET") || YOUTUBE_CLIENT_SECRET;
const GDRIVE_REDIRECT_URI =
  env("GOOGLE_DRIVE_REDIRECT_URI") || `${APP_URL}/googledrive/callback`;

const GDRIVE_SCOPES = (
  env("GOOGLE_DRIVE_SCOPES") ||
  "https://www.googleapis.com/auth/drive.file https://www.googleapis.com/auth/drive.readonly"
)
  .split(/[\s,]+/)
  .filter(Boolean)
  .join(" ");

const GDRIVE_API = "https://www.googleapis.com/drive/v3";
const GDRIVE_UPLOAD_URL = "https://www.googleapis.com/upload/drive/v3/files";
const MAX_GDRIVE_UPLOAD = 100 * 1024 * 1024;

const gdriveEnabled = Boolean(GDRIVE_CLIENT_ID && GDRIVE_CLIENT_SECRET);

// ============================================================
// CONFIGURATION GOOGLE PHOTOS (Picker API)
// ============================================================

const GPHOTOS_CLIENT_ID = env("GOOGLE_PHOTOS_CLIENT_ID") || GDRIVE_CLIENT_ID;
const GPHOTOS_CLIENT_SECRET = env("GOOGLE_PHOTOS_CLIENT_SECRET") || GDRIVE_CLIENT_SECRET;
const GPHOTOS_REDIRECT_URI =
  env("GOOGLE_PHOTOS_REDIRECT_URI") || `${APP_URL}/googlephotos/callback`;

const GPHOTOS_SCOPES = "https://www.googleapis.com/auth/photospicker.mediaitems.readonly";
const GPHOTOS_PICKER_API = "https://photospicker.googleapis.com/v1";
const MAX_GPHOTOS_DOWNLOAD = 100 * 1024 * 1024;
const GPHOTOS_SESSION_ID = /^[\w.~-]{1,256}$/;

const gphotosEnabled = Boolean(GPHOTOS_CLIENT_ID && GPHOTOS_CLIENT_SECRET);

// ============================================================
// CONFIGURATION CANVA
// ============================================================

const CANVA_CLIENT_ID = env("CANVA_CLIENT_ID");
const CANVA_CLIENT_SECRET = env("CANVA_CLIENT_SECRET");
const CANVA_REDIRECT_URI =
  env("CANVA_REDIRECT_URI") || `${APP_URL}/canva/callback`;

const CANVA_SCOPES =
  env("CANVA_SCOPES") ||
  "design:content:read design:content:write design:meta:read profile:read";

const CANVA_API_BASE = "https://api.canva.com/rest/v1";
const CANVA_AUTH_URL = "https://www.canva.com/api/oauth/authorize";

const canvaEnabled = Boolean(CANVA_CLIENT_ID && CANVA_CLIENT_SECRET);

// ============================================================
// CONFIGURATION DROPBOX
// ============================================================

const DROPBOX_APP_KEY = env("DROPBOX_APP_KEY");
const DROPBOX_APP_SECRET = env("DROPBOX_APP_SECRET");
const DROPBOX_REDIRECT_URI =
  env("DROPBOX_REDIRECT_URI") || `${APP_URL}/dropbox/callback`;

const DROPBOX_SCOPES = (
  env("DROPBOX_SCOPES") ||
  "account_info.read files.metadata.read files.content.read files.content.write"
)
  .split(/[\s,]+/)
  .filter(Boolean)
  .join(" ");

const DROPBOX_AUTH_URL = "https://www.dropbox.com/oauth2/authorize";
const DROPBOX_TOKEN_URL = "https://api.dropboxapi.com/oauth2/token";
const DROPBOX_API = "https://api.dropboxapi.com/2";
const DROPBOX_CONTENT_API = "https://content.dropboxapi.com/2";
const MAX_DROPBOX_UPLOAD = 100 * 1024 * 1024;

const dropboxEnabled = Boolean(DROPBOX_APP_KEY && DROPBOX_APP_SECRET);

// ============================================================
// CONFIGURATION TAGS
// ============================================================

const MAX_TAGS_PER_USER = Math.max(1, Number(env("MAX_TAGS_PER_USER") || 100));
const TAG_NAME_MAX = 50;
const TAG_COLOR_PATTERN = /^#[0-9a-f]{6}$/i;
const TAG_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// ------------------------------------------------------------
// BLOC 1 — Configuration des saved replies
// ------------------------------------------------------------

const MAX_SAVED_REPLIES_PER_USER = Math.max(
  1,
  Number(env("MAX_SAVED_REPLIES_PER_USER") || 100)
);
const SAVED_REPLY_NAME_MAX = 100;
const SAVED_REPLY_CONTENT_MAX = 1000;
const SAVED_REPLY_ID_PATTERN = TAG_ID_PATTERN; // même format UUID

// ============================================================
// SECRETS : SIGNATURE DU STATE OAUTH + CHIFFREMENT DES TOKENS
// ============================================================

let OAUTH_STATE_SECRET =
  env("OAUTH_STATE_SECRET") ||
  TIKTOK_CLIENT_SECRET ||
  PINTEREST_APP_SECRET ||
  YOUTUBE_CLIENT_SECRET ||
  CANVA_CLIENT_SECRET ||
  DROPBOX_APP_SECRET;

if (!OAUTH_STATE_SECRET && !IS_PRODUCTION) {
  OAUTH_STATE_SECRET = crypto.randomBytes(32).toString("hex");
}

const TOKEN_ENCRYPTION_KEY = env("TOKEN_ENCRYPTION_KEY")
  ? crypto.createHash("sha256").update(env("TOKEN_ENCRYPTION_KEY")).digest()
  : null;

const ENC_PREFIX = "enc:v1:";

function encryptSecret(value) {
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

function decryptSecret(value) {
  if (!value) return value ?? null;
  if (!String(value).startsWith(ENC_PREFIX)) return value;

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

function decryptTokenRow(row) {
  if (!row) return null;

  try {
    return {
      ...row,
      access_token: decryptSecret(row.access_token),
      refresh_token: decryptSecret(row.refresh_token),
    };
  } catch (error) {
    console.error("Token decryption failed:", error.message);
    return { ...row, access_token: null, refresh_token: null };
  }
}

// ============================================================
// VÉRIFICATION SUPABASE
// ============================================================

const missingVars = [
  ["SUPABASE_URL", SUPABASE_URL],
  ["SUPABASE_ANON_KEY", SUPABASE_ANON_KEY],
  ["SUPABASE_SERVICE_ROLE_KEY", SUPABASE_SERVICE_ROLE_KEY],
]
  .filter(([, value]) => !value)
  .map(([name]) => name);

if (missingVars.length > 0) {
  console.error("");
  console.error("Supabase non configuré. Variables manquantes :");
  for (const name of missingVars) console.error(` - ${name}`);
  console.error("");

  process.exit(1);
}

try {
  const parsed = new URL(SUPABASE_URL);

  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error("Protocole invalide");
  }
} catch {
  console.error("");
  console.error("SUPABASE_URL invalide :", JSON.stringify(SUPABASE_URL));
  console.error("");

  process.exit(1);
}

const SUPABASE_BASE_URL = SUPABASE_URL.replace(/\/+$/, "");
const SUPABASE_AUTH_BASE = `${SUPABASE_BASE_URL}/auth/v1`;

// ============================================================
// FAIL-FAST PRODUCTION
// ============================================================

if (IS_PRODUCTION) {
  const fatalMissing = [];

  if (!env("APP_URL") || APP_URL.startsWith("http://localhost")) {
    fatalMissing.push("APP_URL (URL du frontend de production)");
  }

  if (
    !env("OAUTH_REDIRECT_URL") ||
    DEFAULT_OAUTH_REDIRECT.startsWith("http://localhost")
  ) {
    fatalMissing.push("OAUTH_REDIRECT_URL");
  }

  if (!OAUTH_STATE_SECRET) {
    fatalMissing.push("OAUTH_STATE_SECRET (ou au moins un secret client OAuth)");
  }

  if (fatalMissing.length > 0) {
    console.error("");
    console.error("❌ Configuration de production incomplète :");
    for (const name of fatalMissing) console.error(` - ${name}`);
    console.error("");

    process.exit(1);
  }
}

// ============================================================
// CLIENTS SUPABASE
// ============================================================

const serverAuthOptions = {
  persistSession: false,
  autoRefreshToken: false,
  detectSessionInUrl: false,
};

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: serverAuthOptions,
});

const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: serverAuthOptions,
});

const supabaseOAuth = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: { ...serverAuthOptions, flowType: "implicit" },
});

// ============================================================
// RATE LIMITING (en mémoire)
// ============================================================

const TRUST_PROXY = env("TRUST_PROXY") === "1" || IS_PRODUCTION;
const TRUST_PROXY_HOPS = (() => {
  const n = Number(env("TRUST_PROXY_HOPS"));
  return Number.isSafeInteger(n) && n >= 1 ? n : 1;
})();

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];

  if (TRUST_PROXY && typeof forwarded === "string") {
    const parts = forwarded
      .split(",")
      .map((part) => part.trim())
      .filter(Boolean);

    if (parts.length > 0) {
      return parts[Math.max(0, parts.length - TRUST_PROXY_HOPS)];
    }
  }

  return req.socket?.remoteAddress || "unknown";
}

function authAttemptKey(subjectType, subject, ip) {
  return crypto
    .createHmac("sha256", SUPABASE_SERVICE_ROLE_KEY)
    .update(`${subjectType}\0${subject}\0${ip}`)
    .digest("hex");
}

function authAttemptRateLimitError(retryAfter) {
  return new HttpError(
    429,
    "Too many failed authentication attempts. Please try again later.",
    "RATE_LIMITED",
    { "Retry-After": String(retryAfter) },
    retryAfter
  );
}

// ------------------------------------------------------------
// Fallback mémoire : rate limiting des tentatives d'authentification
// ------------------------------------------------------------

const authAttemptsMemory = new Map();
const AUTH_ATTEMPT_MAX = 5;
const AUTH_ATTEMPT_WINDOW_MS = 15 * 60 * 1000;
const AUTH_ATTEMPT_BLOCK_MS = 15 * 60 * 1000;

function checkAuthAttemptLimitMemory(attemptKey) {
  const now = Date.now();
  const entry = authAttemptsMemory.get(attemptKey);
  if (!entry) return;

  if (entry.blockedUntil && entry.blockedUntil > now) {
    throw authAttemptRateLimitError(
      Math.ceil((entry.blockedUntil - now) / 1000)
    );
  }

  if (now - entry.firstAt > AUTH_ATTEMPT_WINDOW_MS) {
    authAttemptsMemory.delete(attemptKey);
    return;
  }

  if (entry.count >= AUTH_ATTEMPT_MAX) {
    entry.blockedUntil = now + AUTH_ATTEMPT_BLOCK_MS;
    throw authAttemptRateLimitError(
      Math.ceil(AUTH_ATTEMPT_BLOCK_MS / 1000)
    );
  }
}

function recordAuthAttemptFailureMemory(attemptKey) {
  const now = Date.now();
  const entry = authAttemptsMemory.get(attemptKey);

  if (!entry || now - entry.firstAt > AUTH_ATTEMPT_WINDOW_MS) {
    authAttemptsMemory.set(attemptKey, {
      count: 1,
      firstAt: now,
      blockedUntil: null,
    });
    return;
  }

  entry.count += 1;
  entry.blockedUntil = null;
}

async function checkAuthAttemptLimit(attemptKey) {
  const { data, error } = await supabaseAdmin.rpc("auth_attempts_check", {
    p_attempt_key: attemptKey,
  });

  if (error) {
    if (isSchemaCacheMissingError(error)) {
      console.warn(
        "[auth_attempts_check] migration manquante — fallback mémoire actif"
      );
      checkAuthAttemptLimitMemory(attemptKey);
      return;
    }
    throw dbError("auth_attempts_check", error);
  }

  const state = Array.isArray(data) ? data[0] : null;
  if (!state || typeof state.allowed !== "boolean") {
    throw dbError("auth_attempts_check", new Error("Invalid RPC response"));
  }

  if (!state.allowed) {
    const retryAfter = Number(state.retry_after);
    if (!Number.isSafeInteger(retryAfter) || retryAfter < 1) {
      throw dbError("auth_attempts_check", new Error("Invalid retry interval"));
    }
    throw authAttemptRateLimitError(retryAfter);
  }
}

async function recordAuthAttemptFailure(attemptKey) {
  const { error } = await supabaseAdmin.rpc("auth_attempts_record_failure", {
    p_attempt_key: attemptKey,
  });

  if (error) {
    if (isSchemaCacheMissingError(error)) {
      recordAuthAttemptFailureMemory(attemptKey);
      return;
    }
    throw dbError("auth_attempts_record_failure", error);
  }
}

async function resetAuthAttemptFailures(attemptKey) {
  const { error } = await supabaseAdmin.rpc("auth_attempts_reset_success", {
    p_attempt_key: attemptKey,
  });

  if (error) {
    if (isSchemaCacheMissingError(error)) {
      authAttemptsMemory.delete(attemptKey);
      return;
    }
    throw dbError("auth_attempts_reset_success", error);
  }
}

// ------------------------------------------------------------
// Rate limiters en mémoire
// ------------------------------------------------------------

function createRateLimiter({ windowMs, max, label, maxKeys = 50_000 }) {
  const hits = new Map();

  const cleaner = setInterval(() => {
    const cutoff = Date.now() - windowMs;

    for (const [key, timestamps] of hits) {
      const fresh = timestamps.filter((t) => t > cutoff);

      if (fresh.length === 0) hits.delete(key);
      else hits.set(key, fresh);
    }
  }, Math.min(windowMs, 5 * 60 * 1000));

  cleaner.unref?.();

  return {
    check(key) {
      const now = Date.now();
      const cutoff = now - windowMs;

      const timestamps = (hits.get(key) || []).filter((t) => t > cutoff);

      if (timestamps.length >= max) {
        const retryAfterMs = timestamps[0] + windowMs - now;

        console.warn(
          `[ratelimit:${label}] refusé (${timestamps.length}/${max} en ${windowMs / 1000}s)`
        );

        return { allowed: false, retryAfterSec: Math.ceil(retryAfterMs / 1000) };
      }

      timestamps.push(now);

      hits.delete(key);
      hits.set(key, timestamps);

      if (hits.size > maxKeys) {
        const oldest = hits.keys().next().value;
        hits.delete(oldest);
      }

      return { allowed: true, retryAfterSec: null };
    },
  };
}

const limiterStrict = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 10, label: "auth" });
const limiterRefresh = createRateLimiter({ windowMs: 10 * 60 * 1000, max: 30, label: "refresh" });
const limiterOauth = createRateLimiter({ windowMs: 10 * 60 * 1000, max: 30, label: "oauth" });
const limiterApi = createRateLimiter({ windowMs: 60 * 1000, max: 240, label: "api" });

const limiterAccount = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 10, label: "account" });
const limiterPublish = createRateLimiter({ windowMs: 60 * 60 * 1000, max: 20, label: "publish" });

// ✅ NOUVEAU — rate limiter dédié à la création de posts planifiés
const limiterPosts = createRateLimiter({ windowMs: 60 * 60 * 1000, max: 60, label: "posts" });

const limiterPasswordReset = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 3, label: "password-reset" });

const limiterMedia = createRateLimiter({ windowMs: 60 * 1000, max: 600, label: "media" });
const limiterTiktokWebhook = createRateLimiter({ windowMs: 60 * 1000, max: 600, label: "tiktok-webhook" });

const limiterCanva = createRateLimiter({ windowMs: 10 * 60 * 1000, max: 40, label: "canva" });
const limiterDropbox = createRateLimiter({ windowMs: 10 * 60 * 1000, max: 120, label: "dropbox" });
const limiterGDrive = createRateLimiter({ windowMs: 10 * 60 * 1000, max: 120, label: "gdrive" });
const limiterGPhotos = createRateLimiter({ windowMs: 10 * 60 * 1000, max: 240, label: "gphotos" });
const limiterTags = createRateLimiter({ windowMs: 60 * 1000, max: 60, label: "tags" });

// ✅ NOUVEAU — rate limiter dédié à la lecture YouTube (vidéos + commentaires)
const limiterYouTubeRead = createRateLimiter({
  windowMs: 60 * 1000,
  max: 60,
  label: "youtube-read",
});

// ------------------------------------------------------------
// BLOC 2 — Rate limiter saved replies
// ------------------------------------------------------------

const limiterSavedReplies = createRateLimiter({
  windowMs: 60 * 1000,
  max: 60,
  label: "saved-replies",
});

function enforce(limiter, key) {
  const { allowed, retryAfterSec } = limiter.check(key);

  if (!allowed) {
    throw new HttpError(
      429,
      "Too many requests. Please try again later.",
      "RATE_LIMITED",
      retryAfterSec ? { "Retry-After": String(retryAfterSec) } : undefined,
      retryAfterSec
    );
  }
}

const STRICT_PATHS = new Set([
  "/api/auth/login",
  "/api/auth/check-verification",
  "/api/auth/signup",
  "/api/auth/forgot-password",
  "/api/auth/reset-password",
]);

const PROVIDER_AUTH_PATH = /^\/api\/(tiktok|pinterest|youtube|canva|dropbox|googledrive|googlephotos)\/auth\//;

function pickLimiter(pathname) {
  if (STRICT_PATHS.has(pathname)) return limiterStrict;
  if (pathname === "/api/auth/refresh") return limiterRefresh;
  if (pathname.startsWith("/api/auth/") || PROVIDER_AUTH_PATH.test(pathname)) {
    return limiterOauth;
  }
  return limiterApi;
}

// ============================================================
// CORS + EN-TÊTES DE SÉCURITÉ
// ============================================================

function normalizeOrigin(value) {
  return String(value || "")
    .trim()
    .replace(/\/+$/, "");
}

const DEFAULT_ALLOWED_ORIGINS = [
  "http://localhost:5173",
  "http://127.0.0.1:5173",
  "https://stone-prod.vercel.app",
];

const VERCEL_DEPLOYMENT_ORIGIN_PATTERN =
  /^https:\/\/stone-prod(-[a-z0-9]+)?-xsdevs-projects\.vercel\.app$/;

const extraAllowedOrigins = (env("ALLOWED_ORIGINS") || "")
  .split(",")
  .map(normalizeOrigin)
  .filter(Boolean);

const allowedOrigins = new Set(
  [
    ...DEFAULT_ALLOWED_ORIGINS,
    APP_URL,
    ...extraAllowedOrigins.filter((origin) => origin !== "*"),
  ]
    .map(normalizeOrigin)
    .filter(Boolean)
);

function isOriginAllowed(origin) {
  if (!origin || typeof origin !== "string") return false;

  const normalized = normalizeOrigin(origin);

  return (
    allowedOrigins.has(normalized) ||
    VERCEL_DEPLOYMENT_ORIGIN_PATTERN.test(normalized)
  );
}

const warnedRejectedOrigins = new Set();

const CORS_ALLOWED_HEADERS = "Content-Type, Authorization, X-Requested-With";

function setCorsHeaders(req, res) {
  const origin = req.headers.origin;

  res.setHeader("Vary", "Origin");

  if (origin) {
    if (isOriginAllowed(origin)) {
      res.setHeader("Access-Control-Allow-Origin", normalizeOrigin(origin));
      res.setHeader("Access-Control-Allow-Credentials", "true");
      res.setHeader("Access-Control-Expose-Headers", "Retry-After, X-Stone-Server");
    } else if (
      warnedRejectedOrigins.size < 100 &&
      !warnedRejectedOrigins.has(origin)
    ) {
      warnedRejectedOrigins.add(origin);
      console.warn(`[cors] Origine refusée : ${origin}`);
    }
  }

  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, PATCH, DELETE, OPTIONS"
  );
  res.setHeader("Access-Control-Allow-Headers", CORS_ALLOWED_HEADERS);
  res.setHeader("Access-Control-Max-Age", "86400");
}

function setSecurityHeaders(res) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cache-Control", "no-store");
  // ✅ NOUVEAU — diagnostic : permet de vérifier depuis le frontend
  // que la réponse vient bien de CE serveur (et pas d'un SPA fallback).
  res.setHeader("X-Stone-Server", "1");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'none'; frame-ancestors 'none'"
  );

  if (IS_PRODUCTION) {
    res.setHeader(
      "Strict-Transport-Security",
      "max-age=31536000; includeSubDomains"
    );
  }
}

// ============================================================
// VALIDATION DU redirectTo
// ============================================================

function sanitizeRedirectTo(value) {
  if (typeof value !== "string" || !value.trim()) {
    return DEFAULT_OAUTH_REDIRECT;
  }

  try {
    const parsed = new URL(value);

    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      return DEFAULT_OAUTH_REDIRECT;
    }

    if (!isOriginAllowed(parsed.origin)) {
      console.warn(`[oauth] redirectTo refusé : ${parsed.origin}`);
      return DEFAULT_OAUTH_REDIRECT;
    }

    return parsed.toString();
  } catch {
    return DEFAULT_OAUTH_REDIRECT;
  }
}

// ============================================================
// RÉPONSES + ERREURS
// ============================================================

function newRequestId() {
  return crypto.randomUUID().slice(0, 8);
}

function sendJson(res, statusCode, data, extraHeaders) {
  if (res.headersSent) {
    res.end();
    return;
  }

  const payload = JSON.stringify(data);

  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(payload),
    ...(extraHeaders || {}),
  });

  res.end(payload);
}

function internalErrorResponse(res, requestId, error, context) {
  console.error(`[${requestId}] ${context}:`, error);

  if (res.headersSent) {
    res.end();
    return;
  }

  const message =
    error && typeof error.message === "string" && error.message
      ? error.message
      : "Internal server error";

  sendJson(res, 500, {
    success: false,
    error: IS_PRODUCTION ? "Internal server error" : message,
    request_id: requestId,
  });
}

// ============================================================
// CORPS DES REQUÊTES
// ============================================================

const MAX_JSON_BODY = 1024 * 1024;

function tooLargeError(message = "Request body too large") {
  return new HttpError(413, message, "BODY_TOO_LARGE", { Connection: "close" });
}

function readBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const declared = Number(req.headers["content-length"] || 0);

    if (declared > maxBytes) {
      reject(tooLargeError());
      return;
    }

    const chunks = [];
    let size = 0;
    let done = false;

    const finish = (fn, arg) => {
      if (done) return;
      done = true;
      fn(arg);
    };

    req.on("data", (chunk) => {
      if (done) return;

      size += chunk.length;

      if (size > maxBytes) {
        finish(reject, tooLargeError());
        return;
      }

      chunks.push(chunk);
    });

    req.on("end", () => finish(resolve, Buffer.concat(chunks)));
    req.on("error", (error) => finish(reject, error));
    req.on("close", () => {
      if (!req.complete) finish(reject, new HttpError(400, "Request aborted"));
    });
  });
}

async function getJsonBody(req) {
  const raw = await readBody(req, MAX_JSON_BODY);

  if (raw.length === 0) return {};

  try {
    const parsed = JSON.parse(raw.toString("utf8"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed
      : {};
  } catch {
    throw new HttpError(400, "Invalid JSON");
  }
}

const getRawBody = (req) => readBody(req, MAX_JSON_BODY);

// ============================================================
// MULTIPART
// ============================================================

function parseMultipart(req, { fileField, maxSize }) {
  return new Promise((resolve, reject) => {
    let bb;

    try {
      bb = busboy({
        headers: req.headers,
        limits: {
          fileSize: maxSize,
          files: 1,
          fields: 20,
          fieldSize: 16 * 1024,
          parts: 30,
        },
      });
    } catch {
      reject(new HttpError(400, "Invalid multipart request"));
      return;
    }

    const fields = {};
    const chunks = [];
    let fileFound = false;
    let tooLarge = false;
    let mimeType = "";
    let fileName = "";
    let settled = false;

    const settle = (fn, arg) => {
      if (settled) return;
      settled = true;
      fn(arg);
    };

    bb.on("file", (fieldname, file, info) => {
      if (fieldname !== fileField || fileFound) {
        file.resume();
        return;
      }

      fileFound = true;
      mimeType = info?.mimeType || "";
      fileName = info?.filename || "";

      file.on("data", (chunk) => chunks.push(chunk));
      file.on("limit", () => {
        tooLarge = true;
      });
    });

    bb.on("field", (name, value) => {
      fields[name] = value;
    });

    bb.on("filesLimit", () =>
      settle(reject, new HttpError(400, "Too many files"))
    );
    bb.on("partsLimit", () =>
      settle(reject, new HttpError(400, "Too many fields"))
    );

    bb.on("close", () => {
      if (tooLarge) {
        settle(reject, new HttpError(400, "File too large", "FILE_TOO_LARGE"));
        return;
      }

      if (!fileFound) {
        settle(reject, new HttpError(400, "No file", "NO_FILE"));
        return;
      }

      settle(resolve, {
        buffer: Buffer.concat(chunks),
        mimeType,
        fileName,
        fields,
      });
    });

    bb.on("error", () =>
      settle(reject, new HttpError(400, "Could not read the uploaded file."))
    );

    req.on("close", () => {
      if (!req.complete) {
        settle(reject, new HttpError(400, "Upload aborted"));
      }
    });
    req.on("error", () => settle(reject, new HttpError(400, "Upload aborted")));

    req.pipe(bb);
  });
}

function parseMultipartFiles(req, { fileField, maxFiles, maxFileSize }) {
  return new Promise((resolve, reject) => {
    let bb;

    try {
      bb = busboy({
        headers: req.headers,
        limits: {
          fileSize: maxFileSize,
          files: maxFiles,
          fields: 30,
          fieldSize: 16 * 1024,
          parts: maxFiles + 40,
        },
      });
    } catch {
      reject(new HttpError(400, "Invalid multipart request"));
      return;
    }

    const fields = {};
    const files = [];
    let tooLarge = false;
    let tooMany = false;
    let settled = false;

    const settle = (fn, arg) => {
      if (settled) return;
      settled = true;
      fn(arg);
    };

    bb.on("file", (fieldname, file, info) => {
      if (fieldname !== fileField) {
        file.resume();
        return;
      }

      const chunks = [];

      file.on("data", (chunk) => chunks.push(chunk));
      file.on("limit", () => {
        tooLarge = true;
      });
      file.on("end", () => {
        files.push({
          buffer: Buffer.concat(chunks),
          mimeType: info?.mimeType || "",
          fileName: info?.filename || "",
        });
      });
    });

    bb.on("field", (name, value) => {
      fields[name] = value;
    });

    bb.on("filesLimit", () => {
      tooMany = true;
    });

    bb.on("partsLimit", () =>
      settle(reject, new HttpError(400, "Too many fields"))
    );

    bb.on("close", () => {
      if (tooLarge) {
        settle(reject, new HttpError(400, "File too large", "FILE_TOO_LARGE"));
        return;
      }

      if (tooMany) {
        settle(reject, new HttpError(400, "Too many files", "TOO_MANY_FILES"));
        return;
      }

      if (files.length === 0) {
        settle(reject, new HttpError(400, "No file", "NO_FILE"));
        return;
      }

      settle(resolve, { files, fields });
    });

    bb.on("error", () =>
      settle(reject, new HttpError(400, "Could not read the uploaded files."))
    );

    req.on("close", () => {
      if (!req.complete) {
        settle(reject, new HttpError(400, "Upload aborted"));
      }
    });
    req.on("error", () => settle(reject, new HttpError(400, "Upload aborted")));

    req.pipe(bb);
  });
}

// ------------------------------------------------------------
// ✅ NOUVEAU — parseMultipartAny : équivalent `multer.any()`
// ------------------------------------------------------------
function parseMultipartAny(
  req,
  {
    maxFiles = MAX_POST_FILES,
    maxFileSize = MAX_POST_FILE_SIZE,
    maxFieldSize = 1024 * 1024, // 1 Mo pour le champ `data` (JSON)
    requireFile = false,
  } = {}
) {
  return new Promise((resolve, reject) => {
    let bb;

    try {
      bb = busboy({
        headers: req.headers,
        limits: {
          fileSize: maxFileSize,
          files: maxFiles,
          fields: 20,
          fieldSize: maxFieldSize,
          parts: maxFiles + 40,
        },
      });
    } catch {
      reject(new HttpError(400, "Invalid multipart request"));
      return;
    }

    const fields = {};
    const files = [];
    let tooLarge = false;
    let tooMany = false;
    let settled = false;

    const settle = (fn, arg) => {
      if (settled) return;
      settled = true;
      fn(arg);
    };

    bb.on("file", (fieldname, file, info) => {
      const chunks = [];

      file.on("data", (chunk) => chunks.push(chunk));
      file.on("limit", () => {
        tooLarge = true;
      });
      file.on("end", () => {
        if (tooLarge) return; // ignore le fichier tronqué
        files.push({
          fieldname,
          buffer: Buffer.concat(chunks),
          mimeType: info?.mimeType || "",
          fileName: info?.filename || "",
        });
      });
    });

    bb.on("field", (name, value) => {
      fields[name] = value;
    });

    bb.on("filesLimit", () => {
      tooMany = true;
    });

    bb.on("partsLimit", () =>
      settle(reject, new HttpError(400, "Too many fields", "TOO_MANY_FIELDS"))
    );

    bb.on("close", () => {
      if (tooLarge) {
        settle(reject, new HttpError(400, "File too large", "FILE_TOO_LARGE"));
        return;
      }

      if (tooMany) {
        settle(reject, new HttpError(400, "Too many files", "TOO_MANY_FILES"));
        return;
      }

      if (requireFile && files.length === 0) {
        settle(reject, new HttpError(400, "No file", "NO_FILE"));
        return;
      }

      settle(resolve, { files, fields });
    });

    bb.on("error", () =>
      settle(reject, new HttpError(400, "Could not read the uploaded files."))
    );

    req.on("close", () => {
      if (!req.complete) {
        settle(reject, new HttpError(400, "Upload aborted"));
      }
    });
    req.on("error", () => settle(reject, new HttpError(400, "Upload aborted")));

    req.pipe(bb);
  });
}

// ============================================================
// VALIDATION DU TYPE DE FICHIER (magic bytes)
// ============================================================

const ALLOWED_AVATAR_TYPES = ["image/png", "image/jpeg", "image/webp", "image/gif"];

const AVATAR_EXTENSIONS = {
  "image/png": "png",
  "image/jpeg": "jpg",
  "image/webp": "webp",
  "image/gif": "gif",
};

function sniffImageType(buffer) {
  if (!buffer || buffer.length < 12) return null;

  if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4e && buffer[3] === 0x47) {
    return "image/png";
  }

  if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
    return "image/jpeg";
  }

  if (buffer[0] === 0x47 && buffer[1] === 0x49 && buffer[2] === 0x46 && buffer[3] === 0x38) {
    return "image/gif";
  }

  if (
    buffer.toString("ascii", 0, 4) === "RIFF" &&
    buffer.toString("ascii", 8, 12) === "WEBP"
  ) {
    return "image/webp";
  }

  return null;
}

function sniffVideoType(buffer) {
  if (!buffer || buffer.length < 12) return null;

  if (buffer.toString("ascii", 4, 8) === "ftyp") {
    return buffer.toString("ascii", 8, 12) === "qt  "
      ? "video/quicktime"
      : "video/mp4";
  }

  if (buffer[0] === 0x1a && buffer[1] === 0x45 && buffer[2] === 0xdf && buffer[3] === 0xa3) {
    return "video/webm";
  }

  return null;
}

function extractAvatarStoragePath(filePathOrUrl) {
  const marker = `/storage/v1/object/public/${AVATAR_BUCKET}/`;
  const markerIndex = filePathOrUrl.indexOf(marker);

  if (markerIndex !== -1) {
    const raw = filePathOrUrl.slice(markerIndex + marker.length).split("?")[0];

    try {
      return decodeURIComponent(raw);
    } catch {
      return null;
    }
  }

  if (!filePathOrUrl.startsWith("http")) return filePathOrUrl;

  return null;
}

function isOwnedAvatarPath(storagePath, userId) {
  if (typeof storagePath !== "string") return false;
  if (storagePath.includes("..")) return false;
  if (storagePath.startsWith("/")) return false;

  return storagePath.startsWith(`${userId}/`);
}

// ============================================================
// LIMITE DE CONCURRENCE DES UPLOADS
// ============================================================

const MAX_VIDEO_UPLOADS = Math.max(1, Number(env("MAX_VIDEO_UPLOADS") || 2));
const MAX_VIDEO_QUEUE = 10;
const VIDEO_QUEUE_TIMEOUT_MS = 60_000;

let activeVideoUploads = 0;
const videoUploadWaiters = [];

const busyError = () =>
  new HttpError(
    503,
    "Server is busy processing uploads. Try again shortly.",
    "UPLOAD_QUEUE_FULL"
  );

function acquireVideoSlot() {
  if (activeVideoUploads < MAX_VIDEO_UPLOADS) {
    activeVideoUploads++;
    return Promise.resolve();
  }

  if (videoUploadWaiters.length >= MAX_VIDEO_QUEUE) {
    return Promise.reject(busyError());
  }

  return new Promise((resolve, reject) => {
    const waiter = {
      resolve: () => {
        clearTimeout(waiter.timer);
        resolve();
      },
    };

    waiter.timer = setTimeout(() => {
      const index = videoUploadWaiters.indexOf(waiter);
      if (index !== -1) videoUploadWaiters.splice(index, 1);
      reject(busyError());
    }, VIDEO_QUEUE_TIMEOUT_MS);

    videoUploadWaiters.push(waiter);
  });
}

function releaseVideoSlot() {
  const next = videoUploadWaiters.shift();

  if (next) {
    next.resolve();
  } else {
    activeVideoUploads = Math.max(0, activeVideoUploads - 1);
  }
}

// ============================================================
// AUTHENTIFICATION (avec cache court)
// ============================================================

const AUTH_CACHE_TTL_MS = 20_000;
const AUTH_CACHE_MAX = 2_000;
const authCache = new Map();

function authCacheGet(token) {
  const key = sha256(token);
  const entry = authCache.get(key);

  if (!entry) return null;

  if (entry.expires <= Date.now()) {
    authCache.delete(key);
    return null;
  }

  return entry.user;
}

function authCacheSet(token, user) {
  if (authCache.size >= AUTH_CACHE_MAX) {
    authCache.delete(authCache.keys().next().value);
  }

  authCache.set(sha256(token), {
    user,
    expires: Date.now() + AUTH_CACHE_TTL_MS,
  });
}

function authCacheInvalidateUser(userId) {
  for (const [key, entry] of authCache) {
    if (entry.user?.id === userId) authCache.delete(key);
  }
}

setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of authCache) {
    if (entry.expires <= now) authCache.delete(key);
  }
}, 60_000).unref?.();

async function getAuthenticatedUser(req) {
  const authorization = req.headers.authorization;

  if (!authorization) {
    return {
      user: null,
      token: null,
      error: "Missing Authorization header",
      code: "NO_TOKEN",
    };
  }

  const token = authorization.replace(/^Bearer\s+/i, "").trim();

  if (!token || token.length > 4096) {
    return {
      user: null,
      token: null,
      error: "Missing access token",
      code: "NO_TOKEN",
    };
  }

  const cached = authCacheGet(token);
  if (cached) return { user: cached, token, error: null, code: null };

  const {
    data: { user },
    error,
  } = await supabase.auth.getUser(token);

  if (error || !user) {
    const isExpired = Boolean(error?.message?.toLowerCase().includes("expired"));

    return {
      user: null,
      token: null,
      error: isExpired ? "Session expired" : "Invalid or expired session",
      code: isExpired ? "TOKEN_EXPIRED" : "INVALID_TOKEN",
    };
  }

  authCacheSet(token, user);

  return { user, token, error: null, code: null };
}

async function adminUpdateUser(userId, attributes) {
  const result = await supabaseAdmin.auth.admin.updateUserById(userId, attributes);
  authCacheInvalidateUser(userId);
  return result;
}

// ============================================================
// JETON DE RÉCUPÉRATION
// ============================================================

function decodeJwtPayload(token) {
  try {
    const parts = String(token).split(".");
    if (parts.length !== 3) return null;

    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));

    return payload && typeof payload === "object" ? payload : null;
  } catch {
    return null;
  }
}

function isRecoverySessionToken(token) {
  const payload = decodeJwtPayload(token);
  if (!payload) return false;

  const amr = Array.isArray(payload.amr) ? payload.amr : [];

  const viaRecovery = amr.some(
    (entry) => entry?.method === "recovery" || entry?.method === "otp"
  );

  if (!viaRecovery) return false;

  const issuedAt = Number(payload.iat);
  if (!Number.isFinite(issuedAt)) return false;

  return Date.now() / 1000 - issuedAt <= RECOVERY_TOKEN_MAX_AGE_SEC;
}

// ============================================================
// MFA — AAL & FACTEURS (helpers)
// ============================================================

function isTotp(f) {
  return f?.factor_type === "totp" || f?.type === "totp";
}

function getTokenAal(token) {
  if (!token) return null;
  const payload = decodeJwtPayload(token);
  return typeof payload?.aal === "string" ? payload.aal : null;
}

function getTokenSessionId(token) {
  if (!token) return null;
  const sessionId = decodeJwtPayload(token)?.session_id;
  return typeof sessionId === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(sessionId)
    ? sessionId
    : null;
}

function userHasVerifiedMfa(user) {
  const factors = Array.isArray(user?.factors) ? user.factors : [];
  return factors.some((f) => f?.status === "verified" && isTotp(f));
}

function verifiedFactorsOf(user) {
  const factors = Array.isArray(user?.factors) ? user.factors : [];
  return factors.filter((f) => f?.status === "verified");
}

// ------------------------------------------------------------
// Fallback mémoire si la table `mfa_verified_sessions` n'existe pas encore
// ------------------------------------------------------------

const mfaVerifiedMemory = new Map();
const MFA_MEMORY_MAX = 10_000;

function readVerifiedMfaSessionMemory(userId, sessionId) {
  const key = `${userId}:${sessionId}`;
  const expires = mfaVerifiedMemory.get(key);
  if (!expires) return false;
  if (expires <= Date.now()) {
    mfaVerifiedMemory.delete(key);
    return false;
  }
  return true;
}

function writeVerifiedMfaSessionMemory(userId, sessionId) {
  if (mfaVerifiedMemory.size >= MFA_MEMORY_MAX) {
    mfaVerifiedMemory.delete(mfaVerifiedMemory.keys().next().value);
  }
  mfaVerifiedMemory.set(
    `${userId}:${sessionId}`,
    Date.now() + MFA_VERIFIED_SESSION_TTL_MINUTES * 60_000
  );
}

setInterval(() => {
  const now = Date.now();
  for (const [key, expires] of mfaVerifiedMemory) {
    if (expires <= now) mfaVerifiedMemory.delete(key);
  }
}, 60_000).unref?.();

async function hasVerifiedMfaSession(userId, sessionId) {
  if (!sessionId) return false;

  const now = new Date().toISOString();
  const { error: purgeError } = await supabaseAdmin
    .from("mfa_verified_sessions")
    .delete()
    .eq("user_id", userId)
    .lte("expires_at", now);

  if (purgeError) {
    if (isSchemaCacheMissingError(purgeError)) {
      return readVerifiedMfaSessionMemory(userId, sessionId);
    }
    throw dbError("mfa_verified_sessions.purge", purgeError);
  }

  const { data, error } = await supabaseAdmin
    .from("mfa_verified_sessions")
    .select("session_id")
    .eq("user_id", userId)
    .eq("session_id", sessionId)
    .gt("expires_at", now)
    .maybeSingle();

  if (error) {
    if (isSchemaCacheMissingError(error)) {
      return readVerifiedMfaSessionMemory(userId, sessionId);
    }
    throw dbError("mfa_verified_sessions.lookup", error);
  }
  return Boolean(data);
}

async function recordVerifiedMfaSession(userId, sessionId, method) {
  const now = new Date();
  const expiresAt = new Date(
    now.getTime() + MFA_VERIFIED_SESSION_TTL_MINUTES * 60_000
  );

  const { error } = await supabaseAdmin.from("mfa_verified_sessions").upsert(
    {
      user_id: userId,
      session_id: sessionId,
      method,
      verified_at: now.toISOString(),
      expires_at: expiresAt.toISOString(),
    },
    { onConflict: "user_id,session_id" }
  );

  if (error) {
    if (isSchemaCacheMissingError(error)) {
      writeVerifiedMfaSessionMemory(userId, sessionId);
      return;
    }
    throw dbError("mfa_verified_sessions.upsert", error);
  }
}

async function requireAal2(user, token) {
  if (!userHasVerifiedMfa(user)) return;
  if (getTokenAal(token) === "aal2") return;
  if (await hasVerifiedMfaSession(user.id, getTokenSessionId(token))) return;

  throw new HttpError(
    403,
    "Two-factor verification required. Complete the MFA challenge, then try again.",
    "MFA_REQUIRED"
  );
}

const RECOVERY_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

function recoveryCodeHash(code) {
  if (!RECOVERY_CODE_PEPPER || Buffer.byteLength(RECOVERY_CODE_PEPPER) < 32) {
    throw new HttpError(
      503,
      "Recovery codes are temporarily unavailable",
      "RECOVERY_CODES_UNAVAILABLE"
    );
  }

  return crypto
    .createHmac("sha256", RECOVERY_CODE_PEPPER)
    .update(code)
    .digest("hex");
}

function generateRecoveryCode() {
  const bytes = crypto.randomBytes(10);
  const raw = Array.from(bytes, (byte) => RECOVERY_CODE_ALPHABET[byte & 31]).join("");
  return `${raw.slice(0, 5)}-${raw.slice(5)}`;
}

async function getLatestRecoveryCodeBatch(userId) {
  const { data, error } = await supabaseAdmin
    .from("mfa_recovery_codes")
    .select("batch_id,created_at")
    .eq("user_id", userId)
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();

  if (error) throw dbError("mfa_recovery_codes.latest_batch", error);
  return data;
}

async function getRemainingRecoveryCodeCount(userId, batchId) {
  const { count, error } = await supabaseAdmin
    .from("mfa_recovery_codes")
    .select("id", { count: "exact", head: true })
    .eq("user_id", userId)
    .eq("batch_id", batchId)
    .is("used_at", null);

  if (error) throw dbError("mfa_recovery_codes.remaining_count", error);
  if (!Number.isSafeInteger(count)) {
    throw dbError("mfa_recovery_codes.remaining_count", new Error("Invalid row count"));
  }
  return count;
}

async function replaceRecoveryCodeBatch(userId, batchId, hashes) {
  const { error } = await supabaseAdmin.rpc("mfa_recovery_replace_codes", {
    p_user_id: userId,
    p_batch_id: batchId,
    p_code_hashes: hashes,
  });

  if (error) throw dbError("mfa_recovery_replace_codes", error);
}

function sendSecurityEmail(userId, type, meta = {}) {
  if (!userId || typeof type !== "string" || !type) {
    throw new Error("Invalid security email event");
  }

  void meta;
  console.warn(`[security-email] not sent: provider not configured (${type})`);
  return false;
}

const WEBAUTHN_ALLOWED_TRANSPORTS = new Set([
  "ble",
  "hybrid",
  "internal",
  "nfc",
  "smart-card",
  "usb",
]);

function validateWebAuthnResponse(response) {
  if (
    !response ||
    typeof response !== "object" ||
    Array.isArray(response) ||
    typeof response.id !== "string" ||
    response.id.length < 1 ||
    response.id.length > 2048 ||
    typeof response.rawId !== "string" ||
    response.rawId.length < 1 ||
    response.rawId.length > 2048 ||
    response.id !== response.rawId ||
    response.type !== "public-key" ||
    !response.response ||
    typeof response.response !== "object" ||
    Array.isArray(response.response)
  ) {
    throw new HttpError(400, "Invalid WebAuthn response", "INVALID_WEBAUTHN_RESPONSE");
  }

  if (Buffer.byteLength(JSON.stringify(response)) > 64 * 1024) {
    throw new HttpError(400, "Invalid WebAuthn response", "INVALID_WEBAUTHN_RESPONSE");
  }
}

function normalizedWebAuthnTransports(transports) {
  if (!Array.isArray(transports)) return [];
  return transports.filter(
    (transport) =>
      typeof transport === "string" && WEBAUTHN_ALLOWED_TRANSPORTS.has(transport)
  );
}

function requireTotpForPasskey(user) {
  if (!userHasVerifiedMfa(user)) {
    throw new HttpError(400, "Enable an authenticator before using passkeys", "MFA_NOT_ENABLED");
  }
}

async function createWebAuthnChallenge(userId, sessionId, purpose, challenge) {
  const { error } = await supabaseAdmin.rpc("webauthn_create_challenge", {
    p_user_id: userId,
    p_session_id: sessionId,
    p_purpose: purpose,
    p_challenge: challenge,
  });

  if (error) throw dbError("webauthn_create_challenge", error);
}

async function consumeWebAuthnChallenge(userId, sessionId, purpose) {
  const { data, error } = await supabaseAdmin.rpc("webauthn_consume_challenge", {
    p_user_id: userId,
    p_session_id: sessionId,
    p_purpose: purpose,
  });

  if (error) throw dbError("webauthn_consume_challenge", error);
  if (!Array.isArray(data) || typeof data[0]?.challenge !== "string") {
    throw new HttpError(400, "WebAuthn challenge is invalid or expired", "INVALID_WEBAUTHN_CHALLENGE");
  }
  return data[0].challenge;
}

async function getWebAuthnCredentials(userId) {
  const { data, error } = await supabaseAdmin
    .from("webauthn_credentials")
    .select("id,credential_id,transports,name,created_at,last_used_at")
    .eq("user_id", userId)
    .order("created_at", { ascending: true });

  if (error) throw dbError("webauthn_credentials.list", error);
  if (!Array.isArray(data)) {
    throw dbError("webauthn_credentials.list", new Error("Invalid row list"));
  }
  return data;
}

// ============================================================
// MFA — DETECTION PASSWORD VS OAUTH
// ============================================================

function userHasPassword(user) {
  const identities = Array.isArray(user?.identities) ? user.identities : [];
  if (identities.length === 0) return true;
  return identities.some((i) => i?.provider === "email");
}

function userPrimaryProvider(user) {
  const identities = Array.isArray(user?.identities) ? user.identities : [];
  const external = identities.find((i) => i?.provider && i.provider !== "email");
  return external?.provider || "email";
}

// ============================================================
// MFA — PROXY SUPABASE AUTH
// ============================================================

async function supabaseAuthRequest(pathname, { method = "GET", token, json } = {}) {
  const headers = {
    apikey: SUPABASE_ANON_KEY,
    Authorization: `Bearer ${token}`,
    "X-Client-Info": "stone-server/1.0",
  };
  let body;

  if (json) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(json);
  }

  let result;

  try {
    result = await fetchJson(
      `${SUPABASE_AUTH_BASE}${pathname}`,
      { method, headers, body },
      20_000
    );
  } catch (error) {
    throw upstreamError("Supabase Auth", error);
  }

  const { response, data } = result;

  if (!response.ok) {
    const msg =
      data?.msg ||
      data?.message ||
      data?.error_description ||
      (typeof data?.error === "string" ? data.error : null) ||
      `Supabase Auth error (HTTP ${response.status})`;

    throw new HttpError(
      response.status === 429 ? 429 : response.status >= 500 ? 502 : 400,
      msg,
      data?.error_code || data?.code || "SUPABASE_AUTH_ERROR"
    );
  }

  return data;
}

function toPublicFactor(f) {
  return {
    id: f.id,
    friendlyName: f.friendly_name || f.friendlyName || null,
    friendly_name: f.friendly_name || f.friendlyName || null,
    factorType: f.type || f.factor_type || "totp",
    status: f.status || "unverified",
    createdAt: f.created_at || f.createdAt || null,
    created_at: f.created_at || f.createdAt || null,
  };
}

async function verifyMfaCode(factorId, code, token) {
  const challenge = await supabaseAuthRequest(
    `/factors/${encodeURIComponent(factorId)}/challenge`,
    { method: "POST", token, json: {} }
  );

  const challengeId = challenge?.id;
  if (!challengeId) {
    throw new HttpError(
      502,
      "Supabase did not return a challenge",
      "MFA_NO_CHALLENGE"
    );
  }

  const verify = await supabaseAuthRequest(
    `/factors/${encodeURIComponent(factorId)}/verify`,
    {
      method: "POST",
      token,
      json: { challenge_id: challengeId, code },
    }
  );

  if (!verify?.access_token || !verify?.refresh_token) {
    throw new HttpError(
      502,
      "Supabase did not return a session",
      "MFA_NO_SESSION"
    );
  }

  const aal = getTokenAal(verify.access_token);
  if (aal !== "aal2") {
    console.warn(`[mfa] verify returned aal=${aal} instead of aal2`);
  }

  return verify;
}

async function verifyMfaCodeWithAttempts(factorId, code, token, attemptKey) {
  try {
    const session = await verifyMfaCode(factorId, code, token);
    await resetAuthAttemptFailures(attemptKey);
    return session;
  } catch (error) {
    if (!(error instanceof HttpError) || error.status !== 400) throw error;

    await recordAuthAttemptFailure(attemptKey);
    throw new HttpError(400, "Invalid authenticator code", "INVALID_MFA_CODE");
  }
}

// ============================================================
// NORMALISATION UTILISATEUR
// ============================================================

function resolveAvatar(metadata) {
  if (typeof metadata.custom_avatar_url === "string") {
    return metadata.custom_avatar_url;
  }

  return metadata.avatar_url || metadata.avatarUrl || metadata.picture || "";
}

function formatUser(user) {
  if (!user) return null;

  const metadata = user.user_metadata || {};
  const hasPassword = userHasPassword(user);
  const provider = userPrimaryProvider(user);

  const fullName = metadata.full_name || metadata.name || "";
  const [guessedFirst, ...guessedRest] = fullName.split(" ").filter(Boolean);

  return {
    id: user.id,
    email: user.email || "",
    first_name:
      metadata.first_name ||
      metadata.firstName ||
      metadata.given_name ||
      guessedFirst ||
      "",
    last_name:
      metadata.last_name ||
      metadata.lastName ||
      metadata.family_name ||
      guessedRest.join(" ") ||
      "",
    avatar_url: resolveAvatar(metadata),
    bio: metadata.bio || "",
    email_confirmed_at: user.email_confirmed_at || null,
    created_at: user.created_at || null,
    subscription: user.app_metadata?.subscription || null,
    mfa_enabled: userHasVerifiedMfa(user),
    hasPassword,
    provider,
  };
}

const sessionPayload = (session) =>
  session
    ? {
        access_token: session.access_token,
        refresh_token: session.refresh_token,
      }
    : null;

// ============================================================
// APP_METADATA
// ============================================================

async function getAppMetadata(userId) {
  const { data, error } = await supabaseAdmin.auth.admin.getUserById(userId);

  if (error) {
    if (error.status === 404 || /not found/i.test(error.message || "")) {
      throw new HttpError(404, "User not found", "USER_NOT_FOUND");
    }

    throw dbError("auth.admin.getUserById", error);
  }

  if (!data?.user) {
    throw new HttpError(404, "User not found", "USER_NOT_FOUND");
  }

  return data.user.app_metadata || {};
}

function updateAppMetadata(userId, mutate) {
  return runSerial(`app-metadata:${userId}`, async () => {
    const current = await getAppMetadata(userId);
    const next = mutate(current);

    if (next === null || next === undefined) return current;

    const { error } = await adminUpdateUser(userId, { app_metadata: next });

    if (error) throw dbError("auth.admin.updateUserById(app_metadata)", error);

    return next;
  });
}

// ============================================================
// STRIPE — HELPERS
// ============================================================

function requireStripe() {
  if (!stripe) throw new HttpError(500, "Stripe is not configured");
}

const isStripeMissing = (error) => error?.code === "resource_missing";

async function getStripeCustomerId(user, { create = false } = {}) {
  const trusted = user.app_metadata?.stripe_customer_id;
  if (trusted) return trusted;

  const legacy = user.user_metadata?.stripe_customer_id;

  if (legacy) {
    try {
      const customer = await stripe.customers.retrieve(legacy);

      if (
        customer &&
        !customer.deleted &&
        customer.metadata?.supabase_user_id === user.id
      ) {
        try {
          await updateAppMetadata(user.id, (current) => ({
            ...current,
            stripe_customer_id: legacy,
          }));
        } catch (saveError) {
          console.error(
            "Legacy Stripe customer migration not saved:",
            saveError.message
          );
        }

        return legacy;
      }
    } catch (error) {
      console.warn("Legacy Stripe customer check failed:", error.message);
    }
  }

  if (!create) return null;

  return withLock(`stripe-customer:${user.id}`, async () => {
    const fresh = await getAppMetadata(user.id);
    if (fresh.stripe_customer_id) return fresh.stripe_customer_id;

    let customerId = null;

    try {
      const found = await stripe.customers.search({
        query: `metadata['supabase_user_id']:'${user.id}'`,
        limit: 1,
      });

      customerId = found.data[0]?.id || null;
    } catch (searchError) {
      console.warn("Stripe customer search failed:", searchError.message);
    }

    if (!customerId) {
      const customer = await stripe.customers.create({
        email: user.email,
        metadata: { supabase_user_id: user.id },
      });

      customerId = customer.id;
    }

    try {
      await updateAppMetadata(user.id, (current) => ({
        ...current,
        stripe_customer_id: customerId,
      }));
    } catch (saveError) {
      console.error(
        `Stripe customer ${customerId} exists but could not be saved for user ${user.id}:`,
        saveError.message
      );
      throw saveError;
    }

    return customerId;
  });
}

async function resolveUserIdFromCustomer(customerId) {
  if (!customerId) return null;

  const id = typeof customerId === "string" ? customerId : customerId.id;

  try {
    const customer = await stripe.customers.retrieve(id);

    if (customer && !customer.deleted) {
      return customer.metadata?.supabase_user_id || null;
    }

    return null;
  } catch (error) {
    if (isStripeMissing(error)) return null;
    throw error;
  }
}

function subscriptionSnapshot(subscription) {
  const price = subscription.items?.data?.[0]?.price;

  return {
    id: subscription.id,
    status: subscription.status,
    price_id: price?.id || null,
    product_id: price?.product || null,
    ...planDetails(price?.id, subscription.metadata?.plan),
    current_period_end: subscription.current_period_end,
    cancel_at_period_end: subscription.cancel_at_period_end,
    customer_id:
      typeof subscription.customer === "string"
        ? subscription.customer
        : subscription.customer?.id || null,
  };
}

const TERMINAL_SUBSCRIPTION_STATUSES = new Set([
  "canceled",
  "incomplete_expired",
]);

async function syncSubscriptionToUser(
  userId,
  subscription,
  { eventCreated = 0, overrides = {} } = {}
) {
  const snapshot = { ...subscriptionSnapshot(subscription), ...overrides };
  let written = false;

  await updateAppMetadata(userId, (current) => {
    const lastEventAt = Number(current.subscription_event_at || 0);

    if (eventCreated && eventCreated < lastEventAt) return null;

    const stored = current.subscription;

    if (
      stored?.id &&
      stored.id !== snapshot.id &&
      !TERMINAL_SUBSCRIPTION_STATUSES.has(stored.status) &&
      TERMINAL_SUBSCRIPTION_STATUSES.has(snapshot.status)
    ) {
      return null;
    }

    written = true;

    return {
      ...current,
      subscription: snapshot,
      subscription_event_at: Math.max(lastEventAt, eventCreated || 0),
    };
  });

  return written;
}

async function retrieveSubscription(subscriptionId, fallback) {
  try {
    return await stripe.subscriptions.retrieve(subscriptionId);
  } catch (error) {
    if (isStripeMissing(error) && fallback) return fallback;
    throw error;
  }
}

const idOf = (value) =>
  typeof value === "string" ? value : value?.id || null;

async function processStripeEvent(event) {
  const eventCreated = Number(event.created) || 0;

  try {
    switch (event.type) {
      case "checkout.session.completed": {
        const session = event.data.object;
        const subscriptionId = idOf(session.subscription);

        if (session.mode !== "subscription" || !subscriptionId) break;

        const userId =
          session.client_reference_id ||
          (await resolveUserIdFromCustomer(session.customer));

        if (userId) {
          const subscription = await retrieveSubscription(subscriptionId);
          await syncSubscriptionToUser(userId, subscription, { eventCreated });
        }
        break;
      }

      case "customer.subscription.created":
      case "customer.subscription.updated":
      case "customer.subscription.deleted": {
        const payload = event.data.object;
        const userId = await resolveUserIdFromCustomer(payload.customer);

        if (userId) {
          const subscription = await retrieveSubscription(payload.id, payload);
          await syncSubscriptionToUser(userId, subscription, { eventCreated });
        }
        break;
      }

      case "invoice.payment_failed": {
        const invoice = event.data.object;
        const subscriptionId = idOf(invoice.subscription);

        if (!subscriptionId) break;

        const userId = await resolveUserIdFromCustomer(invoice.customer);
        if (!userId) break;

        const [freshInvoice, subscription] = await Promise.all([
          stripe.invoices.retrieve(invoice.id),
          stripe.subscriptions.retrieve(subscriptionId),
        ]);

        const stillUnpaid = freshInvoice.status === "open";
        const liveStatus = subscription.status;

        await syncSubscriptionToUser(userId, subscription, {
          eventCreated,
          overrides:
            stillUnpaid && (liveStatus === "active" || liveStatus === "trialing")
              ? { status: "past_due" }
              : {},
        });
        break;
      }

      case "invoice.payment_succeeded": {
        const invoice = event.data.object;
        const subscriptionId = idOf(invoice.subscription);

        if (!subscriptionId) break;

        const userId = await resolveUserIdFromCustomer(invoice.customer);
        if (!userId) break;

        const subscription = await retrieveSubscription(subscriptionId);
        await syncSubscriptionToUser(userId, subscription, { eventCreated });
        break;
      }

      default:
        break;
    }
  } catch (error) {
    if (error instanceof HttpError && error.code === "USER_NOT_FOUND") {
      console.warn(
        `[stripe:webhook] ${event.id} (${event.type}) ignoré : utilisateur introuvable`
      );
      return;
    }

    throw error;
  }
}

// ============================================================
// STATE OAUTH SIGNÉ
// ============================================================

function hmac(value) {
  return crypto
    .createHmac("sha256", OAUTH_STATE_SECRET)
    .update(value)
    .digest("hex");
}

function createOAuthState(provider, userId) {
  const payload = `${provider}.${userId}.${Date.now() + 10 * 60 * 1000}.${crypto
    .randomBytes(8)
    .toString("hex")}`;

  return Buffer.from(`${payload}.${hmac(payload)}`).toString("base64url");
}

function checkOAuthState(provider, state, userId) {
  if (!state) return "missing_state";

  try {
    const decoded = Buffer.from(String(state), "base64url").toString("utf-8");
    const lastDot = decoded.lastIndexOf(".");

    if (lastDot === -1) return "malformed_state";

    const payload = decoded.slice(0, lastDot);
    const signature = decoded.slice(lastDot + 1);

    const a = Buffer.from(signature);
    const b = Buffer.from(hmac(payload));

    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return "bad_signature";
    }

    const [stateProvider, stateUserId, expiresAt] = payload.split(".");

    if (stateProvider !== provider) return "wrong_provider";
    if (stateUserId !== userId) return "wrong_user";
    if (!(Number(expiresAt) > Date.now())) return "expired";

    return null;
  } catch {
    return "malformed_state";
  }
}

function assertValidOAuthCallback(provider, body, userId) {
  const code = String(body.code || "");

  let reason = null;
  if (!code) reason = "missing_code";
  else if (code.length > 2048) reason = "code_too_long";
  else reason = checkOAuthState(provider, body.state, userId);

  if (reason) {
    console.warn(`[oauth:${provider}] callback rejeté (${reason})`);
    throw new HttpError(400, "Invalid or expired state", "OAUTH_STATE_INVALID");
  }

  return code;
}

// ============================================================
// TOKENS OAUTH — LECTURE / ÉCRITURE
// ============================================================

async function selectTokenRow(table, userId) {
  const { data, error } = await supabaseAdmin
    .from(table)
    .select("*")
    .eq("user_id", userId)
    .maybeSingle();

  if (error) throw dbError(`${table} select`, error);

  return decryptTokenRow(data);
}

function isTokenFresh(account) {
  return Boolean(
    account?.access_token &&
      new Date(account.access_expires_at).getTime() > Date.now() + 60_000
  );
}

const isPast = (value) => new Date(value).getTime() <= Date.now();

async function updateTokensIfUnchanged(table, userId, account, row) {
  let query = supabaseAdmin.from(table).update(row).eq("user_id", userId);

  query = account.updated_at
    ? query.eq("updated_at", account.updated_at)
    : query.is("updated_at", null);

  const { data, error } = await query.select("user_id");

  if (error) throw dbError(`${table} update`, error);

  return Array.isArray(data) && data.length > 0;
}

const iso = (ms) => new Date(ms).toISOString();

// ============================================================
// TIKTOK — APPEL API
// ============================================================

const TIKTOK_FRIENDLY_ERRORS = {
  unaudited_client_can_only_post_to_private_accounts:
    "Mode sandbox : TikTok n'accepte que des posts privés (SELF_ONLY) tant que l'app n'est pas auditée.",
  url_ownership_unverified:
    "TikTok could not verify the media URL prefix. Check PUBLIC_API_URL.",
  spam_risk_too_many_posts: "TikTok daily posting limit reached.",
  spam_risk_user_banned_from_posting: "This TikTok account cannot post right now.",
  reached_active_user_cap: "TikTok daily user cap reached for this app.",
  app_version_check_failed:
    "Please update your TikTok app to the latest version to use this feature.",
  access_denied:
    "Connection refused by TikTok. In sandbox mode, add the TikTok account as a Sandbox tester.",
};

async function tiktokApi(pathname, { method = "POST", token, json, form } = {}) {
  const headers = {};
  let body;

  if (token) headers.Authorization = `Bearer ${token}`;

  if (form) {
    headers["Content-Type"] = "application/x-www-form-urlencoded";
    body = new URLSearchParams(form).toString();
  } else if (json) {
    headers["Content-Type"] = "application/json; charset=UTF-8";
    body = JSON.stringify(json);
  }

  let result;

  try {
    result = await fetchJson(`${TIKTOK_API}${pathname}`, { method, headers, body }, 20_000);
  } catch (error) {
    throw upstreamError("TikTok", error);
  }

  const { response, data } = result;

  if (typeof data.error === "string") {
    throw new HttpError(400, data.error_description || data.error, data.error);
  }

  if (data.error?.code && data.error.code !== "ok") {
    throw new HttpError(
      400,
      TIKTOK_FRIENDLY_ERRORS[data.error.code] || data.error.message || data.error.code,
      data.error.code
    );
  }

  if (!response.ok) {
    throw new HttpError(upstreamStatus(response.status), `TikTok error (HTTP ${response.status})`, "TIKTOK_UPSTREAM");
  }

  return data;
}

// ============================================================
// TIKTOK — TOKENS
// ============================================================

const TIKTOK_PROFILE_REFRESH_MS = 30 * 60 * 1000;
const TIKTOK_PROFILE_MIN_INTERVAL_MS = 10 * 1000;
const TIKTOK_PROFILE_TRANSIENT_RETRY_MS = 30 * 1000;
const TIKTOK_PROFILE_DEAD_RETRY_MS = 5 * 60 * 1000;

const tiktokProfileRefreshedAt = new Map();
const tiktokProfileRetryAt = new Map();

function clearTikTokProfileThrottle(userId) {
  tiktokProfileRefreshedAt.delete(userId);
  tiktokProfileRetryAt.delete(userId);
}

function buildTikTokTokenRow(t) {
  const now = Date.now();
  const accessTtl = Number(t.expires_in) || 24 * 60 * 60;

  const row = {
    access_token: encryptSecret(t.access_token),
    access_expires_at: iso(now + accessTtl * 1000),
    updated_at: new Date().toISOString(),
  };

  if (t.open_id) row.open_id = t.open_id;
  if (t.refresh_token) row.refresh_token = encryptSecret(t.refresh_token);

  const refreshTtl = Number(t.refresh_expires_in);
  if (Number.isFinite(refreshTtl) && refreshTtl > 0) {
    row.refresh_expires_at = iso(now + refreshTtl * 1000);
  }

  if (t.scope) row.scope = t.scope;

  return row;
}

async function saveTikTokTokens(userId, t, extra = {}) {
  const { error } = await supabaseAdmin.from("tiktok_accounts").upsert(
    { user_id: userId, ...buildTikTokTokenRow(t), ...extra },
    { onConflict: "user_id" }
  );

  if (error) throw new Error(error.message);

  clearTikTokProfileThrottle(userId);
}

async function getTikTokAccount(userId) {
  return selectTokenRow("tiktok_accounts", userId);
}

async function getValidTikTokToken(userId) {
  const notConnected = () =>
    new HttpError(400, "TikTok account not connected", "TIKTOK_NOT_CONNECTED");

  const first = await getTikTokAccount(userId);
  if (!first) throw notConnected();
  if (isTokenFresh(first)) return first.access_token;

  return withLock(`tiktok-refresh:${userId}`, async () => {
    for (let attempt = 0; attempt < 2; attempt++) {
      const account = await getTikTokAccount(userId);

      if (!account) throw notConnected();
      if (isTokenFresh(account)) return account.access_token;

      if (!account.refresh_token || isPast(account.refresh_expires_at)) {
        throw reconnectError("TikTok", "TIKTOK_REFRESH_EXPIRED");
      }

      let refreshed;

      try {
        refreshed = await tiktokApi("/v2/oauth/token/", {
          form: {
            client_key: TIKTOK_CLIENT_KEY,
            client_secret: TIKTOK_CLIENT_SECRET,
            grant_type: "refresh_token",
            refresh_token: account.refresh_token,
          },
        });
      } catch (error) {
        if (error instanceof HttpError && error.code === "invalid_grant") {
          throw reconnectError("TikTok", "TIKTOK_REFRESH_EXPIRED");
        }
        throw error;
      }

      if (!refreshed?.access_token) {
        throw new HttpError(502, "TikTok returned an invalid token response", "TIKTOK_BAD_TOKEN_RESPONSE");
      }

      const applied = await updateTokensIfUnchanged(
        "tiktok_accounts",
        userId,
        account,
        buildTikTokTokenRow(refreshed)
      );

      if (applied) return refreshed.access_token;
    }

    throw new HttpError(409, "TikTok account changed during token refresh, please retry", "TIKTOK_REFRESH_CONFLICT");
  });
}

async function refreshTikTokProfile(userId, { force = false } = {}) {
  const lockKey = `tiktok-profile:${userId}:${force ? "force" : "normal"}`;

  return withLock(lockKey, async () => {
    const account = await getTikTokAccount(userId);
    if (!account) return { account: null, needsReconnect: false };

    const now = Date.now();
    const retryAt = tiktokProfileRetryAt.get(userId) || 0;

    if (now < retryAt) return { account, needsReconnect: false };

    const last = tiktokProfileRefreshedAt.get(userId) || 0;
    if (!force && now - last < TIKTOK_PROFILE_REFRESH_MS) {
      return { account, needsReconnect: false };
    }

    if (tiktokProfileRefreshedAt.size > 10_000) {
      tiktokProfileRefreshedAt.delete(tiktokProfileRefreshedAt.keys().next().value);
    }
    if (tiktokProfileRetryAt.size > 10_000) {
      tiktokProfileRetryAt.delete(tiktokProfileRetryAt.keys().next().value);
    }

    try {
      const accessToken = await getValidTikTokToken(userId);

      const info = await tiktokApi(
        "/v2/user/info/?fields=open_id,avatar_url,display_name",
        { method: "GET", token: accessToken }
      );

      const profile = info.data?.user;

      if (!profile?.avatar_url || !/^https:\/\//i.test(profile.avatar_url)) {
        tiktokProfileRefreshedAt.set(userId, now);
        tiktokProfileRetryAt.set(userId, now + TIKTOK_PROFILE_MIN_INTERVAL_MS);
        return { account, needsReconnect: false };
      }

      const displayName = profile.display_name || account.display_name;

      const { error } = await supabaseAdmin
        .from("tiktok_accounts")
        .update({ avatar_url: profile.avatar_url, display_name: displayName })
        .eq("user_id", userId);

      if (error) {
        tiktokProfileRetryAt.set(userId, now + TIKTOK_PROFILE_TRANSIENT_RETRY_MS);
        return { account, needsReconnect: false };
      }

      tiktokProfileRefreshedAt.set(userId, now);
      tiktokProfileRetryAt.set(userId, now + TIKTOK_PROFILE_MIN_INTERVAL_MS);

      return {
        account: { ...account, avatar_url: profile.avatar_url, display_name: displayName },
        needsReconnect: false,
      };
    } catch (error) {
      if (
        error instanceof HttpError &&
        (error.code === "TIKTOK_REFRESH_EXPIRED" || error.code === "TIKTOK_NOT_CONNECTED")
      ) {
        tiktokProfileRetryAt.set(userId, now + TIKTOK_PROFILE_DEAD_RETRY_MS);
        return { account, needsReconnect: true };
      }

      tiktokProfileRetryAt.set(userId, now + TIKTOK_PROFILE_TRANSIENT_RETRY_MS);
      return { account, needsReconnect: false };
    }
  });
}

// ============================================================
// TIKTOK — UPLOAD
// ============================================================

function computeChunking(size) {
  const MB = 1024 * 1024;

  if (size <= 64 * MB) return { chunkSize: size, totalChunks: 1 };

  const chunkSize = 10 * MB;
  return { chunkSize, totalChunks: Math.ceil(size / chunkSize) };
}

async function putChunk(uploadUrl, part, mimeType, start, end, total) {
  const MAX_ATTEMPTS = 3;
  let lastError;

  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    try {
      const { response } = await fetchJson(
        uploadUrl,
        {
          method: "PUT",
          headers: {
            "Content-Type": mimeType,
            "Content-Range": `bytes ${start}-${end}/${total}`,
          },
          body: part,
        },
        120_000
      );

      if (response.ok || response.status === 206) return;

      if (response.status >= 400 && response.status < 500 && response.status !== 429) {
        throw new HttpError(502, `TikTok upload rejected (HTTP ${response.status})`, "TIKTOK_UPLOAD_REJECTED");
      }

      lastError = new Error(`HTTP ${response.status}`);
    } catch (error) {
      if (error instanceof HttpError && error.code === "TIKTOK_UPLOAD_REJECTED") throw error;
      lastError = error;
    }

    if (attempt < MAX_ATTEMPTS) await delay(attempt * 1000);
  }

  throw new HttpError(502, "TikTok upload failed, please retry", "TIKTOK_UPLOAD_FAILED");
}

async function uploadVideoToTikTok(uploadUrl, buffer, mimeType, chunking) {
  const { chunkSize, totalChunks } = chunking;

  for (let i = 0; i < totalChunks; i++) {
    const start = i * chunkSize;
    const end = i === totalChunks - 1 ? buffer.length - 1 : start + chunkSize - 1;
    const part = buffer.subarray(start, end + 1);

    await putChunk(uploadUrl, part, mimeType, start, end, buffer.length);
  }
}

// ============================================================
// TIKTOK — MODES / PRIVACY
// ============================================================

function resolvePrivacy(requested) {
  if (TIKTOK_SANDBOX || TIKTOK_FORCE_DRAFT) return "SELF_ONLY";
  const value = String(requested || "SELF_ONLY");
  return TIKTOK_PRIVACY_LEVELS.has(value) ? value : "SELF_ONLY";
}

function resolveVideoMode(requested) {
  if (TIKTOK_SANDBOX || TIKTOK_FORCE_DRAFT) return "draft";
  return requested === "draft" ? "draft" : "direct";
}

function brandFlags(fields, privacy) {
  const content = toBool(fields.brand_content_toggle);
  const organic = toBool(fields.brand_organic_toggle);

  if ((content || organic) && privacy === "SELF_ONLY") {
    throw new HttpError(
      400,
      "Branded content visibility cannot be set to private" +
        (TIKTOK_SANDBOX ? " (mode sandbox : SELF_ONLY forcé)" : ""),
      "BRANDED_CONTENT_PRIVATE"
    );
  }

  return content || organic
    ? { brand_content_toggle: content, brand_organic_toggle: organic }
    : {};
}

function buildPostInfo(fields) {
  const privacy = resolvePrivacy(fields.privacy_level);

  return {
    title: String(fields.title || "").slice(0, 2200),
    privacy_level: privacy,
    disable_comment: toBool(fields.disable_comment),
    disable_duet: toBool(fields.disable_duet),
    disable_stitch: toBool(fields.disable_stitch),
    ...brandFlags(fields, privacy),
  };
}

async function initTikTokPublish(accessToken, mode, postInfoFields, sourceInfo) {
  return mode === "draft"
    ? tiktokApi("/v2/post/publish/inbox/video/init/", {
        token: accessToken,
        json: { source_info: sourceInfo },
      })
    : tiktokApi("/v2/post/publish/video/init/", {
        token: accessToken,
        json: { post_info: buildPostInfo(postInfoFields), source_info: sourceInfo },
      });
}

const TIKTOK_PUBLISH_ID_PATTERN = /^[\w.:~-]+$/;
const TIKTOK_PUBLISH_ID_MAX = 64;

function isValidTikTokPublishId(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= TIKTOK_PUBLISH_ID_MAX &&
    TIKTOK_PUBLISH_ID_PATTERN.test(value)
  );
}

// ============================================================
// TIKTOK — PHOTOS
// ============================================================

async function ensureTikTokMediaBucket() {
  const { error } = await supabaseAdmin.storage.createBucket(TIKTOK_MEDIA_BUCKET, { public: false });

  if (error && !/already exists|duplicate/i.test(error.message || "")) {
    console.warn("TikTok media bucket:", error.message);
  }
}

// ------------------------------------------------------------
// ✅ NOUVEAU — bucket public pour les médias de posts planifiés
// ------------------------------------------------------------
async function ensurePostMediaBucket() {
  const { error } = await supabaseAdmin.storage.createBucket(POST_MEDIA_BUCKET, { public: true });

  if (error && !/already exists|duplicate/i.test(error.message || "")) {
    console.warn("Post media bucket:", error.message);
  }
}

async function sweepTikTokMedia() {
  try {
    const { data, error } = await supabaseAdmin.storage
      .from(TIKTOK_MEDIA_BUCKET)
      .list("", { limit: 1000 });

    if (error || !data) return;

    const cutoff = Date.now() - TIKTOK_MEDIA_TTL_MS;

    const stale = data
      .filter(
        (file) =>
          /^[a-f0-9]{32}\.(jpg|webp)$/.test(file.name || "") &&
          file.created_at &&
          new Date(file.created_at).getTime() < cutoff
      )
      .map((file) => file.name);

    if (stale.length > 0) {
      await supabaseAdmin.storage.from(TIKTOK_MEDIA_BUCKET).remove(stale);
    }
  } catch (error) {
    console.warn("TikTok media sweep failed:", error?.message || error);
  }
}

async function removeTikTokPhotos(names) {
  try {
    await supabaseAdmin.storage.from(TIKTOK_MEDIA_BUCKET).remove(names);
  } catch {
    // balayage périodique
  }
}

async function storeTikTokPhotos(photos) {
  const names = photos.map(
    (photo) =>
      `${crypto.randomBytes(16).toString("hex")}.${
        photo.type === "image/webp" ? "webp" : "jpg"
      }`
  );

  try {
    const BATCH = 6;

    for (let i = 0; i < photos.length; i += BATCH) {
      await Promise.all(
        photos.slice(i, i + BATCH).map(async (photo, offset) => {
          const { error } = await supabaseAdmin.storage
            .from(TIKTOK_MEDIA_BUCKET)
            .upload(names[i + offset], photo.buffer, {
              contentType: photo.type,
              cacheControl: "3600",
              upsert: false,
            });

          if (error) throw error;
        })
      );
    }
  } catch (error) {
    await removeTikTokPhotos(names);
    throw error;
  }

  return names;
}

async function serveTikTokMedia(req, res, fileName) {
  if (req.method === "HEAD") {
    res.writeHead(200, {
      "Content-Type": fileName.endsWith(".webp") ? "image/webp" : "image/jpeg",
      "Content-Disposition": "inline",
      "Accept-Ranges": "none",
      "Cache-Control": "public, max-age=3600",
    });
    res.end();
    return;
  }

  const { data, error } = await supabaseAdmin.storage.from(TIKTOK_MEDIA_BUCKET).download(fileName);

  if (error || !data) {
    sendJson(res, 404, { success: false, error: "Not found" });
    return;
  }

  const buffer = Buffer.from(await data.arrayBuffer());

  res.writeHead(200, {
    "Content-Type": fileName.endsWith(".webp") ? "image/webp" : "image/jpeg",
    "Content-Length": buffer.length,
    "Content-Disposition": "inline",
    "Accept-Ranges": "none",
    "Cache-Control": "public, max-age=3600",
  });

  res.end(buffer);
}

async function probePublicPhoto(imageUrl, index = 1, total = 1) {
  const label = total > 1 ? ` (photo ${index}/${total})` : "";

  let status = null;
  let contentType = null;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8_000);

    try {
      const response = await fetch(imageUrl, {
        method: "HEAD",
        signal: controller.signal,
        redirect: "manual",
      });

      status = response.status;
      contentType = response.headers.get("content-type");
    } finally {
      clearTimeout(timer);
    }
  } catch {
    throw new HttpError(502, `The photo URL is not reachable${label}. Check PUBLIC_API_URL.`, "PHOTO_URL_UNREACHABLE");
  }

  const okType = /^image\/(jpeg|webp)/i.test(contentType || "");

  if (status !== 200 || !okType) {
    throw new HttpError(502, `Invalid image${label} (HTTP ${status}, ${contentType || "no content-type"})`, "PHOTO_URL_INVALID");
  }
}

async function probePublicPhotos(imageUrls) {
  if (env("TIKTOK_SKIP_PHOTO_PROBE") === "1") return;

  const BATCH = 6;

  for (let i = 0; i < imageUrls.length; i += BATCH) {
    await Promise.all(
      imageUrls
        .slice(i, i + BATCH)
        .map((url, offset) => probePublicPhoto(url, i + offset + 1, imageUrls.length))
    );
  }
}

function buildPhotoPostInfo(mode, fields) {
  const caption = String(fields.title || "").trim();

  const postInfo = {
    title: caption.slice(0, 90),
    description: caption.slice(0, 4000),
  };

  if (mode !== "draft") {
    const privacy = resolvePrivacy(fields.privacy_level);

    postInfo.privacy_level = privacy;
    postInfo.disable_comment = toBool(fields.disable_comment);
    postInfo.auto_add_music = true;

    Object.assign(postInfo, brandFlags(fields, privacy));
  }

  return postInfo;
}

function resolvePhotoMode(requested) {
  if (TIKTOK_SANDBOX || TIKTOK_FORCE_DRAFT) return "draft";
  return requested === "draft" ? "draft" : "direct";
}

function initTikTokPhotoPublish(accessToken, mode, postInfo, imageUrls, coverIndex) {
  const payload = {
    post_info: postInfo,
    source_info: {
      source: "PULL_FROM_URL",
      photo_cover_index: coverIndex,
      photo_images: imageUrls,
    },
    post_mode: mode === "draft" ? "MEDIA_UPLOAD" : "DIRECT_POST",
    media_type: "PHOTO",
  };

  return tiktokApi("/v2/post/publish/content/init/", {
    token: accessToken,
    json: payload,
  });
}

// ============================================================
// PINTEREST
// ============================================================

async function pinterestApi(
  pathname,
  { method = "GET", base = PINTEREST_API_BASE, token, basic = false, form, json } = {}
) {
  const headers = { Accept: "application/json" };
  let body;

  if (basic) {
    headers.Authorization = `Basic ${Buffer.from(`${PINTEREST_APP_ID}:${PINTEREST_APP_SECRET}`).toString("base64")}`;
  } else if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  if (form) {
    headers["Content-Type"] = "application/x-www-form-urlencoded";
    body = new URLSearchParams(form).toString();
  } else if (json) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(json);
  }

  let result;

  try {
    result = await fetchJson(`${base}${pathname}`, { method, headers, body }, 20_000);
  } catch (error) {
    throw upstreamError("Pinterest", error);
  }

  const { response, data } = result;

  if (!response.ok) {
    const error = new HttpError(
      upstreamStatus(response.status),
      data.message ||
        data.error_description ||
        (typeof data.error === "string" ? data.error : "") ||
        `Pinterest error (HTTP ${response.status})`,
      data.code !== undefined ? String(data.code) : undefined
    );

    error.upstreamStatus = response.status;
    throw error;
  }

  return data;
}

function buildPinterestTokenRow(t, { replaceRefresh = false } = {}) {
  const now = Date.now();
  const accessTtl = Number(t.expires_in) || 30 * 24 * 60 * 60;

  const row = {
    access_token: encryptSecret(t.access_token),
    access_expires_at: iso(now + accessTtl * 1000),
    updated_at: new Date().toISOString(),
  };

  if (t.refresh_token) row.refresh_token = encryptSecret(t.refresh_token);
  else if (replaceRefresh) row.refresh_token = null;

  const refreshTtl = Number(t.refresh_token_expires_in);

  if (Number.isFinite(refreshTtl) && refreshTtl > 0) {
    row.refresh_expires_at = iso(now + refreshTtl * 1000);
  } else if (replaceRefresh) {
    row.refresh_expires_at = iso(now + 365 * 24 * 60 * 60 * 1000);
  }

  if (t.scope) row.scope = t.scope;
  else if (replaceRefresh) row.scope = null;

  return row;
}

async function savePinterestTokens(userId, t, extra = {}) {
  const { error } = await supabaseAdmin.from("pinterest_accounts").upsert(
    {
      user_id: userId,
      ...buildPinterestTokenRow(t, { replaceRefresh: true }),
      api_env: PINTEREST_ENVIRONMENT,
      ...extra,
    },
    { onConflict: "user_id" }
  );

  if (error) throw dbError("pinterest_accounts upsert", error);
}

async function getPinterestAccount(userId) {
  return selectTokenRow("pinterest_accounts", userId);
}

const pinterestAccountMatchesEnv = (account) =>
  Boolean(account) && account.api_env === PINTEREST_ENVIRONMENT;

const isPinterestInvalidGrant = (error) =>
  error instanceof HttpError &&
  (error.upstreamStatus === 400 ||
    error.upstreamStatus === 401 ||
    error.code === "invalid_grant");

async function getValidPinterestToken(userId) {
  const load = async () => {
    const account = await getPinterestAccount(userId);

    if (!account) throw new HttpError(400, "Pinterest account not connected", "PINTEREST_NOT_CONNECTED");
    if (!pinterestAccountMatchesEnv(account)) throw reconnectError("Pinterest", "PINTEREST_ENV_MISMATCH");

    return account;
  };

  const first = await load();
  if (isTokenFresh(first)) return first.access_token;

  return withLock(`pinterest-refresh:${userId}`, async () => {
    for (let attempt = 0; attempt < 2; attempt++) {
      const account = await load();

      if (isTokenFresh(account)) return account.access_token;
      if (!account.refresh_token || isPast(account.refresh_expires_at)) {
        throw reconnectError("Pinterest", "PINTEREST_REFRESH_EXPIRED");
      }

      let refreshed;

      try {
        refreshed = await pinterestApi("/oauth/token", {
          method: "POST",
          base: PINTEREST_OAUTH_BASE,
          basic: true,
          form: {
            grant_type: "refresh_token",
            refresh_token: account.refresh_token,
          },
        });
      } catch (error) {
        if (isPinterestInvalidGrant(error)) throw reconnectError("Pinterest", "PINTEREST_REFRESH_EXPIRED");
        throw error;
      }

      if (!refreshed?.access_token) {
        throw new HttpError(502, "Pinterest returned an invalid token response", "PINTEREST_BAD_TOKEN_RESPONSE");
      }

      const applied = await updateTokensIfUnchanged(
        "pinterest_accounts",
        userId,
        account,
        buildPinterestTokenRow(refreshed)
      );

      if (applied) return refreshed.access_token;
    }

    throw new HttpError(409, "Pinterest account changed during token refresh, please retry", "PINTEREST_REFRESH_CONFLICT");
  });
}

// ============================================================
// YOUTUBE
// ============================================================

async function googleRequest(requestUrl, { method = "GET", token, form, json } = {}) {
  const headers = { Accept: "application/json" };
  let body;

  if (token) headers.Authorization = `Bearer ${token}`;

  if (form) {
    headers["Content-Type"] = "application/x-www-form-urlencoded";
    body = new URLSearchParams(form).toString();
  } else if (json) {
    headers["Content-Type"] = "application/json; charset=UTF-8";
    body = JSON.stringify(json);
  }

  let result;

  try {
    result = await fetchJson(requestUrl, { method, headers, body }, 20_000);
  } catch (error) {
    throw upstreamError("Google", error);
  }

  const { response, data } = result;

  if (!response.ok) {
    const oauthError = typeof data.error === "string" ? data.error : undefined;

    throw new HttpError(
      upstreamStatus(response.status),
      data.error_description || data.error?.message || oauthError || `Google error (HTTP ${response.status})`,
      oauthError
    );
  }

  return data;
}

async function fetchYouTubeChannel(accessToken) {
  const data = await googleRequest(`${YOUTUBE_API_BASE}/channels?part=snippet&mine=true`, { token: accessToken });

  const channel = data.items?.[0];
  if (!channel) return null;

  const thumbnails = channel.snippet?.thumbnails || {};

  return {
    id: channel.id,
    title: channel.snippet?.title || null,
    customUrl: channel.snippet?.customUrl || null,
    avatarUrl: thumbnails.high?.url || thumbnails.medium?.url || thumbnails.default?.url || null,
  };
}

function buildYouTubeTokenRow(t) {
  const now = Date.now();
  const accessTtl = Number(t.expires_in) || 3600;

  const row = {
    access_token: encryptSecret(t.access_token),
    access_expires_at: iso(now + accessTtl * 1000),
    updated_at: new Date().toISOString(),
  };

  if (t.refresh_token) row.refresh_token = encryptSecret(t.refresh_token);
  if (t.scope) row.scope = t.scope;

  if (t.refresh_token_expires_in !== undefined) {
    row.refresh_expires_at = t.refresh_token_expires_in
      ? iso(now + Number(t.refresh_token_expires_in) * 1000)
      : null;
  }

  return row;
}

async function saveYouTubeTokens(userId, t, extra = {}) {
  const { error } = await supabaseAdmin
    .from("youtube_accounts")
    .upsert({ user_id: userId, ...buildYouTubeTokenRow(t), ...extra }, { onConflict: "user_id" });

  if (error) throw dbError("youtube_accounts upsert", error);
}

async function getYouTubeAccount(userId) {
  return selectTokenRow("youtube_accounts", userId);
}

const youtubeRefreshExpired = (account) =>
  !account.refresh_token ||
  Boolean(account.refresh_expires_at) && isPast(account.refresh_expires_at);

async function getValidYouTubeToken(userId) {
  const load = async () => {
    const account = await getYouTubeAccount(userId);

    if (!account) throw new HttpError(400, "YouTube account not connected", "YOUTUBE_NOT_CONNECTED");

    return account;
  };

  const first = await load();
  if (isTokenFresh(first)) return first.access_token;

  return withLock(`youtube-refresh:${userId}`, async () => {
    for (let attempt = 0; attempt < 2; attempt++) {
      const account = await load();

      if (isTokenFresh(account)) return account.access_token;
      if (youtubeRefreshExpired(account)) throw reconnectError("YouTube", "YOUTUBE_REFRESH_EXPIRED");

      let refreshed;

      try {
        refreshed = await googleRequest(GOOGLE_TOKEN_URL, {
          method: "POST",
          form: {
            client_id: YOUTUBE_CLIENT_ID,
            client_secret: YOUTUBE_CLIENT_SECRET,
            grant_type: "refresh_token",
            refresh_token: account.refresh_token,
          },
        });
      } catch (error) {
        if (error instanceof HttpError && error.code === "invalid_grant") {
          throw reconnectError("YouTube", "YOUTUBE_REFRESH_EXPIRED");
        }
        throw error;
      }

      if (!refreshed?.access_token) {
        throw new HttpError(502, "Google returned an invalid token response", "YOUTUBE_BAD_TOKEN_RESPONSE");
      }

      const applied = await updateTokensIfUnchanged(
        "youtube_accounts",
        userId,
        account,
        buildYouTubeTokenRow(refreshed)
      );

      if (applied) return refreshed.access_token;
    }

    throw new HttpError(409, "YouTube account changed during token refresh, please retry", "YOUTUBE_REFRESH_CONFLICT");
  });
}

const YOUTUBE_FRIENDLY_ERRORS = {
  quotaExceeded: "YouTube daily quota reached for this app. Please try again tomorrow.",
  dailyLimitExceeded: "YouTube daily quota reached for this app. Please try again tomorrow.",
  uploadLimitExceeded: "This YouTube channel has reached its daily upload limit. Please try again later.",
  youtubeSignupRequired: "This Google account has no YouTube channel. Create one on youtube.com, then reconnect.",
  forbidden: "YouTube refused this upload for this channel.",
  invalidTitle: "Invalid YouTube title.",
  invalidDescription: "Invalid YouTube description.",
  invalidTags: "Invalid YouTube tags.",
  invalidPublishAt: "Invalid scheduled date. Pick a date in the future.",
  invalidVideoMetadata: "YouTube rejected the video metadata.",
  mediaBodyRequired: "The video file is empty.",
  videoTooLong: "This video is too long for your YouTube account.",
};

function youtubeApiError(status, data) {
  const reason =
    data?.error?.errors?.[0]?.reason ||
    (typeof data?.error === "string" ? data.error : undefined) ||
    data?.error?.status;

  if (status === 401 || reason === "authError" || reason === "invalid_grant") {
    return reconnectError("YouTube", "YOUTUBE_REFRESH_EXPIRED");
  }

  // ✅ Log de l'erreur Google brute pour distinguer
  // « scope non stocké en base » de « scope refusé par Google ».
  console.warn("[youtube] erreur Google :", status, JSON.stringify(data?.error || data).slice(0, 400));

  if (reason === "insufficientPermissions") {
    return new HttpError(409, "YouTube permission missing, please reconnect your YouTube account.", "YOUTUBE_SCOPE_MISSING");
  }

  if (reason === "quotaExceeded" || reason === "dailyLimitExceeded") {
    return new HttpError(429, YOUTUBE_FRIENDLY_ERRORS[reason], reason);
  }

  return new HttpError(
    upstreamStatus(status),
    YOUTUBE_FRIENDLY_ERRORS[reason] || data?.error?.message || `YouTube error (HTTP ${status})`,
    reason
  );
}

function parseYouTubeTags(raw) {
  const text = String(raw || "").trim();
  let list = [];

  if (text) {
    try {
      const parsed = JSON.parse(text);
      list = Array.isArray(parsed) ? parsed : [];
    } catch {
      list = text.split(",");
    }
  }

  const tags = [];
  let total = 0;

  for (const item of list) {
    const tag = String(item).replace(/[<>,"]/g, "").trim().slice(0, 100);
    if (!tag || tags.includes(tag)) continue;

    const cost = tag.length + (tag.includes(" ") ? 2 : 0) + 1;
    if (total + cost > 500) break;

    tags.push(tag);
    total += cost;
  }

  return tags;
}

function buildYouTubeMetadata(fields) {
  const title = String(fields.title || "").replace(/[<>]/g, "").trim();

  if (!title) throw new HttpError(400, "A title is required for YouTube videos.", "YOUTUBE_TITLE_REQUIRED");
  if (title.length > YOUTUBE_TITLE_MAX) throw new HttpError(400, `The YouTube title must be at most ${YOUTUBE_TITLE_MAX} characters.`, "YOUTUBE_TITLE_TOO_LONG");

  const description = String(fields.description || "").replace(/[<>]/g, "").trim();

  if (Buffer.byteLength(description, "utf8") > YOUTUBE_DESCRIPTION_MAX_BYTES) {
    throw new HttpError(400, "The YouTube description is too long (max 5,000 characters).", "YOUTUBE_DESCRIPTION_TOO_LONG");
  }

  if (fields.made_for_kids !== "true" && fields.made_for_kids !== "false") {
    throw new HttpError(400, "Tell YouTube if this video is made for kids.", "YOUTUBE_MADE_FOR_KIDS_REQUIRED");
  }

  let privacy = YOUTUBE_PRIVACY_LEVELS.has(fields.privacy_level) ? fields.privacy_level : "private";
  let publishAt = null;

  if (fields.publish_at) {
    const date = new Date(fields.publish_at);

    if (Number.isNaN(date.getTime()) || date.getTime() < Date.now() + 60_000) {
      throw new HttpError(400, "Pick a date and time in the future.", "YOUTUBE_PUBLISH_AT_INVALID");
    }

    publishAt = date.toISOString();
    privacy = "private";
  }

  const tags = parseYouTubeTags(fields.tags);
  const categoryId = /^\d{1,3}$/.test(String(fields.category_id || "")) ? String(fields.category_id) : "22";
  const license = fields.license === "creativeCommon" ? "creativeCommon" : "youtube";
  const notifySubscribers = fields.notify_subscribers !== "false";

  return {
    privacy,
    publishAt,
    notifySubscribers,
    metadata: {
      snippet: { title, description, categoryId, ...(tags.length > 0 ? { tags } : {}) },
      status: {
        privacyStatus: privacy,
        selfDeclaredMadeForKids: fields.made_for_kids === "true",
        embeddable: fields.allow_embedding !== "false",
        license,
        ...(publishAt ? { publishAt } : {}),
      },
    },
  };
}

async function initYouTubeUpload(accessToken, metadata, size, mimeType, notifySubscribers = true) {
  let result;

  try {
    result = await fetchJson(
      `${YOUTUBE_UPLOAD_URL}?uploadType=resumable&part=snippet,status&notifySubscribers=${notifySubscribers}`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json; charset=UTF-8",
          "X-Upload-Content-Length": String(size),
          "X-Upload-Content-Type": mimeType,
        },
        body: JSON.stringify(metadata),
      },
      30_000
    );
  } catch (error) {
    throw upstreamError("YouTube", error);
  }

  const { response, data } = result;

  if (!response.ok) throw youtubeApiError(response.status, data);

  const location = response.headers.get("location");

  if (!location || !location.startsWith("https://www.googleapis.com/")) {
    throw new HttpError(502, "YouTube did not return a valid upload URL", "YOUTUBE_NO_UPLOAD_URL");
  }

  return location;
}

async function youtubePut(uploadUrl, headers, body) {
  const { response, data } = await fetchJson(uploadUrl, { method: "PUT", headers, body, redirect: "manual" }, 120_000);

  if (response.status === 200 || response.status === 201) return { done: true, video: data };

  if (response.status === 308) {
    const match = /bytes=0-(\d+)/.exec(response.headers.get("range") || "");
    return { done: false, next: match ? Number(match[1]) + 1 : 0 };
  }

  const error = new Error(`HTTP ${response.status}`);
  error.status = response.status;
  error.data = data;
  throw error;
}

async function uploadVideoToYouTube(uploadUrl, buffer, mimeType) {
  const total = buffer.length;
  let offset = 0;
  let failures = 0;

  while (true) {
    try {
      const end = Math.min(offset + YOUTUBE_CHUNK_SIZE, total) - 1;

      const result = await youtubePut(
        uploadUrl,
        { "Content-Type": mimeType, "Content-Range": `bytes ${offset}-${end}/${total}` },
        buffer.subarray(offset, end + 1)
      );

      if (result.done) return result.video;

      if (result.next <= offset) throw Object.assign(new Error("No progress"), { status: 500 });

      offset = result.next;
    } catch (error) {
      const status = error?.status;

      if (status && status < 500 && status !== 429) throw youtubeApiError(status, error.data);

      failures++;

      if (failures > 5) {
        throw new HttpError(502, "YouTube upload failed, please retry", "YOUTUBE_UPLOAD_FAILED");
      }

      await delay(failures * 1000);

      try {
        const query = await youtubePut(uploadUrl, { "Content-Range": `bytes */${total}` }, undefined);
        if (query.done) return query.video;
        offset = query.next;
      } catch {
        // retry
      }
    }
  }
}

// ------------------------------------------------------------
// ✅ YOUTUBE — LECTURE DES VIDÉOS & COMMENTAIRES
// ------------------------------------------------------------

async function youtubeGet(pathname, params, token) {
  const query = new URLSearchParams(params).toString();
  let result;

  try {
    result = await fetchJson(
      `${YOUTUBE_API_BASE}${pathname}?${query}`,
      { headers: { Authorization: `Bearer ${token}`, Accept: "application/json" } },
      20_000
    );
  } catch (error) {
    throw upstreamError("YouTube", error);
  }

  if (!result.response.ok) throw youtubeApiError(result.response.status, result.data);
  return result.data;
}

// ✅ `comments: true` → exige explicitement le scope force-ssl
// (nécessaire pour lire les commentaires ET pour y répondre).
async function getYouTubeReader(userId, { comments = false } = {}) {
  const account = await getYouTubeAccount(userId);
  if (!account) {
    throw new HttpError(400, "YouTube account not connected", "YOUTUBE_NOT_CONNECTED");
  }

  const scopes = String(account.scope || "").split(/[\s,]+/).filter(Boolean);
  const needed = comments ? [YOUTUBE_FORCE_SSL_SCOPE] : YOUTUBE_READ_SCOPES;

  if (!scopes.some((s) => needed.includes(s))) {
    throw new HttpError(
      409,
      "YouTube permission missing, please reconnect your YouTube account.",
      "YOUTUBE_SCOPE_MISSING"
    );
  }
  if (!account.channel_id) {
    throw new HttpError(409, "YouTube channel unknown, please reconnect.", "YOUTUBE_CHANNEL_MISSING");
  }

  const token = await getValidYouTubeToken(userId);
  return { token, channelId: account.channel_id };
}

function formatYouTubeThread(item, channelId) {
  const top = item.snippet?.topLevelComment?.snippet || {};
  const replies = item.replies?.comments || [];
  const authorChannelId = top.authorChannelId?.value || null;

  return {
    id: item.id,
    video_id: item.snippet?.videoId || top.videoId || null,
    text: top.textDisplay || top.textOriginal || "",
    author_name: top.authorDisplayName || "",
    author_avatar: top.authorProfileImageUrl || null,
    author_channel_id: authorChannelId,
    published_at: top.publishedAt || null,
    like_count: Number(top.likeCount || 0),
    reply_count: Number(item.snippet?.totalReplyCount || 0),
    // « répondu » = la chaîne a répondu dans les réponses renvoyées par l'API
    answered: replies.some((r) => r.snippet?.authorChannelId?.value === channelId),
    is_own: authorChannelId === channelId,
    can_reply: Boolean(item.snippet?.canReply),
  };
}

// ============================================================
// GOOGLE DRIVE
// ============================================================

function buildGDriveTokenRow(t) {
  const accessTtl = Number(t.expires_in) || 3600;

  const row = {
    access_token: encryptSecret(t.access_token),
    access_expires_at: iso(Date.now() + accessTtl * 1000),
    updated_at: new Date().toISOString(),
  };

  if (t.refresh_token) row.refresh_token = encryptSecret(t.refresh_token);
  if (t.scope) row.scope = t.scope;

  return row;
}

async function saveGDriveTokens(userId, t, extra = {}) {
  const { error } = await supabaseAdmin
    .from("google_drive_accounts")
    .upsert({ user_id: userId, ...buildGDriveTokenRow(t), ...extra }, { onConflict: "user_id" });

  if (error) throw dbError("google_drive_accounts upsert", error);
}

const getGDriveAccount = (userId) => selectTokenRow("google_drive_accounts", userId);

async function getValidGDriveToken(userId) {
  const load = async () => {
    const account = await getGDriveAccount(userId);
    if (!account) throw new HttpError(400, "Google Drive account not connected", "GDRIVE_NOT_CONNECTED");
    return account;
  };

  const first = await load();
  if (isTokenFresh(first)) return first.access_token;

  return withLock(`gdrive-refresh:${userId}`, async () => {
    for (let attempt = 0; attempt < 2; attempt++) {
      const account = await load();

      if (isTokenFresh(account)) return account.access_token;
      if (!account.refresh_token) throw reconnectError("Google Drive", "GDRIVE_REFRESH_EXPIRED");

      let refreshed;

      try {
        refreshed = await googleRequest(GOOGLE_TOKEN_URL, {
          method: "POST",
          form: {
            client_id: GDRIVE_CLIENT_ID,
            client_secret: GDRIVE_CLIENT_SECRET,
            grant_type: "refresh_token",
            refresh_token: account.refresh_token,
          },
        });
      } catch (error) {
        if (error instanceof HttpError && error.code === "invalid_grant") {
          throw reconnectError("Google Drive", "GDRIVE_REFRESH_EXPIRED");
        }
        throw error;
      }

      if (!refreshed?.access_token) {
        throw new HttpError(502, "Google returned an invalid token response", "GDRIVE_BAD_TOKEN_RESPONSE");
      }

      const applied = await updateTokensIfUnchanged(
        "google_drive_accounts",
        userId,
        account,
        buildGDriveTokenRow(refreshed)
      );

      if (applied) return refreshed.access_token;
    }

    throw new HttpError(409, "Google Drive account changed during token refresh, please retry", "GDRIVE_REFRESH_CONFLICT");
  });
}

async function gdriveRequest(requestUrl, { method = "GET", token, headers = {}, body, timeoutMs = 20_000 } = {}) {
  let result;

  try {
    result = await fetchJson(
      requestUrl,
      { method, headers: { Authorization: `Bearer ${token}`, Accept: "application/json", ...headers }, body },
      timeoutMs
    );
  } catch (error) {
    throw upstreamError("Google Drive", error);
  }

  const { response, data } = result;

  if (!response.ok) {
    const reason = data?.error?.errors?.[0]?.reason || data?.error?.status;

    if (response.status === 401) throw reconnectError("Google Drive", "GDRIVE_REFRESH_EXPIRED");
    if (reason === "insufficientPermissions" || reason === "ACCESS_TOKEN_SCOPE_INSUFFICIENT") {
      throw new HttpError(409, "Google Drive permission missing, please reconnect your Google Drive account.", "GDRIVE_SCOPE_MISSING");
    }
    if (reason === "storageQuotaExceeded") throw new HttpError(400, "Your Google Drive is full.", reason);
    if (reason === "rateLimitExceeded" || reason === "userRateLimitExceeded") {
      throw new HttpError(429, "Google Drive rate limit reached. Please try again shortly.", reason);
    }

    throw new HttpError(
      upstreamStatus(response.status),
      data?.error?.message || `Google Drive error (HTTP ${response.status})`,
      reason
    );
  }

  return data;
}

const GDRIVE_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;

function parseGDriveFolderId(value) {
  const id = String(value ?? "").trim();
  if (!id || id === "root") return "root";
  if (!GDRIVE_ID_PATTERN.test(id)) throw new HttpError(400, "Invalid Google Drive folder id", "INVALID_GDRIVE_ID");
  return id;
}

// ============================================================
// GOOGLE PHOTOS
// ============================================================

function buildGPhotosTokenRow(t) {
  const row = {
    access_token: encryptSecret(t.access_token),
    access_expires_at: iso(Date.now() + (Number(t.expires_in) || 3600) * 1000),
    updated_at: new Date().toISOString(),
  };
  if (t.refresh_token) row.refresh_token = encryptSecret(t.refresh_token);
  if (t.scope) row.scope = t.scope;
  return row;
}

async function saveGPhotosTokens(userId, t, extra = {}) {
  const { error } = await supabaseAdmin
    .from("google_photos_accounts")
    .upsert({ user_id: userId, ...buildGPhotosTokenRow(t), ...extra }, { onConflict: "user_id" });
  if (error) throw dbError("google_photos_accounts upsert", error);
}

const getGPhotosAccount = (userId) => selectTokenRow("google_photos_accounts", userId);

async function getValidGPhotosToken(userId) {
  const load = async () => {
    const account = await getGPhotosAccount(userId);
    if (!account) throw new HttpError(400, "Google Photos account not connected", "GPHOTOS_NOT_CONNECTED");
    return account;
  };

  const first = await load();
  if (isTokenFresh(first)) return first.access_token;

  return withLock(`gphotos-refresh:${userId}`, async () => {
    for (let attempt = 0; attempt < 2; attempt++) {
      const account = await load();
      if (isTokenFresh(account)) return account.access_token;
      if (!account.refresh_token) throw reconnectError("Google Photos", "GPHOTOS_REFRESH_EXPIRED");

      let refreshed;
      try {
        refreshed = await googleRequest(GOOGLE_TOKEN_URL, {
          method: "POST",
          form: {
            client_id: GPHOTOS_CLIENT_ID,
            client_secret: GPHOTOS_CLIENT_SECRET,
            grant_type: "refresh_token",
            refresh_token: account.refresh_token,
          },
        });
      } catch (error) {
        if (error instanceof HttpError && error.code === "invalid_grant") {
          throw reconnectError("Google Photos", "GPHOTOS_REFRESH_EXPIRED");
        }
        throw error;
      }

      if (!refreshed?.access_token) {
        throw new HttpError(502, "Google returned an invalid token response", "GPHOTOS_BAD_TOKEN_RESPONSE");
      }

      const applied = await updateTokensIfUnchanged(
        "google_photos_accounts", userId, account, buildGPhotosTokenRow(refreshed)
      );
      if (applied) return refreshed.access_token;
    }
    throw new HttpError(409, "Google Photos account changed during token refresh, please retry", "GPHOTOS_REFRESH_CONFLICT");
  });
}

async function gphotosPicker(pathname, { method = "GET", token, json } = {}) {
  let result;
  try {
    result = await fetchJson(
      `${GPHOTOS_PICKER_API}${pathname}`,
      {
        method,
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/json",
          ...(json ? { "Content-Type": "application/json" } : {}),
        },
        body: json ? JSON.stringify(json) : undefined,
      },
      20_000
    );
  } catch (error) {
    throw upstreamError("Google Photos", error);
  }

  const { response, data } = result;
  if (!response.ok) {
    if (response.status === 401) throw reconnectError("Google Photos", "GPHOTOS_REFRESH_EXPIRED");
    if (response.status === 403) {
      throw new HttpError(409, "Google Photos permission missing, please reconnect.", "GPHOTOS_SCOPE_MISSING");
    }
    throw new HttpError(
      upstreamStatus(response.status),
      data?.error?.message || `Google Photos error (HTTP ${response.status})`,
      data?.error?.status
    );
  }
  return data;
}

function parseGPhotosSessionId(value) {
  const id = String(value ?? "").trim();
  if (!GPHOTOS_SESSION_ID.test(id)) throw new HttpError(400, "Invalid session id", "INVALID_GPHOTOS_SESSION");
  return id;
}

function isGoogleMediaHost(hostname) {
  const h = hostname.toLowerCase();
  return h === "googleusercontent.com" || h.endsWith(".googleusercontent.com");
}

// ============================================================
// CANVA
// ============================================================

const canvaPkce = new Map();
const CANVA_PKCE_TTL_MS = 10 * 60 * 1000;

function createCanvaPkce(state) {
  const now = Date.now();

  for (const [key, entry] of canvaPkce) {
    if (entry.expires <= now) canvaPkce.delete(key);
  }

  if (canvaPkce.size > 5_000) canvaPkce.delete(canvaPkce.keys().next().value);

  const verifier = crypto.randomBytes(48).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");

  canvaPkce.set(sha256(state), { verifier, expires: now + CANVA_PKCE_TTL_MS });

  return challenge;
}

function takeCanvaVerifier(state) {
  const key = sha256(state);
  const entry = canvaPkce.get(key);

  canvaPkce.delete(key);

  return entry && entry.expires > Date.now() ? entry.verifier : null;
}

async function canvaApi(pathname, { method = "GET", token, basic = false, form, json } = {}) {
  const headers = { Accept: "application/json" };
  let body;

  if (basic) {
    headers.Authorization = "Basic " + Buffer.from(`${CANVA_CLIENT_ID}:${CANVA_CLIENT_SECRET}`).toString("base64");
  } else if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  if (form) {
    headers["Content-Type"] = "application/x-www-form-urlencoded";
    body = new URLSearchParams(form).toString();
  } else if (json) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(json);
  }

  let result;

  try {
    result = await fetchJson(`${CANVA_API_BASE}${pathname}`, { method, headers, body }, 20_000);
  } catch (error) {
    throw upstreamError("Canva", error);
  }

  const { response, data } = result;

  if (!response.ok) {
    const error = new HttpError(
      upstreamStatus(response.status),
      data.message ||
        data.error_description ||
        (typeof data.error === "string" ? data.error : "") ||
        `Canva error (HTTP ${response.status})`,
      data.code || (typeof data.error === "string" ? data.error : undefined)
    );

    error.upstreamStatus = response.status;
    throw error;
  }

  return data;
}

function buildCanvaTokenRow(t) {
  const accessTtl = Number(t.expires_in) || 4 * 60 * 60;

  const row = {
    access_token: encryptSecret(t.access_token),
    access_expires_at: iso(Date.now() + accessTtl * 1000),
    updated_at: new Date().toISOString(),
  };

  if (t.refresh_token) row.refresh_token = encryptSecret(t.refresh_token);
  if (t.scope) row.scope = t.scope;

  return row;
}

async function saveCanvaTokens(userId, t, extra = {}) {
  const { error } = await supabaseAdmin
    .from("canva_accounts")
    .upsert({ user_id: userId, ...buildCanvaTokenRow(t), ...extra }, { onConflict: "user_id" });

  if (error) throw dbError("canva_accounts upsert", error);
}

const getCanvaAccount = (userId) => selectTokenRow("canva_accounts", userId);

async function getValidCanvaToken(userId) {
  const load = async () => {
    const account = await getCanvaAccount(userId);
    if (!account) throw new HttpError(400, "Canva account not connected", "CANVA_NOT_CONNECTED");
    return account;
  };

  const first = await load();
  if (isTokenFresh(first)) return first.access_token;

  return withLock(`canva-refresh:${userId}`, async () => {
    for (let attempt = 0; attempt < 2; attempt++) {
      const account = await load();

      if (isTokenFresh(account)) return account.access_token;
      if (!account.refresh_token) throw reconnectError("Canva", "CANVA_REFRESH_EXPIRED");

      let refreshed;

      try {
        refreshed = await canvaApi("/oauth/token", {
          method: "POST",
          basic: true,
          form: { grant_type: "refresh_token", refresh_token: account.refresh_token },
        });
      } catch (error) {
        if (
          error instanceof HttpError &&
          (error.upstreamStatus === 400 ||
            error.upstreamStatus === 401 ||
            error.code === "invalid_grant")
        ) {
          throw reconnectError("Canva", "CANVA_REFRESH_EXPIRED");
        }
        throw error;
      }

      if (!refreshed?.access_token) {
        throw new HttpError(502, "Canva returned an invalid token response", "CANVA_BAD_TOKEN_RESPONSE");
      }

      const applied = await updateTokensIfUnchanged(
        "canva_accounts",
        userId,
        account,
        buildCanvaTokenRow(refreshed)
      );

      if (applied) return refreshed.access_token;
    }

    throw new HttpError(409, "Canva account changed during token refresh, please retry", "CANVA_REFRESH_CONFLICT");
  });
}

// ============================================================
// DROPBOX
// ============================================================

const DROPBOX_FRIENDLY_ERRORS = {
  insufficient_space: "Your Dropbox is full.",
  "path/not_found": "File or folder not found in Dropbox.",
  "path/conflict": "A file already exists at this path.",
  "path/malformed_path": "Invalid Dropbox path.",
  missing_scope: "Dropbox permission missing, please reconnect your Dropbox account.",
};

const dropboxArgHeader = (obj) =>
  JSON.stringify(obj).replace(/[\u007f-\uffff]/g, (c) =>
    "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0")
  );

function dropboxApiError(response, data) {
  const summary = String(data?.error_summary || "");
  const tag = data?.error?.[".tag"];

  if (response.status === 401) {
    return reconnectError("Dropbox", "DROPBOX_REFRESH_EXPIRED");
  }
  if (tag === "missing_scope") {
    return new HttpError(409, DROPBOX_FRIENDLY_ERRORS.missing_scope, "DROPBOX_SCOPE_MISSING");
  }

  const key = Object.keys(DROPBOX_FRIENDLY_ERRORS).find((k) => summary.startsWith(k) || summary.includes(k));

  const error = new HttpError(
    response.status === 429 ? 429 : response.status >= 500 ? 502 : 400,
    (key && DROPBOX_FRIENDLY_ERRORS[key]) || summary || `Dropbox error (HTTP ${response.status})`,
    key || "DROPBOX_ERROR"
  );
  error.upstreamStatus = response.status;
  return error;
}

async function dropboxRpc(pathname, { token, json } = {}) {
  const headers = { Authorization: `Bearer ${token}` };
  let body;

  if (json) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(json);
  }

  let result;
  try {
    result = await fetchJson(`${DROPBOX_API}${pathname}`, { method: "POST", headers, body }, 20_000);
  } catch (error) {
    throw upstreamError("Dropbox", error);
  }

  if (!result.response.ok) throw dropboxApiError(result.response, result.data);
  return result.data;
}

async function dropboxToken(form) {
  let result;
  try {
    result = await fetchJson(
      DROPBOX_TOKEN_URL,
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: DROPBOX_APP_KEY,
          client_secret: DROPBOX_APP_SECRET,
          ...form,
        }).toString(),
      },
      20_000
    );
  } catch (error) {
    throw upstreamError("Dropbox", error);
  }

  const { response, data } = result;

  if (!response.ok) {
    const error = new HttpError(
      upstreamStatus(response.status),
      data.error_description || (typeof data.error === "string" ? data.error : "") || `Dropbox error (HTTP ${response.status})`,
      typeof data.error === "string" ? data.error : undefined
    );
    error.upstreamStatus = response.status;
    throw error;
  }

  return data;
}

function buildDropboxTokenRow(t) {
  const accessTtl = Number(t.expires_in) || 4 * 60 * 60;

  const row = {
    access_token: encryptSecret(t.access_token),
    access_expires_at: iso(Date.now() + accessTtl * 1000),
    updated_at: new Date().toISOString(),
  };

  if (t.refresh_token) row.refresh_token = encryptSecret(t.refresh_token);
  if (t.scope) row.scope = t.scope;
  if (t.account_id) row.account_id = t.account_id;

  return row;
}

async function saveDropboxTokens(userId, t, extra = {}) {
  const { error } = await supabaseAdmin
    .from("dropbox_accounts")
    .upsert({ user_id: userId, ...buildDropboxTokenRow(t), ...extra }, { onConflict: "user_id" });

  if (error) throw dbError("dropbox_accounts upsert", error);
}

const getDropboxAccount = (userId) => selectTokenRow("dropbox_accounts", userId);

async function getValidDropboxToken(userId) {
  const load = async () => {
    const account = await getDropboxAccount(userId);
    if (!account) throw new HttpError(400, "Dropbox account not connected", "DROPBOX_NOT_CONNECTED");
    return account;
  };

  const first = await load();
  if (isTokenFresh(first)) return first.access_token;

  return withLock(`dropbox-refresh:${userId}`, async () => {
    for (let attempt = 0; attempt < 2; attempt++) {
      const account = await load();

      if (isTokenFresh(account)) return account.access_token;
      if (!account.refresh_token) throw reconnectError("Dropbox", "DROPBOX_REFRESH_EXPIRED");

      let refreshed;

      try {
        refreshed = await dropboxToken({
          grant_type: "refresh_token",
          refresh_token: account.refresh_token,
        });
      } catch (error) {
        if (
          error instanceof HttpError &&
          (error.code === "invalid_grant" || error.upstreamStatus === 400 || error.upstreamStatus === 401)
        ) {
          throw reconnectError("Dropbox", "DROPBOX_REFRESH_EXPIRED");
        }
        throw error;
      }

      if (!refreshed?.access_token) {
        throw new HttpError(502, "Dropbox returned an invalid token response", "DROPBOX_BAD_TOKEN_RESPONSE");
      }

      const applied = await updateTokensIfUnchanged(
        "dropbox_accounts",
        userId,
        account,
        buildDropboxTokenRow(refreshed)
      );

      if (applied) return refreshed.access_token;
    }

    throw new HttpError(409, "Dropbox account changed during token refresh, please retry", "DROPBOX_REFRESH_CONFLICT");
  });
}

function parseDropboxPath(value, { allowRoot = false } = {}) {
  const path = String(value ?? "").trim();

  if (allowRoot && (path === "" || path === "/")) return "";
  if (!path.startsWith("/") || path.length > 1000 || path.includes("..") || /[\u0000-\u001f]/.test(path)) {
    throw new HttpError(400, "Invalid Dropbox path", "INVALID_DROPBOX_PATH");
  }
  return path;
}

// ============================================================
// ROUTEUR
// ============================================================

const routes = new Map();

function route(methods, pathname, handler, { auth = false } = {}) {
  for (const method of [].concat(methods)) {
    routes.set(`${method} ${pathname}`, { handler, auth });
  }
}

// ============================================================
// ROUTES — HEALTH
// ============================================================

route("GET", "/api/health", ({ res }) => {
  sendJson(res, 200, {
    success: true,
    server: "Stone",
    supabase: true,
    stripe: Boolean(stripe),
    tiktok: tiktokEnabled ? { enabled: true, ...tiktokCapabilities() } : { enabled: false },
    pinterest: pinterestUsable,
    youtube: youtubeEnabled,
    googledrive: gdriveEnabled,
    googlephotos: gphotosEnabled,
    canva: canvaEnabled,
    dropbox: dropboxEnabled,
    tags: true,
    saved_replies: true,
    posts: true,
  });
});

// ============================================================
// ROUTES — AUTH
// ============================================================

route("POST", "/api/auth/signup", async ({ req, res }) => {
  const body = await getJsonBody(req);
  const email = normalizeEmail(body.email);
  const password = String(body.password || "");
  const firstName = String(body.firstName ?? body.first_name ?? "").trim();
  const lastName = String(body.lastName ?? body.last_name ?? "").trim();

  if (!email || !password) throw new HttpError(400, "Email and password are required");
  if (email.length > 254 || !EMAIL_REGEX.test(email)) throw new HttpError(400, "Invalid email address");
  if (password.length < 8) throw new HttpError(400, "Password must contain at least 8 characters");
  if (password.length > 128) throw new HttpError(400, "Password must contain at most 128 characters");

  enforce(limiterAccount, `signup:${email}`);

  const { data, error } = await supabase.auth.signUp({
    email,
    password,
    options: {
      data: { first_name: firstName.slice(0, 100), last_name: lastName.slice(0, 100) },
    },
  });

  if (error) throw new HttpError(error.status === 429 ? 429 : 400, error.message);

  sendJson(res, 201, {
    success: true,
    user: data.user ? formatUser(data.user) : null,
    session: sessionPayload(data.session),
    mfa_enabled: false,
    mfa_required: false,
    aal: data.session ? getTokenAal(data.session.access_token) : null,
    message: data.session
      ? "Account created successfully"
      : "Account created. Check your email to confirm your account.",
  });
});

route("POST", "/api/auth/login", async ({ req, res }) => {
  const body = await getJsonBody(req);
  const email = typeof body.email === "string" ? normalizeEmail(body.email) : "";
  const password = typeof body.password === "string" ? body.password : "";

  if (!email || email.length > 254 || !EMAIL_REGEX.test(email) || !password || password.length > 128) {
    throw new HttpError(400, "Email and password are required");
  }

  const attemptKey = authAttemptKey("email", email, getClientIp(req));
  await checkAuthAttemptLimit(attemptKey);

  const { data, error } = await supabase.auth.signInWithPassword({ email, password });

  if (error) {
    if (error.status === 429) {
      throw authAttemptRateLimitError(60);
    }
    if (error.status >= 500) throw dbError("auth.signInWithPassword", error);

    await recordAuthAttemptFailure(attemptKey);
    throw new HttpError(401, "Invalid email or password", "INVALID_CREDENTIALS");
  }

  await resetAuthAttemptFailures(attemptKey);

  const hasVerifiedMfa = userHasVerifiedMfa(data.user);
  const sessionAal = data.session ? getTokenAal(data.session.access_token) : null;
  const mfaRequired = hasVerifiedMfa && sessionAal === "aal1";

  sendJson(res, 200, {
    success: true,
    user: data.user ? formatUser(data.user) : null,
    session: sessionPayload(data.session),
    mfa_enabled: hasVerifiedMfa,
    mfa_required: mfaRequired,
    aal: sessionAal,
  });
});

route("POST", "/api/auth/check-verification", async ({ req, res }) => {
  const body = await getJsonBody(req);
  const email = normalizeEmail(body.email);
  const password = String(body.password || "");

  if (!email || !password) throw new HttpError(400, "Email and password are required");

  enforce(limiterAccount, `login:${email}`);

  const { data, error } = await supabase.auth.signInWithPassword({ email, password });

  if (error) {
    const notConfirmed =
      error.code === "email_not_confirmed" ||
      error.message.toLowerCase().includes("not confirmed");

    if (notConfirmed) {
      sendJson(res, 200, { success: true, verified: false });
      return;
    }

    throw new HttpError(401, "Invalid login credentials", "INVALID_CREDENTIALS");
  }

  const hasVerifiedMfa = userHasVerifiedMfa(data.user);
  const sessionAal = data.session ? getTokenAal(data.session.access_token) : null;

  sendJson(res, 200, {
    success: true,
    verified: Boolean(data.user?.email_confirmed_at),
    session: sessionPayload(data.session),
    mfa_enabled: hasVerifiedMfa,
    mfa_required: hasVerifiedMfa && sessionAal === "aal1",
    aal: sessionAal,
  });
});

route("POST", "/api/auth/forgot-password", async ({ req, res, requestId }) => {
  const body = await getJsonBody(req);
  const email = normalizeEmail(body.email);

  if (!email || email.length > 254 || !EMAIL_REGEX.test(email)) {
    throw new HttpError(400, "Enter a valid email address.", "INVALID_EMAIL");
  }

  enforce(limiterPasswordReset, `forgot:${email}`);

  const { error } = await supabase.auth.resetPasswordForEmail(email, {
    redirectTo: PASSWORD_RESET_REDIRECT_URL,
  });

  if (error) {
    if (error.status === 429) throw new HttpError(429, "Too many requests. Please try again later.", "RATE_LIMITED");
    console.error(`[${requestId}] forgot-password: ${error.status || ""} ${error.message}`);
  }

  sendJson(res, 200, {
    success: true,
    message: "If an account exists for this email, a password reset link has been sent.",
  });
});

route("POST", "/api/auth/reset-password", async ({ req, res, requestId }) => {
  const body = await getJsonBody(req);
  const password = String(body.password ?? body.newPassword ?? body.new_password ?? "");
  const accessToken = String(body.accessToken ?? body.access_token ?? "").trim();
  const tokenHash = String(body.tokenHash ?? body.token_hash ?? "").trim();

  if (!password) throw new HttpError(400, "A new password is required");
  if (password.length < 8) throw new HttpError(400, "Password must contain at least 8 characters");
  if (password.length > 128) throw new HttpError(400, "Password must contain at most 128 characters");
  if (!accessToken && !tokenHash) throw new HttpError(400, "Missing recovery token", "RECOVERY_TOKEN_MISSING");

  const invalidLink = () =>
    new HttpError(401, "This reset link is invalid or has expired. Request a new one.", "INVALID_RESET_TOKEN");

  let user = null;
  let sessionToken = null;

  if (tokenHash) {
    if (tokenHash.length > 512) throw invalidLink();

    const { data, error } = await supabase.auth.verifyOtp({ token_hash: tokenHash, type: "recovery" });
    if (error || !data?.user || !data?.session) throw invalidLink();

    user = data.user;
    sessionToken = data.session.access_token;
  } else {
    if (accessToken.length > 4096) throw invalidLink();
    if (!isRecoverySessionToken(accessToken)) throw invalidLink();

    const { data: { user: found }, error } = await supabase.auth.getUser(accessToken);
    if (error || !found) throw invalidLink();

    user = found;
    sessionToken = accessToken;
  }

  enforce(limiterAccount, `reset:${user.id}`);

  const { error: updateError } = await adminUpdateUser(user.id, { password });

  if (updateError) {
    if (updateError.code === "same_password" || updateError.code === "weak_password") {
      throw new HttpError(400, updateError.message || "This password cannot be used.", updateError.code);
    }
    throw dbError("auth.admin.updateUserById(password)", updateError);
  }

  try {
    await supabaseAdmin.auth.admin.signOut(sessionToken, "global");
  } catch (signOutError) {
    console.warn(`[${requestId}] reset-password: session revoke failed:`, signOutError?.message || signOutError);
  }

  authCacheInvalidateUser(user.id);

  sendJson(res, 200, { success: true, message: "Password updated successfully. You can now sign in." });
});

function registerOAuthLoginRoute(provider, extraOptions) {
  route("POST", `/api/auth/${provider}/url`, async ({ req, res }) => {
    const body = await getJsonBody(req).catch(() => ({}));
    const redirectTo = sanitizeRedirectTo(body.redirectTo);

    const { data, error } = await supabaseOAuth.auth.signInWithOAuth({
      provider,
      options: { redirectTo, skipBrowserRedirect: true, ...extraOptions },
    });

    if (error || !data?.url) throw error || new Error(`${provider}/url: no URL returned`);

    sendJson(res, 200, { success: true, url: data.url });
  });
}

registerOAuthLoginRoute("google", {
  queryParams: { access_type: "offline", prompt: "select_account" },
});

registerOAuthLoginRoute("github", { scopes: "read:user user:email" });

route("POST", "/api/auth/logout", async ({ req, res }) => {
  const authorization = req.headers.authorization || "";
  const token = authorization.replace(/^Bearer\s+/i, "").trim();

  if (token && token.length <= 4096) {
    const cachedUser = authCacheGet(token);

    try {
      await supabaseAdmin.auth.admin.signOut(token, "local");
    } catch (error) {
      console.warn("Logout revoke failed:", error?.message || error);
    }

    if (cachedUser) authCacheInvalidateUser(cachedUser.id);
  }

  sendJson(res, 200, { success: true });
});

route("POST", "/api/auth/sessions/revoke-others", async ({ res, user, token }) => {
  const { error } = await supabaseAdmin.auth.admin.signOut(token, "others");

  if (error) throw dbError("auth.admin.signOut(others)", error);

  authCacheInvalidateUser(user.id);
  sendJson(res, 200, { success: true });
}, { auth: true });

route("POST", "/api/auth/refresh", async ({ req, res }) => {
  const body = await getJsonBody(req);
  const refreshToken = String(body.refreshToken ?? body.refresh_token ?? "");

  if (!refreshToken || refreshToken.length > 4096) throw new HttpError(400, "Missing refresh token");

  const { data, error } = await supabase.auth.refreshSession({ refresh_token: refreshToken });

  if (error || !data.session) {
    throw new HttpError(401, "Invalid or expired refresh token", "INVALID_REFRESH_TOKEN");
  }

  sendJson(res, 200, {
    success: true,
    session: sessionPayload(data.session),
    aal: getTokenAal(data.session.access_token),
  });
});

route("POST", "/api/auth/resend-verification", async ({ res, user }) => {
  if (user.email_confirmed_at) throw new HttpError(400, "This email is already verified");
  if (!user.email) throw new HttpError(400, "No email associated with this account");

  enforce(limiterAccount, `resend:${user.id}`);

  const { error } = await supabase.auth.resend({ type: "signup", email: user.email });

  if (error) throw error;

  sendJson(res, 200, { success: true, message: "Verification email sent" });
}, { auth: true });

// ============================================================
// ROUTES — MFA (proxy complet)
// ============================================================

route("GET", "/api/auth/mfa/status", async ({ res, user, token }) => {
  const factors = verifiedFactorsOf(user).filter(isTotp);
  const aal = getTokenAal(token) || "aal1";
  const hasMfa = factors.length > 0;
  const verifiedSession = await hasVerifiedMfaSession(user.id, getTokenSessionId(token));
  const requiresChallenge = hasMfa && aal !== "aal2" && !verifiedSession;

  sendJson(res, 200, {
    success: true,
    aal,
    next_aal: requiresChallenge ? "aal2" : aal,
    mfa_enabled: hasMfa,
    requires_challenge: requiresChallenge,
    factors: factors.map(toPublicFactor),
  });
}, { auth: true });

route("GET", "/api/mfa/factors", ({ res, url, user }) => {
  const includeUnverified = url.searchParams.get("status") === "all";
  const factors = (Array.isArray(user.factors) ? user.factors : [])
    .filter(
      (f) =>
        isTotp(f) &&
        (f.status === "verified" || (includeUnverified && f.status === "unverified"))
    )
    .map(toPublicFactor);

  sendJson(res, 200, { success: true, factors });
}, { auth: true });

route("GET", "/api/mfa/recovery-codes", async ({ res, user }) => {
  const batch = await getLatestRecoveryCodeBatch(user.id);
  const remaining = batch
    ? await getRemainingRecoveryCodeCount(user.id, batch.batch_id)
    : 0;

  sendJson(res, 200, {
    success: true,
    remaining,
    generatedAt: batch?.created_at || null,
  });
}, { auth: true });

route("POST", "/api/mfa/recovery-codes", async ({ res, user, token }) => {
  await requireAal2(user, token);
  if (!userHasVerifiedMfa(user)) {
    throw new HttpError(400, "Enable an authenticator before generating recovery codes");
  }

  const codes = Array.from({ length: 10 }, generateRecoveryCode);
  const hashes = codes.map((code) => recoveryCodeHash(code.replace("-", "")));
  const batchId = crypto.randomUUID();

  await replaceRecoveryCodeBatch(user.id, batchId, hashes);
  sendSecurityEmail(user.id, "recovery_codes_regenerated", { count: codes.length });

  sendJson(res, 200, { success: true, codes });
}, { auth: true });

route("POST", "/api/mfa/recovery-codes/verify", async ({ req, res, user, token }) => {
  const body = await getJsonBody(req);
  if (typeof body.code !== "string" || body.code.length > 32) {
    throw new HttpError(400, "Invalid or already used recovery code", "INVALID_RECOVERY_CODE");
  }

  const normalizedCode = body.code.toUpperCase().replace(/[\s-]/g, "");
  if (!/^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{10}$/.test(normalizedCode)) {
    throw new HttpError(400, "Invalid or already used recovery code", "INVALID_RECOVERY_CODE");
  }

  const attemptKey = authAttemptKey("user", user.id, getClientIp(req));
  await checkAuthAttemptLimit(attemptKey);

  const sessionId = getTokenSessionId(token);
  if (!sessionId) throw new HttpError(401, "Invalid session", "INVALID_SESSION");

  const batch = await getLatestRecoveryCodeBatch(user.id);
  const invalidCode = async () => {
    await recordAuthAttemptFailure(attemptKey);
    throw new HttpError(400, "Invalid or already used recovery code", "INVALID_RECOVERY_CODE");
  };

  if (!batch) return invalidCode();

  const { data: recoveryCodes, error: listError } = await supabaseAdmin
    .from("mfa_recovery_codes")
    .select("code_hash")
    .eq("user_id", user.id)
    .eq("batch_id", batch.batch_id);

  if (listError) throw dbError("mfa_recovery_codes.lookup", listError);
  if (!Array.isArray(recoveryCodes)) {
    throw dbError("mfa_recovery_codes.lookup", new Error("Invalid row list"));
  }

  const candidateHash = recoveryCodeHash(normalizedCode);
  const candidateBuffer = Buffer.from(candidateHash, "hex");
  let matchedHash = null;

  for (const row of recoveryCodes.length
    ? recoveryCodes
    : [{ code_hash: "0".repeat(64) }]) {
    const storedBuffer = Buffer.from(row.code_hash, "hex");
    const matches =
      storedBuffer.length === candidateBuffer.length &&
      crypto.timingSafeEqual(storedBuffer, candidateBuffer);
    if (matches) matchedHash = row.code_hash;
  }

  if (!matchedHash) return invalidCode();

  const now = new Date();
  const expiresAt = new Date(
    now.getTime() + MFA_VERIFIED_SESSION_TTL_MINUTES * 60_000
  ).toISOString();
  const { data: consumed, error: consumeError } = await supabaseAdmin.rpc(
    "mfa_recovery_consume_code",
    {
      p_user_id: user.id,
      p_batch_id: batch.batch_id,
      p_code_hash: matchedHash,
      p_session_id: sessionId,
      p_verified_at: now.toISOString(),
      p_expires_at: expiresAt,
    }
  );

  if (consumeError) throw dbError("mfa_recovery_consume_code", consumeError);
  const result = Array.isArray(consumed) ? consumed[0] : null;
  if (!result) return invalidCode();

  const remaining = Number(result.remaining);
  if (!Number.isSafeInteger(remaining) || remaining < 0) {
    throw dbError("mfa_recovery_consume_code", new Error("Invalid remaining count"));
  }

  await resetAuthAttemptFailures(attemptKey);
  sendSecurityEmail(user.id, "recovery_code_used", { remaining });
  sendJson(res, 200, {
    success: true,
    session: { access_token: token },
    remaining,
  });
}, { auth: true });

route("POST", "/api/mfa/passkeys/register/options", async ({ req, res, user, token }) => {
  requireTotpForPasskey(user);
  await requireAal2(user, token);

  const body = await getJsonBody(req).catch(() => ({}));
  const attachment =
    body.attachment === "platform" || body.attachment === "cross-platform"
      ? body.attachment
      : undefined;

  const sessionId = getTokenSessionId(token);
  if (!sessionId) throw new HttpError(401, "Invalid session", "INVALID_SESSION");

  const credentials = await getWebAuthnCredentials(user.id);
  const displayName = [
    user.user_metadata?.first_name,
    user.user_metadata?.last_name,
  ]
    .filter((part) => typeof part === "string" && part.trim())
    .join(" ")
    .slice(0, 64);

  const options = await generateRegistrationOptions({
    rpName: WEBAUTHN_RP_NAME,
    rpID: WEBAUTHN_RP_ID,
    userName: (user.email || user.id).slice(0, 64),
    userID: Buffer.from(user.id, "utf8"),
    userDisplayName: (displayName || user.email || "Stone user").slice(0, 64),
    timeout: 5 * 60 * 1000,
    attestationType: "none",
    excludeCredentials: credentials.map((credential) => ({
      id: credential.credential_id,
      transports: normalizedWebAuthnTransports(credential.transports),
    })),
    authenticatorSelection: {
      residentKey: "required",
      userVerification: "required",
      ...(attachment ? { authenticatorAttachment: attachment } : {}),
    },
  });

  await createWebAuthnChallenge(user.id, sessionId, "register", options.challenge);
  sendJson(res, 200, { success: true, options });
}, { auth: true });

route("POST", "/api/mfa/passkeys/register/verify", async ({ req, res, user, token }) => {
  requireTotpForPasskey(user);
  await requireAal2(user, token);

  const body = await getJsonBody(req);
  validateWebAuthnResponse(body.response);
  if (
    body.name !== undefined &&
    (typeof body.name !== "string" ||
      body.name.trim().length === 0 ||
      body.name.trim().length > 100 ||
      /[\u0000-\u001f\u007f]/.test(body.name))
  ) {
    throw new HttpError(400, "Invalid passkey name", "INVALID_PASSKEY_NAME");
  }

  const sessionId = getTokenSessionId(token);
  if (!sessionId) throw new HttpError(401, "Invalid session", "INVALID_SESSION");

  const challenge = await consumeWebAuthnChallenge(user.id, sessionId, "register");
  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: body.response,
      expectedChallenge: challenge,
      expectedOrigin: WEBAUTHN_ORIGIN,
      expectedRPID: WEBAUTHN_RP_ID,
      requireUserVerification: true,
    });
  } catch (error) {
    console.error("[webauthn] registration verification failed:", error?.name || "Error");
    throw new HttpError(400, "Invalid WebAuthn response", "INVALID_WEBAUTHN_RESPONSE");
  }

  const credential = verification.registrationInfo?.credential;
  if (
    !verification.verified ||
    !credential ||
    typeof credential.id !== "string" ||
    credential.id !== body.response.id ||
    credential.id.length < 1 ||
    credential.id.length > 2048 ||
    !(credential.publicKey instanceof Uint8Array) ||
    credential.publicKey.length === 0 ||
    !Number.isSafeInteger(credential.counter) ||
    credential.counter < 0
  ) {
    throw new HttpError(400, "Invalid WebAuthn response", "INVALID_WEBAUTHN_RESPONSE");
  }

  const name = body.name?.trim() || "Passkey";
  const { data, error } = await supabaseAdmin
    .from("webauthn_credentials")
    .insert({
      user_id: user.id,
      credential_id: credential.id,
      public_key: Buffer.from(credential.publicKey).toString("base64url"),
      counter: credential.counter,
      transports: normalizedWebAuthnTransports(credential.transports),
      name,
    })
    .select("id,created_at")
    .single();

  if (error) throw dbError("webauthn_credentials.insert", error);

  sendSecurityEmail(user.id, "authenticator_added", { factorType: "passkey" });
  sendJson(res, 200, {
    success: true,
    passkey: { id: data.id, name, createdAt: data.created_at },
  });
}, { auth: true });

route("GET", "/api/mfa/passkeys", async ({ res, user }) => {
  const credentials = await getWebAuthnCredentials(user.id);
  sendJson(res, 200, {
    success: true,
    passkeys: credentials.map((credential) => ({
      id: credential.id,
      name: credential.name,
      createdAt: credential.created_at,
      lastUsedAt: credential.last_used_at,
    })),
  });
}, { auth: true });

route("DELETE", "/api/mfa/passkeys", async ({ res, url, user, token }) => {
  await requireAal2(user, token);

  const id = url.searchParams.get("id");
  if (
    !id ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)
  ) {
    throw new HttpError(400, "Invalid passkey id", "INVALID_PASSKEY_ID");
  }

  const { data, error } = await supabaseAdmin
    .from("webauthn_credentials")
    .delete()
    .eq("id", id)
    .eq("user_id", user.id)
    .select("id")
    .maybeSingle();

  if (error) throw dbError("webauthn_credentials.delete", error);
  if (!data) throw new HttpError(404, "Passkey not found", "PASSKEY_NOT_FOUND");
  sendJson(res, 200, { success: true });
}, { auth: true });

route("POST", "/api/mfa/passkeys/authenticate/options", async ({ res, user, token }) => {
  requireTotpForPasskey(user);

  const sessionId = getTokenSessionId(token);
  if (!sessionId) throw new HttpError(401, "Invalid session", "INVALID_SESSION");

  const credentials = await getWebAuthnCredentials(user.id);
  if (credentials.length === 0) {
    throw new HttpError(400, "No passkeys are registered", "NO_PASSKEYS");
  }

  const options = await generateAuthenticationOptions({
    rpID: WEBAUTHN_RP_ID,
    allowCredentials: credentials.map((credential) => ({
      id: credential.credential_id,
      transports: normalizedWebAuthnTransports(credential.transports),
    })),
    timeout: 5 * 60 * 1000,
    userVerification: "required",
  });

  await createWebAuthnChallenge(user.id, sessionId, "authenticate", options.challenge);
  sendJson(res, 200, { success: true, options });
}, { auth: true });

route("POST", "/api/mfa/passkeys/authenticate/verify", async ({ req, res, user, token }) => {
  requireTotpForPasskey(user);

  const body = await getJsonBody(req);
  validateWebAuthnResponse(body.response);

  const sessionId = getTokenSessionId(token);
  if (!sessionId) throw new HttpError(401, "Invalid session", "INVALID_SESSION");

  const challenge = await consumeWebAuthnChallenge(user.id, sessionId, "authenticate");
  const { data: credential, error: lookupError } = await supabaseAdmin
    .from("webauthn_credentials")
    .select("id,credential_id,public_key,counter,transports")
    .eq("user_id", user.id)
    .eq("credential_id", body.response.id)
    .maybeSingle();

  if (lookupError) throw dbError("webauthn_credentials.lookup", lookupError);
  if (!credential) {
    throw new HttpError(400, "Invalid WebAuthn response", "INVALID_WEBAUTHN_RESPONSE");
  }

  const currentCounter = Number(credential.counter);
  if (
    !Number.isSafeInteger(currentCounter) ||
    currentCounter < 0 ||
    typeof credential.public_key !== "string" ||
    !/^[A-Za-z0-9_-]+$/.test(credential.public_key)
  ) {
    throw dbError("webauthn_credentials.lookup", new Error("Invalid credential data"));
  }

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: body.response,
      expectedChallenge: challenge,
      expectedOrigin: WEBAUTHN_ORIGIN,
      expectedRPID: WEBAUTHN_RP_ID,
      requireUserVerification: true,
      credential: {
        id: credential.credential_id,
        publicKey: Buffer.from(credential.public_key, "base64url"),
        counter: currentCounter,
        transports: normalizedWebAuthnTransports(credential.transports),
      },
    });
  } catch (error) {
    console.error("[webauthn] authentication verification failed:", error?.name || "Error");
    throw new HttpError(400, "Invalid WebAuthn response", "INVALID_WEBAUTHN_RESPONSE");
  }

  if (
    !verification.verified ||
    verification.authenticationInfo.credentialID !== credential.credential_id ||
    !Number.isSafeInteger(verification.authenticationInfo.newCounter) ||
    verification.authenticationInfo.newCounter < currentCounter
  ) {
    throw new HttpError(400, "Invalid WebAuthn response", "INVALID_WEBAUTHN_RESPONSE");
  }

  const now = new Date().toISOString();
  const { data: updatedCredential, error: updateError } = await supabaseAdmin
    .from("webauthn_credentials")
    .update({
      counter: verification.authenticationInfo.newCounter,
      last_used_at: now,
    })
    .eq("id", credential.id)
    .eq("counter", currentCounter)
    .select("id")
    .maybeSingle();

  if (updateError) throw dbError("webauthn_credentials.update_counter", updateError);
  if (!updatedCredential) {
    throw new HttpError(400, "Invalid WebAuthn response", "INVALID_WEBAUTHN_RESPONSE");
  }

  await recordVerifiedMfaSession(user.id, sessionId, "passkey");
  sendJson(res, 200, { success: true, session: { access_token: token } });
}, { auth: true });

route("POST", "/api/mfa/enroll", async ({ res, user, token }) => {
  if (userHasVerifiedMfa(user)) await requireAal2(user, token);

  enforce(limiterAccount, `mfa-enroll:${user.id}`);

  const stale = (Array.isArray(user.factors) ? user.factors : []).filter(
    (f) => isTotp(f) && f.status === "unverified"
  );

  for (const f of stale) {
    try {
      await supabaseAuthRequest(`/factors/${encodeURIComponent(f.id)}`, {
        method: "DELETE",
        token,
      });
    } catch (e) {
      console.warn("[mfa] purge stale factor failed:", e.message);
    }
  }

  const data = await supabaseAuthRequest("/factors", {
    method: "POST",
    token,
    json: {
      factor_type: "totp",
      friendly_name: `Authenticator ${Date.now()}`,
    },
  });

  authCacheInvalidateUser(user.id);

  const factorId = data?.id;
  const qrCode = data?.totp?.qr_code;
  const secret = data?.totp?.secret;

  if (!factorId) {
    throw new HttpError(502, "Supabase did not return a factor id", "MFA_ENROLL_NO_FACTOR");
  }
  if (!qrCode || !secret) {
    throw new HttpError(502, "Supabase did not return TOTP credentials", "MFA_ENROLL_INCOMPLETE");
  }

  sendJson(res, 200, {
    success: true,
    factorId,
    qrCode,
    secret,
  });
}, { auth: true });

route("POST", "/api/mfa/enroll/verify", async ({ req, res, user, token }) => {
  const body = await getJsonBody(req);
  const factorId = typeof body.factorId === "string" ? body.factorId.trim() : "";
  const code = typeof body.code === "string" ? body.code : "";

  if (!factorId || factorId.length > 128) throw new HttpError(400, "Missing factorId");
  if (!/^\d{6,8}$/.test(code)) throw new HttpError(400, "Invalid code", "INVALID_CODE");

  const attemptKey = authAttemptKey("user", user.id, getClientIp(req));
  await checkAuthAttemptLimit(attemptKey);
  const alreadyHadAuthenticator = userHasVerifiedMfa(user);
  const session = await verifyMfaCodeWithAttempts(factorId, code, token, attemptKey);

  authCacheInvalidateUser(user.id);
  sendSecurityEmail(
    user.id,
    alreadyHadAuthenticator ? "authenticator_added" : "mfa_activated",
    { factorType: "totp" }
  );

  sendJson(res, 200, {
    success: true,
    session: {
      access_token: session.access_token,
      refresh_token: session.refresh_token,
    },
  });
}, { auth: true });

route("POST", "/api/mfa/verify", async ({ req, res, user, token }) => {
  const body = await getJsonBody(req);
  let factorId = typeof body.factorId === "string" ? body.factorId.trim() : "";
  const code = typeof body.code === "string" ? body.code : "";

  if (!/^\d{6,8}$/.test(code)) throw new HttpError(400, "Invalid code", "INVALID_CODE");
  if (factorId.length > 128) throw new HttpError(400, "Invalid factorId", "INVALID_FACTOR_ID");

  if (!factorId) {
    const first = (Array.isArray(user.factors) ? user.factors : []).find(
      (f) => isTotp(f) && f.status === "verified"
    );
    if (!first) throw new HttpError(400, "No authenticator found", "NO_MFA_FACTOR");
    factorId = first.id;
  }

  const attemptKey = authAttemptKey("user", user.id, getClientIp(req));
  await checkAuthAttemptLimit(attemptKey);
  const session = await verifyMfaCodeWithAttempts(factorId, code, token, attemptKey);

  sendJson(res, 200, {
    success: true,
    session: {
      access_token: session.access_token,
      refresh_token: session.refresh_token,
    },
  });
}, { auth: true });

route("DELETE", "/api/mfa/factors", async ({ res, url, user, token }) => {
  const factorId = url.searchParams.get("factorId");

  if (!factorId || factorId.length > 128) throw new HttpError(400, "Missing factorId");

  const factor = (Array.isArray(user.factors) ? user.factors : []).find(
    (f) => f.id === factorId
  );
  if (!factor) throw new HttpError(404, "Factor not found", "FACTOR_NOT_FOUND");

  const verifiedTotpCount = verifiedFactorsOf(user).filter(isTotp).length;
  if (factor.status === "verified") {
    await requireAal2(user, token);
  }

  await supabaseAuthRequest(`/factors/${encodeURIComponent(factorId)}`, {
    method: "DELETE",
    token,
  });

  authCacheInvalidateUser(user.id);
  if (factor.status === "verified" && verifiedTotpCount === 1) {
    sendSecurityEmail(user.id, "mfa_disabled", { factorType: "totp" });
  }

  sendJson(res, 200, { success: true });
}, { auth: true });

// ============================================================
// ROUTES — TAGS
// ============================================================

function parseTagInput(body) {
  const name = String(body.name ?? "").trim();

  if (!name) {
    throw new HttpError(400, "Tag name is required", "TAG_NAME_REQUIRED");
  }
  if (name.length > TAG_NAME_MAX) {
    throw new HttpError(
      400,
      `Tag name must be at most ${TAG_NAME_MAX} characters`,
      "TAG_NAME_TOO_LONG"
    );
  }
  if (/[\u0000-\u001f\u007f]/.test(name)) {
    throw new HttpError(400, "Invalid tag name", "TAG_NAME_INVALID");
  }

  let color = null;
  if (body.color !== undefined && body.color !== null && body.color !== "") {
    const raw = String(body.color).trim();
    if (!TAG_COLOR_PATTERN.test(raw)) {
      throw new HttpError(400, "Invalid tag color (expected #RRGGBB)", "TAG_COLOR_INVALID");
    }
    color = raw.toLowerCase();
  }

  return { name, color };
}

function formatTag(row) {
  return {
    id: row.id,
    name: row.name,
    color: row.color || null,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

route("GET", "/api/tags", async ({ res, user }) => {
  const { data, error } = await supabaseAdmin
    .from("tags")
    .select("id,name,color,created_at,updated_at")
    .eq("user_id", user.id)
    .order("name", { ascending: true });

  if (error) {
    if (isSchemaCacheMissingError(error)) {
      console.warn("[tags] table manquante — retourne []");
      sendJson(res, 200, { success: true, tags: [] });
      return;
    }
    throw dbError("tags.list", error);
  }

  sendJson(res, 200, { success: true, tags: (data || []).map(formatTag) });
}, { auth: true });

route(["POST", "PUT"], "/api/tags", async ({ req, res, user }) => {
  enforce(limiterTags, `tags:${user.id}`);

  const body = await getJsonBody(req);
  const { name, color } = parseTagInput(body);

  const idInput = body.id ?? body.tag_id;
  const hasId = idInput !== undefined && idInput !== null && idInput !== "";
  let id = null;

  if (hasId) {
    id = String(idInput);
    if (!TAG_ID_PATTERN.test(id)) {
      throw new HttpError(400, "Invalid tag id", "TAG_ID_INVALID");
    }
  }

  if (!hasId) {
    const { count, error: countError } = await supabaseAdmin
      .from("tags")
      .select("id", { count: "exact", head: true })
      .eq("user_id", user.id);

    if (countError) {
      if (isSchemaCacheMissingError(countError)) {
        throw new HttpError(503, "Tags are not available yet", "TAGS_UNAVAILABLE");
      }
      throw dbError("tags.count", countError);
    }
    if (Number(count) >= MAX_TAGS_PER_USER) {
      throw new HttpError(
        400,
        `You can have at most ${MAX_TAGS_PER_USER} tags.`,
        "TAGS_LIMIT_REACHED"
      );
    }
  }

  const row = {
    user_id: user.id,
    name,
    color,
    updated_at: new Date().toISOString(),
  };

  const query = hasId
    ? supabaseAdmin
        .from("tags")
        .update(row)
        .eq("id", id)
        .eq("user_id", user.id)
        .select("id,name,color,created_at,updated_at")
        .maybeSingle()
    : supabaseAdmin
        .from("tags")
        .insert(row)
        .select("id,name,color,created_at,updated_at")
        .maybeSingle();

  const { data, error } = await query;

  if (error) {
    if (error.code === "23505" || /duplicate key/i.test(error.message || "")) {
      throw new HttpError(409, "A tag with this name already exists", "TAG_DUPLICATE");
    }
    if (isSchemaCacheMissingError(error)) {
      throw new HttpError(503, "Tags are not available yet", "TAGS_UNAVAILABLE");
    }
    throw dbError("tags.save", error);
  }

  if (!data) {
    if (hasId) throw new HttpError(404, "Tag not found", "TAG_NOT_FOUND");
    throw dbError("tags.save", new Error("No row returned"));
  }

  sendJson(res, 200, { success: true, tag: formatTag(data) });
}, { auth: true });

route("DELETE", "/api/tags", async ({ req, res, url, user }) => {
  enforce(limiterTags, `tags:${user.id}`);

  let id = url.searchParams.get("id");
  if (!id) {
    const body = await getJsonBody(req).catch(() => ({}));
    id = body.id ?? body.tag_id ?? null;
  }

  if (!id || !TAG_ID_PATTERN.test(String(id))) {
    throw new HttpError(400, "Invalid tag id", "TAG_ID_INVALID");
  }

  const { data, error } = await supabaseAdmin
    .from("tags")
    .delete()
    .eq("id", id)
    .eq("user_id", user.id)
    .select("id")
    .maybeSingle();

  if (error) {
    if (isSchemaCacheMissingError(error)) {
      sendJson(res, 200, { success: true });
      return;
    }
    throw dbError("tags.delete", error);
  }

  if (!data) throw new HttpError(404, "Tag not found", "TAG_NOT_FOUND");
  sendJson(res, 200, { success: true });
}, { auth: true });

// ============================================================
// BLOC 3 — ROUTES — SAVED REPLIES
// ============================================================

const SAVED_REPLY_COLUMNS = "id,name,content,created_at,updated_at";

function parseSavedReplyInput(body) {
  const name = String(body.name ?? body.title ?? body.label ?? "").trim();
  const content = String(body.content ?? body.text ?? body.body ?? "").trim();

  if (!name) {
    throw new HttpError(400, "Saved reply name is required", "SAVED_REPLY_NAME_REQUIRED");
  }
  if (name.length > SAVED_REPLY_NAME_MAX) {
    throw new HttpError(
      400,
      `Saved reply name must be at most ${SAVED_REPLY_NAME_MAX} characters`,
      "SAVED_REPLY_NAME_TOO_LONG"
    );
  }
  if (/[\u0000-\u001f\u007f]/.test(name)) {
    throw new HttpError(400, "Invalid saved reply name", "SAVED_REPLY_NAME_INVALID");
  }

  if (!content) {
    throw new HttpError(400, "Saved reply content is required", "SAVED_REPLY_CONTENT_REQUIRED");
  }
  if (content.length > SAVED_REPLY_CONTENT_MAX) {
    throw new HttpError(
      400,
      `Saved reply content must be at most ${SAVED_REPLY_CONTENT_MAX} characters`,
      "SAVED_REPLY_CONTENT_TOO_LONG"
    );
  }
  // Autorise \n et \t, refuse les autres caractères de contrôle.
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(content)) {
    throw new HttpError(400, "Invalid saved reply content", "SAVED_REPLY_CONTENT_INVALID");
  }

  return { name, content };
}

function formatSavedReply(row) {
  return {
    id: row.id,
    name: row.name,
    content: row.content,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

route("GET", "/api/saved-replies", async ({ res, user }) => {
  const { data, error } = await supabaseAdmin
    .from("saved_replies")
    .select(SAVED_REPLY_COLUMNS)
    .eq("user_id", user.id)
    .order("created_at", { ascending: true });

  if (error) {
    if (isSchemaCacheMissingError(error)) {
      console.warn("[saved_replies] table manquante — retourne []");
      sendJson(res, 200, { success: true, replies: [] });
      return;
    }
    throw dbError("saved_replies.list", error);
  }

  sendJson(res, 200, { success: true, replies: (data || []).map(formatSavedReply) });
}, { auth: true });

route(["POST", "PUT"], "/api/saved-replies", async ({ req, res, user }) => {
  enforce(limiterSavedReplies, `saved-replies:${user.id}`);

  const body = await getJsonBody(req);
  const { name, content } = parseSavedReplyInput(body);

  const idInput = body.id ?? body.reply_id;
  const hasId = idInput !== undefined && idInput !== null && idInput !== "";
  let id = null;

  if (hasId) {
    id = String(idInput);
    if (!SAVED_REPLY_ID_PATTERN.test(id)) {
      throw new HttpError(400, "Invalid saved reply id", "SAVED_REPLY_ID_INVALID");
    }
  } else {
    const { count, error: countError } = await supabaseAdmin
      .from("saved_replies")
      .select("id", { count: "exact", head: true })
      .eq("user_id", user.id);

    if (countError) {
      if (isSchemaCacheMissingError(countError)) {
        throw new HttpError(503, "Saved replies are not available yet", "SAVED_REPLIES_UNAVAILABLE");
      }
      throw dbError("saved_replies.count", countError);
    }
    if (Number(count) >= MAX_SAVED_REPLIES_PER_USER) {
      throw new HttpError(
        400,
        `You can have at most ${MAX_SAVED_REPLIES_PER_USER} saved replies.`,
        "SAVED_REPLIES_LIMIT_REACHED"
      );
    }
  }

  const row = {
    user_id: user.id,
    name,
    content,
    updated_at: new Date().toISOString(),
  };

  const query = hasId
    ? supabaseAdmin
        .from("saved_replies")
        .update(row)
        .eq("id", id)
        .eq("user_id", user.id)
        .select(SAVED_REPLY_COLUMNS)
        .maybeSingle()
    : supabaseAdmin
        .from("saved_replies")
        .insert(row)
        .select(SAVED_REPLY_COLUMNS)
        .maybeSingle();

  const { data, error } = await query;

  if (error) {
    if (isSchemaCacheMissingError(error)) {
      throw new HttpError(503, "Saved replies are not available yet", "SAVED_REPLIES_UNAVAILABLE");
    }
    throw dbError("saved_replies.save", error);
  }

  if (!data) {
    if (hasId) throw new HttpError(404, "Saved reply not found", "SAVED_REPLY_NOT_FOUND");
    throw dbError("saved_replies.save", new Error("No row returned"));
  }

  sendJson(res, 200, { success: true, reply: formatSavedReply(data) });
}, { auth: true });

route("DELETE", "/api/saved-replies", async ({ req, res, url, user }) => {
  enforce(limiterSavedReplies, `saved-replies:${user.id}`);

  let id = url.searchParams.get("id");
  if (!id) {
    const body = await getJsonBody(req).catch(() => ({}));
    id = body.id ?? body.reply_id ?? null;
  }

  if (!id || !SAVED_REPLY_ID_PATTERN.test(String(id))) {
    throw new HttpError(400, "Invalid saved reply id", "SAVED_REPLY_ID_INVALID");
  }

  const { data, error } = await supabaseAdmin
    .from("saved_replies")
    .delete()
    .eq("id", id)
    .eq("user_id", user.id)
    .select("id")
    .maybeSingle();

  if (error) {
    if (isSchemaCacheMissingError(error)) {
      sendJson(res, 200, { success: true });
      return;
    }
    throw dbError("saved_replies.delete", error);
  }

  if (!data) throw new HttpError(404, "Saved reply not found", "SAVED_REPLY_NOT_FOUND");
  sendJson(res, 200, { success: true });
}, { auth: true });

// ============================================================
// ✅ NOUVEAU — ROUTES — SCHEDULED POSTS
// ============================================================
//
// Équivalent natif du fichier multer :
//   POST   /api/posts   (multipart, `upload.any()`)
//   GET    /api/posts
//   DELETE /api/posts
//
// Le champ `data` contient le JSON de configuration, les fichiers
// sont nommés `media` (partagés) ou `media_<network>` (par réseau).
// Les médias sont stockés dans le bucket public `post-media`.
// ------------------------------------------------------------

function sanitizePostExtension(fileName) {
  const raw = String(fileName || "").split(".").pop() || "";
  const ext = raw.toLowerCase();
  return /^[a-z0-9]{1,10}$/.test(ext) ? ext : "bin";
}

async function uploadPostFile(userId, file) {
  const ext = sanitizePostExtension(file.fileName);
  const objectPath = `${userId}/${crypto.randomUUID()}.${ext}`;
  const mimeType = file.mimeType || "application/octet-stream";

  const { error } = await supabaseAdmin.storage
    .from(POST_MEDIA_BUCKET)
    .upload(objectPath, file.buffer, { contentType: mimeType });

  if (error) throw error;

  const { data: pub } = supabaseAdmin.storage.from(POST_MEDIA_BUCKET).getPublicUrl(objectPath);

  return {
    url: pub.publicUrl,
    path: objectPath,
    kind: mimeType.startsWith("video/") ? "video" : "image",
  };
}

route("POST", "/api/posts", async ({ req, res, user }) => {
  enforce(limiterPosts, `posts:${user.id}`);

  const declared = Number(req.headers["content-length"] || 0);
  if (declared > MAX_POST_UPLOAD_TOTAL + 2 * 1024 * 1024) {
    throw tooLargeError("Post media is too large.");
  }

  let upload;
  try {
    upload = await parseMultipartAny(req, {
      maxFiles: MAX_POST_FILES,
      maxFileSize: MAX_POST_FILE_SIZE,
    });
  } catch (error) {
    if (error?.code === "FILE_TOO_LARGE") {
      throw new HttpError(
        400,
        `Each file must be under ${MAX_POST_FILE_SIZE / 1024 / 1024} MB.`,
        "FILE_TOO_LARGE"
      );
    }
    if (error?.code === "TOO_MANY_FILES") {
      throw new HttpError(
        400,
        `Posts are limited to ${MAX_POST_FILES} files.`,
        "TOO_MANY_FILES"
      );
    }
    throw error instanceof HttpError ? error : new HttpError(400, "Could not read the uploaded files.");
  }

  let data;
  try {
    data = JSON.parse(upload.fields.data || "{}");
  } catch {
    throw new HttpError(400, "Invalid data JSON", "INVALID_DATA_JSON");
  }
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new HttpError(400, "Invalid data payload", "INVALID_DATA_PAYLOAD");
  }

  const userId = user.id;
  const files = upload.files;
  const external = Array.isArray(data.externalNetworks) ? data.externalNetworks : [];
  const networks = [
    ...(Array.isArray(data.networks) ? data.networks : []),
    ...external,
  ];

  if (networks.length === 0) {
    throw new HttpError(400, "At least one network is required", "NO_NETWORK");
  }

  // Upload des médias partagés (fieldname === "media") une seule fois
  const shared = await Promise.all(
    files.filter((f) => f.fieldname === "media").map((f) => uploadPostFile(userId, f))
  );

  const contents = data.contents && typeof data.contents === "object" ? data.contents : {};
  const channelKeys = data.channelKeys && typeof data.channelKeys === "object" ? data.channelKeys : {};

  let scheduledAt = null;
  if (data.scheduleMode === "later") {
    const parsed = new Date(data.scheduledAt);
    if (Number.isNaN(parsed.getTime())) {
      throw new HttpError(400, "Invalid scheduledAt", "INVALID_SCHEDULED_AT");
    }
    scheduledAt = parsed.toISOString();
  } else if (data.scheduleMode === "now") {
    scheduledAt = new Date().toISOString();
  }

  const rows = [];
  for (const network of networks) {
    const own = files.filter((f) => f.fieldname === `media_${network}`);
    const media = own.length
      ? await Promise.all(own.map((f) => uploadPostFile(userId, f)))
      : shared;

    rows.push({
      user_id: userId,
      network,
      channel_key: channelKeys[network] ?? null,
      title: String(data.title || "").slice(0, 500),
      content: String(contents[network] ?? ""),
      scheduled_at: scheduledAt,
      status:
        data.scheduleMode === "save_in_folder"
          ? "draft"
          : external.includes(network)
          ? "external"
          : "scheduled",
      media,
      tag_ids: Array.isArray(data.tagIds) ? data.tagIds : [],
      options: network === "youtube" ? data.youtube ?? null : null,
    });
  }

  const { data: inserted, error } = await supabaseAdmin
    .from("scheduled_posts")
    .insert(rows)
    .select();

  if (error) throw dbError("scheduled_posts.insert", error);

  sendJson(res, 200, { success: true, posts: inserted });
}, { auth: true });

route("GET", "/api/posts", async ({ res, url, user }) => {
  let q = supabaseAdmin
    .from("scheduled_posts")
    .select("*")
    .eq("user_id", user.id) // service role : filtrer explicitement par user
    .not("scheduled_at", "is", null)
    .order("scheduled_at");

  const from = url.searchParams.get("from");
  const to = url.searchParams.get("to");
  if (from) q = q.gte("scheduled_at", from);
  if (to) q = q.lt("scheduled_at", to);

  const { data, error } = await q;
  if (error) throw dbError("scheduled_posts.list", error);

  sendJson(res, 200, { success: true, posts: data });
}, { auth: true });

route("DELETE", "/api/posts", async ({ res, url, user }) => {
  const id = url.searchParams.get("id");
  if (!id) throw new HttpError(400, "Missing post id", "POST_ID_REQUIRED");

  const { error } = await supabaseAdmin
    .from("scheduled_posts")
    .delete()
    .eq("id", id)
    .eq("user_id", user.id);

  if (error) throw dbError("scheduled_posts.delete", error);

  sendJson(res, 200, { success: true });
}, { auth: true });

// ------------------------------------------------------------
// ✅ NOUVEAU — transition périodique scheduled/external → published
// ------------------------------------------------------------
async function publishDueScheduledPosts() {
  const nowIso = new Date().toISOString();
  const { error } = await supabaseAdmin
    .from("scheduled_posts")
    .update({ status: "published" })
    .in("status", ["scheduled", "external"])
    .lte("scheduled_at", nowIso);

  if (error) {
    console.warn("[posts] status refresh failed:", error.message);
  }
}

// ============================================================
// ROUTES — UTILISATEUR
// ============================================================

route("GET", "/api/user", ({ res, user }) => {
  sendJson(res, 200, { success: true, user: formatUser(user) });
}, { auth: true });

route("GET", "/api/user/profile", ({ res, user }) => {
  sendJson(res, 200, { success: true, user: formatUser(user) });
}, { auth: true });

route(["PUT", "PATCH"], "/api/user/profile", async ({ req, res, user, token }) => {
  await requireAal2(user, token);

  const body = await getJsonBody(req);
  const metadata = { ...(user.user_metadata || {}) };
  const limitedString = (value, max) => String(value ?? "").slice(0, max);

  if (body.firstName !== undefined || body.first_name !== undefined) {
    metadata.first_name = limitedString(body.firstName ?? body.first_name ?? "", 100);
  }

  if (body.lastName !== undefined || body.last_name !== undefined) {
    metadata.last_name = limitedString(body.lastName ?? body.last_name ?? "", 100);
  }

  if (body.bio !== undefined) metadata.bio = limitedString(body.bio, 500);

  if (body.avatarUrl !== undefined || body.avatar_url !== undefined) {
    const raw = body.avatarUrl ?? body.avatar_url;

    if (raw === null || raw === "" || raw === undefined) {
      metadata.custom_avatar_url = "";
    } else {
      const avatarUrl = limitedString(raw, 1000);
      const ownPrefix = `${SUPABASE_BASE_URL}/storage/v1/object/public/${AVATAR_BUCKET}/${user.id}/`;

      if (!avatarUrl.startsWith(ownPrefix)) {
        throw new HttpError(400, "Invalid avatar URL");
      }

      metadata.custom_avatar_url = avatarUrl;
    }
  }

  const { data, error } = await adminUpdateUser(user.id, { user_metadata: metadata });
  if (error) throw error;

  sendJson(res, 200, { success: true, user: formatUser(data.user) });
}, { auth: true });

route(["PUT", "POST"], "/api/user/password", async ({ req, res, user, token }) => {
  await requireAal2(user, token);

  const body = await getJsonBody(req);
  const currentPassword = String(body.currentPassword ?? body.current_password ?? "").trim();
  const newPassword = String(body.newPassword ?? body.new_password ?? "");

  if (!newPassword) throw new HttpError(400, "New password is required");
  if (newPassword.length < 8) throw new HttpError(400, "New password must contain at least 8 characters");
  if (newPassword.length > 128) throw new HttpError(400, "New password must contain at most 128 characters");
  if (!user.email) throw new HttpError(400, "No email associated with this account");

  const hasPassword = userHasPassword(user);

  if (hasPassword) {
    if (!currentPassword) {
      throw new HttpError(400, "Current password is required", "CURRENT_PASSWORD_REQUIRED");
    }

    enforce(limiterAccount, `password:${user.id}`);

    const { error: verifyError } = await supabase.auth.signInWithPassword({
      email: user.email,
      password: currentPassword,
    });

    if (verifyError) {
      throw new HttpError(401, "Current password is incorrect", "INVALID_CURRENT_PASSWORD");
    }
  } else {
    enforce(limiterAccount, `password-set:${user.id}`);
  }

  const { error } = await adminUpdateUser(user.id, { password: newPassword });
  if (error) {
    if (error.code === "same_password" || error.code === "weak_password") {
      throw new HttpError(400, error.message || "This password cannot be used.", error.code);
    }
    throw error;
  }

  sendJson(res, 200, {
    success: true,
    message: hasPassword ? "Password updated successfully" : "Password set successfully",
  });
}, { auth: true });

route("POST", "/api/user/avatar", async ({ req, res, user, token }) => {
  await requireAal2(user, token);

  enforce(limiterAccount, `avatar:${user.id}`);

  let upload;

  try {
    upload = await parseMultipart(req, { fileField: "avatar", maxSize: MAX_AVATAR_SIZE });
  } catch (error) {
    if (error?.code === "FILE_TOO_LARGE") throw new HttpError(400, "Avatar is too large. Maximum size is 2 MB.");
    if (error?.code === "NO_FILE") throw new HttpError(400, "No 'avatar' file was provided.");
    throw new HttpError(400, "Could not read the uploaded file.");
  }

  const sniffedType = sniffImageType(upload.buffer);

  if (!sniffedType || !ALLOWED_AVATAR_TYPES.includes(sniffedType)) {
    throw new HttpError(400, "Unsupported image format. Use PNG, JPEG, WebP or GIF.");
  }

  const storagePath = `${user.id}/${crypto.randomUUID()}.${AVATAR_EXTENSIONS[sniffedType]}`;

  const { error: storageError } = await supabaseAdmin.storage
    .from(AVATAR_BUCKET)
    .upload(storagePath, upload.buffer, {
      contentType: sniffedType,
      cacheControl: "31536000",
      upsert: false,
    });

  if (storageError) throw storageError;

  const { data: publicUrlData } = supabaseAdmin.storage.from(AVATAR_BUCKET).getPublicUrl(storagePath);

  sendJson(res, 200, { success: true, avatar_url: publicUrlData.publicUrl });
}, { auth: true });

route("DELETE", "/api/user/avatar", async ({ req, res, user, token }) => {
  await requireAal2(user, token);

  const body = await getJsonBody(req);
  const filePathOrUrl = String(body.filePathOrUrl || "").trim();

  if (!filePathOrUrl) throw new HttpError(400, "Missing filePathOrUrl");

  const storagePath = extractAvatarStoragePath(filePathOrUrl);

  if (!storagePath) {
    sendJson(res, 200, { success: true });
    return;
  }

  if (!isOwnedAvatarPath(storagePath, user.id)) {
    throw new HttpError(403, "You can only delete your own avatar");
  }

  const { error } = await supabaseAdmin.storage.from(AVATAR_BUCKET).remove([storagePath]);
  if (error) throw error;

  sendJson(res, 200, { success: true });
}, { auth: true });

// ============================================================
// ROUTES — STRIPE
// ============================================================

route("POST", "/api/stripe/checkout", async ({ req, res, user }) => {
  requireStripe();

  const body = await getJsonBody(req);
  const plan = String(body.plan || "").toLowerCase();
  const period = body.period === "annual" ? "annual" : "monthly";

  const priceId = Object.hasOwn(STRIPE_PRICES, plan) ? STRIPE_PRICES[plan][period] : undefined;

  if (!priceId) {
    const knownPlan = Object.hasOwn(STRIPE_PRICES, plan);
    throw new HttpError(
      400,
      knownPlan
        ? `Plan "${plan}" (${period}) is not configured — missing STRIPE_PRICE_${plan.toUpperCase()}_${period.toUpperCase()}`
        : `Unknown plan or period (plan="${plan.slice(0, 30)}", period="${period}")`
    );
  }

  const customerId = await getStripeCustomerId(user, { create: true });

  const session = await stripe.checkout.sessions.create({
    mode: "subscription",
    customer: customerId,
    line_items: [{ price: priceId, quantity: 1 }],
    allow_promotion_codes: true,
    client_reference_id: user.id,
    success_url: STRIPE_SUCCESS_URL,
    cancel_url: STRIPE_CANCEL_URL,
    subscription_data: { metadata: { supabase_user_id: user.id, plan, period } },
  });

  sendJson(res, 200, { success: true, id: session.id, url: session.url });
}, { auth: true });

route("POST", "/api/stripe/portal", async ({ res, user }) => {
  requireStripe();

  const customerId = await getStripeCustomerId(user);

  if (!customerId) throw new HttpError(400, "No Stripe customer associated with this account");

  const session = await stripe.billingPortal.sessions.create({
    customer: customerId,
    return_url: STRIPE_PORTAL_RETURN_URL,
  });

  sendJson(res, 200, { success: true, url: session.url });
}, { auth: true });

route("GET", "/api/stripe/subscription", async ({ res, user }) => {
  requireStripe();

  const customerId = await getStripeCustomerId(user);

  if (!customerId) {
    sendJson(res, 200, { success: true, subscription: null });
    return;
  }

  const list = await stripe.subscriptions.list({ customer: customerId, status: "all", limit: 1 });
  const sub = list.data[0];

  if (sub) {
    const stored = user.app_metadata?.subscription;
    const fresh = subscriptionSnapshot(sub);

    const changed =
      !stored ||
      stored.id !== fresh.id ||
      stored.status !== fresh.status ||
      stored.price_id !== fresh.price_id ||
      stored.plan_key !== fresh.plan_key ||
      stored.current_period_end !== fresh.current_period_end ||
      stored.cancel_at_period_end !== fresh.cancel_at_period_end;

    if (changed) {
      try {
        await syncSubscriptionToUser(user.id, sub);
      } catch (syncError) {
        console.error("Subscription self-heal failed:", syncError.message);
      }
    }
  }

  const priceId = sub?.items?.data?.[0]?.price?.id || null;

  sendJson(res, 200, {
    success: true,
    subscription: sub
      ? {
          id: sub.id,
          status: sub.status,
          price_id: priceId,
          ...planDetails(priceId, sub.metadata?.plan),
          current_period_end: sub.current_period_end,
          cancel_at_period_end: sub.cancel_at_period_end,
        }
      : null,
  });
}, { auth: true });

const processedStripeEvents = createSeenCache(10_000, 24 * 60 * 60 * 1000);

route("POST", "/api/stripe/webhook", async ({ req, res, requestId }) => {
  if (!stripe || !STRIPE_WEBHOOK_SECRET) throw new HttpError(500, "Stripe webhook not configured");

  const signature = req.headers["stripe-signature"];
  if (!signature) throw new HttpError(400, "Missing stripe-signature");

  const rawBody = await getRawBody(req);

  let event;

  try {
    event = stripe.webhooks.constructEvent(rawBody, signature, STRIPE_WEBHOOK_SECRET);
  } catch (webhookError) {
    console.warn(`[${requestId}] Webhook signature verification failed:`, webhookError.message);
    throw new HttpError(400, "Webhook signature verification failed");
  }

  if (processedStripeEvents.has(event.id)) {
    sendJson(res, 200, { received: true, duplicate: true });
    return;
  }

  await withLock(`stripe-event:${event.id}`, () => processStripeEvent(event));
  processedStripeEvents.add(event.id);

  sendJson(res, 200, { received: true });
});

// ============================================================
// ROUTES — TIKTOK
// ============================================================

route("POST", "/api/tiktok/auth/url", ({ res, user }) => {
  const params = new URLSearchParams({
    client_key: TIKTOK_CLIENT_KEY,
    scope: TIKTOK_SCOPES,
    response_type: "code",
    redirect_uri: TIKTOK_REDIRECT_URI,
    state: createOAuthState("tiktok", user.id),
  });

  sendJson(res, 200, {
    success: true,
    url: `https://www.tiktok.com/v2/auth/authorize/?${params.toString()}`,
    capabilities: tiktokCapabilities(),
  });
}, { auth: true });

route("POST", "/api/tiktok/auth/callback", async ({ req, res, user }) => {
  const body = await getJsonBody(req);
  const authCode = assertValidOAuthCallback("tiktok", body, user.id);

  const account = await dedupeCallback(`tiktok:${user.id}:${sha256(authCode)}`, async () => {
    let tokens;

    try {
      tokens = await tiktokApi("/v2/oauth/token/", {
        form: {
          client_key: TIKTOK_CLIENT_KEY,
          client_secret: TIKTOK_CLIENT_SECRET,
          code: authCode,
          grant_type: "authorization_code",
          redirect_uri: TIKTOK_REDIRECT_URI,
        },
      });
    } catch (error) {
      if (error instanceof HttpError && (error.code === "access_denied" || /access_denied/i.test(error.message))) {
        throw new HttpError(403, TIKTOK_SANDBOX
          ? "TikTok refused the connection. In sandbox mode, add the TikTok account as a Sandbox tester."
          : "TikTok refused the connection.", "TIKTOK_ACCESS_DENIED");
      }
      throw error;
    }

    let profile = {};

    try {
      const info = await tiktokApi("/v2/user/info/?fields=open_id,avatar_url,display_name", { method: "GET", token: tokens.access_token });
      profile = info.data?.user || {};
    } catch (profileError) {
      console.warn("TikTok user info error:", profileError.message);
    }

    await saveTikTokTokens(user.id, tokens, {
      display_name: profile.display_name || null,
      avatar_url: profile.avatar_url || null,
    });

    return { display_name: profile.display_name || null, avatar_url: profile.avatar_url || null };
  });

  sendJson(res, 200, { success: true, account, capabilities: tiktokCapabilities() });
}, { auth: true });

route("GET", "/api/tiktok/status", async ({ res, url, user }) => {
  const force = url.searchParams.get("refresh") === "1";
  const { account, needsReconnect } = await refreshTikTokProfile(user.id, { force });
  const usable = Boolean(account) && !needsReconnect;

  sendJson(res, 200, {
    success: true,
    connected: usable,
    needs_reconnect: needsReconnect || undefined,
    account: usable
      ? { display_name: account.display_name, avatar_url: account.avatar_url, scope: account.scope }
      : null,
    capabilities: tiktokCapabilities(),
  });
}, { auth: true });

route("DELETE", "/api/tiktok/disconnect", async ({ res, user }) => {
  const account = await getTikTokAccount(user.id);

  if (account) {
    if (account.access_token) {
      try {
        await tiktokApi("/v2/oauth/revoke/", {
          form: { client_key: TIKTOK_CLIENT_KEY, client_secret: TIKTOK_CLIENT_SECRET, token: account.access_token },
        });
      } catch (revokeError) {
        console.warn("TikTok revoke error:", revokeError.message);
      }
    }

    const { error } = await supabaseAdmin.from("tiktok_accounts").delete().eq("user_id", user.id);
    if (error) throw error;

    clearTikTokProfileThrottle(user.id);
  }

  sendJson(res, 200, { success: true });
}, { auth: true });

route("GET", "/api/tiktok/creator-info", async ({ res, user }) => {
  const accessToken = await getValidTikTokToken(user.id);
  const result = await tiktokApi("/v2/post/publish/creator_info/query/", { token: accessToken, json: {} });

  sendJson(res, 200, { success: true, creator: result.data, capabilities: tiktokCapabilities() });
}, { auth: true });

route("POST", "/api/tiktok/publish", async ({ req, res, user }) => {
  enforce(limiterPublish, `tiktok:${user.id}`);

  const declared = Number(req.headers["content-length"] || 0);

  if (declared > MAX_VIDEO_SIZE + 1024 * 1024) {
    throw tooLargeError(`Video is too large. Maximum size is ${MAX_VIDEO_SIZE / 1024 / 1024} MB.`);
  }

  const accessToken = await getValidTikTokToken(user.id);
  await acquireVideoSlot();

  try {
    let upload;

    try {
      upload = await parseMultipart(req, { fileField: "video", maxSize: MAX_VIDEO_SIZE });
    } catch (error) {
      if (error?.code === "FILE_TOO_LARGE") throw new HttpError(400, `Video is too large. Maximum size is ${MAX_VIDEO_SIZE / 1024 / 1024} MB.`);
      if (error?.code === "NO_FILE") throw new HttpError(400, "No 'video' file was provided.");
      throw error instanceof HttpError ? error : new HttpError(400, "Could not read the uploaded file.");
    }

    const mimeType = sniffVideoType(upload.buffer);
    if (!mimeType) throw new HttpError(400, "Unsupported format. Use MP4, MOV or WebM.");

    const requestedMode = upload.fields.mode === "draft" ? "draft" : "direct";
    const mode = resolveVideoMode(requestedMode);
    const chunking = computeChunking(upload.buffer.length);

    const sourceInfo = {
      source: "FILE_UPLOAD",
      video_size: upload.buffer.length,
      chunk_size: chunking.chunkSize,
      total_chunk_count: chunking.totalChunks,
    };

    const init = await initTikTokPublish(accessToken, mode, upload.fields, sourceInfo);
    await uploadVideoToTikTok(init.data.upload_url, upload.buffer, mimeType, chunking);

    sendJson(res, 200, {
      success: true,
      mode,
      requested_mode: requestedMode,
      forced_privacy_level: mode === "direct" ? resolvePrivacy(upload.fields.privacy_level) : null,
      sandbox: TIKTOK_SANDBOX,
      publish_id: init.data.publish_id,
    });
  } finally {
    releaseVideoSlot();
  }
}, { auth: true });

route("POST", "/api/tiktok/publish_url", async ({ req, res, user }) => {
  enforce(limiterPublish, `tiktok:${user.id}`);

  const body = await getJsonBody(req);
  const videoUrl = String(body.videoUrl || "").trim();

  if (!/^https:\/\//i.test(videoUrl) || videoUrl.length > 2048) {
    throw new HttpError(400, "videoUrl must be a valid https URL");
  }

  const requestedMode = body.mode === "draft" ? "draft" : "direct";
  const mode = resolveVideoMode(requestedMode);
  const accessToken = await getValidTikTokToken(user.id);

  const init = await initTikTokPublish(accessToken, mode, body, {
    source: "PULL_FROM_URL",
    video_url: videoUrl,
  });

  sendJson(res, 200, {
    success: true,
    mode,
    requested_mode: requestedMode,
    forced_privacy_level: mode === "direct" ? resolvePrivacy(body.privacy_level) : null,
    sandbox: TIKTOK_SANDBOX,
    publish_id: init.data.publish_id,
  });
}, { auth: true });

route("POST", "/api/tiktok/publish/photos", async ({ req, res, user }) => {
  if (!PUBLIC_API_URL) throw new HttpError(500, "Photo publishing is not configured (PUBLIC_API_URL missing)", "PUBLIC_API_URL_MISSING");
  if (!PUBLIC_API_URL.startsWith("https://")) throw new HttpError(500, "PUBLIC_API_URL must use https", "PUBLIC_API_URL_NOT_HTTPS");
  if (publicApiLooksLikeFrontend()) throw new HttpError(500, "PUBLIC_API_URL points to the frontend instead of the API server", "PUBLIC_API_URL_WRONG_HOST");

  enforce(limiterPublish, `tiktok:${user.id}`);

  const declared = Number(req.headers["content-length"] || 0);

  if (declared > MAX_PHOTOS_TOTAL + 1024 * 1024) {
    throw tooLargeError(`Photos are too large. Maximum total size is ${MAX_PHOTOS_TOTAL / 1024 / 1024} MB.`);
  }

  const accessToken = await getValidTikTokToken(user.id);
  await acquireVideoSlot();

  let storedNames = [];

  try {
    let upload;

    try {
      upload = await parseMultipartFiles(req, { fileField: "photos", maxFiles: MAX_TIKTOK_PHOTOS, maxFileSize: MAX_PHOTO_SIZE });
    } catch (error) {
      if (error?.code === "FILE_TOO_LARGE") throw new HttpError(400, `Each photo must be under ${MAX_PHOTO_SIZE / 1024 / 1024} MB.`);
      if (error?.code === "TOO_MANY_FILES") throw new HttpError(400, `TikTok carousels are limited to ${MAX_TIKTOK_PHOTOS} photos.`);
      if (error?.code === "NO_FILE") throw new HttpError(400, "No photos were provided.");
      throw error instanceof HttpError ? error : new HttpError(400, "Could not read the uploaded files.");
    }

    const photos = [];
    let totalSize = 0;

    for (const file of upload.files) {
      const type = sniffImageType(file.buffer);

      if (type !== "image/jpeg" && type !== "image/webp") {
        throw new HttpError(400, "Unsupported image format. TikTok accepts JPEG and WebP.");
      }

      totalSize += file.buffer.length;
      photos.push({ buffer: file.buffer, type });
    }

    if (totalSize > MAX_PHOTOS_TOTAL) {
      throw tooLargeError(`Photos are too large. Maximum total size is ${MAX_PHOTOS_TOTAL / 1024 / 1024} MB.`);
    }

    const fields = upload.fields;
    const requestedMode = fields.mode === "draft" ? "draft" : "direct";
    const mode = resolvePhotoMode(requestedMode);
    const postInfo = buildPhotoPostInfo(mode, fields);

    const requestedCover = Number.parseInt(fields.cover_index, 10);
    const coverIndex = Math.min(Math.max((Number.isFinite(requestedCover) ? requestedCover : 1) - 1, 0), photos.length - 1);

    storedNames = await storeTikTokPhotos(photos);
    upload = null;

    const imageUrls = storedNames.map((name) => `${PUBLIC_API_URL}/api/media/tiktok/${name}`);
    await probePublicPhotos(imageUrls);

    const init = await initTikTokPhotoPublish(accessToken, mode, postInfo, imageUrls, coverIndex);

    sendJson(res, 200, {
      success: true,
      mode,
      requested_mode: requestedMode,
      sandbox: TIKTOK_SANDBOX,
      publish_id: init.data.publish_id,
      photo_count: photos.length,
    });
  } catch (error) {
    if (storedNames.length > 0) await removeTikTokPhotos(storedNames);
    throw error;
  } finally {
    releaseVideoSlot();
  }
}, { auth: true });

route("GET", "/api/tiktok/publish/status", async ({ res, url, user }) => {
  const publishId = url.searchParams.get("publish_id");
  if (!isValidTikTokPublishId(publishId)) throw new HttpError(400, "Missing or invalid publish_id");

  const accessToken = await getValidTikTokToken(user.id);
  const result = await tiktokApi("/v2/post/publish/status/fetch/", { token: accessToken, json: { publish_id: publishId } });

  sendJson(res, 200, { success: true, ...result.data });
}, { auth: true });

// ============================================================
// TIKTOK WEBHOOK
// ============================================================

const MAX_TIKTOK_WEBHOOK_BODY = 64 * 1024;
const TIKTOK_WEBHOOK_DEDUPE_TTL_MS = 24 * 60 * 60 * 1000;
const TIKTOK_WEBHOOK_DEDUPE_MAX = 5_000;
const TIKTOK_REVOKE_SKEW_SEC = 5;

const processedTikTokWebhooks = createSeenCache(TIKTOK_WEBHOOK_DEDUPE_MAX, TIKTOK_WEBHOOK_DEDUPE_TTL_MS);

function parseTikTokSignatureHeader(header) {
  if (typeof header !== "string" || header.length > 512) return null;

  let timestamp = null;
  let signature = null;

  for (const part of header.split(",")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;

    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();

    if (key === "t" && timestamp === null) timestamp = value;
    else if (key === "s" && signature === null) signature = value;
  }

  if (!timestamp || !/^\d{1,12}$/.test(timestamp)) return null;
  if (!signature || !/^[a-f0-9]{64}$/i.test(signature)) return null;

  return { timestamp, signature: signature.toLowerCase() };
}

function verifyTikTokWebhookSignature(rawBody, header, secret, toleranceSec = TIKTOK_WEBHOOK_TOLERANCE_SEC, nowMs = Date.now()) {
  if (!secret) return { ok: false, reason: "secret_missing" };

  const parsed = parseTikTokSignatureHeader(header);
  if (!parsed) return { ok: false, reason: "malformed_header" };

  const expected = crypto.createHmac("sha256", secret).update(parsed.timestamp + ".").update(rawBody).digest();
  const received = Buffer.from(parsed.signature, "hex");

  if (received.length !== expected.length || !crypto.timingSafeEqual(received, expected)) {
    return { ok: false, reason: "bad_signature" };
  }

  if (toleranceSec > 0) {
    const skewSec = Math.abs(nowMs / 1000 - Number(parsed.timestamp));
    if (skewSec > toleranceSec) return { ok: false, reason: "timestamp_out_of_tolerance" };
  }

  return { ok: true, timestamp: Number(parsed.timestamp) };
}

async function handleTikTokAuthorizationRemoved(payload, requestId) {
  const openId = payload.user_openid;

  if (typeof openId !== "string" || !/^[A-Za-z0-9._:-]{1,256}$/.test(openId)) {
    throw new HttpError(400, "Invalid user_openid", "INVALID_PAYLOAD");
  }

  const createTime = payload.create_time;

  if (!Number.isSafeInteger(createTime) || createTime <= 0) {
    throw new HttpError(400, "Invalid create_time", "INVALID_PAYLOAD");
  }

  const cutoff = new Date((createTime + TIKTOK_REVOKE_SKEW_SEC) * 1000).toISOString();

  const { data, error } = await supabaseAdmin
    .from("tiktok_accounts")
    .delete()
    .eq("open_id", openId)
    .lte("updated_at", cutoff)
    .select("user_id");

  if (error) throw new Error("tiktok_accounts cleanup failed: " + error.message);

  if (Array.isArray(data)) {
    for (const row of data) {
      if (row?.user_id) clearTikTokProfileThrottle(row.user_id);
    }
  }

  console.log(`[${requestId}] [tiktok:webhook] authorization.removed comptes_supprimés=${data ? data.length : 0}`);
}

const TIKTOK_ACK_ONLY_EVENTS = new Set([
  "video.upload.failed",
  "video.publish.completed",
  "portability.download.ready",
]);

route("POST", "/api/tiktok/webhook", async ({ req, res, requestId }) => {
  const rawBody = await readBody(req, MAX_TIKTOK_WEBHOOK_BODY);

  const check = verifyTikTokWebhookSignature(rawBody, req.headers["tiktok-signature"], TIKTOK_CLIENT_SECRET);

  if (!check.ok) {
    console.warn(`[${requestId}] [tiktok:webhook] rejeté (${check.reason})`);
    throw new HttpError(401, "Invalid webhook signature", "INVALID_SIGNATURE");
  }

  let payload;

  try {
    payload = JSON.parse(rawBody.toString("utf8"));
  } catch {
    throw new HttpError(400, "Invalid JSON", "INVALID_JSON");
  }

  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new HttpError(400, "Invalid payload", "INVALID_PAYLOAD");
  }

  const eventName = payload.event;

  if (typeof eventName !== "string" || eventName.length > 100 || !/^[A-Za-z0-9_.]+$/.test(eventName)) {
    throw new HttpError(400, "Invalid event", "INVALID_PAYLOAD");
  }

  if (typeof payload.client_key === "string" && payload.client_key !== TIKTOK_CLIENT_KEY) {
    sendJson(res, 200, { received: true, ignored: true });
    return;
  }

  const dedupeKey = sha256(rawBody.toString("utf8"));

  if (processedTikTokWebhooks.has(dedupeKey)) {
    sendJson(res, 200, { received: true, duplicate: true });
    return;
  }

  if (eventName === "authorization.removed") {
    await handleTikTokAuthorizationRemoved(payload, requestId);
  } else if (TIKTOK_ACK_ONLY_EVENTS.has(eventName)) {
    console.log(`[${requestId}] [tiktok:webhook] ${eventName} reçu`);
  } else {
    console.warn(`[${requestId}] [tiktok:webhook] événement inconnu : ${eventName.slice(0, 60)}`);
  }

  processedTikTokWebhooks.add(dedupeKey);
  sendJson(res, 200, { received: true });
});

// ============================================================
// PINTEREST ROUTES
// ============================================================

route("POST", "/api/pinterest/auth/url", ({ res, user }) => {
  const params = new URLSearchParams({
    client_id: PINTEREST_APP_ID,
    redirect_uri: PINTEREST_REDIRECT_URI,
    response_type: "code",
    scope: PINTEREST_SCOPES,
    state: createOAuthState("pinterest", user.id),
  });

  sendJson(res, 200, { success: true, url: `${PINTEREST_AUTH_URL}?${params.toString()}` });
}, { auth: true });

route("POST", "/api/pinterest/auth/callback", async ({ req, res, user }) => {
  const body = await getJsonBody(req);
  const authCode = assertValidOAuthCallback("pinterest", body, user.id);

  const account = await dedupeCallback(`pinterest:${user.id}:${sha256(authCode)}`, async () => {
    const tokens = await pinterestApi("/oauth/token", {
      method: "POST",
      base: PINTEREST_OAUTH_BASE,
      basic: true,
      form: { grant_type: "authorization_code", code: authCode, redirect_uri: PINTEREST_REDIRECT_URI },
    });

    if (!tokens?.access_token) {
      throw new HttpError(502, "Pinterest returned an invalid token response", "PINTEREST_BAD_TOKEN_RESPONSE");
    }

    let profile = {};

    try {
      profile = await pinterestApi("/user_account", { token: tokens.access_token });
    } catch (profileError) {
      console.warn("Pinterest user_account error:", profileError.message);
    }

    await savePinterestTokens(user.id, tokens, {
      username: profile.username || null,
      avatar_url: profile.profile_image || null,
      account_type: profile.account_type || null,
    });

    return {
      display_name: profile.username || null,
      avatar_url: profile.profile_image || null,
      account_type: profile.account_type || null,
    };
  });

  sendJson(res, 200, { success: true, connected: true, account });
}, { auth: true });

route("POST", "/api/pinterest/auth/token", async ({ req, res, user }) => {
  if (env("PINTEREST_ALLOW_MANUAL_TOKEN") !== "1") {
    throw new HttpError(403, "Manual token connection is disabled");
  }

  const body = await getJsonBody(req);
  const accessToken = String(body.access_token || "").trim();

  if (!accessToken || accessToken.length > 4096) throw new HttpError(400, "Missing access_token");

  let profile;

  try {
    profile = await pinterestApi("/user_account", { token: accessToken });
  } catch (profileError) {
    throw new HttpError(400, `Invalid Pinterest token: ${profileError.message}`);
  }

  await savePinterestTokens(user.id, {
    access_token: accessToken,
    refresh_token: null,
    expires_in: 29 * 24 * 60 * 60,
    refresh_token_expires_in: 29 * 24 * 60 * 60,
  }, {
    username: profile.username || null,
    avatar_url: profile.profile_image || null,
    account_type: profile.account_type || null,
  });

  sendJson(res, 200, {
    success: true,
    connected: true,
    account: {
      display_name: profile.username || null,
      avatar_url: profile.profile_image || null,
      account_type: profile.account_type || null,
    },
  });
}, { auth: true });

route("GET", "/api/pinterest/status", async ({ res, user }) => {
  const account = await getPinterestAccount(user.id);
  const usable = pinterestAccountMatchesEnv(account);

  sendJson(res, 200, {
    success: true,
    connected: usable,
    account: usable
      ? { display_name: account.username, avatar_url: account.avatar_url, account_type: account.account_type, scope: account.scope }
      : null,
    ...(account && !usable ? { needs_reconnect: true } : {}),
  });
}, { auth: true });

route("DELETE", "/api/pinterest/disconnect", async ({ res, user }) => {
  const { error } = await supabaseAdmin.from("pinterest_accounts").delete().eq("user_id", user.id);
  if (error) throw error;

  sendJson(res, 200, { success: true });
}, { auth: true });

// ============================================================
// YOUTUBE ROUTES
// ============================================================

route("POST", "/api/youtube/auth/url", ({ res, user }) => {
  const params = new URLSearchParams({
    client_id: YOUTUBE_CLIENT_ID,
    redirect_uri: YOUTUBE_REDIRECT_URI,
    response_type: "code",
    scope: YOUTUBE_SCOPES,
    access_type: "offline",
    prompt: "consent",
    include_granted_scopes: "true",
    state: createOAuthState("youtube", user.id),
  });

  sendJson(res, 200, { success: true, url: `${GOOGLE_AUTH_URL}?${params.toString()}` });
}, { auth: true });

route("POST", "/api/youtube/auth/callback", async ({ req, res, user }) => {
  const body = await getJsonBody(req);
  const authCode = assertValidOAuthCallback("youtube", body, user.id);

  const account = await dedupeCallback(`youtube:${user.id}:${sha256(authCode)}`, async () => {
    const tokens = await googleRequest(GOOGLE_TOKEN_URL, {
      method: "POST",
      form: {
        client_id: YOUTUBE_CLIENT_ID,
        client_secret: YOUTUBE_CLIENT_SECRET,
        code: authCode,
        grant_type: "authorization_code",
        redirect_uri: YOUTUBE_REDIRECT_URI,
      },
    });

    let channel = null;

    try {
      channel = await fetchYouTubeChannel(tokens.access_token);
    } catch (channelError) {
      console.warn("YouTube channels error:", channelError.message);
    }

    if (!channel) {
      try {
        await googleRequest(GOOGLE_REVOKE_URL, {
          method: "POST",
          form: { token: tokens.refresh_token || tokens.access_token },
        });
      } catch {
        // ignore
      }

      throw new HttpError(400, "No YouTube channel found on this Google account. Create a channel on youtube.com, then try again.");
    }

    await saveYouTubeTokens(user.id, {
      ...tokens,
      refresh_token_expires_in: tokens.refresh_token_expires_in ?? null,
    }, {
      channel_id: channel.id,
      channel_title: channel.title || null,
      custom_url: channel.customUrl || null,
      avatar_url: channel.avatarUrl || null,
    });

    return { display_name: channel.title || null, avatar_url: channel.avatarUrl || null };
  });

  sendJson(res, 200, { success: true, connected: true, account });
}, { auth: true });

route("POST", "/api/youtube/publish", async ({ req, res, user }) => {
  enforce(limiterPublish, `youtube:${user.id}`);

  const declared = Number(req.headers["content-length"] || 0);

  if (declared > MAX_VIDEO_SIZE + 1024 * 1024) {
    throw tooLargeError(`Video is too large. Maximum size is ${MAX_VIDEO_SIZE / 1024 / 1024} MB.`);
  }

  const accessToken = await getValidYouTubeToken(user.id);
  await acquireVideoSlot();

  try {
    let upload;

    try {
      upload = await parseMultipart(req, { fileField: "video", maxSize: MAX_VIDEO_SIZE });
    } catch (error) {
      if (error?.code === "FILE_TOO_LARGE") throw new HttpError(400, `Video is too large. Maximum size is ${MAX_VIDEO_SIZE / 1024 / 1024} MB.`);
      if (error?.code === "NO_FILE") throw new HttpError(400, "No 'video' file was provided.");
      throw error instanceof HttpError ? error : new HttpError(400, "Could not read the uploaded file.");
    }

    const mimeType = sniffVideoType(upload.buffer);
    if (!mimeType) throw new HttpError(400, "Unsupported format. Use MP4, MOV or WebM.");

    const { privacy, publishAt, metadata, notifySubscribers } = buildYouTubeMetadata(upload.fields);

    const uploadUrl = await initYouTubeUpload(accessToken, metadata, upload.buffer.length, mimeType, notifySubscribers);
    const video = await uploadVideoToYouTube(uploadUrl, upload.buffer, mimeType);

    if (!video?.id) throw new HttpError(502, "YouTube did not confirm the upload", "YOUTUBE_NO_VIDEO_ID");

    const actualPrivacy = video.status?.privacyStatus || null;
    const privacyLocked = !publishAt && privacy !== "private" && actualPrivacy === "private";

    sendJson(res, 200, {
      success: true,
      video_id: video.id,
      url: `https://www.youtube.com/watch?v=${video.id}`,
      privacy_status: actualPrivacy,
      requested_privacy: privacy,
      publish_at: publishAt,
      upload_status: video.status?.uploadStatus || null,
      privacy_locked: privacyLocked,
    });
  } finally {
    releaseVideoSlot();
  }
}, { auth: true });

route("GET", "/api/youtube/status", async ({ res, user }) => {
  const account = await getYouTubeAccount(user.id);

  sendJson(res, 200, {
    success: true,
    connected: Boolean(account),
    account: account
      ? {
          display_name: account.channel_title,
          avatar_url: account.avatar_url,
          custom_url: account.custom_url,
          scope: account.scope,
          can_publish: String(account.scope || "").split(/[\s,]+/).includes(YOUTUBE_UPLOAD_SCOPE),
        }
      : null,
  });
}, { auth: true });

route("DELETE", "/api/youtube/disconnect", async ({ res, user }) => {
  const account = await getYouTubeAccount(user.id);

  if (account) {
    const tokenToRevoke = account.refresh_token || account.access_token;

    if (tokenToRevoke) {
      try {
        await googleRequest(GOOGLE_REVOKE_URL, {
          method: "POST",
          form: { token: tokenToRevoke },
        });
      } catch (revokeError) {
        console.warn("YouTube revoke error:", revokeError.message);
      }
    }

    const { error } = await supabaseAdmin.from("youtube_accounts").delete().eq("user_id", user.id);
    if (error) throw error;
  }

  sendJson(res, 200, { success: true });
}, { auth: true });

// ------------------------------------------------------------
// ✅ YOUTUBE — ROUTES DE LECTURE (vidéos + commentaires)
// ------------------------------------------------------------

// Liste des vidéos de la chaîne (panneau « Posts »)
route("GET", "/api/youtube/videos", async ({ res, url, user }) => {
  enforce(limiterYouTubeRead, `youtube-read:${user.id}`);

  const { token, channelId } = await getYouTubeReader(user.id);
  const pageToken = url.searchParams.get("pageToken");

  // La playlist « uploads » d'une chaîne = "UU" + channelId sans le "UC"
  const uploadsPlaylistId = `UU${channelId.slice(2)}`;

  const playlist = await youtubeGet(
    "/playlistItems",
    {
      part: "contentDetails",
      playlistId: uploadsPlaylistId,
      maxResults: "50",
      ...(pageToken ? { pageToken: String(pageToken).slice(0, 2048) } : {}),
    },
    token
  );

  const ids = (playlist.items || [])
    .map((i) => i.contentDetails?.videoId)
    .filter((id) => typeof id === "string" && YOUTUBE_ID_PATTERN.test(id));

  let videos = [];
  if (ids.length > 0) {
    const data = await youtubeGet(
      "/videos",
      { part: "snippet,statistics", id: ids.join(","), maxResults: "50" },
      token
    );
    videos = (data.items || []).map((v) => ({
      id: v.id,
      title: v.snippet?.title || "",
      thumbnail:
        v.snippet?.thumbnails?.medium?.url || v.snippet?.thumbnails?.default?.url || null,
      published_at: v.snippet?.publishedAt || null,
      comment_count: Number(v.statistics?.commentCount || 0),
    }));
  }

  sendJson(res, 200, {
    success: true,
    videos,
    next_page_token: playlist.nextPageToken || null,
  });
}, { auth: true });

// Commentaires (toute la chaîne, ou une vidéo si videoId est fourni)
// → exige explicitement le scope force-ssl (comments: true).
route("GET", "/api/youtube/comments", async ({ res, url, user }) => {
  enforce(limiterYouTubeRead, `youtube-read:${user.id}`);

  const filter = url.searchParams.get("filter") || "all";
  if (!YOUTUBE_COMMENT_FILTERS.has(filter)) {
    throw new HttpError(400, "Invalid filter", "INVALID_FILTER");
  }

  const videoId = url.searchParams.get("videoId");
  if (videoId && !YOUTUBE_ID_PATTERN.test(videoId)) {
    throw new HttpError(400, "Invalid videoId", "INVALID_VIDEO_ID");
  }

  const pageToken = url.searchParams.get("pageToken");
  const { token, channelId } = await getYouTubeReader(user.id, { comments: true });

  const params = {
    part: "snippet,replies",
    maxResults: "50",
    order: "time",
    textFormat: "plainText",
    ...(videoId ? { videoId } : { allThreadsRelatedToChannelId: channelId }),
    ...(pageToken ? { pageToken: String(pageToken).slice(0, 2048) } : {}),
  };

  let data;
  try {
    data = await youtubeGet("/commentThreads", params, token);
  } catch (error) {
    // Vidéo dont les commentaires sont désactivés → liste vide, pas une erreur
    if (error instanceof HttpError && error.code === "commentsDisabled") {
      sendJson(res, 200, { success: true, comments: [], next_page_token: null });
      return;
    }
    throw error;
  }

  const comments = (data.items || [])
    .map((item) => formatYouTubeThread(item, channelId))
    .filter((c) => !c.is_own)
    .filter((c) =>
      filter === "all" ? true : filter === "answered" ? c.answered : !c.answered
    );

  sendJson(res, 200, {
    success: true,
    comments,
    next_page_token: data.nextPageToken || null,
  });
}, { auth: true });

// ============================================================
// GOOGLE DRIVE ROUTES
// ============================================================

route("POST", "/api/googledrive/auth/url", ({ res, user }) => {
  const params = new URLSearchParams({
    client_id: GDRIVE_CLIENT_ID,
    redirect_uri: GDRIVE_REDIRECT_URI,
    response_type: "code",
    scope: GDRIVE_SCOPES,
    access_type: "offline",
    prompt: "consent",
    include_granted_scopes: "true",
    state: createOAuthState("googledrive", user.id),
  });

  sendJson(res, 200, { success: true, url: `${GOOGLE_AUTH_URL}?${params.toString()}` });
}, { auth: true });

route("POST", "/api/googledrive/auth/callback", async ({ req, res, user }) => {
  const body = await getJsonBody(req);
  const authCode = assertValidOAuthCallback("googledrive", body, user.id);

  const account = await dedupeCallback(`googledrive:${user.id}:${sha256(authCode)}`, async () => {
    const tokens = await googleRequest(GOOGLE_TOKEN_URL, {
      method: "POST",
      form: {
        client_id: GDRIVE_CLIENT_ID,
        client_secret: GDRIVE_CLIENT_SECRET,
        code: authCode,
        grant_type: "authorization_code",
        redirect_uri: GDRIVE_REDIRECT_URI,
      },
    });

    if (!tokens?.access_token) {
      throw new HttpError(502, "Google returned an invalid token response", "GDRIVE_BAD_TOKEN_RESPONSE");
    }

    const grantedScopes = String(tokens.scope || "").split(/[\s,]+/);
    if (!grantedScopes.some((s) => s.startsWith("https://www.googleapis.com/auth/drive"))) {
      throw new HttpError(400, "Google Drive access was not granted. Please accept the Drive permission.", "GDRIVE_SCOPE_MISSING");
    }

    let profile = {};

    try {
      const about = await gdriveRequest(
        `${GDRIVE_API}/about?fields=user(displayName,emailAddress,photoLink)`,
        { token: tokens.access_token }
      );
      profile = about.user || {};
    } catch (profileError) {
      console.warn("Google Drive profile error:", profileError.message);
    }

    const extra = {
      display_name: profile.displayName || null,
      email: profile.emailAddress || null,
      avatar_url: profile.photoLink || null,
    };

    await saveGDriveTokens(user.id, tokens, extra);

    return { display_name: extra.display_name, email: extra.email, avatar_url: extra.avatar_url };
  });

  sendJson(res, 200, { success: true, connected: true, account });
}, { auth: true });

route("GET", "/api/googledrive/status", async ({ res, user }) => {
  const account = await getGDriveAccount(user.id);

  sendJson(res, 200, {
    success: true,
    connected: Boolean(account),
    account: account
      ? {
          display_name: account.display_name,
          email: account.email,
          avatar_url: account.avatar_url,
          scope: account.scope,
        }
      : null,
  });
}, { auth: true });

route("DELETE", "/api/googledrive/disconnect", async ({ res, user }) => {
  const account = await getGDriveAccount(user.id);

  if (account) {
    const tokenToRevoke = account.refresh_token || account.access_token;

    if (tokenToRevoke) {
      try {
        await googleRequest(GOOGLE_REVOKE_URL, { method: "POST", form: { token: tokenToRevoke } });
      } catch (revokeError) {
        console.warn("Google Drive revoke error:", revokeError.message);
      }
    }

    const { error } = await supabaseAdmin.from("google_drive_accounts").delete().eq("user_id", user.id);
    if (error) throw error;
  }

  sendJson(res, 200, { success: true });
}, { auth: true });

route("GET", "/api/googledrive/files", async ({ res, url, user }) => {
  enforce(limiterGDrive, `gdrive:${user.id}`);

  const folderId = parseGDriveFolderId(url.searchParams.get("folderId"));
  const pageToken = url.searchParams.get("pageToken");
  const token = await getValidGDriveToken(user.id);

  const params = new URLSearchParams({
    q: `'${folderId}' in parents and trashed = false`,
    fields: "nextPageToken,files(id,name,mimeType,size,modifiedTime,webViewLink,iconLink)",
    orderBy: "folder,name",
    pageSize: "100",
  });
  if (pageToken) params.set("pageToken", String(pageToken).slice(0, 2048));

  const data = await gdriveRequest(`${GDRIVE_API}/files?${params.toString()}`, { token });

  sendJson(res, 200, {
    success: true,
    entries: (data.files || []).map((f) => ({
      type: f.mimeType === "application/vnd.google-apps.folder" ? "folder" : "file",
      id: f.id,
      name: f.name,
      mime_type: f.mimeType,
      size: f.size ? Number(f.size) : null,
      modified: f.modifiedTime ?? null,
      link: f.webViewLink ?? null,
    })),
    next_page_token: data.nextPageToken || null,
    has_more: Boolean(data.nextPageToken),
  });
}, { auth: true });

route("POST", "/api/googledrive/upload", async ({ req, res, user }) => {
  enforce(limiterPublish, `gdrive:${user.id}`);

  const declared = Number(req.headers["content-length"] || 0);
  if (declared > MAX_GDRIVE_UPLOAD + 1024 * 1024) {
    throw tooLargeError(`File is too large. Maximum size is ${MAX_GDRIVE_UPLOAD / 1024 / 1024} MB.`);
  }

  const accessToken = await getValidGDriveToken(user.id);
  await acquireVideoSlot();

  try {
    let upload;

    try {
      upload = await parseMultipart(req, { fileField: "file", maxSize: MAX_GDRIVE_UPLOAD });
    } catch (error) {
      if (error?.code === "FILE_TOO_LARGE") throw new HttpError(400, `File is too large. Maximum size is ${MAX_GDRIVE_UPLOAD / 1024 / 1024} MB.`);
      if (error?.code === "NO_FILE") throw new HttpError(400, "No 'file' was provided.");
      throw error instanceof HttpError ? error : new HttpError(400, "Could not read the uploaded file.");
    }

    const folderId = parseGDriveFolderId(upload.fields.folder_id);
    const safeName = (upload.fileName || "file").replace(/[\\/\u0000-\u001f]/g, "_").slice(0, 200) || "file";
    const mime = /^[\w.+-]+\/[\w.+-]+$/.test(upload.mimeType) ? upload.mimeType : "application/octet-stream";

    const boundary = `stone-${crypto.randomBytes(12).toString("hex")}`;
    const metadata = { name: safeName, ...(folderId !== "root" ? { parents: [folderId] } : {}) };

    const multipartBody = Buffer.concat([
      Buffer.from(
        `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify(metadata)}\r\n` +
          `--${boundary}\r\nContent-Type: ${mime}\r\n\r\n`
      ),
      upload.buffer,
      Buffer.from(`\r\n--${boundary}--`),
    ]);

    const data = await gdriveRequest(
      `${GDRIVE_UPLOAD_URL}?uploadType=multipart&fields=id,name,mimeType,size,webViewLink`,
      {
        method: "POST",
        token: accessToken,
        headers: { "Content-Type": `multipart/related; boundary=${boundary}` },
        body: multipartBody,
        timeoutMs: 120_000,
      }
    );

    sendJson(res, 200, {
      success: true,
      file: {
        id: data.id,
        name: data.name,
        mime_type: data.mimeType,
        size: data.size ? Number(data.size) : null,
        link: data.webViewLink || null,
      },
    });
  } finally {
    releaseVideoSlot();
  }
}, { auth: true });

// ============================================================
// GOOGLE PHOTOS ROUTES
// ============================================================

route("POST", "/api/googlephotos/auth/url", ({ res, user }) => {
  const params = new URLSearchParams({
    client_id: GPHOTOS_CLIENT_ID,
    redirect_uri: GPHOTOS_REDIRECT_URI,
    response_type: "code",
    scope: GPHOTOS_SCOPES,
    access_type: "offline",
    prompt: "consent",
    state: createOAuthState("googlephotos", user.id),
  });
  sendJson(res, 200, { success: true, url: `${GOOGLE_AUTH_URL}?${params.toString()}` });
}, { auth: true });

route("POST", "/api/googlephotos/auth/callback", async ({ req, res, user }) => {
  const body = await getJsonBody(req);
  const authCode = assertValidOAuthCallback("googlephotos", body, user.id);

  const account = await dedupeCallback(`googlephotos:${user.id}:${sha256(authCode)}`, async () => {
    const tokens = await googleRequest(GOOGLE_TOKEN_URL, {
      method: "POST",
      form: {
        client_id: GPHOTOS_CLIENT_ID,
        client_secret: GPHOTOS_CLIENT_SECRET,
        code: authCode,
        grant_type: "authorization_code",
        redirect_uri: GPHOTOS_REDIRECT_URI,
      },
    });

    if (!tokens?.access_token) {
      throw new HttpError(502, "Google returned an invalid token response", "GPHOTOS_BAD_TOKEN_RESPONSE");
    }

    const granted = String(tokens.scope || "").split(/[\s,]+/);
    if (!granted.includes(GPHOTOS_SCOPES)) {
      throw new HttpError(400, "Google Photos access was not granted. Please accept the permission.", "GPHOTOS_SCOPE_MISSING");
    }

    await saveGPhotosTokens(user.id, tokens);
    return { display_name: null, email: null, avatar_url: null };
  });

  sendJson(res, 200, { success: true, connected: true, account });
}, { auth: true });

route("GET", "/api/googlephotos/status", async ({ res, user }) => {
  const account = await getGPhotosAccount(user.id);
  sendJson(res, 200, {
    success: true,
    connected: Boolean(account),
    account: account ? { display_name: account.display_name, scope: account.scope } : null,
  });
}, { auth: true });

route("DELETE", "/api/googlephotos/disconnect", async ({ res, user }) => {
  const account = await getGPhotosAccount(user.id);
  if (account) {
    const tokenToRevoke = account.refresh_token || account.access_token;
    if (tokenToRevoke) {
      try {
        await googleRequest(GOOGLE_REVOKE_URL, { method: "POST", form: { token: tokenToRevoke } });
      } catch (e) {
        console.warn("Google Photos revoke error:", e.message);
      }
    }
    const { error } = await supabaseAdmin.from("google_photos_accounts").delete().eq("user_id", user.id);
    if (error) throw error;
  }
  sendJson(res, 200, { success: true });
}, { auth: true });

route("POST", "/api/googlephotos/picker/session", async ({ res, user }) => {
  enforce(limiterGPhotos, `gphotos:${user.id}`);
  const token = await getValidGPhotosToken(user.id);

  const session = await gphotosPicker("/sessions", { method: "POST", token, json: {} });
  if (!session?.id || !session?.pickerUri) {
    throw new HttpError(502, "Google Photos did not return a session", "GPHOTOS_NO_SESSION");
  }

  sendJson(res, 200, {
    success: true,
    session_id: session.id,
    picker_uri: `${String(session.pickerUri).replace(/\/+$/, "")}/autoclose`,
    poll_interval_ms: Number.parseInt(session.pollingConfig?.pollInterval, 10) * 1000 || 3000,
    timeout_ms: Number.parseInt(session.pollingConfig?.timeoutIn, 10) * 1000 || 5 * 60 * 1000,
  });
}, { auth: true });

route("GET", "/api/googlephotos/picker/session", async ({ res, url, user }) => {
  enforce(limiterGPhotos, `gphotos:${user.id}`);
  const sessionId = parseGPhotosSessionId(url.searchParams.get("sessionId"));
  const token = await getValidGPhotosToken(user.id);

  const session = await gphotosPicker(`/sessions/${encodeURIComponent(sessionId)}`, { token });
  sendJson(res, 200, { success: true, media_items_set: Boolean(session.mediaItemsSet) });
}, { auth: true });

route("GET", "/api/googlephotos/picker/items", async ({ res, url, user }) => {
  enforce(limiterGPhotos, `gphotos:${user.id}`);
  const sessionId = parseGPhotosSessionId(url.searchParams.get("sessionId"));
  const pageToken = url.searchParams.get("pageToken");
  const token = await getValidGPhotosToken(user.id);

  const params = new URLSearchParams({ sessionId, pageSize: "100" });
  if (pageToken) params.set("pageToken", String(pageToken).slice(0, 2048));

  const data = await gphotosPicker(`/mediaItems?${params.toString()}`, { token });

  sendJson(res, 200, {
    success: true,
    items: (data.mediaItems || []).map((m) => ({
      id: m.id,
      type: m.type,
      name: m.mediaFile?.filename || m.id,
      mime_type: m.mediaFile?.mimeType || null,
      base_url: m.mediaFile?.baseUrl || null,
      width: m.mediaFile?.mediaFileMetadata?.width ?? null,
      height: m.mediaFile?.mediaFileMetadata?.height ?? null,
    })),
    next_page_token: data.nextPageToken || null,
  });
}, { auth: true });

route("POST", "/api/googlephotos/picker/download", async ({ req, res, user }) => {
  enforce(limiterGPhotos, `gphotos:${user.id}`);

  const body = await getJsonBody(req);
  let baseUrl;
  try {
    baseUrl = new URL(String(body.baseUrl || ""));
  } catch {
    throw new HttpError(400, "Invalid baseUrl", "INVALID_GPHOTOS_URL");
  }
  if (baseUrl.protocol !== "https:" || !isGoogleMediaHost(baseUrl.hostname)) {
    throw new HttpError(400, "Invalid baseUrl", "INVALID_GPHOTOS_URL");
  }

  const isVideo = body.type === "VIDEO";
  const token = await getValidGPhotosToken(user.id);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 120_000);
  let upstream;
  let buffer;

  try {
    upstream = await fetch(`${baseUrl.toString()}${isVideo ? "=dv" : "=d"}`, {
      headers: { Authorization: `Bearer ${token}` },
      signal: controller.signal,
    });

    if (!upstream.ok) {
      throw new HttpError(
        upstream.status === 401 ? 409 : 502,
        "Could not download this media from Google Photos",
        "GPHOTOS_DOWNLOAD_FAILED"
      );
    }

    const declared = Number(upstream.headers.get("content-length") || 0);
    if (declared > MAX_GPHOTOS_DOWNLOAD) throw tooLargeError("This media is too large.");

    buffer = Buffer.from(await upstream.arrayBuffer());
  } catch (error) {
    if (error instanceof HttpError) throw error;
    throw upstreamError("Google Photos", error);
  } finally {
    clearTimeout(timer);
  }

  if (buffer.length > MAX_GPHOTOS_DOWNLOAD) throw tooLargeError("This media is too large.");

  const type = sniffImageType(buffer) || sniffVideoType(buffer) || "application/octet-stream";

  res.writeHead(200, {
    "Content-Type": type,
    "Content-Length": buffer.length,
    "Cache-Control": "no-store",
  });
  res.end(buffer);
}, { auth: true });

route("DELETE", "/api/googlephotos/picker/session", async ({ res, url, user }) => {
  const sessionId = parseGPhotosSessionId(url.searchParams.get("sessionId"));
  const token = await getValidGPhotosToken(user.id);
  try {
    await gphotosPicker(`/sessions/${encodeURIComponent(sessionId)}`, { method: "DELETE", token });
  } catch (e) {
    console.warn("Google Photos session delete:", e.message);
  }
  sendJson(res, 200, { success: true });
}, { auth: true });

// ============================================================
// CANVA ROUTES
// ============================================================

route("POST", "/api/canva/auth/url", ({ res, user }) => {
  const state = createOAuthState("canva", user.id);

  const params = new URLSearchParams({
    response_type: "code",
    client_id: CANVA_CLIENT_ID,
    redirect_uri: CANVA_REDIRECT_URI,
    scope: CANVA_SCOPES,
    code_challenge: createCanvaPkce(state),
    code_challenge_method: "S256",
    state,
  });

  sendJson(res, 200, { success: true, url: `${CANVA_AUTH_URL}?${params.toString()}` });
}, { auth: true });

route("POST", "/api/canva/auth/callback", async ({ req, res, user }) => {
  const body = await getJsonBody(req);
  const authCode = assertValidOAuthCallback("canva", body, user.id);
  const state = String(body.state);

  await dedupeCallback(`canva:${user.id}:${sha256(authCode)}`, async () => {
    const verifier = takeCanvaVerifier(state);

    if (!verifier) throw new HttpError(400, "Invalid or expired state", "OAUTH_STATE_INVALID");

    const tokens = await canvaApi("/oauth/token", {
      method: "POST",
      basic: true,
      form: { grant_type: "authorization_code", code: authCode, code_verifier: verifier, redirect_uri: CANVA_REDIRECT_URI },
    });

    if (!tokens?.access_token) {
      throw new HttpError(502, "Canva returned an invalid token response", "CANVA_BAD_TOKEN_RESPONSE");
    }

    let displayName = null;

    try {
      const profile = await canvaApi("/users/me/profile", { token: tokens.access_token });
      displayName = profile.profile?.display_name || null;
    } catch (profileError) {
      console.warn("Canva profile error:", profileError.message);
    }

    await saveCanvaTokens(user.id, tokens, { display_name: displayName });
  });

  sendJson(res, 200, { success: true, connected: true });
}, { auth: true });

route("GET", "/api/canva/status", async ({ res, user }) => {
  const account = await getCanvaAccount(user.id);

  sendJson(res, 200, {
    success: true,
    connected: Boolean(account),
    account: account ? { display_name: account.display_name } : null,
  });
}, { auth: true });

route("DELETE", "/api/canva/disconnect", async ({ res, user }) => {
  const account = await getCanvaAccount(user.id);

  if (account) {
    const tokenToRevoke = account.refresh_token || account.access_token;

    if (tokenToRevoke) {
      try {
        await canvaApi("/oauth/revoke", { method: "POST", basic: true, form: { token: tokenToRevoke } });
      } catch (revokeError) {
        console.warn("Canva revoke error:", revokeError.message);
      }
    }

    const { error } = await supabaseAdmin.from("canva_accounts").delete().eq("user_id", user.id);
    if (error) throw error;
  }

  sendJson(res, 200, { success: true });
}, { auth: true });

route("POST", "/api/canva/designs", async ({ req, res, user }) => {
  enforce(limiterCanva, `canva:${user.id}`);

  const body = await getJsonBody(req);
  const width = Number(body.width);
  const height = Number(body.height);
  const valid = (n) => Number.isInteger(n) && n >= 40 && n <= 8000;

  if (!valid(width) || !valid(height)) throw new HttpError(400, "Invalid design size (40 to 8000 px).");

  const title = String(body.title || "Stone post").slice(0, 255);
  const token = await getValidCanvaToken(user.id);

  const data = await canvaApi("/designs", {
    method: "POST",
    token,
    json: { design_type: { type: "custom", width, height }, title },
  });

  const design = data.design;

  if (!design?.id || !design.urls?.edit_url) throw new HttpError(502, "Canva did not return a design", "CANVA_NO_DESIGN");

  sendJson(res, 200, { success: true, design_id: design.id, edit_url: design.urls.edit_url });
}, { auth: true });

const CANVA_EXPORT_MAX_PAGES = 10;
const CANVA_EXPORT_MAX_TOTAL = 30 * 1024 * 1024;

route("POST", "/api/canva/export", async ({ req, res, user }) => {
  enforce(limiterCanva, `canva:${user.id}`);

  const body = await getJsonBody(req);
  const designId = String(body.design_id || "");

  if (!/^[A-Za-z0-9_-]{1,64}$/.test(designId)) throw new HttpError(400, "Invalid design_id");

  const token = await getValidCanvaToken(user.id);

  const created = await canvaApi("/exports", {
    method: "POST",
    token,
    json: { design_id: designId, format: { type: "png" } },
  });

  const jobId = created.job?.id;
  if (!jobId) throw new HttpError(502, "Canva did not start the export", "CANVA_NO_EXPORT_JOB");

  let urls = null;

  for (let attempt = 0; attempt < 30; attempt++) {
    await delay(1000);

    const poll = await canvaApi(`/exports/${encodeURIComponent(jobId)}`, { token });
    const job = poll.job;

    if (job?.status === "success") {
      urls = Array.isArray(job.urls) ? job.urls : [];
      break;
    }

    if (job?.status === "failed") {
      throw new HttpError(502, job.error?.message || "Canva could not export this design.", "CANVA_EXPORT_FAILED");
    }
  }

  if (!urls) throw new HttpError(504, "Canva export timed out, please retry", "CANVA_EXPORT_TIMEOUT");

  const pages = [];
  let total = 0;

  for (const fileUrl of urls.slice(0, CANVA_EXPORT_MAX_PAGES)) {
    if (typeof fileUrl !== "string" || !fileUrl.startsWith("https://")) continue;

    let download;

    try {
      download = await fetch(fileUrl);
    } catch (error) {
      throw upstreamError("Canva", error);
    }

    if (!download.ok) throw new HttpError(502, "Could not download the exported design", "CANVA_DOWNLOAD_FAILED");

    const buffer = Buffer.from(await download.arrayBuffer());
    const mime = sniffImageType(buffer);

    if (mime !== "image/png" && mime !== "image/jpeg") continue;

    total += buffer.length;

    if (total > CANVA_EXPORT_MAX_TOTAL) throw tooLargeError("The exported design is too large.");

    pages.push({ mime, data: buffer.toString("base64") });
  }

  if (pages.length === 0) throw new HttpError(502, "Canva returned no image", "CANVA_EMPTY_EXPORT");

  sendJson(res, 200, { success: true, pages });
}, { auth: true });

// ============================================================
// DROPBOX ROUTES
// ============================================================

route("POST", "/api/dropbox/auth/url", ({ res, user }) => {
  const params = new URLSearchParams({
    client_id: DROPBOX_APP_KEY,
    redirect_uri: DROPBOX_REDIRECT_URI,
    response_type: "code",
    token_access_type: "offline",
    scope: DROPBOX_SCOPES,
    state: createOAuthState("dropbox", user.id),
  });

  sendJson(res, 200, { success: true, url: `${DROPBOX_AUTH_URL}?${params.toString()}` });
}, { auth: true });

route("POST", "/api/dropbox/auth/callback", async ({ req, res, user }) => {
  const body = await getJsonBody(req);
  const authCode = assertValidOAuthCallback("dropbox", body, user.id);

  const account = await dedupeCallback(`dropbox:${user.id}:${sha256(authCode)}`, async () => {
    const tokens = await dropboxToken({
      grant_type: "authorization_code",
      code: authCode,
      redirect_uri: DROPBOX_REDIRECT_URI,
    });

    if (!tokens?.access_token) {
      throw new HttpError(502, "Dropbox returned an invalid token response", "DROPBOX_BAD_TOKEN_RESPONSE");
    }

    let profile = {};

    try {
      profile = await dropboxRpc("/users/get_current_account", { token: tokens.access_token });
    } catch (profileError) {
      console.warn("Dropbox profile error:", profileError.message);
    }

    const extra = {
      display_name: profile.name?.display_name || null,
      email: profile.email || null,
      avatar_url: profile.profile_photo_url || null,
    };

    await saveDropboxTokens(user.id, tokens, extra);

    return { display_name: extra.display_name, email: extra.email, avatar_url: extra.avatar_url };
  });

  sendJson(res, 200, { success: true, connected: true, account });
}, { auth: true });

const dropboxProfileCheckedAt = new Map();
const DROPBOX_PROFILE_REFRESH_MS = 30 * 60 * 1000;
const DROPBOX_PROFILE_RETRY_MS = 60 * 1000;

async function refreshDropboxProfile(userId, account) {
  const incomplete = !account.avatar_url || !account.display_name || !account.email;
  const interval = incomplete ? DROPBOX_PROFILE_RETRY_MS : DROPBOX_PROFILE_REFRESH_MS;
  const now = Date.now();

  if (now - (dropboxProfileCheckedAt.get(userId) || 0) < interval) return account;

  if (dropboxProfileCheckedAt.size > 10_000) {
    dropboxProfileCheckedAt.delete(dropboxProfileCheckedAt.keys().next().value);
  }
  dropboxProfileCheckedAt.set(userId, now);

  try {
    const token = await getValidDropboxToken(userId);
    const profile = await dropboxRpc("/users/get_current_account", { token });

    if (!profile?.account_id) return account;

    const update = {
      display_name: profile.name?.display_name || null,
      email: profile.email || null,
      avatar_url: profile.profile_photo_url || null,
    };

    const { error } = await supabaseAdmin
      .from("dropbox_accounts")
      .update(update)
      .eq("user_id", userId);

    if (error) {
      console.warn("Dropbox profile update error:", error.message);
      return account;
    }

    return { ...account, ...update };
  } catch (error) {
    console.warn("Dropbox profile refresh error:", error?.message || error);
    return account;
  }
}

route("GET", "/api/dropbox/status", async ({ res, user }) => {
  let account = await getDropboxAccount(user.id);
  if (account) account = await refreshDropboxProfile(user.id, account);

  sendJson(res, 200, {
    success: true,
    connected: Boolean(account),
    account: account
      ? {
          display_name: account.display_name,
          email: account.email,
          avatar_url: account.avatar_url,
          scope: account.scope,
        }
      : null,
  });
}, { auth: true });

route("DELETE", "/api/dropbox/disconnect", async ({ res, user }) => {
  const account = await getDropboxAccount(user.id);

  if (account) {
    try {
      const accessToken = await getValidDropboxToken(user.id);
      await dropboxRpc("/auth/token/revoke", { token: accessToken });
    } catch (revokeError) {
      console.warn("Dropbox revoke error:", revokeError.message);
    }

    const { error } = await supabaseAdmin
      .from("dropbox_accounts")
      .delete()
      .eq("user_id", user.id);
    if (error) throw error;

    dropboxProfileCheckedAt.delete(user.id);
  }

  sendJson(res, 200, { success: true });
}, { auth: true });

route("GET", "/api/dropbox/files", async ({ res, url, user }) => {
  enforce(limiterDropbox, `dropbox:${user.id}`);

  const path = parseDropboxPath(url.searchParams.get("path"), { allowRoot: true });
  const cursor = url.searchParams.get("cursor");
  const token = await getValidDropboxToken(user.id);

  const data = cursor
    ? await dropboxRpc("/files/list_folder/continue", { token, json: { cursor: String(cursor).slice(0, 2048) } })
    : await dropboxRpc("/files/list_folder", { token, json: { path, limit: 100, include_deleted: false } });

  sendJson(res, 200, {
    success: true,
    entries: (data.entries || []).map((e) => ({
      type: e[".tag"],
      id: e.id,
      name: e.name,
      path: e.path_display,
      size: e.size ?? null,
      modified: e.server_modified ?? null,
    })),
    cursor: data.cursor,
    has_more: Boolean(data.has_more),
  });
}, { auth: true });

route("GET", "/api/dropbox/temporary-link", async ({ res, url, user }) => {
  enforce(limiterDropbox, `dropbox:${user.id}`);

  const path = parseDropboxPath(url.searchParams.get("path"));
  const token = await getValidDropboxToken(user.id);
  const data = await dropboxRpc("/files/get_temporary_link", { token, json: { path } });

  sendJson(res, 200, { success: true, link: data.link, name: data.metadata?.name });
}, { auth: true });

route("POST", "/api/dropbox/upload", async ({ req, res, user }) => {
  enforce(limiterPublish, `dropbox:${user.id}`);

  const declared = Number(req.headers["content-length"] || 0);
  if (declared > MAX_DROPBOX_UPLOAD + 1024 * 1024) {
    throw tooLargeError(`File is too large. Maximum size is ${MAX_DROPBOX_UPLOAD / 1024 / 1024} MB.`);
  }

  const accessToken = await getValidDropboxToken(user.id);
  await acquireVideoSlot();

  try {
    let upload;

    try {
      upload = await parseMultipart(req, { fileField: "file", maxSize: MAX_DROPBOX_UPLOAD });
    } catch (error) {
      if (error?.code === "FILE_TOO_LARGE") throw new HttpError(400, `File is too large. Maximum size is ${MAX_DROPBOX_UPLOAD / 1024 / 1024} MB.`);
      if (error?.code === "NO_FILE") throw new HttpError(400, "No 'file' was provided.");
      throw error instanceof HttpError ? error : new HttpError(400, "Could not read the uploaded file.");
    }

    const folder = parseDropboxPath(upload.fields.path, { allowRoot: true });
    const safeName = (upload.fileName || "file").replace(/[\\/\u0000-\u001f]/g, "_").slice(0, 200) || "file";
    const destination = `${folder}/${safeName}`;

    let result;

    try {
      result = await fetchJson(
        `${DROPBOX_CONTENT_API}/files/upload`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${accessToken}`,
            "Content-Type": "application/octet-stream",
            "Dropbox-API-Arg": dropboxArgHeader({
              path: destination,
              mode: "add",
              autorename: true,
              mute: true,
            }),
          },
          body: upload.buffer,
        },
        120_000
      );
    } catch (error) {
      throw upstreamError("Dropbox", error);
    }

    if (!result.response.ok) throw dropboxApiError(result.response, result.data);

    sendJson(res, 200, {
      success: true,
      file: {
        id: result.data.id,
        name: result.data.name,
        path: result.data.path_display,
        size: result.data.size,
      },
    });
  } finally {
    releaseVideoSlot();
  }
}, { auth: true });

// ============================================================
// SERVER
// ============================================================

const providerGuards = [
  ["/api/tiktok/", tiktokEnabled, "TikTok"],
  ["/api/pinterest/", pinterestEnabled, "Pinterest"],
  ["/api/youtube/", youtubeEnabled, "YouTube"],
  ["/api/googledrive/", gdriveEnabled, "Google Drive"],
  ["/api/googlephotos/", gphotosEnabled, "Google Photos"],
  ["/api/canva/", canvaEnabled, "Canva"],
  ["/api/dropbox/", dropboxEnabled, "Dropbox"],
];

const server = createServer(async (req, res) => {
  const requestId = newRequestId();

  // ✅ NOUVEAU — diagnostic : prouve dans les logs que la requête
  // atteint bien CE serveur. Si la ligne n'apparaît pas quand le
  // frontend appelle /api/youtube/videos, c'est que la requête est
  // interceptée ailleurs (SPA fallback, proxy mal configuré…).
  console.log(
    `[${requestId}] → ${req.method} ${req.url} origin=${req.headers.origin || "-"} host=${req.headers.host || "-"}`
  );
  res.on("finish", () => {
    console.log(`[${requestId}] ← ${res.statusCode} ${req.method} ${req.url}`);
  });

  setSecurityHeaders(res);

  try {
    setCorsHeaders(req, res);
  } catch (corsError) {
    console.error(`[${requestId}] CORS error:`, corsError);
  }

  if (req.method === "OPTIONS") {
    res.writeHead(204, { "Content-Length": "0" });
    res.end();
    return;
  }

  let routeLabel = `${req.method} ${req.url}`;

  try {
    const url = new URL(req.url || "/", `http://${req.headers.host || `localhost:${PORT}`}`);

    const pathname = url.pathname.length > 1 ? url.pathname.replace(/\/+$/, "") : url.pathname;

    routeLabel = `${req.method} ${pathname}`;

    if (req.method === "GET" || req.method === "HEAD") {
      let decodedPath = pathname;

      try {
        decodedPath = decodeURIComponent(pathname);
      } catch {
        // ignore
      }

      if (decodedPath === `/api/media/tiktok/${TIKTOK_VERIFICATION_NAME}.txt`) {
        res.writeHead(200, {
          "Content-Type": "text/plain; charset=utf-8",
          "Content-Length": Buffer.byteLength(TIKTOK_VERIFICATION_NAME),
          "Cache-Control": "no-store",
        });
        res.end(req.method === "HEAD" ? undefined : TIKTOK_VERIFICATION_NAME);
        return;
      }

      const mediaMatch = pathname.match(/^\/api\/media\/tiktok\/([a-f0-9]{32}\.(?:jpg|webp))$/);

      if (mediaMatch) {
        enforce(limiterMedia, getClientIp(req));
        await serveTikTokMedia(req, res, mediaMatch[1]);
        return;
      }
    }

    const isStripeWebhook = req.method === "POST" && pathname === "/api/stripe/webhook";
    const isHealth = req.method === "GET" && pathname === "/api/health";
    const isTiktokWebhook = req.method === "POST" && pathname === "/api/tiktok/webhook";

    if (isTiktokWebhook) {
      enforce(limiterTiktokWebhook, getClientIp(req));
    } else if (!isStripeWebhook && !isHealth) {
      enforce(pickLimiter(pathname), getClientIp(req));
    }

    for (const [prefix, enabled, name] of providerGuards) {
      if (pathname.startsWith(prefix) && !enabled) {
        throw new HttpError(500, `${name} is not configured`);
      }
    }

    if (pathname.startsWith("/api/pinterest/") && pinterestConfigError) {
      console.error(`[${requestId}] Pinterest config: ${pinterestConfigError}`);
      throw new HttpError(500, "Pinterest configuration is inconsistent (sandbox / production mismatch)", "PINTEREST_CONFIG_INVALID");
    }

    const entry = routes.get(`${req.method} ${pathname}`);

    if (!entry) {
      sendJson(res, 404, {
        success: false,
        error: "Route not found",
        path: pathname,
        method: req.method,
      });
      return;
    }

    const ctx = { req, res, url, requestId, user: null, token: null };

    if (entry.auth) {
      const { user, token, error, code } = await getAuthenticatedUser(req);

      if (!user) {
        sendJson(res, 401, { success: false, error, code });
        return;
      }

      ctx.user = user;
      ctx.token = token;
    }

    await entry.handler(ctx);
  } catch (error) {
    if (error instanceof HttpError) {
      if (error.status >= 500) console.error(`[${requestId}] ${routeLabel}:`, error.message);

      sendJson(
        res,
        error.status,
        {
          success: false,
          error: error.message,
          code: error.code || undefined,
          retryAfter: error.retryAfter || undefined,
          request_id: error.status >= 500 ? requestId : undefined,
        },
        error.headers
      );
      return;
    }

    internalErrorResponse(res, requestId, error, routeLabel);
  }
});

server.keepAliveTimeout = 65_000;
server.headersTimeout = 66_000;
server.requestTimeout = 5 * 60_000;

server.listen(PORT, "0.0.0.0", async () => {
  console.log(`Stone server running on port ${PORT}`);
  console.log(`  NODE_ENV        : ${env("NODE_ENV") || "(non défini)"}`);
  console.log(`  TRUST_PROXY     : ${TRUST_PROXY ? `1 (${TRUST_PROXY_HOPS} hop)` : "0"}`);
  console.log(`  Token encryption: ${TOKEN_ENCRYPTION_KEY ? "on" : "off"}`);
  console.log(`  MFA             : proxy /api/mfa/* → Supabase /auth/v1/factors*`);
  console.log(`  MFA policy      : AAL2 requis pour profil, avatar, mot de passe et gestion MFA`);
  console.log(`  Video uploads   : max ${MAX_VIDEO_UPLOADS} concurrent(s)`);
  console.log(`  TikTok mode     : ${TIKTOK_SANDBOX ? "SANDBOX" : "auditée"}${TIKTOK_FORCE_DRAFT ? " + FORCE_DRAFT" : ""}`);
  console.log(`  TikTok photos   : ${PUBLIC_API_URL ? PUBLIC_API_URL : "désactivé"}${PUBLIC_API_URL_SOURCE ? ` (via ${publicApiSourceLabel(PUBLIC_API_URL_SOURCE)})` : ""}`);
  console.log(`  Pinterest       : ${pinterestUsable ? PINTEREST_ENVIRONMENT.toUpperCase() : "désactivé"}`);
  console.log(`  YouTube publish : ${youtubeEnabled && YOUTUBE_SCOPES.split(" ").includes(YOUTUBE_UPLOAD_SCOPE) ? "activée" : "désactivée"}`);
  console.log(`  YouTube read    : ${youtubeEnabled ? "vidéos + commentaires activés" : "désactivé"}`);
  console.log(`  YouTube scopes  : ${YOUTUBE_SCOPES}`);
  console.log(`  Google Drive    : ${gdriveEnabled ? "activé" : "désactivé"}`);
  console.log(`  Google Photos   : ${gphotosEnabled ? "activé" : "désactivé"}`);
  console.log(`  Canva           : ${canvaEnabled ? "activé" : "désactivé"}`);
  console.log(`  Dropbox         : ${dropboxEnabled ? "activé" : "désactivé"}`);
  console.log(`  Tags            : activé (max ${MAX_TAGS_PER_USER} par utilisateur)`);
  console.log(`  Saved replies   : activé (max ${MAX_SAVED_REPLIES_PER_USER} par utilisateur)`);
  console.log(`  Scheduled posts : activé (${MAX_POST_FILES} fichiers max / post, ${MAX_POST_FILE_SIZE / 1024 / 1024} MB par fichier)`);
  console.log(`  Stripe checkout : success ${STRIPE_SUCCESS_URL} · cancel ${STRIPE_CANCEL_URL}`);
  console.log(`  Diagnostic      : en-tête X-Stone-Server: 1 ajouté à toutes les réponses`);

  // ✅ NOUVEAU — initialisation du bucket pour les posts
  try {
    await ensurePostMediaBucket();
    console.log(`  Post media      : bucket "${POST_MEDIA_BUCKET}" prêt`);
  } catch (error) {
    console.warn(`  Post media      : initialisation échouée (${error?.message || error})`);
  }

  // ✅ NOUVEAU — timer de transition scheduled/external → published
  const postsTimer = setInterval(() => {
    void publishDueScheduledPosts();
  }, POSTS_PUBLISH_INTERVAL_MS);
  postsTimer.unref?.();
  // premier passage rapide (5 s après démarrage)
  setTimeout(() => void publishDueScheduledPosts(), 5_000).unref?.();

  if (tiktokEnabled) {
    try {
      await ensureTikTokMediaBucket();
      console.log(`  TikTok bucket   : ${TIKTOK_MEDIA_BUCKET} prêt`);
    } catch (error) {
      console.warn(`  TikTok bucket   : initialisation échouée (${error?.message || error})`);
    }
    const sweepTimer = setInterval(() => {
      void sweepTikTokMedia();
    }, 30 * 60 * 1000);
    sweepTimer.unref?.();
    setTimeout(() => void sweepTikTokMedia(), 5 * 60 * 1000).unref?.();
  }
});

server.on("error", (error) => {
  if (error.code === "EADDRINUSE") {
    console.error(`Le port ${PORT} est déjà utilisé.`);
  } else {
    console.error("Server error:", error);
  }
});

server.on("clientError", (error, socket) => {
  if (socket.writable) {
    socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
  } else {
    socket.destroy();
  }
});

let shuttingDown = false;

function shutdown(signal, exitCode = 0) {
  if (shuttingDown) return;
  shuttingDown = true;

  console.log(`\n${signal} reçu — arrêt du serveur...`);

  server.close(() => {
    console.log("Serveur arrêté proprement.");
    process.exit(exitCode);
  });

  server.closeIdleConnections?.();

  setTimeout(() => {
    console.error("Arrêt forcé : connexions encore ouvertes.");
    process.exit(1);
  }, 10_000).unref?.();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

process.on("unhandledRejection", (reason) => {
  console.error("Unhandled rejection:", reason);
});

process.on("uncaughtException", (error) => {
  console.error("Uncaught exception:", error);
  shutdown("uncaughtException", 1);
});