// ============================================================
// STONE — API SERVER
// ============================================================
//
// Variables d'environnement
//   Obligatoires : SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY
//   Production   : NODE_ENV=production, APP_URL, OAUTH_REDIRECT_URL,
//                  OAUTH_STATE_SECRET (32+ caractères aléatoires)
//   Recommandé   : TOKEN_ENCRYPTION_KEY (32+ caractères aléatoires) →
//                  chiffre les tokens TikTok / Pinterest / YouTube en base
//                  (AES-256-GCM). Les anciens tokens en clair restent lisibles.
//   Photos TikTok: URL publique de CE serveur (domaine de l'API, PAS le
//                  frontend), lue dans l'ordre :
//                  PUBLIC_API_URL → VITE_API_BASE_URL → RAILWAY_PUBLIC_DOMAIN
//                  (le préfixe /api/media/tiktok/ doit être vérifié chez TikTok).
//   TikTok       : TIKTOK_AUDITED=1 une fois l'app auditée par TikTok.
//                  Sinon l'app est en MODE SANDBOX :
//                    - seuls les « Sandbox testers » du portail peuvent
//                      autoriser l'app (sinon access_denied → 403 explicite)
//                    - DIRECT_POST limité à privacy_level = SELF_ONLY
//                    - posts photos forcés en brouillon (MEDIA_UPLOAD)
//                  TIKTOK_FORCE_DRAFT=1 force TOUT en brouillons, même
//                  après audit (pratique pour tester sans publier).
//   Pinterest    : PINTEREST_APP_ID, PINTEREST_APP_SECRET.
//                  Par défaut : SANDBOX (PINTEREST_API_BASE =
//                  https://api-sandbox.pinterest.com/v5) et l'endpoint OAuth
//                  est dérivé de l'environnement de l'API.
//                  Production : PINTEREST_API_BASE=https://api.pinterest.com/v5
//                  (PINTEREST_OAUTH_BASE est alors dérivé automatiquement ;
//                  s'il est défini, il doit être du MÊME environnement, sinon
//                  les routes Pinterest répondent 500 plutôt que de mélanger
//                  sandbox et production). PINTEREST_AUTH_URL est surchargeable.
//                  Chaque compte relié mémorise son environnement (colonne
//                  pinterest_accounts.api_env) : un jeton d'un autre
//                  environnement n'est jamais utilisé (reconnexion demandée).
//   YouTube      : YOUTUBE_CLIENT_ID, YOUTUBE_CLIENT_SECRET.
//                  Les scopes par défaut incluent youtube.upload (nécessaire
//                  pour publier). Tant que le projet Google n'a pas passé
//                  l'audit « YouTube API Services », YouTube force les
//                  vidéos envoyées par l'API en PRIVÉ.
//   Optionnel    : ALLOWED_ORIGINS, TRUST_PROXY, TRUST_PROXY_HOPS,
//                  MAX_VIDEO_UPLOADS, TIKTOK_VERIFICATION_FILE,
//                  TIKTOK_SKIP_PHOTO_PROBE=1, STRIPE_*, TIKTOK_*,
//                  PINTEREST_*, YOUTUBE_*
// ============================================================

import { fileURLToPath } from "node:url";
import path from "node:path";
import { createServer } from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import { createClient } from "@supabase/supabase-js";
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
  constructor(status, message, code, headers) {
    super(message);
    this.name = "HttpError";
    this.status = status;
    this.code = code;
    this.headers = headers;
  }
}

const sha256 = (value) =>
  crypto.createHash("sha256").update(String(value)).digest("hex");

const normalizeEmail = (value) => String(value ?? "").trim().toLowerCase();

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const toBool = (v) => v === true || v === "true" || v === "1";

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Mutualise les appels concurrents identiques (refresh de token,
// création de client Stripe...) : un seul vol, tout le monde attend
// le même résultat. Évite les courses entre refresh tokens.
// ATTENTION : les appelants partagent le MÊME résultat. Ne pas l'utiliser
// pour des écritures différentes sur la même clé (voir runSerial).
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

// File d'attente par clé : les tâches s'exécutent UNE PAR UNE, chacune avec
// son propre résultat (contrairement à withLock). Sert aux écritures
// « lire → modifier → écrire » qui ne doivent pas s'écraser entre elles
// (ex. app_metadata d'un utilisateur).
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

// Cache de déduplication à durée de vie limitée (événements webhook).
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

// Les callbacks OAuth peuvent être appelés deux fois (React StrictMode,
// double clic) : le code étant à usage unique côté provider, on renvoie
// le même résultat pendant 60 s au lieu d'une erreur.
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

// fetch + lecture JSON avec timeout global (en-têtes ET corps).
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

// Erreur de base de données : le détail reste dans les logs serveur, le
// client reçoit un message générique (jamais de secret ni de requête).
function dbError(context, error) {
  console.error(`[db] ${context}:`, error?.message || error);
  return new HttpError(500, "Database error", "DB_ERROR");
}

// ============================================================
// CONFIGURATION
// ============================================================

const PORT = Number(env("PORT") || 3002);

const SUPABASE_URL = env("SUPABASE_URL");
const SUPABASE_ANON_KEY = env("SUPABASE_ANON_KEY");
const SUPABASE_SERVICE_ROLE_KEY = env("SUPABASE_SERVICE_ROLE_KEY");

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

// ---- Mode sandbox -------------------------------------------------------
//
// TIKTOK_AUDITED=1  → app auditée : comportement normal (DIRECT_POST,
//                     privacy au choix, photos en direct).
// sinon             → SANDBOX :
//                     - DIRECT_POST limité à privacy_level = SELF_ONLY
//                     - photos forcées en brouillon (MEDIA_UPLOAD)
//                     - seuls les « Sandbox testers » du portail peuvent
//                       autoriser l'app (sinon access_denied)
// TIKTOK_FORCE_DRAFT=1 → tout part en brouillon, même audité.

const TIKTOK_AUDITED = env("TIKTOK_AUDITED") === "1";
const TIKTOK_SANDBOX = !TIKTOK_AUDITED;
const TIKTOK_FORCE_DRAFT = env("TIKTOK_FORCE_DRAFT") === "1";

const tiktokEnabled = Boolean(TIKTOK_CLIENT_KEY && TIKTOK_CLIENT_SECRET);

// Résumé des capacités effectives, renvoyé par les routes TikTok :
// le frontend affiche un bandeau sandbox à partir de là.
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

// Webhook TikTok : écart maximal (en secondes) toléré entre l'horodatage signé
// par TikTok et l'heure du serveur. 0 = contrôle désactivé. Défaut : 300 s.
const TIKTOK_WEBHOOK_TOLERANCE_SEC = (() => {
  const raw = env("TIKTOK_WEBHOOK_TOLERANCE_SEC");
  const value = raw ? Number(raw) : Number.NaN;
  return Number.isFinite(value) && value >= 0 ? value : 300;
})();

// Vérification du préfixe d'URL chez TikTok (URL properties).
// TikTok fournit un fichier "<nom>.txt" dont le contenu est "<nom>".
// Il est servi sur /api/media/tiktok/<nom>.txt (voir createServer).
// Surchargeable via TIKTOK_VERIFICATION_FILE (avec ou sans ".txt").
const TIKTOK_VERIFICATION_NAME = (
  env("TIKTOK_VERIFICATION_FILE") ||
  "tiktok-developers-site-verification=mRJN1EDyG6GdEuRBeOe9A5VyNF5FZTlU"
).replace(/\.txt$/i, "");

// URL publique de CE serveur, utilisée pour que TikTok télécharge les photos.
// Ordre de lecture : PUBLIC_API_URL → VITE_API_BASE_URL → RAILWAY_PUBLIC_DOMAIN.
// On retire le slash final ET un éventuel "/api" final (les routes média
// ajoutent déjà "/api/media/tiktok/..."). Une valeur relative (ex. "/api")
// ou invalide est ignorée.
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
      // valeur relative ou invalide : on essaie la suivante
    }
  }

  return { url: "", source: null };
}

// Photos / carrousels : TikTok ne les accepte que par PULL_FROM_URL.
// Les images sont déposées temporairement dans un bucket Supabase privé,
// puis servies par CE serveur sur PUBLIC_API_URL (préfixe vérifié chez TikTok).
const { url: PUBLIC_API_URL, source: PUBLIC_API_URL_SOURCE } =
  resolvePublicApiUrl();
const TIKTOK_MEDIA_BUCKET = "tiktok-media";
const TIKTOK_MEDIA_TTL_MS = 2 * 60 * 60 * 1000;
const MAX_TIKTOK_PHOTOS = 35;
const MAX_PHOTO_SIZE = 10 * 1024 * 1024;
const MAX_PHOTOS_TOTAL = 80 * 1024 * 1024;

// Un PUBLIC_API_URL qui pointe vers le frontend (Vercel / APP_URL) est la
// cause n°1 de « The request source info is empty or incorrect ».
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

if (tiktokEnabled && !PUBLIC_API_URL) {
  console.warn(
    "⚠️  PUBLIC_API_URL / VITE_API_BASE_URL manquant — la publication de photos TikTok sera désactivée (ex. https://api.tondomaine.com)."
  );
}

if (tiktokEnabled && PUBLIC_API_URL && !PUBLIC_API_URL.startsWith("https://")) {
  console.warn(
    `⚠️  ${publicApiSourceLabel(PUBLIC_API_URL_SOURCE)} (${PUBLIC_API_URL}) n'est pas en https — TikTok refusera de télécharger les photos.`
  );
}

if (tiktokEnabled && publicApiLooksLikeFrontend()) {
  console.warn(
    `⚠️  ${publicApiSourceLabel(PUBLIC_API_URL_SOURCE)} (${PUBLIC_API_URL}) ressemble au FRONTEND, pas à l'API. Définis PUBLIC_API_URL=https://<domaine-de-ce-serveur>.`
  );
}

if (tiktokEnabled && TIKTOK_SANDBOX) {
  console.warn(
    "ℹ️  TikTok en MODE SANDBOX (TIKTOK_AUDITED≠1) — DIRECT_POST limité à SELF_ONLY, photos en brouillon, seuls les « Sandbox testers » du portail peuvent se connecter."
  );
}

if (tiktokEnabled && TIKTOK_FORCE_DRAFT) {
  console.warn(
    "ℹ️  TIKTOK_FORCE_DRAFT=1 — toutes les publications partent en brouillon."
  );
}

// ============================================================
// CONFIGURATION PINTEREST
// ============================================================
//
// L'environnement (sandbox / production) est déduit de PINTEREST_API_BASE
// (défaut : SANDBOX). L'endpoint OAuth (échange de code + refresh) est
// dérivé du MÊME environnement, sauf si PINTEREST_OAUTH_BASE est défini
// explicitement. Si les deux ne sont pas du même environnement, la
// configuration est jugée incohérente : les routes Pinterest répondent 500
// (PINTEREST_CONFIG_INVALID) au lieu de mélanger les environnements.

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

const YOUTUBE_SCOPES = (
  env("YOUTUBE_SCOPES") ||
  "https://www.googleapis.com/auth/youtube.readonly https://www.googleapis.com/auth/youtube.upload"
)
  .split(/[\s,]+/)
  .filter(Boolean)
  .join(" ");

const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke";
const YOUTUBE_API_BASE = "https://www.googleapis.com/youtube/v3";

const youtubeEnabled = Boolean(YOUTUBE_CLIENT_ID && YOUTUBE_CLIENT_SECRET);

// ---- Publication YouTube ------------------------------------------------
const YOUTUBE_UPLOAD_URL = "https://www.googleapis.com/upload/youtube/v3/videos";
// Les chunks doivent être un multiple de 256 Kio (sauf le dernier).
const YOUTUBE_CHUNK_SIZE = 8 * 1024 * 1024;
const YOUTUBE_PRIVACY_LEVELS = new Set(["public", "unlisted", "private"]);
const YOUTUBE_TITLE_MAX = 100;
const YOUTUBE_DESCRIPTION_MAX_BYTES = 5000;
const YOUTUBE_UPLOAD_SCOPE = "https://www.googleapis.com/auth/youtube.upload";

if (youtubeEnabled && !YOUTUBE_SCOPES.split(" ").includes(YOUTUBE_UPLOAD_SCOPE)) {
  console.warn(
    "⚠️  YOUTUBE_SCOPES ne contient pas youtube.upload — la publication YouTube sera impossible."
  );
}

// ============================================================
// SECRETS : SIGNATURE DU STATE OAUTH + CHIFFREMENT DES TOKENS
// ============================================================

let OAUTH_STATE_SECRET =
  env("OAUTH_STATE_SECRET") ||
  TIKTOK_CLIENT_SECRET ||
  PINTEREST_APP_SECRET ||
  YOUTUBE_CLIENT_SECRET;

if (!OAUTH_STATE_SECRET && !IS_PRODUCTION) {
  // Dev uniquement : secret éphémère (les states ne survivent pas au redémarrage).
  OAUTH_STATE_SECRET = crypto.randomBytes(32).toString("hex");
  console.warn(
    "⚠️  OAUTH_STATE_SECRET manquant — secret éphémère généré (dev uniquement)."
  );
}

if (IS_PRODUCTION && !env("OAUTH_STATE_SECRET")) {
  console.warn(
    "⚠️  OAUTH_STATE_SECRET manquant : définis un secret dédié (32+ caractères aléatoires) en production."
  );
}

const TOKEN_ENCRYPTION_KEY = env("TOKEN_ENCRYPTION_KEY")
  ? crypto.createHash("sha256").update(env("TOKEN_ENCRYPTION_KEY")).digest()
  : null;

const ENC_PREFIX = "enc:v1:";

if (!TOKEN_ENCRYPTION_KEY) {
  console.warn(
    "⚠️  TOKEN_ENCRYPTION_KEY manquant — les tokens TikTok / Pinterest / YouTube sont stockés en clair."
  );
}

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

  return (
    ENC_PREFIX + Buffer.concat([iv, tag, encrypted]).toString("base64url")
  );
}

function decryptSecret(value) {
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
    // L'utilisateur devra reconnecter son compte.
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
  console.error("Définis-les dans les variables d'environnement de");
  console.error("ton hébergeur, ou dans le fichier :");
  console.error(envPath);
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
  console.error(
    "Elle doit ressembler à : https://xxxxxxxx.supabase.co (sans guillemets)."
  );
  console.error("");

  process.exit(1);
}

const SUPABASE_BASE_URL = SUPABASE_URL.replace(/\/+$/, "");

// Debug optionnel : DEBUG_ENV=1 (n'affiche jamais les secrets)
if (env("DEBUG_ENV") === "1") {
  console.log("[env] SUPABASE_URL      :", JSON.stringify(SUPABASE_URL));
  console.log("[env] ANON key length   :", SUPABASE_ANON_KEY.length);
  console.log("[env] SERVICE key length:", SUPABASE_SERVICE_ROLE_KEY.length);
  console.log("[env] APP_URL           :", JSON.stringify(APP_URL));
  console.log("[env] PUBLIC_API_URL    :", JSON.stringify(PUBLIC_API_URL), `(${PUBLIC_API_URL_SOURCE || "aucune source"})`);
  console.log("[env] TIKTOK_REDIRECT   :", JSON.stringify(TIKTOK_REDIRECT_URI));
  console.log("[env] TIKTOK_AUDITED    :", TIKTOK_AUDITED);
  console.log("[env] TIKTOK_FORCE_DRAFT:", TIKTOK_FORCE_DRAFT);
  console.log("[env] PINTEREST_REDIRECT:", JSON.stringify(PINTEREST_REDIRECT_URI));
  console.log("[env] PINTEREST_API_BASE:", JSON.stringify(PINTEREST_API_BASE));
  console.log("[env] PINTEREST_OAUTH   :", JSON.stringify(PINTEREST_OAUTH_BASE));
  console.log("[env] PINTEREST_ENV     :", PINTEREST_ENVIRONMENT);
  console.log("[env] YOUTUBE_REDIRECT  :", JSON.stringify(YOUTUBE_REDIRECT_URI));
  console.log("[env] YOUTUBE_SCOPES    :", JSON.stringify(YOUTUBE_SCOPES));
  console.log("[env] TOKEN ENCRYPTION  :", Boolean(TOKEN_ENCRYPTION_KEY));
}

// ============================================================
// FAIL-FAST EN PRODUCTION
// ============================================================
//
// Sans APP_URL / OAUTH_REDIRECT_URL en production, les redirections
// Stripe et OAuth pointeraient silencieusement vers localhost.

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
} else {
  if (!env("APP_URL")) {
    console.warn(
      "⚠️  APP_URL manquant — fallback http://localhost:5173 (dev uniquement)."
    );
  }

  if (!env("OAUTH_REDIRECT_URL")) {
    console.warn(
      "⚠️  OAUTH_REDIRECT_URL manquant — fallback http://localhost:5173/ (dev uniquement)."
    );
  }
}

if (!STRIPE_SECRET_KEY) {
  console.warn("⚠️  Stripe non configuré (STRIPE_SECRET_KEY manquant).");
}

if (!STRIPE_WEBHOOK_SECRET) {
  console.warn(
    "⚠️  STRIPE_WEBHOOK_SECRET manquant — les webhooks seront refusés."
  );
}

if (!tiktokEnabled) {
  console.warn(
    "⚠️  TikTok non configuré (TIKTOK_CLIENT_KEY / TIKTOK_CLIENT_SECRET manquant)."
  );
}

if (!pinterestEnabled) {
  console.warn(
    "⚠️  Pinterest non configuré (PINTEREST_APP_ID / PINTEREST_APP_SECRET manquant)."
  );
}

if (!youtubeEnabled) {
  console.warn(
    "⚠️  YouTube non configuré (YOUTUBE_CLIENT_ID / YOUTUBE_CLIENT_SECRET manquant)."
  );
}

for (const [label, value] of [
  ["TIKTOK_REDIRECT_URI", TIKTOK_REDIRECT_URI],
  ["PINTEREST_REDIRECT_URI", PINTEREST_REDIRECT_URI],
  ["YOUTUBE_REDIRECT_URI", YOUTUBE_REDIRECT_URI],
]) {
  if (value.includes("#")) {
    console.warn(
      `⚠️  ${label} contient un "#" (${value}) — c'est invalide. Utilise https://<frontend>/<provider>/callback.`
    );
  }
}

if (pinterestEnabled && pinterestConfigError) {
  console.error(
    `❌ Pinterest : configuration incohérente (${pinterestConfigError}). Les routes Pinterest répondront 500 tant que ce n'est pas corrigé (API = ${PINTEREST_API_BASE}, OAuth = ${PINTEREST_OAUTH_BASE}).`
  );
}

if (pinterestEnabled && !pinterestConfigError) {
  console.warn(
    PINTEREST_ENVIRONMENT === "sandbox"
      ? `ℹ️  Pinterest en mode SANDBOX (API = ${PINTEREST_API_BASE}, OAuth = ${PINTEREST_OAUTH_BASE}).`
      : `ℹ️  Pinterest en mode PRODUCTION (API = ${PINTEREST_API_BASE}, OAuth = ${PINTEREST_OAUTH_BASE}).`
  );
}

// ============================================================
// CLIENTS SUPABASE
// ============================================================
//
// Pas de session persistée ni d'auto-refresh : ce serveur est
// stateless, un client partagé ne doit jamais mémoriser la
// session d'un utilisateur.

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
//
// Sliding window. Suffisant pour un backend Railway mono-instance ;
// pour du multi-instance, passe à Redis (rate-limiter-flexible).
//
// TRUST_PROXY=1 derrière Railway pour utiliser X-Forwarded-For.
// TRUST_PROXY_HOPS = nombre de proxies de confiance devant l'app
// (on lit l'entrée située à cette distance de la FIN de la liste,
// donc une valeur injectée par le client n'est jamais utilisée).

const TRUST_PROXY = env("TRUST_PROXY") === "1" || IS_PRODUCTION;
const TRUST_PROXY_HOPS = Math.max(1, Number(env("TRUST_PROXY_HOPS") || 1));

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

      // Réinsère en fin de Map (ordre d'insertion = ordre d'activité).
      hits.delete(key);
      hits.set(key, timestamps);

      // Borne mémoire : on évince les clés les plus anciennes.
      if (hits.size > maxKeys) {
        const oldest = hits.keys().next().value;
        hits.delete(oldest);
      }

      return { allowed: true, retryAfterSec: null };
    },
  };
}

// Par IP
const limiterStrict = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 10, label: "auth" });
const limiterRefresh = createRateLimiter({ windowMs: 10 * 60 * 1000, max: 30, label: "refresh" });
const limiterOauth = createRateLimiter({ windowMs: 10 * 60 * 1000, max: 30, label: "oauth" });
const limiterApi = createRateLimiter({ windowMs: 60 * 1000, max: 240, label: "api" });

// Par compte (empêche de contourner la limite IP en changeant d'IP)
const limiterAccount = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 10, label: "account" });
const limiterPublish = createRateLimiter({ windowMs: 60 * 60 * 1000, max: 20, label: "publish" });

// Les serveurs TikTok téléchargent jusqu'à 35 images par publication
// (et ce serveur en sonde autant avant publication).
const limiterMedia = createRateLimiter({ windowMs: 60 * 1000, max: 600, label: "media" });
// Webhook TikTok (serveur -> serveur, signature vérifiée). Limite dédiée par IP :
// large pour absorber les rafales/retries légitimes de TikTok, mais bornée.
const limiterTiktokWebhook = createRateLimiter({ windowMs: 60 * 1000, max: 600, label: "tiktok-webhook" });

function enforce(limiter, key) {
  const { allowed, retryAfterSec } = limiter.check(key);

  if (!allowed) {
    throw new HttpError(
      429,
      "Too many requests. Please try again later.",
      "RATE_LIMITED",
      retryAfterSec ? { "Retry-After": String(retryAfterSec) } : undefined
    );
  }
}

const STRICT_PATHS = new Set([
  "/api/auth/login",
  "/api/auth/check-verification",
  "/api/auth/signup",
]);

const PROVIDER_AUTH_PATH = /^\/api\/(tiktok|pinterest|youtube)\/auth\//;

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
  "https://stone-prod-2fpb2146e-xsdevs-projects.vercel.app",
];

const VERCEL_DEPLOYMENT_ORIGIN_PATTERN =
  /^https:\/\/stone-prod(-[a-z0-9]+)?-xsdevs-projects\.vercel\.app$/;

const extraAllowedOrigins = (env("ALLOWED_ORIGINS") || "")
  .split(",")
  .map(normalizeOrigin)
  .filter(Boolean);

if (extraAllowedOrigins.includes("*")) {
  console.warn(
    '⚠️  ALLOWED_ORIGINS contient "*" : ignoré (incompatible avec les credentials). Liste les origines explicitement.'
  );
}

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
      res.setHeader("Access-Control-Expose-Headers", "Retry-After");
    } else if (
      warnedRejectedOrigins.size < 100 &&
      !warnedRejectedOrigins.has(origin)
    ) {
      warnedRejectedOrigins.add(origin);
      console.warn(
        `[cors] Origine refusée : ${origin} — ajoute-la à ALLOWED_ORIGINS ou APP_URL si elle est légitime.`
      );
    }
  }

  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, PATCH, DELETE, OPTIONS"
  );
  res.setHeader("Access-Control-Allow-Headers", CORS_ALLOWED_HEADERS);
  res.setHeader("Access-Control-Max-Age", "86400");
}

// API JSON pure : on interdit tout (framing, ressources, cache).
function setSecurityHeaders(res) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cache-Control", "no-store");
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
// VALIDATION DU redirectTo (anti open redirect)
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
      console.warn(
        `[oauth] redirectTo refusé (origine non autorisée) : ${parsed.origin}`
      );
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

// En production, le client ne reçoit JAMAIS le message d'erreur
// interne : seulement un message générique + un requestId
// corrélable aux logs serveur.
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

const MAX_JSON_BODY = 1024 * 1024; // 1 Mo suffit pour toutes nos routes JSON

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

// Corps brut (signature Stripe : les payloads sont petits)
const getRawBody = (req) => readBody(req, MAX_JSON_BODY);

// ============================================================
// MULTIPART (avatar, vidéo)
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

    // Un client qui coupe la connexion ne doit jamais laisser la
    // promesse (et donc un slot d'upload) pendante.
    req.on("close", () => {
      if (!req.complete) {
        settle(reject, new HttpError(400, "Upload aborted"));
      }
    });
    req.on("error", () =>
      settle(reject, new HttpError(400, "Upload aborted"))
    );

    req.pipe(bb);
  });
}

// Variante multi-fichiers (carrousel de photos).
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
    req.on("error", () =>
      settle(reject, new HttpError(400, "Upload aborted"))
    );

    req.pipe(bb);
  });
}

// ============================================================
// VALIDATION DU TYPE DE FICHIER (magic bytes, pas le header client)
// ============================================================
//
// SVG volontairement EXCLU pour les avatars (XSS possible via un
// SVG servi depuis le domaine public du bucket).

const ALLOWED_AVATAR_TYPES = ["image/png", "image/jpeg", "image/webp", "image/gif"];

const AVATAR_EXTENSIONS = {
  "image/png": "png",
  "image/jpeg": "jpg",
  "image/webp": "webp",
  "image/gif": "gif",
};

function sniffImageType(buffer) {
  if (!buffer || buffer.length < 12) return null;

  // PNG : 89 50 4E 47
  if (
    buffer[0] === 0x89 &&
    buffer[1] === 0x50 &&
    buffer[2] === 0x4e &&
    buffer[3] === 0x47
  ) {
    return "image/png";
  }

  // JPEG : FF D8 FF
  if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
    return "image/jpeg";
  }

  // GIF : "GIF8"
  if (
    buffer[0] === 0x47 &&
    buffer[1] === 0x49 &&
    buffer[2] === 0x46 &&
    buffer[3] === 0x38
  ) {
    return "image/gif";
  }

  // WebP : "RIFF"...."WEBP"
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

  // MP4 / MOV : "ftyp" aux octets 4-7 ; la marque "qt  " = QuickTime
  if (buffer.toString("ascii", 4, 8) === "ftyp") {
    return buffer.toString("ascii", 8, 12) === "qt  "
      ? "video/quicktime"
      : "video/mp4";
  }

  // WebM / Matroska : 1A 45 DF A3
  if (
    buffer[0] === 0x1a &&
    buffer[1] === 0x45 &&
    buffer[2] === 0xdf &&
    buffer[3] === 0xa3
  ) {
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

  if (!filePathOrUrl.startsWith("http")) {
    return filePathOrUrl;
  }

  return null;
}

function isOwnedAvatarPath(storagePath, userId) {
  if (typeof storagePath !== "string") return false;
  if (storagePath.includes("..")) return false;
  if (storagePath.startsWith("/")) return false;

  return storagePath.startsWith(`${userId}/`);
}

// ============================================================
// LIMITE DE CONCURRENCE DES UPLOADS VIDÉO (anti OOM)
// ============================================================
//
// Chaque upload TikTok / YouTube bufferise jusqu'à 100 Mo en RAM. Le slot
// est acquis AVANT de lire le corps de la requête : au plus
// MAX_VIDEO_UPLOADS vidéos en mémoire simultanément.

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
    // Le slot est transféré au suivant : le compteur ne bouge pas.
    next.resolve();
  } else {
    activeVideoUploads = Math.max(0, activeVideoUploads - 1);
  }
}

// ============================================================
// AUTHENTIFICATION (avec cache court)
// ============================================================
//
// supabase.auth.getUser(token) est un appel réseau : on met le
// résultat en cache 20 s (clé = hash du token). Le cache est vidé
// pour un utilisateur dès qu'on modifie son compte ou qu'il se
// déconnecte.

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
    const isExpired = Boolean(
      error?.message?.toLowerCase().includes("expired")
    );

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

// Toute modification admin d'un compte passe par ici (invalide le cache).
async function adminUpdateUser(userId, attributes) {
  const result = await supabaseAdmin.auth.admin.updateUserById(
    userId,
    attributes
  );

  authCacheInvalidateUser(userId);
  return result;
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
    // app_metadata n'est modifiable QUE par le serveur (service role) :
    // un utilisateur ne peut pas s'auto-attribuer un abonnement.
    subscription: user.app_metadata?.subscription || null,
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
// APP_METADATA — LECTURE / ÉCRITURE FIABLES
// ============================================================
//
// app_metadata contient l'abonnement et l'id client Stripe : une erreur
// ignorée ici crée une incohérence Stripe ↔ Supabase. Toute lecture ou
// écriture passe par ces fonctions, qui lèvent une erreur explicite.

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

// Lit → modifie → écrit, en série par utilisateur (pas de perte de mise à
// jour entre deux événements Stripe / deux requêtes concurrentes de CE
// processus). `mutate(current)` renvoie le nouvel objet app_metadata, ou
// null pour ne rien écrire. Renvoie l'état final.
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

// Retourne l'identifiant de client Stripe de l'utilisateur.
// - source de vérité : app_metadata (serveur uniquement)
// - migration : un ancien id stocké dans user_metadata n'est accepté
//   que si le client Stripe correspondant appartient bien à cet
//   utilisateur (user_metadata est modifiable par le client).
// - création : sous verrou, après relecture d'app_metadata, et en
//   réutilisant un client Stripe déjà créé pour cet utilisateur (cas d'une
//   écriture Supabase échouée lors d'une tentative précédente).
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
          // L'id reste valide (vérifié) : on continue, la migration sera
          // retentée au prochain appel.
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
    // Un autre appel a pu créer / enregistrer le client entre-temps.
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

// null UNIQUEMENT si le client est supprimé / inconnu / sans lien utilisateur.
// Une erreur réseau ou API est propagée : le webhook répond 500 et Stripe
// réessaie, au lieu d'ignorer silencieusement l'événement.
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

// Écrit l'état d'abonnement (issu de Stripe) dans app_metadata.
//  - eventCreated : horodatage Stripe (s) de l'événement à l'origine de
//    l'écriture. Un événement plus ancien que le dernier appliqué est ignoré
//    (livraison dans le désordre).
//  - Un événement terminal (canceled...) d'un ANCIEN abonnement n'écrase pas
//    un abonnement différent encore actif (annulation puis réabonnement).
//  - overrides : champs forcés dans le snapshot (ex. status "past_due"
//    prouvé par une facture Stripe impayée).
// Renvoie true si l'état a été écrit.
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

// Traite UN événement Stripe (déjà authentifié par sa signature).
// Toute erreur remonte → 500 → Stripe réessaie. Les handlers sont
// idempotents : l'état est toujours relu depuis Stripe, jamais déduit du
// seul contenu de l'événement.
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
          // Données fraîches de Stripe : un événement en retard ne peut pas
          // réinjecter un ancien état.
          const subscription = await retrieveSubscription(payload.id, payload);
          await syncSubscriptionToUser(userId, subscription, { eventCreated });
        }
        break;
      }

      case "invoice.payment_failed": {
        const invoice = event.data.object;
        const subscriptionId = idOf(invoice.subscription);

        if (!subscriptionId) break; // facture hors abonnement

        const userId = await resolveUserIdFromCustomer(invoice.customer);
        if (!userId) break;

        // Preuve côté Stripe : la facture est-elle TOUJOURS impayée ?
        // (un paiement réussi entre-temps ne doit pas être écrasé.)
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

      default:
        // Événement ignoré
        break;
    }
  } catch (error) {
    if (error instanceof HttpError && error.code === "USER_NOT_FOUND") {
      // Utilisateur supprimé côté Supabase : inutile que Stripe réessaie.
      console.warn(
        `[stripe:webhook] ${event.id} (${event.type}) ignoré : utilisateur introuvable`
      );
      return;
    }

    throw error;
  }
}

// ============================================================
// STATE OAUTH SIGNÉ (anti-CSRF, stateless)
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

// Renvoie null si le state est valide, sinon la raison précise de l'échec.
// Les raisons ne sont écrites que dans les logs serveur (jamais renvoyées au client).
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

    // Signature différente : autre OAUTH_STATE_SECRET (serveur local vs prod,
    // secret éphémère après un redémarrage...) ou state modifié.
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

function verifyOAuthState(provider, state, userId) {
  return checkOAuthState(provider, state, userId) === null;
}

const OAUTH_REJECT_HINTS = {
  missing_code:
    "le frontend n'a pas envoyé de `code` (refus de l'utilisateur, ou paramètres mal lus dans l'URL)",
  code_too_long: "`code` anormalement long",
  missing_state:
    "le frontend n'a pas envoyé de `state` (paramètres perdus par le routeur / le hash)",
  malformed_state: "`state` illisible ou tronqué",
  bad_signature:
    "le state n'a pas été signé avec le même OAUTH_STATE_SECRET (serveur redémarré avec un secret éphémère, ou URL de départ et de retour sur deux environnements différents)",
  wrong_provider: "le state a été créé pour un autre réseau",
  wrong_user:
    "le state appartient à un autre utilisateur (changement de compte pendant l'autorisation)",
  expired: "le state a plus de 10 minutes : relance la connexion",
};

function assertValidOAuthCallback(provider, body, userId) {
  const code = String(body.code || "");

  let reason = null;
  if (!code) reason = "missing_code";
  else if (code.length > 2048) reason = "code_too_long";
  else reason = checkOAuthState(provider, body.state, userId);

  if (reason) {
    console.warn(
      `[oauth:${provider}] callback rejeté (${reason}) : ${OAUTH_REJECT_HINTS[reason] || ""}`
    );
    throw new HttpError(400, "Invalid or expired state", "OAUTH_STATE_INVALID");
  }

  return code;
}

// ============================================================
// TOKENS OAUTH — LECTURE / ÉCRITURE COMMUNES (TikTok, Pinterest, YouTube)
// ============================================================

// Une erreur de base de données n'est JAMAIS traitée comme « compte absent ».
async function selectTokenRow(table, userId) {
  const { data, error } = await supabaseAdmin
    .from(table)
    .select("*")
    .eq("user_id", userId)
    .maybeSingle();

  if (error) throw dbError(`${table} select`, error);

  return decryptTokenRow(data);
}

// Le jeton d'accès est utilisable s'il expire dans plus de 60 s.
function isTokenFresh(account) {
  return Boolean(
    account?.access_token &&
      new Date(account.access_expires_at).getTime() > Date.now() + 60_000
  );
}

const isPast = (value) => new Date(value).getTime() <= Date.now();

// Mise à jour « compare-and-swap » : la ligne n'est modifiée que si
// updated_at est celui que l'on a lu. Si un autre traitement (autre
// instance, reconnexion, déconnexion) est passé entre-temps, rien n'est
// écrit et on renvoie false : un ancien jeton ne réécrase jamais un plus
// récent, et une ligne supprimée n'est jamais recréée.
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

// Messages lisibles pour les erreurs TikTok les plus fréquentes,
// enrichis du contexte sandbox.
const TIKTOK_FRIENDLY_ERRORS = {
  unaudited_client_can_only_post_to_private_accounts:
    "Mode sandbox : TikTok n'accepte que des posts privés (SELF_ONLY) tant que l'app n'est pas auditée. Définis privacy_level=SELF_ONLY ou passe en mode brouillon.",
  url_ownership_unverified:
    "TikTok could not verify the media URL prefix. Check PUBLIC_API_URL and the URL properties in the TikTok developer portal.",
  spam_risk_too_many_posts:
    "TikTok daily posting limit reached. Please try again later.",
  spam_risk_user_banned_from_posting:
    "This TikTok account cannot post right now.",
  reached_active_user_cap:
    "TikTok daily user cap reached for this app. Try again later.",
  // Renvoyée par TikTok pour les brouillons photo (MEDIA_UPLOAD) quand
  // l'appli TikTok de l'utilisateur est trop ancienne (< 31.8).
  app_version_check_failed:
    "Please update your TikTok app to the latest version to use this feature, then try again.",
  // En sandbox, seuls les « Sandbox testers » du portail peuvent
  // autoriser l'app.
  access_denied:
    "Connection refused by TikTok. In sandbox mode, add the TikTok account as a Sandbox tester in the TikTok developer portal, then try again.",
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
    result = await fetchJson(
      `${TIKTOK_API}${pathname}`,
      { method, headers, body },
      20_000
    );
  } catch (error) {
    throw upstreamError("TikTok", error);
  }

  const { response, data } = result;

  // Erreurs OAuth (/oauth/token, /oauth/revoke...)
  if (typeof data.error === "string") {
    throw new HttpError(400, data.error_description || data.error, data.error);
  }

  // Erreurs API ("ok" = succès)
  if (data.error?.code && data.error.code !== "ok") {
    // Log serveur : code + log_id TikTok pour diagnostiquer.
    console.error(
      "[tiktok]",
      pathname,
      JSON.stringify({
        code: data.error.code,
        message: data.error.message,
        log_id: data.error.log_id,
      })
    );

    throw new HttpError(
      400,
      TIKTOK_FRIENDLY_ERRORS[data.error.code] ||
        data.error.message ||
        data.error.code,
      data.error.code
    );
  }

  if (!response.ok) {
    throw new HttpError(
      upstreamStatus(response.status),
      `TikTok error (HTTP ${response.status})`,
      "TIKTOK_UPSTREAM"
    );
  }

  return data;
}

// ============================================================
// TIKTOK — STOCKAGE / REFRESH DES TOKENS
// ============================================================

// Champs à écrire pour un jeu de jetons TikTok. Un champ absent de la
// réponse du provider n'est PAS écrasé (ex. refresh_token non renvoyé).
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

// Connexion initiale : crée ou remplace la ligne.
async function saveTikTokTokens(userId, t, extra = {}) {
  const { error } = await supabaseAdmin.from("tiktok_accounts").upsert(
    {
      user_id: userId,
      ...buildTikTokTokenRow(t),
      ...extra,
    },
    { onConflict: "user_id" }
  );

  if (error) throw new Error(error.message);
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
    // Deux tentatives : la seconde n'a lieu que si la ligne a changé
    // pendant le refresh (autre instance, reconnexion...).
    for (let attempt = 0; attempt < 2; attempt++) {
      // Relecture APRÈS verrou : un autre traitement a peut-être déjà
      // renouvelé le jeton (et TikTok fait tourner les refresh tokens).
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
        throw new HttpError(
          502,
          "TikTok returned an invalid token response",
          "TIKTOK_BAD_TOKEN_RESPONSE"
        );
      }

      const applied = await updateTokensIfUnchanged(
        "tiktok_accounts",
        userId,
        account,
        buildTikTokTokenRow(refreshed)
      );

      if (applied) return refreshed.access_token;
    }

    throw new HttpError(
      409,
      "TikTok account changed during token refresh, please retry",
      "TIKTOK_REFRESH_CONFLICT"
    );
  });
}

// ============================================================
// TIKTOK — RAFRAÎCHISSEMENT DU PROFIL (avatar)
// ============================================================
//
// Les URLs d'avatar renvoyées par TikTok sont signées et expirent au
// bout de quelques heures. On re-télécharge donc le profil
// périodiquement (throttle en mémoire : 30 min par utilisateur).

const TIKTOK_PROFILE_REFRESH_MS = 30 * 60 * 1000;
const tiktokProfileRefreshedAt = new Map();

async function refreshTikTokProfile(userId, account, { force = false } = {}) {
  const last = tiktokProfileRefreshedAt.get(userId) || 0;

  if (!force && Date.now() - last < TIKTOK_PROFILE_REFRESH_MS) {
    return account;
  }

  // Marqué avant l'appel : en cas d'échec on ne martèle pas TikTok.
  tiktokProfileRefreshedAt.set(userId, Date.now());

  // Borne mémoire du throttle.
  if (tiktokProfileRefreshedAt.size > 10_000) {
    tiktokProfileRefreshedAt.delete(tiktokProfileRefreshedAt.keys().next().value);
  }

  try {
    const accessToken = await getValidTikTokToken(userId);

    const info = await tiktokApi(
      "/v2/user/info/?fields=open_id,avatar_url,display_name",
      { method: "GET", token: accessToken }
    );

    const profile = info.data?.user;

    if (!profile?.avatar_url) return account;

    const displayName = profile.display_name || account.display_name;

    // On ne touche PAS à updated_at : il sert au webhook
    // authorization.removed pour ne pas supprimer une connexion
    // rétablie après la révocation (et au compare-and-swap du refresh).
    const { error } = await supabaseAdmin
      .from("tiktok_accounts")
      .update({
        avatar_url: profile.avatar_url,
        display_name: displayName,
      })
      .eq("user_id", userId);

    if (error) {
      console.warn("TikTok profile save failed:", error.message);
    }

    return {
      ...account,
      avatar_url: profile.avatar_url,
      display_name: displayName,
    };
  } catch (error) {
    console.warn("TikTok profile refresh failed:", error.message);
    return account;
  }
}

// ============================================================
// TIKTOK — UPLOAD VIDÉO
// ============================================================

// TikTok : total_chunk_count = floor(taille / chunk_size) ; le dernier
// chunk absorbe le reste (entre 5 et 128 Mo). Une vidéo ≤ 64 Mo part en
// un seul chunk.
function computeChunking(size) {
  const MB = 1024 * 1024;

  if (size <= 64 * MB) {
    return { chunkSize: size, totalChunks: 1 };
  }

  const chunkSize = 10 * MB;
  return { chunkSize, totalChunks: Math.floor(size / chunkSize) };
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

      // Erreur client (4xx hors 429) : inutile de réessayer.
      if (
        response.status >= 400 &&
        response.status < 500 &&
        response.status !== 429
      ) {
        throw new HttpError(
          502,
          `TikTok upload rejected (HTTP ${response.status})`,
          "TIKTOK_UPLOAD_REJECTED"
        );
      }

      lastError = new Error(`HTTP ${response.status}`);
    } catch (error) {
      if (error instanceof HttpError && error.code === "TIKTOK_UPLOAD_REJECTED") {
        throw error;
      }
      lastError = error;
    }

    if (attempt < MAX_ATTEMPTS) {
      await delay(attempt * 1000);
    }
  }

  console.error("TikTok chunk upload failed:", lastError?.message);
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
// TIKTOK — MODES / PRIVACY (logique sandbox)
// ============================================================

// Niveau de confidentialité effectif.
//   - sandbox (non audité) → SELF_ONLY forcé
//   - TIKTOK_FORCE_DRAFT   → SELF_ONLY (un brouillon reste consultable
//     uniquement par le créateur, mais on borne quand même)
//   - sinon                : valeur demandée si valide, sinon SELF_ONLY
function resolvePrivacy(requested) {
  if (TIKTOK_SANDBOX || TIKTOK_FORCE_DRAFT) return "SELF_ONLY";

  const value = String(requested || "SELF_ONLY");
  return TIKTOK_PRIVACY_LEVELS.has(value) ? value : "SELF_ONLY";
}

// Mode de publication vidéo :
//   - "draft" demandé  → brouillon (inbox), toujours OK
//   - "direct" demandé → brouillon si FORCE_DRAFT, sinon direct
//     (en sandbox le direct reste possible mais SELF_ONLY)
function resolveVideoMode(requested) {
  if (TIKTOK_FORCE_DRAFT) return "draft";
  return requested === "draft" ? "draft" : "direct";
}

// Divulgation de contenu commercial (exigence TikTok) :
//   brand_organic_toggle = « Your brand »      → « Promotional content »
//   brand_content_toggle = « Branded content » → « Paid partnership »
// Le contenu de marque ne peut pas être privé (SELF_ONLY) → en sandbox
// on le refuse explicitement (il serait de toute façon écrasé en SELF_ONLY).
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
        json: {
          post_info: buildPostInfo(postInfoFields),
          source_info: sourceInfo,
        },
      });
}

// publish_id TikTok : lettres, chiffres, _ . : ~ -  (le « ~ » est utilisé
// par TikTok), 64 caractères maximum.
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
// TIKTOK — PHOTOS (carrousel)
// ============================================================
//
// 1 photo = post photo, 2 à 35 photos = carrousel.
// Les fichiers vivent dans un bucket privé (nom aléatoire de 128 bits),
// servis sans authentification sur /api/media/tiktok/<nom> pour que
// TikTok puisse les télécharger, puis supprimés après TIKTOK_MEDIA_TTL_MS.
//
// SANDBOX : TikTok refuse les posts photos DIRECT_POST des apps non
// auditées → resolvePhotoMode() force le brouillon (MEDIA_UPLOAD).

async function ensureTikTokMediaBucket() {
  const { error } = await supabaseAdmin.storage.createBucket(
    TIKTOK_MEDIA_BUCKET,
    { public: false }
  );

  if (error && !/already exists|duplicate/i.test(error.message || "")) {
    console.warn("TikTok media bucket:", error.message);
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
    // le balayage périodique s'en chargera
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
    // Par lots pour ne pas ouvrir 35 connexions d'un coup.
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

// Route publique appelée par les serveurs TikTok (GET / HEAD).
async function serveTikTokMedia(req, res, fileName) {
  const { data, error } = await supabaseAdmin.storage
    .from(TIKTOK_MEDIA_BUCKET)
    .download(fileName);

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

  res.end(req.method === "HEAD" ? undefined : buffer);
}

// Vérifie, AVANT d'appeler TikTok, qu'une image est bien joignable depuis
// Internet avec le bon Content-Type. Évite l'erreur opaque « The request
// source info is empty or incorrect » : on remonte la vraie cause (mauvais
// PUBLIC_API_URL, proxy, 404...). `index` / `total` (1-based) précisent
// quelle photo pose problème.
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
  } catch (error) {
    console.error(
      "[tiktok:photos] probe failed:",
      imageUrl,
      error?.message || error
    );

    throw new HttpError(
      502,
      `The photo URL is not reachable from the internet${label}. Check PUBLIC_API_URL (it must be the public domain of this API server).`,
      "PHOTO_URL_UNREACHABLE"
    );
  }

  const okType = /^image\/(jpeg|webp)/i.test(contentType || "");

  console.log("[tiktok:photos] probe", status, contentType, imageUrl);

  if (status !== 200 || !okType) {
    throw new HttpError(
      502,
      `The photo URL did not return a valid image${label} (HTTP ${status}, ${contentType || "no content-type"}). PUBLIC_API_URL probably points to the wrong host.`,
      "PHOTO_URL_INVALID"
    );
  }
}

// Sonde TOUTES les images du carrousel (pas seulement la première), par
// lots pour ne pas saturer le serveur. Désactivable avec
// TIKTOK_SKIP_PHOTO_PROBE=1.
async function probePublicPhotos(imageUrls) {
  if (env("TIKTOK_SKIP_PHOTO_PROBE") === "1") return;

  const BATCH = 6;

  for (let i = 0; i < imageUrls.length; i += BATCH) {
    await Promise.all(
      imageUrls
        .slice(i, i + BATCH)
        .map((imageUrl, offset) =>
          probePublicPhoto(imageUrl, i + offset + 1, imageUrls.length)
        )
    );
  }
}

// Post_info d'un post photo.
//   - mode "draft" : pas de privacy (TikTok l'ignore en MEDIA_UPLOAD)
//   - mode "direct" : privacy résolue via resolvePrivacy()
//     (SELF_ONLY forcé en sandbox)
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

// Mode de publication photo :
//   - sandbox / FORCE_DRAFT → TOUJOURS "draft" (MEDIA_UPLOAD)
//   - sinon : "draft" ou "direct" selon la demande
function resolvePhotoMode(requested) {
  if (TIKTOK_SANDBOX || TIKTOK_FORCE_DRAFT) return "draft";
  return requested === "draft" ? "draft" : "direct";
}

function initTikTokPhotoPublish(accessToken, mode, postInfo, imageUrls, coverIndex) {
  const payload = {
    post_info: postInfo,
    source_info: {
      source: "PULL_FROM_URL",
      photo_cover_index: coverIndex, // 0 = première photo
      photo_images: imageUrls,
    },
    post_mode: mode === "draft" ? "MEDIA_UPLOAD" : "DIRECT_POST",
    media_type: "PHOTO",
  };

  console.log(
    "[tiktok:photos] init",
    JSON.stringify({
      post_mode: payload.post_mode,
      cover: coverIndex,
      count: imageUrls.length,
      first_url: imageUrls[0],
    })
  );

  return tiktokApi("/v2/post/publish/content/init/", {
    token: accessToken,
    json: payload,
  });
}

// ============================================================
// PINTEREST — APPEL API
// ============================================================

async function pinterestApi(
  pathname,
  { method = "GET", base = PINTEREST_API_BASE, token, basic = false, form, json } = {}
) {
  const headers = { Accept: "application/json" };
  let body;

  if (basic) {
    const credentials = Buffer.from(
      `${PINTEREST_APP_ID}:${PINTEREST_APP_SECRET}`
    ).toString("base64");

    headers.Authorization = `Basic ${credentials}`;
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
    // On ne renvoie JAMAIS le 401 de Pinterest tel quel : le frontend
    // le confondrait avec l'expiration de la session Stone.
    const error = new HttpError(
      upstreamStatus(response.status),
      data.message ||
        data.error_description ||
        (typeof data.error === "string" ? data.error : "") ||
        `Pinterest error (HTTP ${response.status})`,
      data.code !== undefined ? String(data.code) : undefined
    );

    // Statut réel du provider (le refresh s'en sert pour distinguer un
    // jeton révoqué / expiré d'une panne temporaire).
    error.upstreamStatus = response.status;
    throw error;
  }

  return data;
}

// ============================================================
// PINTEREST — STOCKAGE / REFRESH DES TOKENS
// ============================================================
//
// Chaque compte mémorise l'environnement dans lequel ses jetons ont été
// émis (colonne api_env). Un jeton sandbox n'est jamais envoyé à
// l'API de production, ni l'inverse : la reconnexion est demandée.

// replaceRefresh = true (connexion initiale) : les champs absents sont
// remis à zéro. false (refresh) : un refresh_token / une expiration non
// renvoyés par Pinterest ne sont PAS écrasés.
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

// Connexion initiale : crée ou remplace la ligne, et fixe l'environnement.
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

// Renvoyé par Pinterest quand le refresh token est révoqué / expiré.
const isPinterestInvalidGrant = (error) =>
  error instanceof HttpError &&
  (error.upstreamStatus === 400 ||
    error.upstreamStatus === 401 ||
    error.code === "invalid_grant");

async function getValidPinterestToken(userId) {
  const load = async () => {
    const account = await getPinterestAccount(userId);

    if (!account) {
      throw new HttpError(
        400,
        "Pinterest account not connected",
        "PINTEREST_NOT_CONNECTED"
      );
    }

    // Jetons émis pour un autre environnement (ou ligne d'avant la
    // migration api_env) : jamais utilisés.
    if (!pinterestAccountMatchesEnv(account)) {
      throw reconnectError("Pinterest", "PINTEREST_ENV_MISMATCH");
    }

    return account;
  };

  const first = await load();
  if (isTokenFresh(first)) return first.access_token;

  return withLock(`pinterest-refresh:${userId}`, async () => {
    for (let attempt = 0; attempt < 2; attempt++) {
      // Relecture APRÈS verrou : un autre traitement a pu renouveler.
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
        if (isPinterestInvalidGrant(error)) {
          throw reconnectError("Pinterest", "PINTEREST_REFRESH_EXPIRED");
        }
        throw error;
      }

      if (!refreshed?.access_token) {
        throw new HttpError(
          502,
          "Pinterest returned an invalid token response",
          "PINTEREST_BAD_TOKEN_RESPONSE"
        );
      }

      // Pinterest ne renvoie pas toujours un nouveau refresh_token : dans
      // ce cas l'ancien est conservé (buildPinterestTokenRow ne l'écrase pas).
      const applied = await updateTokensIfUnchanged(
        "pinterest_accounts",
        userId,
        account,
        buildPinterestTokenRow(refreshed)
      );

      if (applied) return refreshed.access_token;
    }

    throw new HttpError(
      409,
      "Pinterest account changed during token refresh, please retry",
      "PINTEREST_REFRESH_CONFLICT"
    );
  });
}

// ============================================================
// YOUTUBE — APPEL API GOOGLE
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
      data.error_description ||
        data.error?.message ||
        oauthError ||
        `Google error (HTTP ${response.status})`,
      oauthError
    );
  }

  return data;
}

async function fetchYouTubeChannel(accessToken) {
  const data = await googleRequest(
    `${YOUTUBE_API_BASE}/channels?part=snippet&mine=true`,
    { token: accessToken }
  );

  const channel = data.items?.[0];
  if (!channel) return null;

  const thumbnails = channel.snippet?.thumbnails || {};

  return {
    id: channel.id,
    title: channel.snippet?.title || null,
    customUrl: channel.snippet?.customUrl || null,
    avatarUrl:
      thumbnails.high?.url ||
      thumbnails.medium?.url ||
      thumbnails.default?.url ||
      null,
  };
}

// ============================================================
// YOUTUBE — STOCKAGE / REFRESH DES TOKENS
// ============================================================
//
// Particularité Google : le refresh token est durable et n'est PAS renvoyé
// lors d'un refresh → on ne l'écrase jamais s'il est absent de la réponse.
// invalid_grant = autorisation révoquée / expirée → reconnexion.

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

// Connexion initiale : crée ou remplace la ligne.
async function saveYouTubeTokens(userId, t, extra = {}) {
  const { error } = await supabaseAdmin
    .from("youtube_accounts")
    .upsert(
      { user_id: userId, ...buildYouTubeTokenRow(t), ...extra },
      { onConflict: "user_id" }
    );

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

    if (!account) {
      throw new HttpError(
        400,
        "YouTube account not connected",
        "YOUTUBE_NOT_CONNECTED"
      );
    }

    return account;
  };

  const first = await load();
  if (isTokenFresh(first)) return first.access_token;

  return withLock(`youtube-refresh:${userId}`, async () => {
    for (let attempt = 0; attempt < 2; attempt++) {
      // Relecture APRÈS verrou : un autre traitement a pu renouveler.
      const account = await load();

      if (isTokenFresh(account)) return account.access_token;

      if (youtubeRefreshExpired(account)) {
        throw reconnectError("YouTube", "YOUTUBE_REFRESH_EXPIRED");
      }

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
        throw new HttpError(
          502,
          "Google returned an invalid token response",
          "YOUTUBE_BAD_TOKEN_RESPONSE"
        );
      }

      const applied = await updateTokensIfUnchanged(
        "youtube_accounts",
        userId,
        account,
        buildYouTubeTokenRow(refreshed)
      );

      if (applied) return refreshed.access_token;
    }

    throw new HttpError(
      409,
      "YouTube account changed during token refresh, please retry",
      "YOUTUBE_REFRESH_CONFLICT"
    );
  });
}

// ============================================================
// YOUTUBE — PUBLICATION (upload resumable)
// ============================================================

const YOUTUBE_FRIENDLY_ERRORS = {
  quotaExceeded:
    "YouTube daily quota reached for this app. Please try again tomorrow.",
  dailyLimitExceeded:
    "YouTube daily quota reached for this app. Please try again tomorrow.",
  uploadLimitExceeded:
    "This YouTube channel has reached its daily upload limit. Please try again later.",
  youtubeSignupRequired:
    "This Google account has no YouTube channel. Create one on youtube.com, then reconnect.",
  forbidden: "YouTube refused this upload for this channel.",
  invalidTitle: "Invalid YouTube title.",
  invalidDescription: "Invalid YouTube description.",
  invalidTags: "Invalid YouTube tags.",
  invalidPublishAt: "Invalid scheduled date. Pick a date in the future.",
  invalidVideoMetadata: "YouTube rejected the video metadata.",
  mediaBodyRequired: "The video file is empty.",
  videoTooLong:
    "This video is too long for your YouTube account. Verify your channel to upload longer videos.",
};

// Transforme une réponse d'erreur Google en HttpError lisible.
// Ne renvoie JAMAIS un 401 brut (le front le confondrait avec la session Stone).
function youtubeApiError(status, data) {
  const reason =
    data?.error?.errors?.[0]?.reason ||
    (typeof data?.error === "string" ? data.error : undefined) ||
    data?.error?.status;

  console.error(
    "[youtube]",
    JSON.stringify({ status, reason, message: data?.error?.message })
  );

  if (status === 401 || reason === "authError" || reason === "invalid_grant") {
    return reconnectError("YouTube", "YOUTUBE_REFRESH_EXPIRED");
  }

  if (reason === "insufficientPermissions") {
    return new HttpError(
      409,
      "YouTube permission missing, please reconnect your YouTube account.",
      "YOUTUBE_SCOPE_MISSING"
    );
  }

  if (reason === "quotaExceeded" || reason === "dailyLimitExceeded") {
    return new HttpError(429, YOUTUBE_FRIENDLY_ERRORS[reason], reason);
  }

  return new HttpError(
    upstreamStatus(status),
    YOUTUBE_FRIENDLY_ERRORS[reason] ||
      data?.error?.message ||
      `YouTube error (HTTP ${status})`,
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

  // Limite YouTube : 500 caractères au total (guillemets autour des tags
  // contenant un espace + séparateur compris).
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

// Valide les champs AVANT tout appel à YouTube.
function buildYouTubeMetadata(fields) {
  const title = String(fields.title || "").replace(/[<>]/g, "").trim();

  if (!title) {
    throw new HttpError(
      400,
      "A title is required for YouTube videos.",
      "YOUTUBE_TITLE_REQUIRED"
    );
  }

  if (title.length > YOUTUBE_TITLE_MAX) {
    throw new HttpError(
      400,
      `The YouTube title must be at most ${YOUTUBE_TITLE_MAX} characters.`,
      "YOUTUBE_TITLE_TOO_LONG"
    );
  }

  const description = String(fields.description || "").replace(/[<>]/g, "").trim();

  if (Buffer.byteLength(description, "utf8") > YOUTUBE_DESCRIPTION_MAX_BYTES) {
    throw new HttpError(
      400,
      "The YouTube description is too long (max 5,000 characters).",
      "YOUTUBE_DESCRIPTION_TOO_LONG"
    );
  }

  // Déclaration « conçue pour les enfants » : choix explicite obligatoire.
  if (fields.made_for_kids !== "true" && fields.made_for_kids !== "false") {
    throw new HttpError(
      400,
      "Tell YouTube if this video is made for kids.",
      "YOUTUBE_MADE_FOR_KIDS_REQUIRED"
    );
  }

  let privacy = YOUTUBE_PRIVACY_LEVELS.has(fields.privacy_level)
    ? fields.privacy_level
    : "private";

  // Programmation : YouTube exige privacyStatus = private + publishAt futur ;
  // la vidéo devient publique à l'heure choisie.
  let publishAt = null;

  if (fields.publish_at) {
    const date = new Date(fields.publish_at);

    if (Number.isNaN(date.getTime()) || date.getTime() < Date.now() + 60_000) {
      throw new HttpError(
        400,
        "Pick a date and time in the future.",
        "YOUTUBE_PUBLISH_AT_INVALID"
      );
    }

    publishAt = date.toISOString();
    privacy = "private";
  }

  const tags = parseYouTubeTags(fields.tags);
  const categoryId = /^\d{1,3}$/.test(String(fields.category_id || ""))
    ? String(fields.category_id)
    : "22"; // People & Blogs

  return {
    privacy,
    publishAt,
    metadata: {
      snippet: {
        title,
        description,
        categoryId,
        ...(tags.length > 0 ? { tags } : {}),
      },
      status: {
        privacyStatus: privacy,
        selfDeclaredMadeForKids: fields.made_for_kids === "true",
        embeddable: true,
        ...(publishAt ? { publishAt } : {}),
      },
    },
  };
}

// 1. Ouvre une session d'upload resumable : Google répond avec l'URL
//    d'upload dans l'en-tête Location.
async function initYouTubeUpload(accessToken, metadata, size, mimeType) {
  let result;

  try {
    result = await fetchJson(
      `${YOUTUBE_UPLOAD_URL}?uploadType=resumable&part=snippet,status`,
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
    throw new HttpError(
      502,
      "YouTube did not return a valid upload URL",
      "YOUTUBE_NO_UPLOAD_URL"
    );
  }

  return location;
}

// Un PUT sur l'URL resumable.
//   200 / 201 → terminé (corps = ressource vidéo)
//   308       → incomplet (en-tête Range = octets reçus)
async function youtubePut(uploadUrl, headers, body) {
  const { response, data } = await fetchJson(
    uploadUrl,
    { method: "PUT", headers, body, redirect: "manual" },
    120_000
  );

  if (response.status === 200 || response.status === 201) {
    return { done: true, video: data };
  }

  if (response.status === 308) {
    const match = /bytes=0-(\d+)/.exec(response.headers.get("range") || "");
    return { done: false, next: match ? Number(match[1]) + 1 : 0 };
  }

  const error = new Error(`HTTP ${response.status}`);
  error.status = response.status;
  error.data = data;
  throw error;
}

// 2. Envoie le fichier par chunks, avec reprise après erreur réseau / 5xx
//    (on interroge YouTube pour savoir combien d'octets il a reçus).
async function uploadVideoToYouTube(uploadUrl, buffer, mimeType) {
  const total = buffer.length;
  let offset = 0;
  let failures = 0;

  while (true) {
    try {
      const end = Math.min(offset + YOUTUBE_CHUNK_SIZE, total) - 1;

      const result = await youtubePut(
        uploadUrl,
        {
          "Content-Type": mimeType,
          "Content-Range": `bytes ${offset}-${end}/${total}`,
        },
        buffer.subarray(offset, end + 1)
      );

      if (result.done) return result.video;

      if (result.next <= offset) {
        // Aucun progrès : on compte comme un échec pour éviter une boucle infinie.
        throw Object.assign(new Error("No progress"), { status: 500 });
      }

      offset = result.next;
    } catch (error) {
      const status = error?.status;

      // Erreur client définitive (hors 429) : inutile de réessayer.
      if (status && status < 500 && status !== 429) {
        throw youtubeApiError(status, error.data);
      }

      failures++;

      if (failures > 5) {
        console.error("YouTube upload failed:", error?.message);
        throw new HttpError(
          502,
          "YouTube upload failed, please retry",
          "YOUTUBE_UPLOAD_FAILED"
        );
      }

      await delay(failures * 1000);

      // Reprise : combien d'octets YouTube a-t-il réellement reçus ?
      try {
        const query = await youtubePut(
          uploadUrl,
          { "Content-Range": `bytes */${total}` },
          undefined
        );

        if (query.done) return query.video;
        offset = query.next;
      } catch {
        // on retentera au prochain tour
      }
    }
  }
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
    tiktok: tiktokEnabled
      ? { enabled: true, ...tiktokCapabilities() }
      : { enabled: false },
    pinterest: pinterestUsable,
    youtube: youtubeEnabled,
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

  if (!email || !password) {
    throw new HttpError(400, "Email and password are required");
  }

  if (email.length > 254 || !EMAIL_REGEX.test(email)) {
    throw new HttpError(400, "Invalid email address");
  }

  if (password.length < 8) {
    throw new HttpError(400, "Password must contain at least 8 characters");
  }

  if (password.length > 128) {
    throw new HttpError(400, "Password must contain at most 128 characters");
  }

  enforce(limiterAccount, `signup:${email}`);

  const { data, error } = await supabase.auth.signUp({
    email,
    password,
    options: {
      data: {
        first_name: firstName.slice(0, 100),
        last_name: lastName.slice(0, 100),
      },
    },
  });

  if (error) {
    throw new HttpError(error.status === 429 ? 429 : 400, error.message);
  }

  sendJson(res, 201, {
    success: true,
    user: data.user ? formatUser(data.user) : null,
    session: sessionPayload(data.session),
    message: data.session
      ? "Account created successfully"
      : "Account created. Check your email to confirm your account.",
  });
});

route("POST", "/api/auth/login", async ({ req, res }) => {
  const body = await getJsonBody(req);

  const email = normalizeEmail(body.email);
  const password = String(body.password || "");

  if (!email || !password) {
    throw new HttpError(400, "Email and password are required");
  }

  // Limite par compte en plus de la limite par IP (anti brute-force distribué).
  enforce(limiterAccount, `login:${email}`);

  const { data, error } = await supabase.auth.signInWithPassword({
    email,
    password,
  });

  if (error) {
    if (error.status === 429) {
      throw new HttpError(429, "Too many requests. Please try again later.");
    }

    const notConfirmed =
      error.code === "email_not_confirmed" ||
      error.message.toLowerCase().includes("not confirmed");

    throw new HttpError(
      401,
      notConfirmed ? error.message : "Invalid login credentials",
      notConfirmed ? "EMAIL_NOT_CONFIRMED" : "INVALID_CREDENTIALS"
    );
  }

  sendJson(res, 200, {
    success: true,
    user: data.user ? formatUser(data.user) : null,
    session: sessionPayload(data.session),
  });
});

// Cette route est un oracle de credentials : même limites que le login.
route("POST", "/api/auth/check-verification", async ({ req, res }) => {
  const body = await getJsonBody(req);

  const email = normalizeEmail(body.email);
  const password = String(body.password || "");

  if (!email || !password) {
    throw new HttpError(400, "Email and password are required");
  }

  enforce(limiterAccount, `login:${email}`);

  const { data, error } = await supabase.auth.signInWithPassword({
    email,
    password,
  });

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

  sendJson(res, 200, {
    success: true,
    verified: Boolean(data.user?.email_confirmed_at),
    session: sessionPayload(data.session),
  });
});

// Google / GitHub : URL d'autorisation.
// redirectTo est validé avec sanitizeRedirectTo() (origine autorisée).
function registerOAuthLoginRoute(provider, extraOptions) {
  route("POST", `/api/auth/${provider}/url`, async ({ req, res }) => {
    const body = await getJsonBody(req).catch(() => ({}));
    const redirectTo = sanitizeRedirectTo(body.redirectTo);

    const { data, error } = await supabaseOAuth.auth.signInWithOAuth({
      provider,
      options: {
        redirectTo,
        skipBrowserRedirect: true,
        ...extraOptions,
      },
    });

    if (error || !data?.url) {
      throw error || new Error(`${provider}/url: no URL returned`);
    }

    sendJson(res, 200, { success: true, url: data.url });
  });
}

registerOAuthLoginRoute("google", {
  queryParams: { access_type: "offline", prompt: "select_account" },
});

registerOAuthLoginRoute("github", { scopes: "read:user user:email" });

// Révoque réellement la session côté Supabase (et vide le cache).
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

route("POST", "/api/auth/refresh", async ({ req, res }) => {
  const body = await getJsonBody(req);

  const refreshToken = String(body.refreshToken ?? body.refresh_token ?? "");

  if (!refreshToken || refreshToken.length > 4096) {
    throw new HttpError(400, "Missing refresh token");
  }

  const { data, error } = await supabase.auth.refreshSession({
    refresh_token: refreshToken,
  });

  if (error || !data.session) {
    throw new HttpError(
      401,
      "Invalid or expired refresh token",
      "INVALID_REFRESH_TOKEN"
    );
  }

  sendJson(res, 200, {
    success: true,
    session: sessionPayload(data.session),
  });
});

route(
  "POST",
  "/api/auth/resend-verification",
  async ({ res, user }) => {
    if (user.email_confirmed_at) {
      throw new HttpError(400, "This email is already verified");
    }

    if (!user.email) {
      throw new HttpError(400, "No email associated with this account");
    }

    enforce(limiterAccount, `resend:${user.id}`);

    const { error } = await supabase.auth.resend({
      type: "signup",
      email: user.email,
    });

    if (error) throw error;

    sendJson(res, 200, { success: true, message: "Verification email sent" });
  },
  { auth: true }
);

// ============================================================
// ROUTES — UTILISATEUR
// ============================================================

route(
  "GET",
  "/api/user",
  ({ res, user }) => {
    sendJson(res, 200, { success: true, user: formatUser(user) });
  },
  { auth: true }
);

route(
  "GET",
  "/api/user/profile",
  ({ res, user }) => {
    sendJson(res, 200, { success: true, user: formatUser(user) });
  },
  { auth: true }
);

route(
  ["PUT", "PATCH"],
  "/api/user/profile",
  async ({ req, res, user }) => {
    const body = await getJsonBody(req);

    const metadata = { ...(user.user_metadata || {}) };

    // Limitation des longueurs : user_metadata est borné côté Supabase.
    const limitedString = (value, max) => String(value ?? "").slice(0, max);

    if (body.firstName !== undefined || body.first_name !== undefined) {
      metadata.first_name = limitedString(
        body.firstName ?? body.first_name ?? "",
        100
      );
    }

    if (body.lastName !== undefined || body.last_name !== undefined) {
      metadata.last_name = limitedString(
        body.lastName ?? body.last_name ?? "",
        100
      );
    }

    if (body.bio !== undefined) {
      metadata.bio = limitedString(body.bio, 500);
    }

    if (body.avatarUrl !== undefined || body.avatar_url !== undefined) {
      const avatarUrl = limitedString(
        body.avatarUrl ?? body.avatar_url ?? "",
        1000
      );

      // Uniquement une image de NOTRE bucket, dans le dossier de
      // l'utilisateur (ou vide pour retirer l'avatar). Empêche les
      // URLs arbitraires (pixels de tracking, javascript:, etc.).
      const ownPrefix = `${SUPABASE_BASE_URL}/storage/v1/object/public/${AVATAR_BUCKET}/${user.id}/`;

      if (avatarUrl && !avatarUrl.startsWith(ownPrefix)) {
        throw new HttpError(400, "Invalid avatar URL");
      }

      metadata.custom_avatar_url = avatarUrl;
    }

    const { data, error } = await adminUpdateUser(user.id, {
      user_metadata: metadata,
    });

    if (error) throw error;

    sendJson(res, 200, { success: true, user: formatUser(data.user) });
  },
  { auth: true }
);

// NOTE : signInWithPassword pour vérifier le mot de passe courant
// crée une session Supabase supplémentaire (impact limité).
route(
  ["PUT", "POST"],
  "/api/user/password",
  async ({ req, res, user }) => {
    const body = await getJsonBody(req);

    const currentPassword = String(
      body.currentPassword ?? body.current_password ?? ""
    );
    const newPassword = String(body.newPassword ?? body.new_password ?? "");

    if (!currentPassword || !newPassword) {
      throw new HttpError(400, "Current and new password are required");
    }

    if (newPassword.length < 8) {
      throw new HttpError(
        400,
        "New password must contain at least 8 characters"
      );
    }

    if (newPassword.length > 128) {
      throw new HttpError(
        400,
        "New password must contain at most 128 characters"
      );
    }

    if (!user.email) {
      throw new HttpError(400, "No email associated with this account");
    }

    // Un token volé ne doit pas permettre de deviner le mot de passe actuel.
    enforce(limiterAccount, `password:${user.id}`);

    const { error: verifyError } = await supabase.auth.signInWithPassword({
      email: user.email,
      password: currentPassword,
    });

    if (verifyError) {
      throw new HttpError(401, "Current password is incorrect");
    }

    const { error } = await adminUpdateUser(user.id, { password: newPassword });

    if (error) throw error;

    sendJson(res, 200, {
      success: true,
      message: "Password updated successfully",
    });
  },
  { auth: true }
);

// Le type est validé par MAGIC BYTES (pas par le Content-Type client).
// Whitelist : PNG / JPEG / WebP / GIF.
route(
  "POST",
  "/api/user/avatar",
  async ({ req, res, user }) => {
    enforce(limiterAccount, `avatar:${user.id}`);

    let upload;

    try {
      upload = await parseMultipart(req, {
        fileField: "avatar",
        maxSize: MAX_AVATAR_SIZE,
      });
    } catch (error) {
      if (error?.code === "FILE_TOO_LARGE") {
        throw new HttpError(400, "Avatar is too large. Maximum size is 2 MB.");
      }
      if (error?.code === "NO_FILE") {
        throw new HttpError(400, "No 'avatar' file was provided.");
      }
      throw new HttpError(400, "Could not read the uploaded file.");
    }

    const sniffedType = sniffImageType(upload.buffer);

    if (!sniffedType || !ALLOWED_AVATAR_TYPES.includes(sniffedType)) {
      throw new HttpError(
        400,
        "Unsupported image format. Use PNG, JPEG, WebP or GIF."
      );
    }

    // Extension dérivée du type RÉEL, pas du nom de fichier client.
    const storagePath = `${user.id}/${crypto.randomUUID()}.${AVATAR_EXTENSIONS[sniffedType]}`;

    const { error: storageError } = await supabaseAdmin.storage
      .from(AVATAR_BUCKET)
      .upload(storagePath, upload.buffer, {
        contentType: sniffedType,
        cacheControl: "31536000",
        upsert: false,
      });

    if (storageError) throw storageError;

    const { data: publicUrlData } = supabaseAdmin.storage
      .from(AVATAR_BUCKET)
      .getPublicUrl(storagePath);

    sendJson(res, 200, { success: true, avatar_url: publicUrlData.publicUrl });
  },
  { auth: true }
);

route(
  "DELETE",
  "/api/user/avatar",
  async ({ req, res, user }) => {
    const body = await getJsonBody(req);

    const filePathOrUrl = String(body.filePathOrUrl || "").trim();

    if (!filePathOrUrl) {
      throw new HttpError(400, "Missing filePathOrUrl");
    }

    const storagePath = extractAvatarStoragePath(filePathOrUrl);

    if (!storagePath) {
      sendJson(res, 200, { success: true });
      return;
    }

    if (!isOwnedAvatarPath(storagePath, user.id)) {
      throw new HttpError(403, "You can only delete your own avatar");
    }

    const { error } = await supabaseAdmin.storage
      .from(AVATAR_BUCKET)
      .remove([storagePath]);

    if (error) throw error;

    sendJson(res, 200, { success: true });
  },
  { auth: true }
);

// ============================================================
// ROUTES — STRIPE
// ============================================================

route(
  "POST",
  "/api/stripe/checkout",
  async ({ req, res, user }) => {
    requireStripe();

    const body = await getJsonBody(req);
    const plan = String(body.plan || "").toLowerCase();
    const period = body.period === "annual" ? "annual" : "monthly";

    const priceId = Object.hasOwn(STRIPE_PRICES, plan)
      ? STRIPE_PRICES[plan][period]
      : undefined;

    if (!priceId) {
      throw new HttpError(
        400,
        `Unknown plan or period (plan="${plan.slice(0, 30)}", period="${period}")`
      );
    }

    const customerId = await getStripeCustomerId(user, { create: true });

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      customer: customerId,
      line_items: [{ price: priceId, quantity: 1 }],
      allow_promotion_codes: true,
      client_reference_id: user.id,
      success_url: `${APP_URL}/account?checkout=success&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${APP_URL}/pricing?checkout=cancel`,
      subscription_data: {
        metadata: { supabase_user_id: user.id, plan, period },
      },
    });

    sendJson(res, 200, { success: true, id: session.id, url: session.url });
  },
  { auth: true }
);

route(
  "POST",
  "/api/stripe/portal",
  async ({ res, user }) => {
    requireStripe();

    const customerId = await getStripeCustomerId(user);

    if (!customerId) {
      throw new HttpError(
        400,
        "No Stripe customer associated with this account"
      );
    }

    const session = await stripe.billingPortal.sessions.create({
      customer: customerId,
      return_url: `${APP_URL}/account`,
    });

    sendJson(res, 200, { success: true, url: session.url });
  },
  { auth: true }
);

// Interroge Stripe en direct puis resynchronise le compte si besoin :
// l'abonnement apparaît immédiatement après le checkout, même si le
// webhook est en retard. Un échec de resynchronisation est journalisé
// (la réponse reste celle de Stripe, source de vérité).
route(
  "GET",
  "/api/stripe/subscription",
  async ({ res, user }) => {
    requireStripe();

    const customerId = await getStripeCustomerId(user);

    if (!customerId) {
      sendJson(res, 200, { success: true, subscription: null });
      return;
    }

    const list = await stripe.subscriptions.list({
      customer: customerId,
      status: "all",
      limit: 1,
    });

    const sub = list.data[0];

    if (sub) {
      const stored = user.app_metadata?.subscription;
      const fresh = subscriptionSnapshot(sub);

      const changed =
        !stored ||
        stored.id !== fresh.id ||
        stored.status !== fresh.status ||
        stored.price_id !== fresh.price_id ||
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

    sendJson(res, 200, {
      success: true,
      subscription: sub
        ? {
            id: sub.id,
            status: sub.status,
            price_id: sub.items.data[0]?.price?.id || null,
            current_period_end: sub.current_period_end,
            cancel_at_period_end: sub.cancel_at_period_end,
          }
        : null,
    });
  },
  { auth: true }
);

// Idempotence : un événement déjà traité (même id) n'est pas rejoué ; deux
// livraisons simultanées du même événement sont fusionnées. L'état est
// ensuite toujours relu depuis Stripe et les événements plus anciens que
// le dernier appliqué sont ignorés (voir processStripeEvent).
const processedStripeEvents = createSeenCache(10_000, 24 * 60 * 60 * 1000);

route("POST", "/api/stripe/webhook", async ({ req, res, requestId }) => {
  if (!stripe || !STRIPE_WEBHOOK_SECRET) {
    throw new HttpError(500, "Stripe webhook not configured");
  }

  const signature = req.headers["stripe-signature"];

  if (!signature) {
    throw new HttpError(400, "Missing stripe-signature");
  }

  // Corps BRUT (octets exacts reçus) : indispensable à la signature.
  // Une erreur de lecture (413, requête interrompue) garde son vrai statut.
  const rawBody = await getRawBody(req);

  let event;

  try {
    event = stripe.webhooks.constructEvent(
      rawBody,
      signature,
      STRIPE_WEBHOOK_SECRET
    );
  } catch (webhookError) {
    console.warn(
      `[${requestId}] Webhook signature verification failed:`,
      webhookError.message
    );
    throw new HttpError(400, "Webhook signature verification failed");
  }

  if (processedStripeEvents.has(event.id)) {
    sendJson(res, 200, { received: true, duplicate: true });
    return;
  }

  // En cas d'erreur, l'exception remonte → 500 → Stripe retentera
  // l'événement (il n'est marqué « traité » qu'après succès).
  await withLock(`stripe-event:${event.id}`, () => processStripeEvent(event));

  processedStripeEvents.add(event.id);

  sendJson(res, 200, { received: true });
});

// ============================================================
// ROUTES — TIKTOK
// ============================================================

route(
  "POST",
  "/api/tiktok/auth/url",
  ({ res, user }) => {
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
      // Le frontend peut afficher l'avertissement sandbox AVANT la popup.
      capabilities: tiktokCapabilities(),
    });
  },
  { auth: true }
);

route(
  "POST",
  "/api/tiktok/auth/callback",
  async ({ req, res, user }) => {
    const body = await getJsonBody(req);
    const authCode = assertValidOAuthCallback("tiktok", body, user.id);

    const account = await dedupeCallback(
      `tiktok:${user.id}:${sha256(authCode)}`,
      async () => {
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
          // En sandbox, seuls les « Sandbox testers » déclarés dans le
          // portail peuvent autoriser l'app : on remonte un message
          // actionnable plutôt qu'un access_denied brut.
          if (
            error instanceof HttpError &&
            (error.code === "access_denied" ||
              /access_denied/i.test(error.message))
          ) {
            throw new HttpError(
              403,
              TIKTOK_SANDBOX
                ? "TikTok refused the connection. In sandbox mode, add the TikTok account as a Sandbox tester in the TikTok developer portal, then try again."
                : "TikTok refused the connection.",
              "TIKTOK_ACCESS_DENIED"
            );
          }
          throw error;
        }

        let profile = {};

        try {
          const info = await tiktokApi(
            "/v2/user/info/?fields=open_id,avatar_url,display_name",
            { method: "GET", token: tokens.access_token }
          );

          profile = info.data?.user || {};
        } catch (profileError) {
          console.warn("TikTok user info error:", profileError.message);
        }

        await saveTikTokTokens(user.id, tokens, {
          display_name: profile.display_name || null,
          avatar_url: profile.avatar_url || null,
        });

        return {
          display_name: profile.display_name || null,
          avatar_url: profile.avatar_url || null,
        };
      }
    );

    sendJson(res, 200, {
      success: true,
      account,
      capabilities: tiktokCapabilities(),
    });
  },
  { auth: true }
);

route(
  "GET",
  "/api/tiktok/status",
  async ({ res, url, user }) => {
    let account = await getTikTokAccount(user.id);

    // ?refresh=1 : le front a détecté une image cassée → on ignore le throttle.
    const force = url.searchParams.get("refresh") === "1";

    if (account) {
      account = await refreshTikTokProfile(user.id, account, { force });
    }

    sendJson(res, 200, {
      success: true,
      connected: Boolean(account),
      account: account
        ? {
            display_name: account.display_name,
            avatar_url: account.avatar_url,
            scope: account.scope,
          }
        : null,
      // Le frontend affiche le bandeau sandbox à partir de là.
      capabilities: tiktokCapabilities(),
    });
  },
  { auth: true }
);

route(
  "DELETE",
  "/api/tiktok/disconnect",
  async ({ res, user }) => {
    const account = await getTikTokAccount(user.id);

    if (account) {
      if (account.access_token) {
        try {
          await tiktokApi("/v2/oauth/revoke/", {
            form: {
              client_key: TIKTOK_CLIENT_KEY,
              client_secret: TIKTOK_CLIENT_SECRET,
              token: account.access_token,
            },
          });
        } catch (revokeError) {
          console.warn("TikTok revoke error:", revokeError.message);
        }
      }

      const { error } = await supabaseAdmin
        .from("tiktok_accounts")
        .delete()
        .eq("user_id", user.id);

      if (error) throw error;
    }

    sendJson(res, 200, { success: true });
  },
  { auth: true }
);

// creator_info/query est un POST : un body JSON (même vide) est requis.
route(
  "GET",
  "/api/tiktok/creator-info",
  async ({ res, user }) => {
    const accessToken = await getValidTikTokToken(user.id);

    const result = await tiktokApi("/v2/post/publish/creator_info/query/", {
      token: accessToken,
      json: {},
    });

    sendJson(res, 200, {
      success: true,
      creator: result.data,
      capabilities: tiktokCapabilities(),
    });
  },
  { auth: true }
);

// Upload de fichier. Ordre important pour la mémoire :
//   1. vérifications bon marché (token TikTok, taille annoncée)
//   2. acquisition d'un slot de concurrence
//   3. SEULEMENT ENSUITE lecture du corps (jusqu'à 100 Mo en RAM)
route(
  "POST",
  "/api/tiktok/publish",
  async ({ req, res, user }) => {
    enforce(limiterPublish, `tiktok:${user.id}`);

    const declared = Number(req.headers["content-length"] || 0);

    if (declared > MAX_VIDEO_SIZE + 1024 * 1024) {
      throw tooLargeError(
        `Video is too large. Maximum size is ${MAX_VIDEO_SIZE / 1024 / 1024} MB.`
      );
    }

    // Échoue vite si le compte n'est pas connecté / expiré.
    const accessToken = await getValidTikTokToken(user.id);

    await acquireVideoSlot();

    try {
      let upload;

      try {
        upload = await parseMultipart(req, {
          fileField: "video",
          maxSize: MAX_VIDEO_SIZE,
        });
      } catch (error) {
        if (error?.code === "FILE_TOO_LARGE") {
          throw new HttpError(
            400,
            `Video is too large. Maximum size is ${MAX_VIDEO_SIZE / 1024 / 1024} MB.`
          );
        }
        if (error?.code === "NO_FILE") {
          throw new HttpError(400, "No 'video' file was provided.");
        }
        throw error instanceof HttpError
          ? error
          : new HttpError(400, "Could not read the uploaded file.");
      }

      const mimeType = sniffVideoType(upload.buffer);

      if (!mimeType) {
        throw new HttpError(400, "Unsupported format. Use MP4, MOV or WebM.");
      }

      // Sandbox : "direct" reste possible (SELF_ONLY forcé par
      // resolvePrivacy) ; FORCE_DRAFT bascule tout en brouillon.
      const requestedMode = upload.fields.mode === "draft" ? "draft" : "direct";
      const mode = resolveVideoMode(requestedMode);
      const chunking = computeChunking(upload.buffer.length);

      const sourceInfo = {
        source: "FILE_UPLOAD",
        video_size: upload.buffer.length,
        chunk_size: chunking.chunkSize,
        total_chunk_count: chunking.totalChunks,
      };

      const init = await initTikTokPublish(
        accessToken,
        mode,
        upload.fields,
        sourceInfo
      );

      await uploadVideoToTikTok(
        init.data.upload_url,
        upload.buffer,
        mimeType,
        chunking
      );

      sendJson(res, 200, {
        success: true,
        mode,
        // mode_demandé ≠ mode_effectif quand FORCE_DRAFT est actif :
        // le frontend peut informer l'utilisateur.
        requested_mode: requestedMode,
        forced_privacy_level:
          mode === "direct" ? resolvePrivacy(upload.fields.privacy_level) : null,
        sandbox: TIKTOK_SANDBOX,
        publish_id: init.data.publish_id,
      });
    } finally {
      releaseVideoSlot();
    }
  },
  { auth: true }
);

route(
  "POST",
  "/api/tiktok/publish_url",
  async ({ req, res, user }) => {
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
      forced_privacy_level:
        mode === "direct" ? resolvePrivacy(body.privacy_level) : null,
      sandbox: TIKTOK_SANDBOX,
      publish_id: init.data.publish_id,
    });
  },
  { auth: true }
);

// Photo(s) : 1 image = post photo, 2 à 35 images = carrousel.
// EN SANDBOX : mode brouillon forcé (MEDIA_UPLOAD) — TikTok refuse
// les posts photos DIRECT_POST des apps non auditées.
route(
  "POST",
  "/api/tiktok/publish/photos",
  async ({ req, res, user }) => {
    if (!PUBLIC_API_URL) {
      throw new HttpError(
        500,
        "Photo publishing is not configured (PUBLIC_API_URL / VITE_API_BASE_URL missing)",
        "PUBLIC_API_URL_MISSING"
      );
    }

    if (!PUBLIC_API_URL.startsWith("https://")) {
      throw new HttpError(
        500,
        "PUBLIC_API_URL must use https for TikTok photo publishing",
        "PUBLIC_API_URL_NOT_HTTPS"
      );
    }

    if (publicApiLooksLikeFrontend()) {
      throw new HttpError(
        500,
        "PUBLIC_API_URL points to the frontend instead of the API server",
        "PUBLIC_API_URL_WRONG_HOST"
      );
    }

    enforce(limiterPublish, `tiktok:${user.id}`);

    const declared = Number(req.headers["content-length"] || 0);

    if (declared > MAX_PHOTOS_TOTAL + 1024 * 1024) {
      throw tooLargeError(
        `Photos are too large. Maximum total size is ${MAX_PHOTOS_TOTAL / 1024 / 1024} MB.`
      );
    }

    const accessToken = await getValidTikTokToken(user.id);

    // Même sémaphore que les vidéos : borne la mémoire utilisée.
    await acquireVideoSlot();

    let storedNames = [];

    try {
      let upload;

      try {
        upload = await parseMultipartFiles(req, {
          fileField: "photos",
          maxFiles: MAX_TIKTOK_PHOTOS,
          maxFileSize: MAX_PHOTO_SIZE,
        });
      } catch (error) {
        if (error?.code === "FILE_TOO_LARGE") {
          throw new HttpError(
            400,
            `Each photo must be under ${MAX_PHOTO_SIZE / 1024 / 1024} MB.`
          );
        }
        if (error?.code === "TOO_MANY_FILES") {
          throw new HttpError(
            400,
            `TikTok carousels are limited to ${MAX_TIKTOK_PHOTOS} photos.`
          );
        }
        if (error?.code === "NO_FILE") {
          throw new HttpError(400, "No photos were provided.");
        }
        throw error instanceof HttpError
          ? error
          : new HttpError(400, "Could not read the uploaded files.");
      }

      const photos = [];
      let totalSize = 0;

      for (const file of upload.files) {
        const type = sniffImageType(file.buffer);

        if (type !== "image/jpeg" && type !== "image/webp") {
          throw new HttpError(
            400,
            "Unsupported image format. TikTok accepts JPEG and WebP."
          );
        }

        totalSize += file.buffer.length;
        photos.push({ buffer: file.buffer, type });
      }

      if (totalSize > MAX_PHOTOS_TOTAL) {
        throw tooLargeError(
          `Photos are too large. Maximum total size is ${MAX_PHOTOS_TOTAL / 1024 / 1024} MB.`
        );
      }

      const fields = upload.fields;
      const requestedMode = fields.mode === "draft" ? "draft" : "direct";
      // SANDBOX : resolvePhotoMode() force "draft" tant que l'app
      // n'est pas auditée (les photos DIRECT_POST sont refusées).
      const mode = resolvePhotoMode(requestedMode);

      // Validé AVANT de stocker les photos (ex. contenu de marque en privé).
      const postInfo = buildPhotoPostInfo(mode, fields);

      // Le frontend envoie cover_index à partir de 1 (1 = première photo).
      // TikTok attend photo_cover_index à partir de 0 : on convertit et on
      // borne dans [0, nombre de photos - 1].
      const requestedCover = Number.parseInt(fields.cover_index, 10);
      const coverIndex = Math.min(
        Math.max((Number.isFinite(requestedCover) ? requestedCover : 1) - 1, 0),
        photos.length - 1
      );

      storedNames = await storeTikTokPhotos(photos);
      upload = null; // libère les buffers

      const imageUrls = storedNames.map(
        (name) => `${PUBLIC_API_URL}/api/media/tiktok/${name}`
      );

      // Vérifie que TikTok pourra réellement télécharger TOUTES les images.
      await probePublicPhotos(imageUrls);

      const init = await initTikTokPhotoPublish(
        accessToken,
        mode,
        postInfo,
        imageUrls,
        coverIndex
      );

      // Les fichiers restent disponibles : TikTok les télécharge de
      // façon asynchrone. Le balayage périodique les supprime ensuite.
      sendJson(res, 200, {
        success: true,
        mode,
        requested_mode: requestedMode,
        // Le frontend affiche : « Mode sandbox : tes photos partent en
        // brouillon sur TikTok. »
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
  },
  { auth: true }
);

route(
  "GET",
  "/api/tiktok/publish/status",
  async ({ res, url, user }) => {
    const publishId = url.searchParams.get("publish_id");

    // Les publish_id TikTok contiennent parfois « ~ » ; 64 caractères max.
    if (!isValidTikTokPublishId(publishId)) {
      throw new HttpError(400, "Missing or invalid publish_id");
    }

    const accessToken = await getValidTikTokToken(user.id);

    const result = await tiktokApi("/v2/post/publish/status/fetch/", {
      token: accessToken,
      json: { publish_id: publishId },
    });

    sendJson(res, 200, { success: true, ...result.data });
  },
  { auth: true }
);

// ============================================================
// ROUTES — TIKTOK WEBHOOK
// ============================================================
//
// POST /api/tiktok/webhook  → URL à déclarer dans le portail TikTok for Developers
// (≠ TIKTOK_REDIRECT_URI, qui est l'URL de retour OAuth du FRONTEND).
//
// - En-tête  : TikTok-Signature: t=<timestamp>,s=<signature>
// - Signature: HMAC-SHA256(client_secret, "<timestamp>.<corps brut>"), en hexadécimal
// - TikTok exige une réponse 200 ; sinon il réessaie jusqu'à 72 h (livraison
//   "au moins une fois" : le traitement doit être idempotent).

const MAX_TIKTOK_WEBHOOK_BODY = 64 * 1024;
const TIKTOK_WEBHOOK_DEDUPE_TTL_MS = 24 * 60 * 60 * 1000;
const TIKTOK_WEBHOOK_DEDUPE_MAX = 5_000;
// Marge (s) appliquée à la date de l'événement pour ne pas supprimer une
// connexion rétablie APRÈS la révocation.
const TIKTOK_REVOKE_SKEW_SEC = 5;

const processedTikTokWebhooks = createSeenCache(
  TIKTOK_WEBHOOK_DEDUPE_MAX,
  TIKTOK_WEBHOOK_DEDUPE_TTL_MS
);

// "t=1633174587,s=<64 hex>" -> { timestamp, signature } ou null.
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

function verifyTikTokWebhookSignature(
  rawBody,
  header,
  secret,
  toleranceSec = TIKTOK_WEBHOOK_TOLERANCE_SEC,
  nowMs = Date.now()
) {
  if (!secret) return { ok: false, reason: "secret_missing" };

  const parsed = parseTikTokSignatureHeader(header);
  if (!parsed) return { ok: false, reason: "malformed_header" };

  const expected = crypto
    .createHmac("sha256", secret)
    .update(parsed.timestamp + ".")
    .update(rawBody)
    .digest();

  const received = Buffer.from(parsed.signature, "hex");

  if (
    received.length !== expected.length ||
    !crypto.timingSafeEqual(received, expected)
  ) {
    return { ok: false, reason: "bad_signature" };
  }

  if (toleranceSec > 0) {
    const skewSec = Math.abs(nowMs / 1000 - Number(parsed.timestamp));

    if (skewSec > toleranceSec) {
      return { ok: false, reason: "timestamp_out_of_tolerance" };
    }
  }

  return { ok: true, timestamp: Number(parsed.timestamp) };
}

// Événement "authorization.removed" : l'utilisateur TikTok a retiré l'accès.
// Les tokens sont déjà révoqués côté TikTok : on supprime l'association.
// Sécurité / idempotence :
//  - le compte est identifié par open_id, jamais par autre chose
//  - on ne supprime que les lignes dont updated_at est antérieur à l'événement
//  - rejouer l'événement est sans effet (0 ligne supprimée)
async function handleTikTokAuthorizationRemoved(payload, requestId) {
  const openId = payload.user_openid;

  if (typeof openId !== "string" || !/^[A-Za-z0-9._:-]{1,256}$/.test(openId)) {
    throw new HttpError(400, "Invalid user_openid", "INVALID_PAYLOAD");
  }

  const createTime = payload.create_time;

  if (!Number.isSafeInteger(createTime) || createTime <= 0) {
    throw new HttpError(400, "Invalid create_time", "INVALID_PAYLOAD");
  }

  let reason = null;

  if (typeof payload.content === "string") {
    try {
      const content = JSON.parse(payload.content);
      if (content && Number.isInteger(content.reason)) reason = content.reason;
    } catch {
      // content illisible : la déconnexion est traitée quand même
    }
  }

  const cutoff = new Date((createTime + TIKTOK_REVOKE_SKEW_SEC) * 1000).toISOString();

  const { data, error } = await supabaseAdmin
    .from("tiktok_accounts")
    .delete()
    .eq("open_id", openId)
    .lte("updated_at", cutoff)
    .select("user_id");

  if (error) {
    throw new Error("tiktok_accounts cleanup failed: " + error.message);
  }

  console.log(
    "[" + requestId + "] [tiktok:webhook] authorization.removed" +
      " openid=" + sha256(openId).slice(0, 10) +
      " reason=" + (reason === null ? "n/a" : reason) +
      " comptes_supprimés=" + (data ? data.length : 0)
  );
}

// Événements documentés mais sans action pour cette application
// (Video Kit / Data Portability) : accusés de réception uniquement.
const TIKTOK_ACK_ONLY_EVENTS = new Set([
  "video.upload.failed",
  "video.publish.completed",
  "portability.download.ready",
]);

route("POST", "/api/tiktok/webhook", async ({ req, res, requestId }) => {
  // 1. Corps BRUT : la signature porte sur les octets exacts reçus.
  const rawBody = await readBody(req, MAX_TIKTOK_WEBHOOK_BODY);

  // 2. Authenticité, AVANT tout parsing JSON.
  const check = verifyTikTokWebhookSignature(
    rawBody,
    req.headers["tiktok-signature"],
    TIKTOK_CLIENT_SECRET
  );

  if (!check.ok) {
    console.warn("[" + requestId + "] [tiktok:webhook] rejeté (" + check.reason + ")");
    throw new HttpError(401, "Invalid webhook signature", "INVALID_SIGNATURE");
  }

  // 3. Structure du message (signé, donc émis par TikTok).
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

  if (
    typeof eventName !== "string" ||
    eventName.length > 100 ||
    !/^[A-Za-z0-9_.]+$/.test(eventName)
  ) {
    throw new HttpError(400, "Invalid event", "INVALID_PAYLOAD");
  }

  if (typeof payload.client_key === "string" && payload.client_key !== TIKTOK_CLIENT_KEY) {
    // Signé avec notre secret mais destiné à une autre clé : on ignore (200
    // pour éviter des retries inutiles).
    console.warn("[" + requestId + "] [tiktok:webhook] client_key inattendu : ignoré");
    sendJson(res, 200, { received: true, ignored: true });
    return;
  }

  // 4. Événement déjà traité (livraison "au moins une fois").
  const dedupeKey = sha256(rawBody.toString("utf8"));

  if (processedTikTokWebhooks.has(dedupeKey)) {
    sendJson(res, 200, { received: true, duplicate: true });
    return;
  }

  // 5. Traitement. Une exception => 500 => TikTok réessaiera (jusqu'à 72 h).
  if (eventName === "authorization.removed") {
    await handleTikTokAuthorizationRemoved(payload, requestId);
  } else if (TIKTOK_ACK_ONLY_EVENTS.has(eventName)) {
    console.log("[" + requestId + "] [tiktok:webhook] " + eventName + " reçu (aucune action)");
  } else {
    console.warn("[" + requestId + "] [tiktok:webhook] événement inconnu ignoré : " + eventName.slice(0, 60));
  }

  processedTikTokWebhooks.add(dedupeKey);
  sendJson(res, 200, { received: true });
});

// ============================================================
// ROUTES — PINTEREST
// ============================================================

route(
  "POST",
  "/api/pinterest/auth/url",
  ({ res, user }) => {
    const params = new URLSearchParams({
      client_id: PINTEREST_APP_ID,
      redirect_uri: PINTEREST_REDIRECT_URI,
      response_type: "code",
      scope: PINTEREST_SCOPES,
      state: createOAuthState("pinterest", user.id),
    });

    sendJson(res, 200, {
      success: true,
      url: `${PINTEREST_AUTH_URL}?${params.toString()}`,
    });
  },
  { auth: true }
);

// L'échange du code utilise l'endpoint OAuth de l'environnement choisi
// (PINTEREST_OAUTH_BASE) ; le compte est enregistré avec cet environnement
// (api_env) pour ne jamais mélanger jetons sandbox et production.
route(
  "POST",
  "/api/pinterest/auth/callback",
  async ({ req, res, user }) => {
    const body = await getJsonBody(req);
    const authCode = assertValidOAuthCallback("pinterest", body, user.id);

    const account = await dedupeCallback(
      `pinterest:${user.id}:${sha256(authCode)}`,
      async () => {
        const tokens = await pinterestApi("/oauth/token", {
          method: "POST",
          base: PINTEREST_OAUTH_BASE,
          basic: true,
          form: {
            grant_type: "authorization_code",
            code: authCode,
            redirect_uri: PINTEREST_REDIRECT_URI,
          },
        });

        if (!tokens?.access_token) {
          throw new HttpError(
            502,
            "Pinterest returned an invalid token response",
            "PINTEREST_BAD_TOKEN_RESPONSE"
          );
        }

        let profile = {};

        try {
          profile = await pinterestApi("/user_account", {
            token: tokens.access_token,
          });
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
      }
    );

    sendJson(res, 200, { success: true, connected: true, account });
  },
  { auth: true }
);

// Connexion par token manuel (DEV / SANDBOX uniquement).
// Le jeton est validé contre l'API de l'environnement ACTIF : il est donc
// enregistré avec le bon api_env.
route(
  "POST",
  "/api/pinterest/auth/token",
  async ({ req, res, user }) => {
    if (env("PINTEREST_ALLOW_MANUAL_TOKEN") !== "1") {
      throw new HttpError(403, "Manual token connection is disabled");
    }

    const body = await getJsonBody(req);
    const accessToken = String(body.access_token || "").trim();

    if (!accessToken || accessToken.length > 4096) {
      throw new HttpError(400, "Missing access_token");
    }

    let profile;

    try {
      profile = await pinterestApi("/user_account", { token: accessToken });
    } catch (profileError) {
      throw new HttpError(
        400,
        `Invalid Pinterest token: ${profileError.message}`
      );
    }

    await savePinterestTokens(
      user.id,
      {
        access_token: accessToken,
        refresh_token: null,
        expires_in: 29 * 24 * 60 * 60,
        refresh_token_expires_in: 29 * 24 * 60 * 60,
      },
      {
        username: profile.username || null,
        avatar_url: profile.profile_image || null,
        account_type: profile.account_type || null,
      }
    );

    sendJson(res, 200, {
      success: true,
      connected: true,
      account: {
        display_name: profile.username || null,
        avatar_url: profile.profile_image || null,
        account_type: profile.account_type || null,
      },
    });
  },
  { auth: true }
);

// Un compte relié dans un AUTRE environnement (ou avant la migration
// api_env) n'est pas présenté comme connecté : needs_reconnect = true.
route(
  "GET",
  "/api/pinterest/status",
  async ({ res, user }) => {
    const account = await getPinterestAccount(user.id);
    const usable = pinterestAccountMatchesEnv(account);

    sendJson(res, 200, {
      success: true,
      connected: usable,
      account: usable
        ? {
            display_name: account.username,
            avatar_url: account.avatar_url,
            account_type: account.account_type,
            scope: account.scope,
          }
        : null,
      ...(account && !usable ? { needs_reconnect: true } : {}),
    });
  },
  { auth: true }
);

route(
  "DELETE",
  "/api/pinterest/disconnect",
  async ({ res, user }) => {
    const { error } = await supabaseAdmin
      .from("pinterest_accounts")
      .delete()
      .eq("user_id", user.id);

    if (error) throw error;

    sendJson(res, 200, { success: true });
  },
  { auth: true }
);

// ============================================================
// ROUTES — YOUTUBE
// ============================================================

route(
  "POST",
  "/api/youtube/auth/url",
  ({ res, user }) => {
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

    sendJson(res, 200, {
      success: true,
      url: `${GOOGLE_AUTH_URL}?${params.toString()}`,
    });
  },
  { auth: true }
);

// Si le lookup de chaîne ÉCHOUE (erreur API) ou s'il n'y a pas de
// chaîne, on REFUSE la connexion (et on révoque l'accès) au lieu de
// sauvegarder silencieusement un compte sans chaîne.
route(
  "POST",
  "/api/youtube/auth/callback",
  async ({ req, res, user }) => {
    const body = await getJsonBody(req);
    const authCode = assertValidOAuthCallback("youtube", body, user.id);

    const account = await dedupeCallback(
      `youtube:${user.id}:${sha256(authCode)}`,
      async () => {
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

          throw new HttpError(
            400,
            "No YouTube channel found on this Google account. Create a channel on youtube.com, then try again."
          );
        }

        await saveYouTubeTokens(
          user.id,
          {
            ...tokens,
            refresh_token_expires_in: tokens.refresh_token_expires_in ?? null,
          },
          {
            channel_id: channel.id,
            channel_title: channel.title || null,
            custom_url: channel.customUrl || null,
            avatar_url: channel.avatarUrl || null,
          }
        );

        return {
          display_name: channel.title || null,
          avatar_url: channel.avatarUrl || null,
        };
      }
    );

    sendJson(res, 200, { success: true, connected: true, account });
  },
  { auth: true }
);

// ---- Publication d'une vidéo YouTube ------------------------------------
//
// multipart/form-data :
//   video (fichier) · title · description · tags (JSON ou "a,b")
//   privacy_level (public|unlisted|private) · made_for_kids ("true"|"false")
//   publish_at (ISO 8601, optionnel → programmation) · category_id (optionnel)
//
// Même ordre que TikTok pour la mémoire : vérifications bon marché,
// slot de concurrence, puis seulement lecture du corps.
route(
  "POST",
  "/api/youtube/publish",
  async ({ req, res, user }) => {
    enforce(limiterPublish, `youtube:${user.id}`);

    const declared = Number(req.headers["content-length"] || 0);

    if (declared > MAX_VIDEO_SIZE + 1024 * 1024) {
      throw tooLargeError(
        `Video is too large. Maximum size is ${MAX_VIDEO_SIZE / 1024 / 1024} MB.`
      );
    }

    // Échoue vite si la chaîne n'est pas connectée / expirée.
    const accessToken = await getValidYouTubeToken(user.id);

    await acquireVideoSlot();

    try {
      let upload;

      try {
        upload = await parseMultipart(req, {
          fileField: "video",
          maxSize: MAX_VIDEO_SIZE,
        });
      } catch (error) {
        if (error?.code === "FILE_TOO_LARGE") {
          throw new HttpError(
            400,
            `Video is too large. Maximum size is ${MAX_VIDEO_SIZE / 1024 / 1024} MB.`
          );
        }
        if (error?.code === "NO_FILE") {
          throw new HttpError(400, "No 'video' file was provided.");
        }
        throw error instanceof HttpError
          ? error
          : new HttpError(400, "Could not read the uploaded file.");
      }

      const mimeType = sniffVideoType(upload.buffer);

      if (!mimeType) {
        throw new HttpError(400, "Unsupported format. Use MP4, MOV or WebM.");
      }

      // Validé AVANT tout appel à YouTube.
      const { privacy, publishAt, metadata } = buildYouTubeMetadata(upload.fields);

      const uploadUrl = await initYouTubeUpload(
        accessToken,
        metadata,
        upload.buffer.length,
        mimeType
      );

      const video = await uploadVideoToYouTube(uploadUrl, upload.buffer, mimeType);

      if (!video?.id) {
        throw new HttpError(
          502,
          "YouTube did not confirm the upload",
          "YOUTUBE_NO_VIDEO_ID"
        );
      }

      const actualPrivacy = video.status?.privacyStatus || null;

      // Projet Google API non vérifié : YouTube force les vidéos en privé.
      const privacyLocked =
        !publishAt && privacy !== "private" && actualPrivacy === "private";

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
  },
  { auth: true }
);

route(
  "GET",
  "/api/youtube/status",
  async ({ res, user }) => {
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
            // false → l'utilisateur doit reconnecter YouTube (scope upload absent)
            can_publish: String(account.scope || "")
              .split(/[\s,]+/)
              .includes(YOUTUBE_UPLOAD_SCOPE),
          }
        : null,
    });
  },
  { auth: true }
);

route(
  "DELETE",
  "/api/youtube/disconnect",
  async ({ res, user }) => {
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

      const { error } = await supabaseAdmin
        .from("youtube_accounts")
        .delete()
        .eq("user_id", user.id);

      if (error) throw error;
    }

    sendJson(res, 200, { success: true });
  },
  { auth: true }
);

// ============================================================
// SERVER
// ============================================================

const providerGuards = [
  ["/api/tiktok/", tiktokEnabled, "TikTok"],
  ["/api/pinterest/", pinterestEnabled, "Pinterest"],
  ["/api/youtube/", youtubeEnabled, "YouTube"],
];

const server = createServer(async (req, res) => {
  const requestId = newRequestId();

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
    const url = new URL(
      req.url || "/",
      `http://${req.headers.host || `localhost:${PORT}`}`
    );

    // Normalise le trailing slash ("/api/user/" → "/api/user").
    const pathname =
      url.pathname.length > 1 ? url.pathname.replace(/\/+$/, "") : url.pathname;

    routeLabel = `${req.method} ${pathname}`;

    if (req.method === "GET" || req.method === "HEAD") {
      // Fichier de vérification TikTok (préfixe d'URL /api/media/tiktok/).
      // Doit passer AVANT la route des médias : sa regex n'accepte que des
      // noms hexadécimaux.
      let decodedPath = pathname;

      try {
        decodedPath = decodeURIComponent(pathname);
      } catch {
        // chemin mal encodé : on garde la valeur brute
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

      // Images servies à TikTok (publique, nom aléatoire non devinable).
      const mediaMatch = pathname.match(
        /^\/api\/media\/tiktok\/([a-f0-9]{32}\.(?:jpg|webp))$/
      );

      if (mediaMatch) {
        enforce(limiterMedia, getClientIp(req));
        await serveTikTokMedia(req, res, mediaMatch[1]);
        return;
      }
    }

    // ----------------------------------------------------------
    // Rate limiting par IP, avant toute logique métier.
    // Exemptés : webhooks Stripe (serveur → serveur, signature
    // vérifiée) et health check.
    // ----------------------------------------------------------
    const isStripeWebhook =
      req.method === "POST" && pathname === "/api/stripe/webhook";
    const isHealth = req.method === "GET" && pathname === "/api/health";

    const isTiktokWebhook =
      req.method === "POST" && pathname === "/api/tiktok/webhook";

    if (isTiktokWebhook) {
      enforce(limiterTiktokWebhook, getClientIp(req));
    } else if (!isStripeWebhook && !isHealth) {
      enforce(pickLimiter(pathname), getClientIp(req));
    }

    // ----------------------------------------------------------
    // Garde « provider non configuré »
    // ----------------------------------------------------------
    for (const [prefix, enabled, name] of providerGuards) {
      if (pathname.startsWith(prefix) && !enabled) {
        throw new HttpError(500, `${name} is not configured`);
      }
    }

    // Pinterest : sandbox et production ne se mélangent jamais.
    if (pathname.startsWith("/api/pinterest/") && pinterestConfigError) {
      console.error(`[${requestId}] Pinterest config: ${pinterestConfigError}`);
      throw new HttpError(
        500,
        "Pinterest configuration is inconsistent (sandbox / production mismatch)",
        "PINTEREST_CONFIG_INVALID"
      );
    }

    // ----------------------------------------------------------
    // Résolution de la route
    // ----------------------------------------------------------
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

    const ctx = {
      req,
      res,
      url,
      requestId,
      user: null,
      token: null,
    };

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
      if (error.status >= 500) {
        console.error(`[${requestId}] ${routeLabel}:`, error.message);
      }

      sendJson(
        res,
        error.status,
        {
          success: false,
          error: error.message,
          code: error.code || undefined,
          request_id: error.status >= 500 ? requestId : undefined,
        },
        error.headers
      );
      return;
    }

    internalErrorResponse(res, requestId, error, routeLabel);
  }
});

// Timeouts : keepAlive > délai d'inactivité des proxies (Railway ≈ 60 s)
// pour éviter les 502 sporadiques ; requestTimeout borne les uploads lents.
server.keepAliveTimeout = 65_000;
server.headersTimeout = 66_000;
server.requestTimeout = 5 * 60_000;

server.listen(PORT, () => {
  console.log(`Stone server running on port ${PORT}`);
  console.log(`  NODE_ENV        : ${env("NODE_ENV") || "(non défini)"}`);
  console.log(`  TRUST_PROXY     : ${TRUST_PROXY ? `1 (${TRUST_PROXY_HOPS} hop)` : "0"}`);
  console.log(`  Token encryption: ${TOKEN_ENCRYPTION_KEY ? "on" : "off"}`);
  console.log(`  Rate limits     : strict 10/15min · oauth 30/10min · api 240/min`);
  console.log(`  Video uploads   : max ${MAX_VIDEO_UPLOADS} concurrent(s)`);
  console.log(
    `  TikTok mode     : ${
      TIKTOK_SANDBOX
        ? "SANDBOX (SELF_ONLY + photos en brouillon, testers uniquement)"
        : "auditée (comportement normal)"
    }${TIKTOK_FORCE_DRAFT ? " + FORCE_DRAFT (tout en brouillon)" : ""}`
  );
  console.log(
    `  TikTok photos   : ${
      PUBLIC_API_URL
        ? `${PUBLIC_API_URL} (via ${PUBLIC_API_URL_SOURCE})`
        : "désactivé (PUBLIC_API_URL / VITE_API_BASE_URL manquant)"
    }`
  );
  console.log(
    `  Pinterest       : ${
      !pinterestEnabled
        ? "désactivé (Pinterest non configuré)"
        : pinterestConfigError
          ? `CONFIG INCOHÉRENTE (${pinterestConfigError})`
          : `${PINTEREST_ENVIRONMENT.toUpperCase()} · API ${PINTEREST_API_BASE} · OAuth ${PINTEREST_OAUTH_BASE}`
    }`
  );
  console.log(
    `  YouTube publish : ${
      youtubeEnabled
        ? YOUTUBE_SCOPES.split(" ").includes(YOUTUBE_UPLOAD_SCOPE)
          ? "activée (scope youtube.upload présent)"
          : "impossible (scope youtube.upload manquant)"
        : "désactivée (YouTube non configuré)"
    }`
  );

  if (tiktokEnabled) {
    console.log(
      "  TikTok webhook  : " +
        (PUBLIC_API_URL
          ? PUBLIC_API_URL + "/api/tiktok/webhook"
          : "/api/tiktok/webhook (PUBLIC_API_URL manquant : utilise le domaine public de ce serveur)")
    );
  }

  if (tiktokEnabled && PUBLIC_API_URL) {
    console.log(
      `  TikTok verif    : ${PUBLIC_API_URL}/api/media/tiktok/${TIKTOK_VERIFICATION_NAME}.txt`
    );
    ensureTikTokMediaBucket()
      .then(sweepTikTokMedia)
      .catch((error) =>
        console.warn("TikTok media init failed:", error?.message || error)
      );
    setInterval(sweepTikTokMedia, 15 * 60 * 1000).unref?.();
  }

  // La colonne api_env (migration) est indispensable pour relier Pinterest.
  if (pinterestUsable) {
    supabaseAdmin
      .from("pinterest_accounts")
      .select("api_env")
      .limit(1)
      .then(({ error }) => {
        if (error) {
          console.error(
            "❌ pinterest_accounts.api_env inaccessible — applique la migration SQL (colonne api_env) :",
            error.message
          );
        }
      })
      .catch((error) =>
        console.warn("Pinterest api_env check failed:", error?.message || error)
      );
  }
});

// ============================================================
// SERVER ERRORS
// ============================================================

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

// ============================================================
// ARRÊT PROPRE
// ============================================================

let shuttingDown = false;

function shutdown(signal, exitCode = 0) {
  if (shuttingDown) return;
  shuttingDown = true;

  console.log(`\n${signal} reçu — arrêt du serveur...`);

  server.close(() => {
    console.log("Serveur arrêté proprement.");
    process.exit(exitCode);
  });

  // Ferme tout de suite les connexions keep-alive inactives.
  server.closeIdleConnections?.();

  // Force l'arrêt si des connexions persistent.
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