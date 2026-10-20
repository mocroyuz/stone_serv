// Configuration TikTok (mode sandbox, photos, webhook).

import { env } from "./env.js";
import { APP_URL } from "./app.js";

export const TIKTOK_CLIENT_KEY = env("TIKTOK_CLIENT_KEY");
export const TIKTOK_CLIENT_SECRET = env("TIKTOK_CLIENT_SECRET");
export const TIKTOK_REDIRECT_URI =
  env("TIKTOK_REDIRECT_URI") || `${APP_URL}/tiktok/callback`;

export const TIKTOK_SCOPES = "user.info.basic,video.publish,video.upload";
export const TIKTOK_API = "https://open.tiktokapis.com";
export const MAX_VIDEO_SIZE = 100 * 1024 * 1024;
export const TIKTOK_PRIVACY_LEVELS = new Set([
  "PUBLIC_TO_EVERYONE",
  "MUTUAL_FOLLOW_FRIENDS",
  "FOLLOWER_OF_CREATOR",
  "SELF_ONLY",
]);

// Mode sandbox : voir README / en-tête de l'ancien fichier.
//   TIKTOK_AUDITED=1     → app auditée : comportement normal
//   sinon                → SANDBOX (SELF_ONLY, photos en brouillon, testers)
//   TIKTOK_FORCE_DRAFT=1 → tout part en brouillon, même audité
export const TIKTOK_AUDITED = env("TIKTOK_AUDITED") === "1";
export const TIKTOK_SANDBOX = !TIKTOK_AUDITED;
export const TIKTOK_FORCE_DRAFT = env("TIKTOK_FORCE_DRAFT") === "1";

export const tiktokEnabled = Boolean(TIKTOK_CLIENT_KEY && TIKTOK_CLIENT_SECRET);

// Résumé des capacités effectives, renvoyé par les routes TikTok.
export function tiktokCapabilities() {
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

// Webhook : écart maximal (s) toléré. 0 = contrôle désactivé. Défaut : 300 s.
export const TIKTOK_WEBHOOK_TOLERANCE_SEC = (() => {
  const raw = env("TIKTOK_WEBHOOK_TOLERANCE_SEC");
  const value = raw ? Number(raw) : Number.NaN;
  return Number.isFinite(value) && value >= 0 ? value : 300;
})();

// Fichier de vérification du préfixe d'URL chez TikTok.
export const TIKTOK_VERIFICATION_NAME = (
  env("TIKTOK_VERIFICATION_FILE") ||
  "tiktok-developers-site-verification=mRJN1EDyG6GdEuRBeOe9A5VyNF5FZTlU"
).replace(/\.txt$/i, "");

// URL publique de CE serveur (PUBLIC_API_URL → VITE_API_BASE_URL →
// RAILWAY_PUBLIC_DOMAIN). Un éventuel "/api" final est retiré.
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

const resolved = resolvePublicApiUrl();
export const PUBLIC_API_URL = resolved.url;
export const PUBLIC_API_URL_SOURCE = resolved.source;

export const TIKTOK_MEDIA_BUCKET = "tiktok-media";
export const TIKTOK_MEDIA_TTL_MS = 2 * 60 * 60 * 1000;
export const MAX_TIKTOK_PHOTOS = 35;
export const MAX_PHOTO_SIZE = 10 * 1024 * 1024;
export const MAX_PHOTOS_TOTAL = 80 * 1024 * 1024;

// Un PUBLIC_API_URL qui pointe vers le frontend est la cause n°1 de
// « The request source info is empty or incorrect ».
export function publicApiLooksLikeFrontend() {
  if (!PUBLIC_API_URL) return false;

  try {
    const apiHost = new URL(PUBLIC_API_URL).host;
    const appHost = new URL(APP_URL).host;

    return apiHost === appHost || apiHost.endsWith(".vercel.app");
  } catch {
    return false;
  }
}

export function publicApiSourceLabel(source) {
  return source || "URL publique";
}
