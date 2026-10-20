// Configuration générale : serveur, Supabase, URLs de l'app, mot de passe oublié.

import { env } from "./env.js";

export const PORT = Number(env("PORT") || 3002);

export const SUPABASE_URL = env("SUPABASE_URL");
export const SUPABASE_ANON_KEY = env("SUPABASE_ANON_KEY");
export const SUPABASE_SERVICE_ROLE_KEY = env("SUPABASE_SERVICE_ROLE_KEY");
export const SUPABASE_BASE_URL = String(SUPABASE_URL || "").replace(/\/+$/, "");

export const DEFAULT_OAUTH_REDIRECT =
  env("OAUTH_REDIRECT_URL") || "http://localhost:5173/";

export const AVATAR_BUCKET = "avatars";
export const MAX_AVATAR_SIZE = 2 * 1024 * 1024;

export const APP_URL = (env("APP_URL") || "http://localhost:5173").replace(
  /\/+$/,
  ""
);

// Le frontend utilise un routage par hash (#/...). Supabase ajoute les
// jetons de récupération après cette URL (dans le hash).
export const PASSWORD_RESET_REDIRECT_URL =
  env("PASSWORD_RESET_REDIRECT_URL") || `${APP_URL}/#/reset-password`;

// Âge maximal (en secondes) d'un jeton de récupération accepté.
export const RECOVERY_TOKEN_MAX_AGE_SEC = 60 * 60;

// Proxy de confiance (X-Forwarded-For)
export const TRUST_PROXY =
  env("TRUST_PROXY") === "1" || env("NODE_ENV") === "production";
export const TRUST_PROXY_HOPS = Math.max(1, Number(env("TRUST_PROXY_HOPS") || 1));

// Limite de concurrence des uploads (vidéos / photos)
export const MAX_VIDEO_UPLOADS = Math.max(
  1,
  Number(env("MAX_VIDEO_UPLOADS") || 2)
);
