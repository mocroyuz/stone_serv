// Vérifications de démarrage : variables obligatoires, fail-fast en
// production, avertissements de configuration, debug optionnel.
// Importé en dernier par config/index.js.

import { env, envPath, IS_PRODUCTION } from "./env.js";
import {
  SUPABASE_URL,
  SUPABASE_ANON_KEY,
  SUPABASE_SERVICE_ROLE_KEY,
  APP_URL,
  DEFAULT_OAUTH_REDIRECT,
  PASSWORD_RESET_REDIRECT_URL,
} from "./app.js";
import {
  STRIPE_SECRET_KEY,
  STRIPE_WEBHOOK_SECRET,
  STRIPE_PRICES,
  STRIPE_SUCCESS_URL,
  STRIPE_CANCEL_URL,
  STRIPE_PORTAL_RETURN_URL,
} from "./stripe.js";
import {
  TIKTOK_CLIENT_KEY,
  TIKTOK_REDIRECT_URI,
  TIKTOK_AUDITED,
  TIKTOK_SANDBOX,
  TIKTOK_FORCE_DRAFT,
  tiktokEnabled,
  PUBLIC_API_URL,
  PUBLIC_API_URL_SOURCE,
  publicApiLooksLikeFrontend,
  publicApiSourceLabel,
} from "./tiktok.js";
import {
  PINTEREST_REDIRECT_URI,
  PINTEREST_API_BASE,
  PINTEREST_OAUTH_BASE,
  PINTEREST_ENVIRONMENT,
  pinterestEnabled,
  pinterestConfigError,
} from "./pinterest.js";
import {
  YOUTUBE_REDIRECT_URI,
  YOUTUBE_SCOPES,
  YOUTUBE_UPLOAD_SCOPE,
  youtubeEnabled,
} from "./youtube.js";
import {
  CANVA_REDIRECT_URI,
  CANVA_SCOPES,
  canvaEnabled,
} from "./canva.js";
import { OAUTH_STATE_SECRET, TOKEN_ENCRYPTION_KEY } from "./secrets.js";

// ---- Supabase -------------------------------------------------------------

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

// ---- Debug optionnel : DEBUG_ENV=1 (n'affiche jamais les secrets) ---------

if (env("DEBUG_ENV") === "1") {
  console.log("[env] SUPABASE_URL      :", JSON.stringify(SUPABASE_URL));
  console.log("[env] ANON key length   :", SUPABASE_ANON_KEY.length);
  console.log("[env] SERVICE key length:", SUPABASE_SERVICE_ROLE_KEY.length);
  console.log("[env] APP_URL           :", JSON.stringify(APP_URL));
  console.log("[env] PASSWORD_RESET    :", JSON.stringify(PASSWORD_RESET_REDIRECT_URL));
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
  console.log("[env] CANVA_REDIRECT    :", JSON.stringify(CANVA_REDIRECT_URI));
  console.log("[env] CANVA_SCOPES      :", JSON.stringify(CANVA_SCOPES));
  console.log("[env] TOKEN ENCRYPTION  :", Boolean(TOKEN_ENCRYPTION_KEY));
  console.log("[env] STRIPE success    :", JSON.stringify(STRIPE_SUCCESS_URL));
  console.log("[env] STRIPE cancel     :", JSON.stringify(STRIPE_CANCEL_URL));
  console.log("[env] STRIPE portal     :", JSON.stringify(STRIPE_PORTAL_RETURN_URL));
}

// ---- Fail-fast en production ----------------------------------------------

if (IS_PRODUCTION && !env("OAUTH_STATE_SECRET")) {
  console.warn(
    "⚠️  OAUTH_STATE_SECRET manquant : définis un secret dédié (32+ caractères aléatoires) en production."
  );
}

if (!TOKEN_ENCRYPTION_KEY) {
  console.warn(
    "⚠️  TOKEN_ENCRYPTION_KEY manquant — les tokens TikTok / Pinterest / YouTube / Canva sont stockés en clair."
  );
}

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

if (IS_PRODUCTION && PASSWORD_RESET_REDIRECT_URL.startsWith("http://localhost")) {
  console.warn(
    "⚠️  PASSWORD_RESET_REDIRECT_URL pointe vers localhost en production — les liens de réinitialisation seront inutilisables."
  );
}

// ---- Stripe ---------------------------------------------------------------

if (!STRIPE_SECRET_KEY) {
  console.warn("⚠️  Stripe non configuré (STRIPE_SECRET_KEY manquant).");
}

if (!STRIPE_WEBHOOK_SECRET) {
  console.warn(
    "⚠️  STRIPE_WEBHOOK_SECRET manquant — les webhooks seront refusés."
  );
}

if (STRIPE_SECRET_KEY) {
  const missingPrices = [];

  for (const [plan, periods] of Object.entries(STRIPE_PRICES)) {
    for (const [period, priceId] of Object.entries(periods)) {
      if (!priceId) {
        missingPrices.push(
          `STRIPE_PRICE_${plan.toUpperCase()}_${period.toUpperCase()}`
        );
      }
    }
  }

  if (missingPrices.length > 0) {
    console.error("");
    console.error("❌ Price IDs Stripe manquants :");
    for (const name of missingPrices) console.error(` - ${name}`);
    console.error("");
    console.error("Récupère-les dans Stripe Dashboard → Products →");
    console.error("(ton produit) → Pricing, puis ajoute-les aux variables");
    console.error("d'environnement. Le checkout échouera pour ces plans.");
    console.error("");
  }
}

// ---- TikTok ---------------------------------------------------------------

if (!tiktokEnabled) {
  console.warn(
    "⚠️  TikTok non configuré (TIKTOK_CLIENT_KEY / TIKTOK_CLIENT_SECRET manquant)."
  );
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

// ---- Pinterest / YouTube / Canva ------------------------------------------

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

if (youtubeEnabled && !YOUTUBE_SCOPES.split(" ").includes(YOUTUBE_UPLOAD_SCOPE)) {
  console.warn(
    "⚠️  YOUTUBE_SCOPES ne contient pas youtube.upload — la publication YouTube sera impossible."
  );
}

if (!canvaEnabled) {
  console.warn(
    "⚠️  Canva non configuré (CANVA_CLIENT_ID / CANVA_CLIENT_SECRET manquant)."
  );
}

for (const [label, value] of [
  ["TIKTOK_REDIRECT_URI", TIKTOK_REDIRECT_URI],
  ["PINTEREST_REDIRECT_URI", PINTEREST_REDIRECT_URI],
  ["YOUTUBE_REDIRECT_URI", YOUTUBE_REDIRECT_URI],
  ["CANVA_REDIRECT_URI", CANVA_REDIRECT_URI],
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

// TIKTOK_CLIENT_KEY importé pour d'éventuels contrôles futurs
void TIKTOK_CLIENT_KEY;
