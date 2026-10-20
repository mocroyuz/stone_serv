// ============================================================
// STONE — API SERVER (point d'entrée)
// ============================================================
//
// Structure :
//   src/config/    variables d'environnement, constantes, vérifications
//   src/lib/       utilitaires partagés (http, auth, rate limit, upload...)
//   src/services/  intégrations externes (Stripe, TikTok, Pinterest, YouTube, Canva)
//   src/routes/    une famille de routes /api/... par fichier
//
// Variables d'environnement : voir .env.example

import { createServer } from "node:http";
import {
  env,
  PORT,
  TRUST_PROXY,
  TRUST_PROXY_HOPS,
  TOKEN_ENCRYPTION_KEY,
  PASSWORD_RESET_REDIRECT_URL,
  MAX_VIDEO_UPLOADS,
  TIKTOK_SANDBOX,
  TIKTOK_FORCE_DRAFT,
  TIKTOK_VERIFICATION_NAME,
  PUBLIC_API_URL,
  PUBLIC_API_URL_SOURCE,
  tiktokEnabled,
  pinterestEnabled,
  pinterestUsable,
  pinterestConfigError,
  PINTEREST_ENVIRONMENT,
  PINTEREST_API_BASE,
  PINTEREST_OAUTH_BASE,
  youtubeEnabled,
  YOUTUBE_SCOPES,
  YOUTUBE_UPLOAD_SCOPE,
  canvaEnabled,
  CANVA_REDIRECT_URI,
  STRIPE_SUCCESS_URL,
  STRIPE_CANCEL_URL,
  STRIPE_PORTAL_RETURN_URL,
} from "./src/config/index.js";
import { supabaseAdmin } from "./src/lib/supabase.js";
import { HttpError, newRequestId } from "./src/lib/utils.js";
import {
  setCorsHeaders,
  setSecurityHeaders,
  sendJson,
  internalErrorResponse,
} from "./src/lib/http.js";
import {
  enforce,
  pickLimiter,
  getClientIp,
  limiterMedia,
  limiterTiktokWebhook,
} from "./src/lib/rateLimit.js";
import { getAuthenticatedUser } from "./src/lib/auth.js";
import { routes } from "./src/lib/router.js";
import {
  serveTikTokMedia,
  ensureTikTokMediaBucket,
  sweepTikTokMedia,
} from "./src/services/tiktok.js";

// Enregistre toutes les routes.
import "./src/routes/index.js";

// ============================================================
// SERVER
// ============================================================

const providerGuards = [
  ["/api/tiktok/", tiktokEnabled, "TikTok"],
  ["/api/pinterest/", pinterestEnabled, "Pinterest"],
  ["/api/youtube/", youtubeEnabled, "YouTube"],
  ["/api/canva/", canvaEnabled, "Canva"],
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
      // Doit passer AVANT la route des médias (regex hexadécimale).
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
    // Exemptés : webhook Stripe (signature vérifiée) et health check.
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
  console.log(`  Password reset  : redirect ${PASSWORD_RESET_REDIRECT_URL} · 3 demandes/15min par email`);
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
  console.log(
    `  Canva           : ${
      canvaEnabled
        ? `activé (redirect ${CANVA_REDIRECT_URI})`
        : "désactivé (Canva non configuré)"
    }`
  );
  console.log(
    `  Stripe checkout : success ${STRIPE_SUCCESS_URL} · cancel ${STRIPE_CANCEL_URL}`
  );
  console.log(`  Stripe portal   : return ${STRIPE_PORTAL_RETURN_URL}`);

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

  // Canva : vérifie que la table existe (sinon message explicite).
  if (canvaEnabled) {
    supabaseAdmin
      .from("canva_accounts")
      .select("user_id")
      .limit(1)
      .then(({ error }) => {
        if (error) {
          console.error(
            "❌ canva_accounts inaccessible — crée la table (voir bloc SQL du README Canva) :",
            error.message
          );
        }
      })
      .catch((error) =>
        console.warn("Canva accounts check failed:", error?.message || error)
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
