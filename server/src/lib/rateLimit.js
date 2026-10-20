// Rate limiting en mémoire (sliding window). Suffisant en mono-instance ;
// pour du multi-instance, passe à Redis (rate-limiter-flexible).

import { TRUST_PROXY, TRUST_PROXY_HOPS } from "../config/index.js";
import { HttpError } from "./utils.js";

// On lit l'entrée située à TRUST_PROXY_HOPS de la FIN de X-Forwarded-For :
// une valeur injectée par le client n'est jamais utilisée.
export function getClientIp(req) {
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
export const limiterStrict = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 10, label: "auth" });
export const limiterRefresh = createRateLimiter({ windowMs: 10 * 60 * 1000, max: 30, label: "refresh" });
export const limiterOauth = createRateLimiter({ windowMs: 10 * 60 * 1000, max: 30, label: "oauth" });
export const limiterApi = createRateLimiter({ windowMs: 60 * 1000, max: 240, label: "api" });

// Par compte (empêche de contourner la limite IP en changeant d'IP)
export const limiterAccount = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 10, label: "account" });
export const limiterPublish = createRateLimiter({ windowMs: 60 * 60 * 1000, max: 20, label: "publish" });

// Mot de passe oublié : 3 demandes / 15 min par adresse email.
export const limiterPasswordReset = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 3, label: "password-reset" });

// Les serveurs TikTok téléchargent jusqu'à 35 images par publication.
export const limiterMedia = createRateLimiter({ windowMs: 60 * 1000, max: 600, label: "media" });
// Webhook TikTok (serveur -> serveur, signature vérifiée).
export const limiterTiktokWebhook = createRateLimiter({ windowMs: 60 * 1000, max: 600, label: "tiktok-webhook" });

// Canva : création de design + export, par utilisateur.
export const limiterCanva = createRateLimiter({ windowMs: 10 * 60 * 1000, max: 40, label: "canva" });

export function enforce(limiter, key) {
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
  "/api/auth/forgot-password",
  "/api/auth/reset-password",
]);

const PROVIDER_AUTH_PATH = /^\/api\/(tiktok|pinterest|youtube|canva)\/auth\//;

export function pickLimiter(pathname) {
  if (STRICT_PATHS.has(pathname)) return limiterStrict;
  if (pathname === "/api/auth/refresh") return limiterRefresh;
  if (pathname.startsWith("/api/auth/") || PROVIDER_AUTH_PATH.test(pathname)) {
    return limiterOauth;
  }
  return limiterApi;
}
