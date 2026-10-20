// HTTP : CORS, en-têtes de sécurité, réponses JSON, lecture des corps.

import {
  APP_URL,
  DEFAULT_OAUTH_REDIRECT,
  IS_PRODUCTION,
  env,
} from "../config/index.js";
import { HttpError } from "./utils.js";

// ---- CORS -----------------------------------------------------------------

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

export function isOriginAllowed(origin) {
  if (!origin || typeof origin !== "string") return false;

  const normalized = normalizeOrigin(origin);

  return (
    allowedOrigins.has(normalized) ||
    VERCEL_DEPLOYMENT_ORIGIN_PATTERN.test(normalized)
  );
}

const warnedRejectedOrigins = new Set();

const CORS_ALLOWED_HEADERS = "Content-Type, Authorization, X-Requested-With";

export function setCorsHeaders(req, res) {
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
export function setSecurityHeaders(res) {
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

// Validation du redirectTo (anti open redirect)
export function sanitizeRedirectTo(value) {
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

// ---- Réponses -------------------------------------------------------------

export function sendJson(res, statusCode, data, extraHeaders) {
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

// En production, le client ne reçoit JAMAIS le message d'erreur interne :
// seulement un message générique + un requestId corrélable aux logs.
export function internalErrorResponse(res, requestId, error, context) {
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

// ---- Corps des requêtes ---------------------------------------------------

export const MAX_JSON_BODY = 1024 * 1024; // 1 Mo suffit pour toutes nos routes JSON

export function tooLargeError(message = "Request body too large") {
  return new HttpError(413, message, "BODY_TOO_LARGE", { Connection: "close" });
}

export function readBody(req, maxBytes) {
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

export async function getJsonBody(req) {
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
export const getRawBody = (req) => readBody(req, MAX_JSON_BODY);
