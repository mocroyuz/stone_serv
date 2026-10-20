// Utilitaires génériques : erreurs HTTP, verrous, caches, fetch avec timeout.

import crypto from "node:crypto";

export class HttpError extends Error {
  constructor(status, message, code, headers) {
    super(message);
    this.name = "HttpError";
    this.status = status;
    this.code = code;
    this.headers = headers;
  }
}

export const sha256 = (value) =>
  crypto.createHash("sha256").update(String(value)).digest("hex");

export const normalizeEmail = (value) => String(value ?? "").trim().toLowerCase();

export const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export const toBool = (v) => v === true || v === "true" || v === "1";

export const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export const iso = (ms) => new Date(ms).toISOString();

export const isPast = (value) => new Date(value).getTime() <= Date.now();

export const idOf = (value) =>
  typeof value === "string" ? value : value?.id || null;

export function newRequestId() {
  return crypto.randomUUID().slice(0, 8);
}

// Mutualise les appels concurrents identiques (refresh de token,
// création de client Stripe...) : un seul vol, tout le monde attend
// le même résultat. Ne pas l'utiliser pour des écritures différentes
// sur la même clé (voir runSerial).
const inflight = new Map();

export function withLock(key, fn) {
  const existing = inflight.get(key);
  if (existing) return existing;

  const promise = Promise.resolve()
    .then(fn)
    .finally(() => inflight.delete(key));

  inflight.set(key, promise);
  return promise;
}

// File d'attente par clé : les tâches s'exécutent UNE PAR UNE, chacune avec
// son propre résultat. Sert aux écritures « lire → modifier → écrire ».
const serialChains = new Map();

export function runSerial(key, fn) {
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
export function createSeenCache(maxEntries, ttlMs) {
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
// double clic) : le code est à usage unique côté provider, on renvoie
// le même résultat pendant 60 s au lieu d'une erreur.
const callbackCache = new Map();
const CALLBACK_TTL_MS = 60_000;

export function dedupeCallback(key, fn) {
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
export async function fetchJson(resource, options = {}, timeoutMs = 15_000) {
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

export function upstreamError(name, error) {
  if (error instanceof HttpError) return error;
  console.error(`[upstream:${name}]`, error?.message || error);
  return new HttpError(502, `${name} is unreachable`, "UPSTREAM_UNREACHABLE");
}

export function upstreamStatus(status) {
  if (status === 429) return 429;
  return status >= 500 ? 502 : 400;
}

export const reconnectError = (name, code) =>
  new HttpError(409, `${name} session expired, please reconnect`, code);

// Erreur de base de données : le détail reste dans les logs serveur.
export function dbError(context, error) {
  console.error(`[db] ${context}:`, error?.message || error);
  return new HttpError(500, "Database error", "DB_ERROR");
}
