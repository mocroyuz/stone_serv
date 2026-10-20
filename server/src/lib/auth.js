// Authentification : cache court, utilisateur, jeton de récupération,
// normalisation utilisateur, app_metadata.

import { RECOVERY_TOKEN_MAX_AGE_SEC } from "../config/index.js";
import { supabase, supabaseAdmin } from "./supabase.js";
import { HttpError, sha256, runSerial, dbError } from "./utils.js";

// supabase.auth.getUser(token) est un appel réseau : on met le résultat en
// cache 20 s (clé = hash du token). Le cache est vidé pour un utilisateur
// dès qu'on modifie son compte ou qu'il se déconnecte.

const AUTH_CACHE_TTL_MS = 20_000;
const AUTH_CACHE_MAX = 2_000;
const authCache = new Map();

export function authCacheGet(token) {
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

export function authCacheInvalidateUser(userId) {
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

export async function getAuthenticatedUser(req) {
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
export async function adminUpdateUser(userId, attributes) {
  const result = await supabaseAdmin.auth.admin.updateUserById(
    userId,
    attributes
  );

  authCacheInvalidateUser(userId);
  return result;
}

// ---- Jeton de récupération (mot de passe oublié) ---------------------------
//
// Le lien de l'email Supabase ouvre une session de « récupération » dont le
// JWT contient amr = [{ method: "recovery" | "otp" }]. On exige une méthode
// recovery/otp ET un jeton émis il y a moins de RECOVERY_TOKEN_MAX_AGE_SEC.
// (la signature est vérifiée ensuite par supabase.auth.getUser).

function decodeJwtPayload(token) {
  try {
    const parts = String(token).split(".");
    if (parts.length !== 3) return null;

    const payload = JSON.parse(
      Buffer.from(parts[1], "base64url").toString("utf8")
    );

    return payload && typeof payload === "object" ? payload : null;
  } catch {
    return null;
  }
}

export function isRecoverySessionToken(token) {
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

// ---- Normalisation utilisateur --------------------------------------------

function resolveAvatar(metadata) {
  if (typeof metadata.custom_avatar_url === "string") {
    return metadata.custom_avatar_url;
  }

  return metadata.avatar_url || metadata.avatarUrl || metadata.picture || "";
}

export function formatUser(user) {
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

export const sessionPayload = (session) =>
  session
    ? {
        access_token: session.access_token,
        refresh_token: session.refresh_token,
      }
    : null;

// ---- app_metadata : lecture / écriture fiables ----------------------------
//
// app_metadata contient l'abonnement et l'id client Stripe : une erreur
// ignorée ici crée une incohérence Stripe ↔ Supabase.

export async function getAppMetadata(userId) {
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

// Lit → modifie → écrit, en série par utilisateur. `mutate(current)` renvoie
// le nouvel objet app_metadata, ou null pour ne rien écrire.
export function updateAppMetadata(userId, mutate) {
  return runSerial(`app-metadata:${userId}`, async () => {
    const current = await getAppMetadata(userId);
    const next = mutate(current);

    if (next === null || next === undefined) return current;

    const { error } = await adminUpdateUser(userId, { app_metadata: next });

    if (error) throw dbError("auth.admin.updateUserById(app_metadata)", error);

    return next;
  });
}
