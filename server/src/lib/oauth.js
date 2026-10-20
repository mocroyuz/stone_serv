// OAuth commun : state signé (anti-CSRF, stateless) + lecture/écriture des
// tokens (TikTok, Pinterest, YouTube, Canva).

import crypto from "node:crypto";
import { OAUTH_STATE_SECRET } from "../config/index.js";
import { supabaseAdmin } from "./supabase.js";
import { decryptTokenRow } from "./crypto.js";
import { HttpError, dbError } from "./utils.js";

function hmac(value) {
  return crypto
    .createHmac("sha256", OAUTH_STATE_SECRET)
    .update(value)
    .digest("hex");
}

export function createOAuthState(provider, userId) {
  const payload = `${provider}.${userId}.${Date.now() + 10 * 60 * 1000}.${crypto
    .randomBytes(8)
    .toString("hex")}`;

  return Buffer.from(`${payload}.${hmac(payload)}`).toString("base64url");
}

// Renvoie null si le state est valide, sinon la raison précise de l'échec.
// Les raisons ne sont écrites que dans les logs serveur.
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

export function assertValidOAuthCallback(provider, body, userId) {
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

// ---- Tokens OAuth : lecture / écriture communes ---------------------------

// Une erreur de base de données n'est JAMAIS traitée comme « compte absent ».
export async function selectTokenRow(table, userId) {
  const { data, error } = await supabaseAdmin
    .from(table)
    .select("*")
    .eq("user_id", userId)
    .maybeSingle();

  if (error) throw dbError(`${table} select`, error);

  return decryptTokenRow(data);
}

// Le jeton d'accès est utilisable s'il expire dans plus de 60 s.
export function isTokenFresh(account) {
  return Boolean(
    account?.access_token &&
      new Date(account.access_expires_at).getTime() > Date.now() + 60_000
  );
}

// Mise à jour « compare-and-swap » : la ligne n'est modifiée que si
// updated_at est celui que l'on a lu. Un ancien jeton ne réécrase jamais un
// plus récent, et une ligne supprimée n'est jamais recréée.
export async function updateTokensIfUnchanged(table, userId, account, row) {
  let query = supabaseAdmin.from(table).update(row).eq("user_id", userId);

  query = account.updated_at
    ? query.eq("updated_at", account.updated_at)
    : query.is("updated_at", null);

  const { data, error } = await query.select("user_id");

  if (error) throw dbError(`${table} update`, error);

  return Array.isArray(data) && data.length > 0;
}
