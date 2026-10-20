// Service Canva : PKCE, appel API, tokens.
//
// PKCE : le code_verifier reste côté serveur (en mémoire, 10 min), indexé
// par le hash du state. Mono-instance ; en multi-instance, stocke-le en base.

import crypto from "node:crypto";
import {
  CANVA_CLIENT_ID,
  CANVA_CLIENT_SECRET,
  CANVA_API_BASE,
} from "../config/index.js";
import { supabaseAdmin } from "../lib/supabase.js";
import { encryptSecret } from "../lib/crypto.js";
import {
  selectTokenRow,
  isTokenFresh,
  updateTokensIfUnchanged,
} from "../lib/oauth.js";
import {
  HttpError,
  fetchJson,
  upstreamError,
  upstreamStatus,
  reconnectError,
  withLock,
  sha256,
  dbError,
  iso,
} from "../lib/utils.js";

const canvaPkce = new Map();
const CANVA_PKCE_TTL_MS = 10 * 60 * 1000;

export function createCanvaPkce(state) {
  const now = Date.now();

  for (const [key, entry] of canvaPkce) {
    if (entry.expires <= now) canvaPkce.delete(key);
  }

  if (canvaPkce.size > 5_000) canvaPkce.delete(canvaPkce.keys().next().value);

  const verifier = crypto.randomBytes(48).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");

  canvaPkce.set(sha256(state), { verifier, expires: now + CANVA_PKCE_TTL_MS });

  return challenge;
}

export function takeCanvaVerifier(state) {
  const key = sha256(state);
  const entry = canvaPkce.get(key);

  canvaPkce.delete(key);

  return entry && entry.expires > Date.now() ? entry.verifier : null;
}

export async function canvaApi(
  pathname,
  { method = "GET", token, basic = false, form, json } = {}
) {
  const headers = { Accept: "application/json" };
  let body;

  if (basic) {
    headers.Authorization =
      "Basic " +
      Buffer.from(`${CANVA_CLIENT_ID}:${CANVA_CLIENT_SECRET}`).toString("base64");
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
    result = await fetchJson(`${CANVA_API_BASE}${pathname}`, { method, headers, body }, 20_000);
  } catch (error) {
    throw upstreamError("Canva", error);
  }

  const { response, data } = result;

  if (!response.ok) {
    // Jamais de 401 brut : le front le confondrait avec la session Stone.
    const error = new HttpError(
      upstreamStatus(response.status),
      data.message ||
        data.error_description ||
        (typeof data.error === "string" ? data.error : "") ||
        `Canva error (HTTP ${response.status})`,
      data.code || (typeof data.error === "string" ? data.error : undefined)
    );

    error.upstreamStatus = response.status;
    throw error;
  }

  return data;
}

function buildCanvaTokenRow(t) {
  const accessTtl = Number(t.expires_in) || 4 * 60 * 60;

  const row = {
    access_token: encryptSecret(t.access_token),
    access_expires_at: iso(Date.now() + accessTtl * 1000),
    updated_at: new Date().toISOString(),
  };

  // Canva fait tourner les refresh tokens : toujours stocker le nouveau.
  if (t.refresh_token) row.refresh_token = encryptSecret(t.refresh_token);
  if (t.scope) row.scope = t.scope;

  return row;
}

export async function saveCanvaTokens(userId, t, extra = {}) {
  const { error } = await supabaseAdmin
    .from("canva_accounts")
    .upsert(
      { user_id: userId, ...buildCanvaTokenRow(t), ...extra },
      { onConflict: "user_id" }
    );

  if (error) throw dbError("canva_accounts upsert", error);
}

export const getCanvaAccount = (userId) => selectTokenRow("canva_accounts", userId);

export async function getValidCanvaToken(userId) {
  const load = async () => {
    const account = await getCanvaAccount(userId);

    if (!account) {
      throw new HttpError(400, "Canva account not connected", "CANVA_NOT_CONNECTED");
    }

    return account;
  };

  const first = await load();
  if (isTokenFresh(first)) return first.access_token;

  return withLock(`canva-refresh:${userId}`, async () => {
    for (let attempt = 0; attempt < 2; attempt++) {
      const account = await load();

      if (isTokenFresh(account)) return account.access_token;

      if (!account.refresh_token) {
        throw reconnectError("Canva", "CANVA_REFRESH_EXPIRED");
      }

      let refreshed;

      try {
        refreshed = await canvaApi("/oauth/token", {
          method: "POST",
          basic: true,
          form: {
            grant_type: "refresh_token",
            refresh_token: account.refresh_token,
          },
        });
      } catch (error) {
        if (
          error instanceof HttpError &&
          (error.upstreamStatus === 400 ||
            error.upstreamStatus === 401 ||
            error.code === "invalid_grant")
        ) {
          throw reconnectError("Canva", "CANVA_REFRESH_EXPIRED");
        }
        throw error;
      }

      if (!refreshed?.access_token) {
        throw new HttpError(502, "Canva returned an invalid token response", "CANVA_BAD_TOKEN_RESPONSE");
      }

      const applied = await updateTokensIfUnchanged(
        "canva_accounts",
        userId,
        account,
        buildCanvaTokenRow(refreshed)
      );

      if (applied) return refreshed.access_token;
    }

    throw new HttpError(409, "Canva account changed during token refresh, please retry", "CANVA_REFRESH_CONFLICT");
  });
}
