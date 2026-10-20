// Service Pinterest : appel API, stockage / refresh des tokens.
//
// Chaque compte mémorise l'environnement dans lequel ses jetons ont été
// émis (colonne api_env). Un jeton sandbox n'est jamais envoyé à l'API de
// production, ni l'inverse : la reconnexion est demandée.

import {
  PINTEREST_APP_ID,
  PINTEREST_APP_SECRET,
  PINTEREST_API_BASE,
  PINTEREST_OAUTH_BASE,
  PINTEREST_ENVIRONMENT,
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
  iso,
  isPast,
  dbError,
} from "../lib/utils.js";

export async function pinterestApi(
  pathname,
  { method = "GET", base = PINTEREST_API_BASE, token, basic = false, form, json } = {}
) {
  const headers = { Accept: "application/json" };
  let body;

  if (basic) {
    const credentials = Buffer.from(
      `${PINTEREST_APP_ID}:${PINTEREST_APP_SECRET}`
    ).toString("base64");

    headers.Authorization = `Basic ${credentials}`;
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
    result = await fetchJson(`${base}${pathname}`, { method, headers, body }, 20_000);
  } catch (error) {
    throw upstreamError("Pinterest", error);
  }

  const { response, data } = result;

  if (!response.ok) {
    // On ne renvoie JAMAIS le 401 de Pinterest tel quel : le frontend le
    // confondrait avec l'expiration de la session Stone.
    const error = new HttpError(
      upstreamStatus(response.status),
      data.message ||
        data.error_description ||
        (typeof data.error === "string" ? data.error : "") ||
        `Pinterest error (HTTP ${response.status})`,
      data.code !== undefined ? String(data.code) : undefined
    );

    // Statut réel du provider (le refresh s'en sert pour distinguer un
    // jeton révoqué / expiré d'une panne temporaire).
    error.upstreamStatus = response.status;
    throw error;
  }

  return data;
}

// replaceRefresh = true (connexion initiale) : les champs absents sont
// remis à zéro. false (refresh) : un refresh_token / une expiration non
// renvoyés par Pinterest ne sont PAS écrasés.
function buildPinterestTokenRow(t, { replaceRefresh = false } = {}) {
  const now = Date.now();
  const accessTtl = Number(t.expires_in) || 30 * 24 * 60 * 60;

  const row = {
    access_token: encryptSecret(t.access_token),
    access_expires_at: iso(now + accessTtl * 1000),
    updated_at: new Date().toISOString(),
  };

  if (t.refresh_token) row.refresh_token = encryptSecret(t.refresh_token);
  else if (replaceRefresh) row.refresh_token = null;

  const refreshTtl = Number(t.refresh_token_expires_in);

  if (Number.isFinite(refreshTtl) && refreshTtl > 0) {
    row.refresh_expires_at = iso(now + refreshTtl * 1000);
  } else if (replaceRefresh) {
    row.refresh_expires_at = iso(now + 365 * 24 * 60 * 60 * 1000);
  }

  if (t.scope) row.scope = t.scope;
  else if (replaceRefresh) row.scope = null;

  return row;
}

// Connexion initiale : crée ou remplace la ligne, et fixe l'environnement.
export async function savePinterestTokens(userId, t, extra = {}) {
  const { error } = await supabaseAdmin.from("pinterest_accounts").upsert(
    {
      user_id: userId,
      ...buildPinterestTokenRow(t, { replaceRefresh: true }),
      api_env: PINTEREST_ENVIRONMENT,
      ...extra,
    },
    { onConflict: "user_id" }
  );

  if (error) throw dbError("pinterest_accounts upsert", error);
}

export async function getPinterestAccount(userId) {
  return selectTokenRow("pinterest_accounts", userId);
}

export const pinterestAccountMatchesEnv = (account) =>
  Boolean(account) && account.api_env === PINTEREST_ENVIRONMENT;

// Renvoyé par Pinterest quand le refresh token est révoqué / expiré.
const isPinterestInvalidGrant = (error) =>
  error instanceof HttpError &&
  (error.upstreamStatus === 400 ||
    error.upstreamStatus === 401 ||
    error.code === "invalid_grant");

export async function getValidPinterestToken(userId) {
  const load = async () => {
    const account = await getPinterestAccount(userId);

    if (!account) {
      throw new HttpError(
        400,
        "Pinterest account not connected",
        "PINTEREST_NOT_CONNECTED"
      );
    }

    // Jetons émis pour un autre environnement : jamais utilisés.
    if (!pinterestAccountMatchesEnv(account)) {
      throw reconnectError("Pinterest", "PINTEREST_ENV_MISMATCH");
    }

    return account;
  };

  const first = await load();
  if (isTokenFresh(first)) return first.access_token;

  return withLock(`pinterest-refresh:${userId}`, async () => {
    for (let attempt = 0; attempt < 2; attempt++) {
      // Relecture APRÈS verrou : un autre traitement a pu renouveler.
      const account = await load();

      if (isTokenFresh(account)) return account.access_token;

      if (!account.refresh_token || isPast(account.refresh_expires_at)) {
        throw reconnectError("Pinterest", "PINTEREST_REFRESH_EXPIRED");
      }

      let refreshed;

      try {
        refreshed = await pinterestApi("/oauth/token", {
          method: "POST",
          base: PINTEREST_OAUTH_BASE,
          basic: true,
          form: {
            grant_type: "refresh_token",
            refresh_token: account.refresh_token,
          },
        });
      } catch (error) {
        if (isPinterestInvalidGrant(error)) {
          throw reconnectError("Pinterest", "PINTEREST_REFRESH_EXPIRED");
        }
        throw error;
      }

      if (!refreshed?.access_token) {
        throw new HttpError(
          502,
          "Pinterest returned an invalid token response",
          "PINTEREST_BAD_TOKEN_RESPONSE"
        );
      }

      const applied = await updateTokensIfUnchanged(
        "pinterest_accounts",
        userId,
        account,
        buildPinterestTokenRow(refreshed)
      );

      if (applied) return refreshed.access_token;
    }

    throw new HttpError(
      409,
      "Pinterest account changed during token refresh, please retry",
      "PINTEREST_REFRESH_CONFLICT"
    );
  });
}
