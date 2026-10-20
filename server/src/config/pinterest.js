// Configuration Pinterest. L'environnement (sandbox / production) est déduit
// de PINTEREST_API_BASE (défaut : SANDBOX). L'endpoint OAuth est dérivé du
// MÊME environnement ; en cas d'incohérence les routes répondent 500.

import { env } from "./env.js";
import { APP_URL } from "./app.js";

export const PINTEREST_APP_ID = env("PINTEREST_APP_ID");
export const PINTEREST_APP_SECRET = env("PINTEREST_APP_SECRET");
export const PINTEREST_REDIRECT_URI =
  env("PINTEREST_REDIRECT_URI") || `${APP_URL}/pinterest/callback`;

export const PINTEREST_SCOPES =
  env("PINTEREST_SCOPES") ||
  "user_accounts:read,boards:read,boards:write,pins:read,pins:write";

const PINTEREST_PROD_API_BASE = "https://api.pinterest.com/v5";
const PINTEREST_SANDBOX_API_BASE = "https://api-sandbox.pinterest.com/v5";

const trimSlashes = (value) => String(value).trim().replace(/\/+$/, "");
const isSandboxUrl = (value) => /sandbox/i.test(String(value));

export const PINTEREST_AUTH_URL =
  env("PINTEREST_AUTH_URL") || "https://www.pinterest.com/oauth/";

export const PINTEREST_API_BASE = trimSlashes(
  env("PINTEREST_API_BASE") || PINTEREST_SANDBOX_API_BASE
);

export const PINTEREST_ENVIRONMENT = isSandboxUrl(PINTEREST_API_BASE)
  ? "sandbox"
  : "production";

export const PINTEREST_OAUTH_BASE = trimSlashes(
  env("PINTEREST_OAUTH_BASE") ||
    (PINTEREST_ENVIRONMENT === "sandbox"
      ? PINTEREST_SANDBOX_API_BASE
      : PINTEREST_PROD_API_BASE)
);

export const pinterestEnabled = Boolean(PINTEREST_APP_ID && PINTEREST_APP_SECRET);

export const pinterestConfigError = (() => {
  for (const [label, value] of [
    ["PINTEREST_API_BASE", PINTEREST_API_BASE],
    ["PINTEREST_OAUTH_BASE", PINTEREST_OAUTH_BASE],
    ["PINTEREST_AUTH_URL", PINTEREST_AUTH_URL],
  ]) {
    try {
      const parsed = new URL(value);

      if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
        return `${label} invalide`;
      }
    } catch {
      return `${label} invalide`;
    }
  }

  if (isSandboxUrl(PINTEREST_OAUTH_BASE) !== isSandboxUrl(PINTEREST_API_BASE)) {
    return "PINTEREST_API_BASE et PINTEREST_OAUTH_BASE ne sont pas du même environnement (sandbox / production)";
  }

  return null;
})();

export const pinterestUsable = pinterestEnabled && !pinterestConfigError;
