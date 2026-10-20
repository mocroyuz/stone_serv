// Configuration Canva (Connect API, OAuth PKCE).

import { env } from "./env.js";
import { APP_URL } from "./app.js";

export const CANVA_CLIENT_ID = env("CANVA_CLIENT_ID");
export const CANVA_CLIENT_SECRET = env("CANVA_CLIENT_SECRET");
export const CANVA_REDIRECT_URI =
  env("CANVA_REDIRECT_URI") || `${APP_URL}/canva/callback`;

export const CANVA_SCOPES =
  env("CANVA_SCOPES") ||
  "design:content:read design:content:write design:meta:read profile:read";

export const CANVA_API_BASE = "https://api.canva.com/rest/v1";
export const CANVA_AUTH_URL = "https://www.canva.com/api/oauth/authorize";

export const canvaEnabled = Boolean(CANVA_CLIENT_ID && CANVA_CLIENT_SECRET);
