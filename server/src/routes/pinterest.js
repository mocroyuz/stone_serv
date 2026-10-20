// Routes /api/pinterest/*

import {
  PINTEREST_APP_ID,
  PINTEREST_REDIRECT_URI,
  PINTEREST_SCOPES,
  PINTEREST_AUTH_URL,
  PINTEREST_OAUTH_BASE,
  env,
} from "../config/index.js";
import { route } from "../lib/router.js";
import { supabaseAdmin } from "../lib/supabase.js";
import { HttpError, sha256, dedupeCallback } from "../lib/utils.js";
import { getJsonBody, sendJson } from "../lib/http.js";
import { createOAuthState, assertValidOAuthCallback } from "../lib/oauth.js";
import {
  pinterestApi,
  savePinterestTokens,
  getPinterestAccount,
  pinterestAccountMatchesEnv,
} from "../services/pinterest.js";

route(
  "POST",
  "/api/pinterest/auth/url",
  ({ res, user }) => {
    const params = new URLSearchParams({
      client_id: PINTEREST_APP_ID,
      redirect_uri: PINTEREST_REDIRECT_URI,
      response_type: "code",
      scope: PINTEREST_SCOPES,
      state: createOAuthState("pinterest", user.id),
    });

    sendJson(res, 200, {
      success: true,
      url: `${PINTEREST_AUTH_URL}?${params.toString()}`,
    });
  },
  { auth: true }
);

// L'échange du code utilise l'endpoint OAuth de l'environnement choisi ;
// le compte est enregistré avec cet environnement (api_env).
route(
  "POST",
  "/api/pinterest/auth/callback",
  async ({ req, res, user }) => {
    const body = await getJsonBody(req);
    const authCode = assertValidOAuthCallback("pinterest", body, user.id);

    const account = await dedupeCallback(
      `pinterest:${user.id}:${sha256(authCode)}`,
      async () => {
        const tokens = await pinterestApi("/oauth/token", {
          method: "POST",
          base: PINTEREST_OAUTH_BASE,
          basic: true,
          form: {
            grant_type: "authorization_code",
            code: authCode,
            redirect_uri: PINTEREST_REDIRECT_URI,
          },
        });

        if (!tokens?.access_token) {
          throw new HttpError(
            502,
            "Pinterest returned an invalid token response",
            "PINTEREST_BAD_TOKEN_RESPONSE"
          );
        }

        let profile = {};

        try {
          profile = await pinterestApi("/user_account", {
            token: tokens.access_token,
          });
        } catch (profileError) {
          console.warn("Pinterest user_account error:", profileError.message);
        }

        await savePinterestTokens(user.id, tokens, {
          username: profile.username || null,
          avatar_url: profile.profile_image || null,
          account_type: profile.account_type || null,
        });

        return {
          display_name: profile.username || null,
          avatar_url: profile.profile_image || null,
          account_type: profile.account_type || null,
        };
      }
    );

    sendJson(res, 200, { success: true, connected: true, account });
  },
  { auth: true }
);

// Connexion par token manuel (DEV / SANDBOX uniquement).
route(
  "POST",
  "/api/pinterest/auth/token",
  async ({ req, res, user }) => {
    if (env("PINTEREST_ALLOW_MANUAL_TOKEN") !== "1") {
      throw new HttpError(403, "Manual token connection is disabled");
    }

    const body = await getJsonBody(req);
    const accessToken = String(body.access_token || "").trim();

    if (!accessToken || accessToken.length > 4096) {
      throw new HttpError(400, "Missing access_token");
    }

    let profile;

    try {
      profile = await pinterestApi("/user_account", { token: accessToken });
    } catch (profileError) {
      throw new HttpError(
        400,
        `Invalid Pinterest token: ${profileError.message}`
      );
    }

    await savePinterestTokens(
      user.id,
      {
        access_token: accessToken,
        refresh_token: null,
        expires_in: 29 * 24 * 60 * 60,
        refresh_token_expires_in: 29 * 24 * 60 * 60,
      },
      {
        username: profile.username || null,
        avatar_url: profile.profile_image || null,
        account_type: profile.account_type || null,
      }
    );

    sendJson(res, 200, {
      success: true,
      connected: true,
      account: {
        display_name: profile.username || null,
        avatar_url: profile.profile_image || null,
        account_type: profile.account_type || null,
      },
    });
  },
  { auth: true }
);

// Un compte relié dans un AUTRE environnement n'est pas présenté comme
// connecté : needs_reconnect = true.
route(
  "GET",
  "/api/pinterest/status",
  async ({ res, user }) => {
    const account = await getPinterestAccount(user.id);
    const usable = pinterestAccountMatchesEnv(account);

    sendJson(res, 200, {
      success: true,
      connected: usable,
      account: usable
        ? {
            display_name: account.username,
            avatar_url: account.avatar_url,
            account_type: account.account_type,
            scope: account.scope,
          }
        : null,
      ...(account && !usable ? { needs_reconnect: true } : {}),
    });
  },
  { auth: true }
);

route(
  "DELETE",
  "/api/pinterest/disconnect",
  async ({ res, user }) => {
    const { error } = await supabaseAdmin
      .from("pinterest_accounts")
      .delete()
      .eq("user_id", user.id);

    if (error) throw error;

    sendJson(res, 200, { success: true });
  },
  { auth: true }
);
