// Routes /api/canva/*
//
//   1. POST /api/canva/auth/url       → URL d'autorisation + PKCE
//   2. (redirection Canva) → /canva/callback (frontend)
//   3. POST /api/canva/auth/callback  → échange code + verifier
//   4. POST /api/canva/designs        → crée un design vide
//   5. POST /api/canva/export         → exporte en PNG (base64)

import {
  CANVA_CLIENT_ID,
  CANVA_REDIRECT_URI,
  CANVA_SCOPES,
  CANVA_AUTH_URL,
} from "../config/index.js";
import { route } from "../lib/router.js";
import { supabaseAdmin } from "../lib/supabase.js";
import {
  HttpError,
  sha256,
  dedupeCallback,
  delay,
  upstreamError,
} from "../lib/utils.js";
import { getJsonBody, sendJson, tooLargeError } from "../lib/http.js";
import { sniffImageType } from "../lib/fileTypes.js";
import { enforce, limiterCanva } from "../lib/rateLimit.js";
import { createOAuthState, assertValidOAuthCallback } from "../lib/oauth.js";
import {
  createCanvaPkce,
  takeCanvaVerifier,
  canvaApi,
  saveCanvaTokens,
  getCanvaAccount,
  getValidCanvaToken,
} from "../services/canva.js";

route(
  "POST",
  "/api/canva/auth/url",
  ({ res, user }) => {
    const state = createOAuthState("canva", user.id);

    const params = new URLSearchParams({
      response_type: "code",
      client_id: CANVA_CLIENT_ID,
      redirect_uri: CANVA_REDIRECT_URI,
      scope: CANVA_SCOPES,
      code_challenge: createCanvaPkce(state),
      code_challenge_method: "S256",
      state,
    });

    sendJson(res, 200, {
      success: true,
      url: `${CANVA_AUTH_URL}?${params.toString()}`,
    });
  },
  { auth: true }
);

route(
  "POST",
  "/api/canva/auth/callback",
  async ({ req, res, user }) => {
    const body = await getJsonBody(req);
    const authCode = assertValidOAuthCallback("canva", body, user.id);
    const state = String(body.state);

    await dedupeCallback(`canva:${user.id}:${sha256(authCode)}`, async () => {
      const verifier = takeCanvaVerifier(state);

      if (!verifier) {
        throw new HttpError(400, "Invalid or expired state", "OAUTH_STATE_INVALID");
      }

      const tokens = await canvaApi("/oauth/token", {
        method: "POST",
        basic: true,
        form: {
          grant_type: "authorization_code",
          code: authCode,
          code_verifier: verifier,
          redirect_uri: CANVA_REDIRECT_URI,
        },
      });

      if (!tokens?.access_token) {
        throw new HttpError(502, "Canva returned an invalid token response", "CANVA_BAD_TOKEN_RESPONSE");
      }

      let displayName = null;

      try {
        const profile = await canvaApi("/users/me/profile", { token: tokens.access_token });
        displayName = profile.profile?.display_name || null;
      } catch (profileError) {
        console.warn("Canva profile error:", profileError.message);
      }

      await saveCanvaTokens(user.id, tokens, { display_name: displayName });

      return { display_name: displayName };
    });

    sendJson(res, 200, { success: true, connected: true });
  },
  { auth: true }
);

route(
  "GET",
  "/api/canva/status",
  async ({ res, user }) => {
    const account = await getCanvaAccount(user.id);

    sendJson(res, 200, {
      success: true,
      connected: Boolean(account),
      account: account ? { display_name: account.display_name } : null,
    });
  },
  { auth: true }
);

route(
  "DELETE",
  "/api/canva/disconnect",
  async ({ res, user }) => {
    const account = await getCanvaAccount(user.id);

    if (account) {
      const tokenToRevoke = account.refresh_token || account.access_token;

      if (tokenToRevoke) {
        try {
          await canvaApi("/oauth/revoke", {
            method: "POST",
            basic: true,
            form: { token: tokenToRevoke },
          });
        } catch (revokeError) {
          console.warn("Canva revoke error:", revokeError.message);
        }
      }

      const { error } = await supabaseAdmin
        .from("canva_accounts")
        .delete()
        .eq("user_id", user.id);

      if (error) throw error;
    }

    sendJson(res, 200, { success: true });
  },
  { auth: true }
);

// Crée un design vide aux dimensions choisies (40 à 8000 px) et renvoie
// l'URL de l'éditeur Canva.
route(
  "POST",
  "/api/canva/designs",
  async ({ req, res, user }) => {
    enforce(limiterCanva, `canva:${user.id}`);

    const body = await getJsonBody(req);
    const width = Number(body.width);
    const height = Number(body.height);

    const valid = (n) => Number.isInteger(n) && n >= 40 && n <= 8000;

    if (!valid(width) || !valid(height)) {
      throw new HttpError(400, "Invalid design size (40 to 8000 px).");
    }

    const title = String(body.title || "Stone post").slice(0, 255);
    const token = await getValidCanvaToken(user.id);

    const data = await canvaApi("/designs", {
      method: "POST",
      token,
      json: { design_type: { type: "custom", width, height }, title },
    });

    const design = data.design;

    if (!design?.id || !design.urls?.edit_url) {
      throw new HttpError(502, "Canva did not return a design", "CANVA_NO_DESIGN");
    }

    sendJson(res, 200, {
      success: true,
      design_id: design.id,
      edit_url: design.urls.edit_url,
    });
  },
  { auth: true }
);

// Exporte le design en PNG et renvoie les pages en base64.
const CANVA_EXPORT_MAX_PAGES = 10;
const CANVA_EXPORT_MAX_TOTAL = 30 * 1024 * 1024;

route(
  "POST",
  "/api/canva/export",
  async ({ req, res, user }) => {
    enforce(limiterCanva, `canva:${user.id}`);

    const body = await getJsonBody(req);
    const designId = String(body.design_id || "");

    if (!/^[A-Za-z0-9_-]{1,64}$/.test(designId)) {
      throw new HttpError(400, "Invalid design_id");
    }

    const token = await getValidCanvaToken(user.id);

    const created = await canvaApi("/exports", {
      method: "POST",
      token,
      json: { design_id: designId, format: { type: "png" } },
    });

    const jobId = created.job?.id;

    if (!jobId) throw new HttpError(502, "Canva did not start the export", "CANVA_NO_EXPORT_JOB");

    let urls = null;

    for (let attempt = 0; attempt < 30; attempt++) {
      await delay(1000);

      const poll = await canvaApi(`/exports/${encodeURIComponent(jobId)}`, { token });
      const job = poll.job;

      if (job?.status === "success") {
        urls = Array.isArray(job.urls) ? job.urls : [];
        break;
      }

      if (job?.status === "failed") {
        throw new HttpError(
          502,
          job.error?.message || "Canva could not export this design.",
          "CANVA_EXPORT_FAILED"
        );
      }
    }

    if (!urls) {
      throw new HttpError(504, "Canva export timed out, please retry", "CANVA_EXPORT_TIMEOUT");
    }

    const pages = [];
    let total = 0;

    for (const fileUrl of urls.slice(0, CANVA_EXPORT_MAX_PAGES)) {
      if (typeof fileUrl !== "string" || !fileUrl.startsWith("https://")) continue;

      let download;

      try {
        download = await fetch(fileUrl);
      } catch (error) {
        throw upstreamError("Canva", error);
      }

      if (!download.ok) {
        throw new HttpError(502, "Could not download the exported design", "CANVA_DOWNLOAD_FAILED");
      }

      const buffer = Buffer.from(await download.arrayBuffer());
      const mime = sniffImageType(buffer);

      if (mime !== "image/png" && mime !== "image/jpeg") continue;

      total += buffer.length;

      if (total > CANVA_EXPORT_MAX_TOTAL) {
        throw tooLargeError("The exported design is too large.");
      }

      pages.push({ mime, data: buffer.toString("base64") });
    }

    if (pages.length === 0) {
      throw new HttpError(502, "Canva returned no image", "CANVA_EMPTY_EXPORT");
    }

    sendJson(res, 200, { success: true, pages });
  },
  { auth: true }
);
