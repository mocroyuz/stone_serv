// Routes /api/youtube/*

import {
  YOUTUBE_CLIENT_ID,
  YOUTUBE_CLIENT_SECRET,
  YOUTUBE_REDIRECT_URI,
  YOUTUBE_SCOPES,
  YOUTUBE_UPLOAD_SCOPE,
  GOOGLE_AUTH_URL,
  GOOGLE_TOKEN_URL,
  GOOGLE_REVOKE_URL,
  MAX_VIDEO_SIZE,
} from "../config/index.js";
import { route } from "../lib/router.js";
import { supabaseAdmin } from "../lib/supabase.js";
import { HttpError, sha256, dedupeCallback } from "../lib/utils.js";
import { getJsonBody, sendJson, tooLargeError } from "../lib/http.js";
import { parseMultipart } from "../lib/multipart.js";
import { sniffVideoType } from "../lib/fileTypes.js";
import { acquireVideoSlot, releaseVideoSlot } from "../lib/uploadSlots.js";
import { enforce, limiterPublish } from "../lib/rateLimit.js";
import { createOAuthState, assertValidOAuthCallback } from "../lib/oauth.js";
import {
  googleRequest,
  fetchYouTubeChannel,
  saveYouTubeTokens,
  getYouTubeAccount,
  getValidYouTubeToken,
  buildYouTubeMetadata,
  initYouTubeUpload,
  uploadVideoToYouTube,
} from "../services/youtube.js";

route(
  "POST",
  "/api/youtube/auth/url",
  ({ res, user }) => {
    const params = new URLSearchParams({
      client_id: YOUTUBE_CLIENT_ID,
      redirect_uri: YOUTUBE_REDIRECT_URI,
      response_type: "code",
      scope: YOUTUBE_SCOPES,
      access_type: "offline",
      prompt: "consent",
      include_granted_scopes: "true",
      state: createOAuthState("youtube", user.id),
    });

    sendJson(res, 200, {
      success: true,
      url: `${GOOGLE_AUTH_URL}?${params.toString()}`,
    });
  },
  { auth: true }
);

// Si le lookup de chaîne ÉCHOUE ou s'il n'y a pas de chaîne, on REFUSE la
// connexion (et on révoque l'accès) au lieu de sauvegarder un compte sans chaîne.
route(
  "POST",
  "/api/youtube/auth/callback",
  async ({ req, res, user }) => {
    const body = await getJsonBody(req);
    const authCode = assertValidOAuthCallback("youtube", body, user.id);

    const account = await dedupeCallback(
      `youtube:${user.id}:${sha256(authCode)}`,
      async () => {
        const tokens = await googleRequest(GOOGLE_TOKEN_URL, {
          method: "POST",
          form: {
            client_id: YOUTUBE_CLIENT_ID,
            client_secret: YOUTUBE_CLIENT_SECRET,
            code: authCode,
            grant_type: "authorization_code",
            redirect_uri: YOUTUBE_REDIRECT_URI,
          },
        });

        let channel = null;

        try {
          channel = await fetchYouTubeChannel(tokens.access_token);
        } catch (channelError) {
          console.warn("YouTube channels error:", channelError.message);
        }

        if (!channel) {
          try {
            await googleRequest(GOOGLE_REVOKE_URL, {
              method: "POST",
              form: { token: tokens.refresh_token || tokens.access_token },
            });
          } catch {
            // ignore
          }

          throw new HttpError(
            400,
            "No YouTube channel found on this Google account. Create a channel on youtube.com, then try again."
          );
        }

        await saveYouTubeTokens(
          user.id,
          {
            ...tokens,
            refresh_token_expires_in: tokens.refresh_token_expires_in ?? null,
          },
          {
            channel_id: channel.id,
            channel_title: channel.title || null,
            custom_url: channel.customUrl || null,
            avatar_url: channel.avatarUrl || null,
          }
        );

        return {
          display_name: channel.title || null,
          avatar_url: channel.avatarUrl || null,
        };
      }
    );

    sendJson(res, 200, { success: true, connected: true, account });
  },
  { auth: true }
);

// Publication d'une vidéo YouTube.
// multipart/form-data :
//   video (fichier) · title · description · tags (JSON ou "a,b")
//   privacy_level (public|unlisted|private) · made_for_kids ("true"|"false")
//   publish_at (ISO 8601, optionnel → programmation) · category_id (optionnel)
route(
  "POST",
  "/api/youtube/publish",
  async ({ req, res, user }) => {
    enforce(limiterPublish, `youtube:${user.id}`);

    const declared = Number(req.headers["content-length"] || 0);

    if (declared > MAX_VIDEO_SIZE + 1024 * 1024) {
      throw tooLargeError(
        `Video is too large. Maximum size is ${MAX_VIDEO_SIZE / 1024 / 1024} MB.`
      );
    }

    // Échoue vite si la chaîne n'est pas connectée / expirée.
    const accessToken = await getValidYouTubeToken(user.id);

    await acquireVideoSlot();

    try {
      let upload;

      try {
        upload = await parseMultipart(req, {
          fileField: "video",
          maxSize: MAX_VIDEO_SIZE,
        });
      } catch (error) {
        if (error?.code === "FILE_TOO_LARGE") {
          throw new HttpError(
            400,
            `Video is too large. Maximum size is ${MAX_VIDEO_SIZE / 1024 / 1024} MB.`
          );
        }
        if (error?.code === "NO_FILE") {
          throw new HttpError(400, "No 'video' file was provided.");
        }
        throw error instanceof HttpError
          ? error
          : new HttpError(400, "Could not read the uploaded file.");
      }

      const mimeType = sniffVideoType(upload.buffer);

      if (!mimeType) {
        throw new HttpError(400, "Unsupported format. Use MP4, MOV or WebM.");
      }

      // Validé AVANT tout appel à YouTube.
      const { privacy, publishAt, metadata } = buildYouTubeMetadata(upload.fields);

      const uploadUrl = await initYouTubeUpload(
        accessToken,
        metadata,
        upload.buffer.length,
        mimeType
      );

      const video = await uploadVideoToYouTube(uploadUrl, upload.buffer, mimeType);

      if (!video?.id) {
        throw new HttpError(
          502,
          "YouTube did not confirm the upload",
          "YOUTUBE_NO_VIDEO_ID"
        );
      }

      const actualPrivacy = video.status?.privacyStatus || null;

      // Projet Google API non vérifié : YouTube force les vidéos en privé.
      const privacyLocked =
        !publishAt && privacy !== "private" && actualPrivacy === "private";

      sendJson(res, 200, {
        success: true,
        video_id: video.id,
        url: `https://www.youtube.com/watch?v=${video.id}`,
        privacy_status: actualPrivacy,
        requested_privacy: privacy,
        publish_at: publishAt,
        upload_status: video.status?.uploadStatus || null,
        privacy_locked: privacyLocked,
      });
    } finally {
      releaseVideoSlot();
    }
  },
  { auth: true }
);

route(
  "GET",
  "/api/youtube/status",
  async ({ res, user }) => {
    const account = await getYouTubeAccount(user.id);

    sendJson(res, 200, {
      success: true,
      connected: Boolean(account),
      account: account
        ? {
            display_name: account.channel_title,
            avatar_url: account.avatar_url,
            custom_url: account.custom_url,
            scope: account.scope,
            // false → l'utilisateur doit reconnecter YouTube (scope upload absent)
            can_publish: String(account.scope || "")
              .split(/[\s,]+/)
              .includes(YOUTUBE_UPLOAD_SCOPE),
          }
        : null,
    });
  },
  { auth: true }
);

route(
  "DELETE",
  "/api/youtube/disconnect",
  async ({ res, user }) => {
    const account = await getYouTubeAccount(user.id);

    if (account) {
      const tokenToRevoke = account.refresh_token || account.access_token;

      if (tokenToRevoke) {
        try {
          await googleRequest(GOOGLE_REVOKE_URL, {
            method: "POST",
            form: { token: tokenToRevoke },
          });
        } catch (revokeError) {
          console.warn("YouTube revoke error:", revokeError.message);
        }
      }

      const { error } = await supabaseAdmin
        .from("youtube_accounts")
        .delete()
        .eq("user_id", user.id);

      if (error) throw error;
    }

    sendJson(res, 200, { success: true });
  },
  { auth: true }
);
