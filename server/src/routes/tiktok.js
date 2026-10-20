// Routes /api/tiktok/* : OAuth, statut, publication vidéo / photos.

import {
  TIKTOK_CLIENT_KEY,
  TIKTOK_CLIENT_SECRET,
  TIKTOK_REDIRECT_URI,
  TIKTOK_SCOPES,
  TIKTOK_SANDBOX,
  MAX_VIDEO_SIZE,
  MAX_TIKTOK_PHOTOS,
  MAX_PHOTO_SIZE,
  MAX_PHOTOS_TOTAL,
  PUBLIC_API_URL,
  publicApiLooksLikeFrontend,
  tiktokCapabilities,
} from "../config/index.js";
import { route } from "../lib/router.js";
import { supabaseAdmin } from "../lib/supabase.js";
import { HttpError, sha256, dedupeCallback } from "../lib/utils.js";
import { getJsonBody, sendJson, tooLargeError } from "../lib/http.js";
import { parseMultipart, parseMultipartFiles } from "../lib/multipart.js";
import { sniffImageType, sniffVideoType } from "../lib/fileTypes.js";
import { acquireVideoSlot, releaseVideoSlot } from "../lib/uploadSlots.js";
import { enforce, limiterPublish } from "../lib/rateLimit.js";
import { createOAuthState, assertValidOAuthCallback } from "../lib/oauth.js";
import {
  tiktokApi,
  saveTikTokTokens,
  getTikTokAccount,
  getValidTikTokToken,
  refreshTikTokProfile,
  clearTikTokProfileThrottle,
  computeChunking,
  uploadVideoToTikTok,
  resolvePrivacy,
  resolveVideoMode,
  initTikTokPublish,
  isValidTikTokPublishId,
  removeTikTokPhotos,
  storeTikTokPhotos,
  probePublicPhotos,
  buildPhotoPostInfo,
  resolvePhotoMode,
  initTikTokPhotoPublish,
} from "../services/tiktok.js";

route(
  "POST",
  "/api/tiktok/auth/url",
  ({ res, user }) => {
    const params = new URLSearchParams({
      client_key: TIKTOK_CLIENT_KEY,
      scope: TIKTOK_SCOPES,
      response_type: "code",
      redirect_uri: TIKTOK_REDIRECT_URI,
      state: createOAuthState("tiktok", user.id),
    });

    sendJson(res, 200, {
      success: true,
      url: `https://www.tiktok.com/v2/auth/authorize/?${params.toString()}`,
      // Le frontend peut afficher l'avertissement sandbox AVANT la popup.
      capabilities: tiktokCapabilities(),
    });
  },
  { auth: true }
);

route(
  "POST",
  "/api/tiktok/auth/callback",
  async ({ req, res, user }) => {
    const body = await getJsonBody(req);
    const authCode = assertValidOAuthCallback("tiktok", body, user.id);

    const account = await dedupeCallback(
      `tiktok:${user.id}:${sha256(authCode)}`,
      async () => {
        let tokens;

        try {
          tokens = await tiktokApi("/v2/oauth/token/", {
            form: {
              client_key: TIKTOK_CLIENT_KEY,
              client_secret: TIKTOK_CLIENT_SECRET,
              code: authCode,
              grant_type: "authorization_code",
              redirect_uri: TIKTOK_REDIRECT_URI,
            },
          });
        } catch (error) {
          // En sandbox, seuls les « Sandbox testers » du portail peuvent
          // autoriser l'app : message actionnable plutôt qu'access_denied.
          if (
            error instanceof HttpError &&
            (error.code === "access_denied" ||
              /access_denied/i.test(error.message))
          ) {
            throw new HttpError(
              403,
              TIKTOK_SANDBOX
                ? "TikTok refused the connection. In sandbox mode, add the TikTok account as a Sandbox tester in the TikTok developer portal, then try again."
                : "TikTok refused the connection.",
              "TIKTOK_ACCESS_DENIED"
            );
          }
          throw error;
        }

        let profile = {};

        try {
          const info = await tiktokApi(
            "/v2/user/info/?fields=open_id,avatar_url,display_name",
            { method: "GET", token: tokens.access_token }
          );

          profile = info.data?.user || {};
        } catch (profileError) {
          console.warn("TikTok user info error:", profileError.message);
        }

        await saveTikTokTokens(user.id, tokens, {
          display_name: profile.display_name || null,
          avatar_url: profile.avatar_url || null,
        });

        return {
          display_name: profile.display_name || null,
          avatar_url: profile.avatar_url || null,
        };
      }
    );

    sendJson(res, 200, {
      success: true,
      account,
      capabilities: tiktokCapabilities(),
    });
  },
  { auth: true }
);

// `connected` reflète une connexion UTILISABLE (jeton mort → false +
// needs_reconnect). Les pannes transitoires ne cassent pas le cache frontend.
route(
  "GET",
  "/api/tiktok/status",
  async ({ res, url, user }) => {
    // ?refresh=1 : le frontend a détecté une image cassée → on ignore le
    // throttle normal (mais on respecte l'anti-martèlement court).
    const force = url.searchParams.get("refresh") === "1";

    const { account, needsReconnect } = await refreshTikTokProfile(user.id, {
      force,
    });

    const usable = Boolean(account) && !needsReconnect;

    sendJson(res, 200, {
      success: true,
      connected: usable,
      needs_reconnect: needsReconnect || undefined,
      account: usable
        ? {
            display_name: account.display_name,
            avatar_url: account.avatar_url,
            scope: account.scope,
          }
        : null,
      capabilities: tiktokCapabilities(),
    });
  },
  { auth: true }
);

route(
  "DELETE",
  "/api/tiktok/disconnect",
  async ({ res, user }) => {
    const account = await getTikTokAccount(user.id);

    if (account) {
      if (account.access_token) {
        try {
          await tiktokApi("/v2/oauth/revoke/", {
            form: {
              client_key: TIKTOK_CLIENT_KEY,
              client_secret: TIKTOK_CLIENT_SECRET,
              token: account.access_token,
            },
          });
        } catch (revokeError) {
          console.warn("TikTok revoke error:", revokeError.message);
        }
      }

      const { error } = await supabaseAdmin
        .from("tiktok_accounts")
        .delete()
        .eq("user_id", user.id);

      if (error) throw error;

      clearTikTokProfileThrottle(user.id);
    }

    sendJson(res, 200, { success: true });
  },
  { auth: true }
);

// creator_info/query est un POST : un body JSON (même vide) est requis.
route(
  "GET",
  "/api/tiktok/creator-info",
  async ({ res, user }) => {
    const accessToken = await getValidTikTokToken(user.id);

    const result = await tiktokApi("/v2/post/publish/creator_info/query/", {
      token: accessToken,
      json: {},
    });

    sendJson(res, 200, {
      success: true,
      creator: result.data,
      capabilities: tiktokCapabilities(),
    });
  },
  { auth: true }
);

// Upload de fichier. Ordre important pour la mémoire :
//   1. vérifications bon marché (token TikTok, taille annoncée)
//   2. acquisition d'un slot de concurrence
//   3. SEULEMENT ENSUITE lecture du corps (jusqu'à 100 Mo en RAM)
route(
  "POST",
  "/api/tiktok/publish",
  async ({ req, res, user }) => {
    enforce(limiterPublish, `tiktok:${user.id}`);

    const declared = Number(req.headers["content-length"] || 0);

    if (declared > MAX_VIDEO_SIZE + 1024 * 1024) {
      throw tooLargeError(
        `Video is too large. Maximum size is ${MAX_VIDEO_SIZE / 1024 / 1024} MB.`
      );
    }

    // Échoue vite si le compte n'est pas connecté / expiré.
    const accessToken = await getValidTikTokToken(user.id);

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

      // Sandbox : "direct" reste possible (SELF_ONLY forcé par
      // resolvePrivacy) ; FORCE_DRAFT bascule tout en brouillon.
      const requestedMode = upload.fields.mode === "draft" ? "draft" : "direct";
      const mode = resolveVideoMode(requestedMode);
      const chunking = computeChunking(upload.buffer.length);

      const sourceInfo = {
        source: "FILE_UPLOAD",
        video_size: upload.buffer.length,
        chunk_size: chunking.chunkSize,
        total_chunk_count: chunking.totalChunks,
      };

      const init = await initTikTokPublish(
        accessToken,
        mode,
        upload.fields,
        sourceInfo
      );

      await uploadVideoToTikTok(
        init.data.upload_url,
        upload.buffer,
        mimeType,
        chunking
      );

      sendJson(res, 200, {
        success: true,
        mode,
        // mode demandé ≠ mode effectif quand FORCE_DRAFT est actif.
        requested_mode: requestedMode,
        forced_privacy_level:
          mode === "direct" ? resolvePrivacy(upload.fields.privacy_level) : null,
        sandbox: TIKTOK_SANDBOX,
        publish_id: init.data.publish_id,
      });
    } finally {
      releaseVideoSlot();
    }
  },
  { auth: true }
);

route(
  "POST",
  "/api/tiktok/publish_url",
  async ({ req, res, user }) => {
    enforce(limiterPublish, `tiktok:${user.id}`);

    const body = await getJsonBody(req);
    const videoUrl = String(body.videoUrl || "").trim();

    if (!/^https:\/\//i.test(videoUrl) || videoUrl.length > 2048) {
      throw new HttpError(400, "videoUrl must be a valid https URL");
    }

    const requestedMode = body.mode === "draft" ? "draft" : "direct";
    const mode = resolveVideoMode(requestedMode);
    const accessToken = await getValidTikTokToken(user.id);

    const init = await initTikTokPublish(accessToken, mode, body, {
      source: "PULL_FROM_URL",
      video_url: videoUrl,
    });

    sendJson(res, 200, {
      success: true,
      mode,
      requested_mode: requestedMode,
      forced_privacy_level:
        mode === "direct" ? resolvePrivacy(body.privacy_level) : null,
      sandbox: TIKTOK_SANDBOX,
      publish_id: init.data.publish_id,
    });
  },
  { auth: true }
);

// Photo(s) : 1 image = post photo, 2 à 35 images = carrousel.
// EN SANDBOX : mode brouillon forcé (MEDIA_UPLOAD).
route(
  "POST",
  "/api/tiktok/publish/photos",
  async ({ req, res, user }) => {
    if (!PUBLIC_API_URL) {
      throw new HttpError(
        500,
        "Photo publishing is not configured (PUBLIC_API_URL / VITE_API_BASE_URL missing)",
        "PUBLIC_API_URL_MISSING"
      );
    }

    if (!PUBLIC_API_URL.startsWith("https://")) {
      throw new HttpError(
        500,
        "PUBLIC_API_URL must use https for TikTok photo publishing",
        "PUBLIC_API_URL_NOT_HTTPS"
      );
    }

    if (publicApiLooksLikeFrontend()) {
      throw new HttpError(
        500,
        "PUBLIC_API_URL points to the frontend instead of the API server",
        "PUBLIC_API_URL_WRONG_HOST"
      );
    }

    enforce(limiterPublish, `tiktok:${user.id}`);

    const declared = Number(req.headers["content-length"] || 0);

    if (declared > MAX_PHOTOS_TOTAL + 1024 * 1024) {
      throw tooLargeError(
        `Photos are too large. Maximum total size is ${MAX_PHOTOS_TOTAL / 1024 / 1024} MB.`
      );
    }

    const accessToken = await getValidTikTokToken(user.id);

    // Même sémaphore que les vidéos : borne la mémoire utilisée.
    await acquireVideoSlot();

    let storedNames = [];

    try {
      let upload;

      try {
        upload = await parseMultipartFiles(req, {
          fileField: "photos",
          maxFiles: MAX_TIKTOK_PHOTOS,
          maxFileSize: MAX_PHOTO_SIZE,
        });
      } catch (error) {
        if (error?.code === "FILE_TOO_LARGE") {
          throw new HttpError(
            400,
            `Each photo must be under ${MAX_PHOTO_SIZE / 1024 / 1024} MB.`
          );
        }
        if (error?.code === "TOO_MANY_FILES") {
          throw new HttpError(
            400,
            `TikTok carousels are limited to ${MAX_TIKTOK_PHOTOS} photos.`
          );
        }
        if (error?.code === "NO_FILE") {
          throw new HttpError(400, "No photos were provided.");
        }
        throw error instanceof HttpError
          ? error
          : new HttpError(400, "Could not read the uploaded files.");
      }

      const photos = [];
      let totalSize = 0;

      for (const file of upload.files) {
        const type = sniffImageType(file.buffer);

        if (type !== "image/jpeg" && type !== "image/webp") {
          throw new HttpError(
            400,
            "Unsupported image format. TikTok accepts JPEG and WebP."
          );
        }

        totalSize += file.buffer.length;
        photos.push({ buffer: file.buffer, type });
      }

      if (totalSize > MAX_PHOTOS_TOTAL) {
        throw tooLargeError(
          `Photos are too large. Maximum total size is ${MAX_PHOTOS_TOTAL / 1024 / 1024} MB.`
        );
      }

      const fields = upload.fields;
      const requestedMode = fields.mode === "draft" ? "draft" : "direct";
      // SANDBOX : resolvePhotoMode() force "draft" tant que l'app n'est pas
      // auditée (les photos DIRECT_POST sont refusées).
      const mode = resolvePhotoMode(requestedMode);

      // Validé AVANT de stocker les photos (ex. contenu de marque en privé).
      const postInfo = buildPhotoPostInfo(mode, fields);

      // Le frontend envoie cover_index à partir de 1 ; TikTok attend un
      // index à partir de 0 : on convertit et on borne.
      const requestedCover = Number.parseInt(fields.cover_index, 10);
      const coverIndex = Math.min(
        Math.max((Number.isFinite(requestedCover) ? requestedCover : 1) - 1, 0),
        photos.length - 1
      );

      storedNames = await storeTikTokPhotos(photos);
      upload = null; // libère les buffers

      const imageUrls = storedNames.map(
        (name) => `${PUBLIC_API_URL}/api/media/tiktok/${name}`
      );

      // Vérifie que TikTok pourra réellement télécharger TOUTES les images.
      await probePublicPhotos(imageUrls);

      const init = await initTikTokPhotoPublish(
        accessToken,
        mode,
        postInfo,
        imageUrls,
        coverIndex
      );

      // Les fichiers restent disponibles : TikTok les télécharge de façon
      // asynchrone. Le balayage périodique les supprime ensuite.
      sendJson(res, 200, {
        success: true,
        mode,
        requested_mode: requestedMode,
        sandbox: TIKTOK_SANDBOX,
        publish_id: init.data.publish_id,
        photo_count: photos.length,
      });
    } catch (error) {
      if (storedNames.length > 0) await removeTikTokPhotos(storedNames);
      throw error;
    } finally {
      releaseVideoSlot();
    }
  },
  { auth: true }
);

route(
  "GET",
  "/api/tiktok/publish/status",
  async ({ res, url, user }) => {
    const publishId = url.searchParams.get("publish_id");

    // Les publish_id TikTok contiennent parfois « ~ » ; 64 caractères max.
    if (!isValidTikTokPublishId(publishId)) {
      throw new HttpError(400, "Missing or invalid publish_id");
    }

    const accessToken = await getValidTikTokToken(user.id);

    const result = await tiktokApi("/v2/post/publish/status/fetch/", {
      token: accessToken,
      json: { publish_id: publishId },
    });

    sendJson(res, 200, { success: true, ...result.data });
  },
  { auth: true }
);
