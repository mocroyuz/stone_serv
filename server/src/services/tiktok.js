// Service TikTok : appel API, tokens, profil, upload vidéo, privacy/modes,
// photos (carrousel).

import crypto from "node:crypto";
import {
  TIKTOK_CLIENT_KEY,
  TIKTOK_CLIENT_SECRET,
  TIKTOK_API,
  TIKTOK_PRIVACY_LEVELS,
  TIKTOK_SANDBOX,
  TIKTOK_FORCE_DRAFT,
  TIKTOK_MEDIA_BUCKET,
  TIKTOK_MEDIA_TTL_MS,
  env,
} from "../config/index.js";
import { supabaseAdmin } from "../lib/supabase.js";
import { sendJson } from "../lib/http.js";
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
  delay,
  iso,
  isPast,
  toBool,
} from "../lib/utils.js";

// Messages lisibles pour les erreurs TikTok les plus fréquentes.
const TIKTOK_FRIENDLY_ERRORS = {
  unaudited_client_can_only_post_to_private_accounts:
    "Mode sandbox : TikTok n'accepte que des posts privés (SELF_ONLY) tant que l'app n'est pas auditée. Définis privacy_level=SELF_ONLY ou passe en mode brouillon.",
  url_ownership_unverified:
    "TikTok could not verify the media URL prefix. Check PUBLIC_API_URL and the URL properties in the TikTok developer portal.",
  spam_risk_too_many_posts:
    "TikTok daily posting limit reached. Please try again later.",
  spam_risk_user_banned_from_posting:
    "This TikTok account cannot post right now.",
  reached_active_user_cap:
    "TikTok daily user cap reached for this app. Try again later.",
  // Brouillons photo (MEDIA_UPLOAD) : appli TikTok trop ancienne (< 31.8).
  app_version_check_failed:
    "Please update your TikTok app to the latest version to use this feature, then try again.",
  // En sandbox, seuls les « Sandbox testers » peuvent autoriser l'app.
  access_denied:
    "Connection refused by TikTok. In sandbox mode, add the TikTok account as a Sandbox tester in the TikTok developer portal, then try again.",
};

export async function tiktokApi(pathname, { method = "POST", token, json, form } = {}) {
  const headers = {};
  let body;

  if (token) headers.Authorization = `Bearer ${token}`;

  if (form) {
    headers["Content-Type"] = "application/x-www-form-urlencoded";
    body = new URLSearchParams(form).toString();
  } else if (json) {
    headers["Content-Type"] = "application/json; charset=UTF-8";
    body = JSON.stringify(json);
  }

  let result;

  try {
    result = await fetchJson(
      `${TIKTOK_API}${pathname}`,
      { method, headers, body },
      20_000
    );
  } catch (error) {
    throw upstreamError("TikTok", error);
  }

  const { response, data } = result;

  // Erreurs OAuth (/oauth/token, /oauth/revoke...)
  if (typeof data.error === "string") {
    throw new HttpError(400, data.error_description || data.error, data.error);
  }

  // Erreurs API ("ok" = succès)
  if (data.error?.code && data.error.code !== "ok") {
    console.error(
      "[tiktok]",
      pathname,
      JSON.stringify({
        code: data.error.code,
        message: data.error.message,
        log_id: data.error.log_id,
      })
    );

    throw new HttpError(
      400,
      TIKTOK_FRIENDLY_ERRORS[data.error.code] ||
        data.error.message ||
        data.error.code,
      data.error.code
    );
  }

  if (!response.ok) {
    throw new HttpError(
      upstreamStatus(response.status),
      `TikTok error (HTTP ${response.status})`,
      "TIKTOK_UPSTREAM"
    );
  }

  return data;
}

// ============================================================
// Stockage / refresh des tokens
// ============================================================

// Throttles de rafraîchissement du PROFIL (avatar).
const TIKTOK_PROFILE_REFRESH_MS = 30 * 60 * 1000;
const TIKTOK_PROFILE_MIN_INTERVAL_MS = 10 * 1000;
const TIKTOK_PROFILE_TRANSIENT_RETRY_MS = 30 * 1000;
const TIKTOK_PROFILE_DEAD_RETRY_MS = 5 * 60 * 1000;

const tiktokProfileRefreshedAt = new Map();
const tiktokProfileRetryAt = new Map();

export function clearTikTokProfileThrottle(userId) {
  tiktokProfileRefreshedAt.delete(userId);
  tiktokProfileRetryAt.delete(userId);
}

// Un champ absent de la réponse du provider n'est PAS écrasé.
function buildTikTokTokenRow(t) {
  const now = Date.now();
  const accessTtl = Number(t.expires_in) || 24 * 60 * 60;

  const row = {
    access_token: encryptSecret(t.access_token),
    access_expires_at: iso(now + accessTtl * 1000),
    updated_at: new Date().toISOString(),
  };

  if (t.open_id) row.open_id = t.open_id;
  if (t.refresh_token) row.refresh_token = encryptSecret(t.refresh_token);

  const refreshTtl = Number(t.refresh_expires_in);
  if (Number.isFinite(refreshTtl) && refreshTtl > 0) {
    row.refresh_expires_at = iso(now + refreshTtl * 1000);
  }

  if (t.scope) row.scope = t.scope;

  return row;
}

// Connexion initiale : crée ou remplace la ligne.
export async function saveTikTokTokens(userId, t, extra = {}) {
  const { error } = await supabaseAdmin.from("tiktok_accounts").upsert(
    {
      user_id: userId,
      ...buildTikTokTokenRow(t),
      ...extra,
    },
    { onConflict: "user_id" }
  );

  if (error) throw new Error(error.message);

  // Le prochain GET /api/tiktok/status récupère immédiatement l'avatar.
  clearTikTokProfileThrottle(userId);
}

export async function getTikTokAccount(userId) {
  return selectTokenRow("tiktok_accounts", userId);
}

export async function getValidTikTokToken(userId) {
  const notConnected = () =>
    new HttpError(400, "TikTok account not connected", "TIKTOK_NOT_CONNECTED");

  const first = await getTikTokAccount(userId);
  if (!first) throw notConnected();
  if (isTokenFresh(first)) return first.access_token;

  return withLock(`tiktok-refresh:${userId}`, async () => {
    // Deux tentatives : la seconde n'a lieu que si la ligne a changé
    // pendant le refresh (autre instance, reconnexion...).
    for (let attempt = 0; attempt < 2; attempt++) {
      // Relecture APRÈS verrou (TikTok fait tourner les refresh tokens).
      const account = await getTikTokAccount(userId);

      if (!account) throw notConnected();
      if (isTokenFresh(account)) return account.access_token;

      if (!account.refresh_token || isPast(account.refresh_expires_at)) {
        throw reconnectError("TikTok", "TIKTOK_REFRESH_EXPIRED");
      }

      let refreshed;

      try {
        refreshed = await tiktokApi("/v2/oauth/token/", {
          form: {
            client_key: TIKTOK_CLIENT_KEY,
            client_secret: TIKTOK_CLIENT_SECRET,
            grant_type: "refresh_token",
            refresh_token: account.refresh_token,
          },
        });
      } catch (error) {
        if (error instanceof HttpError && error.code === "invalid_grant") {
          throw reconnectError("TikTok", "TIKTOK_REFRESH_EXPIRED");
        }
        throw error;
      }

      if (!refreshed?.access_token) {
        throw new HttpError(
          502,
          "TikTok returned an invalid token response",
          "TIKTOK_BAD_TOKEN_RESPONSE"
        );
      }

      const applied = await updateTokensIfUnchanged(
        "tiktok_accounts",
        userId,
        account,
        buildTikTokTokenRow(refreshed)
      );

      if (applied) return refreshed.access_token;
    }

    throw new HttpError(
      409,
      "TikTok account changed during token refresh, please retry",
      "TIKTOK_REFRESH_CONFLICT"
    );
  });
}

// ============================================================
// Rafraîchissement du profil (avatar)
// ============================================================
//
// Renvoie toujours { account, needsReconnect } :
//   needsReconnect : true  → refresh token mort/absent (reconnexion)
//                    false → tout va bien (succès, throttle, absence
//                    d'avatar, ou panne transitoire : on retentera)
// Le throttle normal n'est armé QU'EN CAS DE SUCCÈS (ou d'absence d'avatar).

export async function refreshTikTokProfile(userId, { force = false } = {}) {
  const lockKey = `tiktok-profile:${userId}:${force ? "force" : "normal"}`;

  return withLock(lockKey, async () => {
    const account = await getTikTokAccount(userId);
    if (!account) return { account: null, needsReconnect: false };

    const now = Date.now();
    const retryAt = tiktokProfileRetryAt.get(userId) || 0;

    // Anti-martèlement (respecté même par force).
    if (now < retryAt) {
      return { account, needsReconnect: false };
    }

    const last = tiktokProfileRefreshedAt.get(userId) || 0;
    if (!force && now - last < TIKTOK_PROFILE_REFRESH_MS) {
      return { account, needsReconnect: false };
    }

    // Borne mémoire des deux Maps.
    if (tiktokProfileRefreshedAt.size > 10_000) {
      tiktokProfileRefreshedAt.delete(
        tiktokProfileRefreshedAt.keys().next().value
      );
    }
    if (tiktokProfileRetryAt.size > 10_000) {
      tiktokProfileRetryAt.delete(tiktokProfileRetryAt.keys().next().value);
    }

    try {
      const accessToken = await getValidTikTokToken(userId);

      const info = await tiktokApi(
        "/v2/user/info/?fields=open_id,avatar_url,display_name",
        { method: "GET", token: accessToken }
      );

      const profile = info.data?.user;

      // Pas d'avatar (ou URL non https) : on conserve l'ancien.
      if (!profile?.avatar_url || !/^https:\/\//i.test(profile.avatar_url)) {
        tiktokProfileRefreshedAt.set(userId, now);
        tiktokProfileRetryAt.set(userId, now + TIKTOK_PROFILE_MIN_INTERVAL_MS);
        return { account, needsReconnect: false };
      }

      const displayName = profile.display_name || account.display_name;

      // On ne touche PAS à updated_at : il sert au webhook
      // authorization.removed et au compare-and-swap du refresh.
      const { error } = await supabaseAdmin
        .from("tiktok_accounts")
        .update({
          avatar_url: profile.avatar_url,
          display_name: displayName,
        })
        .eq("user_id", userId);

      if (error) {
        console.warn("TikTok profile save failed:", error.message);
        tiktokProfileRetryAt.set(userId, now + TIKTOK_PROFILE_TRANSIENT_RETRY_MS);
        return { account, needsReconnect: false };
      }

      tiktokProfileRefreshedAt.set(userId, now);
      tiktokProfileRetryAt.set(userId, now + TIKTOK_PROFILE_MIN_INTERVAL_MS);

      return {
        account: {
          ...account,
          avatar_url: profile.avatar_url,
          display_name: displayName,
        },
        needsReconnect: false,
      };
    } catch (error) {
      // Jeton mort → reconnexion indispensable (signalé EXPLICITEMENT).
      if (
        error instanceof HttpError &&
        (error.code === "TIKTOK_REFRESH_EXPIRED" ||
          error.code === "TIKTOK_NOT_CONNECTED")
      ) {
        tiktokProfileRetryAt.set(userId, now + TIKTOK_PROFILE_DEAD_RETRY_MS);
        return { account, needsReconnect: true };
      }

      // Panne transitoire : on garde l'ancien avatar et on retente dans 30 s.
      console.warn("TikTok profile refresh failed:", error.message);
      tiktokProfileRetryAt.set(userId, now + TIKTOK_PROFILE_TRANSIENT_RETRY_MS);
      return { account, needsReconnect: false };
    }
  });
}

// ============================================================
// Upload vidéo
// ============================================================

// total_chunk_count = floor(taille / chunk_size) ; le dernier chunk absorbe
// le reste (entre 5 et 128 Mo). Une vidéo ≤ 64 Mo part en un seul chunk.
export function computeChunking(size) {
  const MB = 1024 * 1024;

  if (size <= 64 * MB) {
    return { chunkSize: size, totalChunks: 1 };
  }

  const chunkSize = 10 * MB;
  return { chunkSize, totalChunks: Math.floor(size / chunkSize) };
}

async function putChunk(uploadUrl, part, mimeType, start, end, total) {
  const MAX_ATTEMPTS = 3;
  let lastError;

  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    try {
      const { response } = await fetchJson(
        uploadUrl,
        {
          method: "PUT",
          headers: {
            "Content-Type": mimeType,
            "Content-Range": `bytes ${start}-${end}/${total}`,
          },
          body: part,
        },
        120_000
      );

      if (response.ok || response.status === 206) return;

      // Erreur client (4xx hors 429) : inutile de réessayer.
      if (
        response.status >= 400 &&
        response.status < 500 &&
        response.status !== 429
      ) {
        throw new HttpError(
          502,
          `TikTok upload rejected (HTTP ${response.status})`,
          "TIKTOK_UPLOAD_REJECTED"
        );
      }

      lastError = new Error(`HTTP ${response.status}`);
    } catch (error) {
      if (error instanceof HttpError && error.code === "TIKTOK_UPLOAD_REJECTED") {
        throw error;
      }
      lastError = error;
    }

    if (attempt < MAX_ATTEMPTS) {
      await delay(attempt * 1000);
    }
  }

  console.error("TikTok chunk upload failed:", lastError?.message);
  throw new HttpError(502, "TikTok upload failed, please retry", "TIKTOK_UPLOAD_FAILED");
}

export async function uploadVideoToTikTok(uploadUrl, buffer, mimeType, chunking) {
  const { chunkSize, totalChunks } = chunking;

  for (let i = 0; i < totalChunks; i++) {
    const start = i * chunkSize;
    const end = i === totalChunks - 1 ? buffer.length - 1 : start + chunkSize - 1;
    const part = buffer.subarray(start, end + 1);

    await putChunk(uploadUrl, part, mimeType, start, end, buffer.length);
  }
}

// ============================================================
// Modes / privacy (logique sandbox)
// ============================================================

//   - sandbox (non audité) ou FORCE_DRAFT → SELF_ONLY forcé
//   - sinon : valeur demandée si valide, sinon SELF_ONLY
export function resolvePrivacy(requested) {
  if (TIKTOK_SANDBOX || TIKTOK_FORCE_DRAFT) return "SELF_ONLY";

  const value = String(requested || "SELF_ONLY");
  return TIKTOK_PRIVACY_LEVELS.has(value) ? value : "SELF_ONLY";
}

//   - "draft" demandé  → brouillon (inbox)
//   - "direct" demandé → brouillon si FORCE_DRAFT, sinon direct
export function resolveVideoMode(requested) {
  if (TIKTOK_FORCE_DRAFT) return "draft";
  return requested === "draft" ? "draft" : "direct";
}

// Divulgation de contenu commercial (exigence TikTok). Le contenu de marque
// ne peut pas être privé (SELF_ONLY).
function brandFlags(fields, privacy) {
  const content = toBool(fields.brand_content_toggle);
  const organic = toBool(fields.brand_organic_toggle);

  if ((content || organic) && privacy === "SELF_ONLY") {
    throw new HttpError(
      400,
      "Branded content visibility cannot be set to private" +
        (TIKTOK_SANDBOX ? " (mode sandbox : SELF_ONLY forcé)" : ""),
      "BRANDED_CONTENT_PRIVATE"
    );
  }

  return content || organic
    ? { brand_content_toggle: content, brand_organic_toggle: organic }
    : {};
}

function buildPostInfo(fields) {
  const privacy = resolvePrivacy(fields.privacy_level);

  return {
    title: String(fields.title || "").slice(0, 2200),
    privacy_level: privacy,
    disable_comment: toBool(fields.disable_comment),
    disable_duet: toBool(fields.disable_duet),
    disable_stitch: toBool(fields.disable_stitch),
    ...brandFlags(fields, privacy),
  };
}

export async function initTikTokPublish(accessToken, mode, postInfoFields, sourceInfo) {
  return mode === "draft"
    ? tiktokApi("/v2/post/publish/inbox/video/init/", {
        token: accessToken,
        json: { source_info: sourceInfo },
      })
    : tiktokApi("/v2/post/publish/video/init/", {
        token: accessToken,
        json: {
          post_info: buildPostInfo(postInfoFields),
          source_info: sourceInfo,
        },
      });
}

// publish_id TikTok : lettres, chiffres, _ . : ~ -  (64 caractères max).
const TIKTOK_PUBLISH_ID_PATTERN = /^[\w.:~-]+$/;
const TIKTOK_PUBLISH_ID_MAX = 64;

export function isValidTikTokPublishId(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= TIKTOK_PUBLISH_ID_MAX &&
    TIKTOK_PUBLISH_ID_PATTERN.test(value)
  );
}

// ============================================================
// Photos (carrousel) : 1 photo = post photo, 2 à 35 = carrousel.
// Les fichiers vivent dans un bucket privé (nom aléatoire de 128 bits),
// servis sans authentification sur /api/media/tiktok/<nom> pour que TikTok
// puisse les télécharger, puis supprimés après TIKTOK_MEDIA_TTL_MS.
// SANDBOX : posts photos forcés en brouillon (MEDIA_UPLOAD).
// ============================================================

export async function ensureTikTokMediaBucket() {
  const { error } = await supabaseAdmin.storage.createBucket(
    TIKTOK_MEDIA_BUCKET,
    { public: false }
  );

  if (error && !/already exists|duplicate/i.test(error.message || "")) {
    console.warn("TikTok media bucket:", error.message);
  }
}

export async function sweepTikTokMedia() {
  try {
    const { data, error } = await supabaseAdmin.storage
      .from(TIKTOK_MEDIA_BUCKET)
      .list("", { limit: 1000 });

    if (error || !data) return;

    const cutoff = Date.now() - TIKTOK_MEDIA_TTL_MS;

    const stale = data
      .filter(
        (file) =>
          /^[a-f0-9]{32}\.(jpg|webp)$/.test(file.name || "") &&
          file.created_at &&
          new Date(file.created_at).getTime() < cutoff
      )
      .map((file) => file.name);

    if (stale.length > 0) {
      await supabaseAdmin.storage.from(TIKTOK_MEDIA_BUCKET).remove(stale);
    }
  } catch (error) {
    console.warn("TikTok media sweep failed:", error?.message || error);
  }
}

export async function removeTikTokPhotos(names) {
  try {
    await supabaseAdmin.storage.from(TIKTOK_MEDIA_BUCKET).remove(names);
  } catch {
    // le balayage périodique s'en chargera
  }
}

export async function storeTikTokPhotos(photos) {
  const names = photos.map(
    (photo) =>
      `${crypto.randomBytes(16).toString("hex")}.${
        photo.type === "image/webp" ? "webp" : "jpg"
      }`
  );

  try {
    // Par lots pour ne pas ouvrir 35 connexions d'un coup.
    const BATCH = 6;

    for (let i = 0; i < photos.length; i += BATCH) {
      await Promise.all(
        photos.slice(i, i + BATCH).map(async (photo, offset) => {
          const { error } = await supabaseAdmin.storage
            .from(TIKTOK_MEDIA_BUCKET)
            .upload(names[i + offset], photo.buffer, {
              contentType: photo.type,
              cacheControl: "3600",
              upsert: false,
            });

          if (error) throw error;
        })
      );
    }
  } catch (error) {
    await removeTikTokPhotos(names);
    throw error;
  }

  return names;
}

// Route publique appelée par les serveurs TikTok (GET / HEAD).
export async function serveTikTokMedia(req, res, fileName) {
  const { data, error } = await supabaseAdmin.storage
    .from(TIKTOK_MEDIA_BUCKET)
    .download(fileName);

  if (error || !data) {
    sendJson(res, 404, { success: false, error: "Not found" });
    return;
  }

  const buffer = Buffer.from(await data.arrayBuffer());

  res.writeHead(200, {
    "Content-Type": fileName.endsWith(".webp") ? "image/webp" : "image/jpeg",
    "Content-Length": buffer.length,
    "Content-Disposition": "inline",
    "Accept-Ranges": "none",
    "Cache-Control": "public, max-age=3600",
  });

  res.end(req.method === "HEAD" ? undefined : buffer);
}

// Vérifie, AVANT d'appeler TikTok, qu'une image est joignable depuis
// Internet avec le bon Content-Type. Évite l'erreur opaque « The request
// source info is empty or incorrect ».
async function probePublicPhoto(imageUrl, index = 1, total = 1) {
  const label = total > 1 ? ` (photo ${index}/${total})` : "";

  let status = null;
  let contentType = null;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8_000);

    try {
      const response = await fetch(imageUrl, {
        method: "HEAD",
        signal: controller.signal,
        redirect: "manual",
      });

      status = response.status;
      contentType = response.headers.get("content-type");
    } finally {
      clearTimeout(timer);
    }
  } catch (error) {
    console.error(
      "[tiktok:photos] probe failed:",
      imageUrl,
      error?.message || error
    );

    throw new HttpError(
      502,
      `The photo URL is not reachable from the internet${label}. Check PUBLIC_API_URL (it must be the public domain of this API server).`,
      "PHOTO_URL_UNREACHABLE"
    );
  }

  const okType = /^image\/(jpeg|webp)/i.test(contentType || "");

  console.log("[tiktok:photos] probe", status, contentType, imageUrl);

  if (status !== 200 || !okType) {
    throw new HttpError(
      502,
      `The photo URL did not return a valid image${label} (HTTP ${status}, ${contentType || "no content-type"}). PUBLIC_API_URL probably points to the wrong host.`,
      "PHOTO_URL_INVALID"
    );
  }
}

// Sonde TOUTES les images du carrousel, par lots.
// Désactivable avec TIKTOK_SKIP_PHOTO_PROBE=1.
export async function probePublicPhotos(imageUrls) {
  if (env("TIKTOK_SKIP_PHOTO_PROBE") === "1") return;

  const BATCH = 6;

  for (let i = 0; i < imageUrls.length; i += BATCH) {
    await Promise.all(
      imageUrls
        .slice(i, i + BATCH)
        .map((imageUrl, offset) =>
          probePublicPhoto(imageUrl, i + offset + 1, imageUrls.length)
        )
    );
  }
}

// Post_info d'un post photo.
//   - "draft"  : pas de privacy (ignorée en MEDIA_UPLOAD)
//   - "direct" : privacy via resolvePrivacy() (SELF_ONLY forcé en sandbox)
export function buildPhotoPostInfo(mode, fields) {
  const caption = String(fields.title || "").trim();

  const postInfo = {
    title: caption.slice(0, 90),
    description: caption.slice(0, 4000),
  };

  if (mode !== "draft") {
    const privacy = resolvePrivacy(fields.privacy_level);

    postInfo.privacy_level = privacy;
    postInfo.disable_comment = toBool(fields.disable_comment);
    postInfo.auto_add_music = true;

    Object.assign(postInfo, brandFlags(fields, privacy));
  }

  return postInfo;
}

//   - sandbox / FORCE_DRAFT → TOUJOURS "draft" (MEDIA_UPLOAD)
export function resolvePhotoMode(requested) {
  if (TIKTOK_SANDBOX || TIKTOK_FORCE_DRAFT) return "draft";
  return requested === "draft" ? "draft" : "direct";
}

export function initTikTokPhotoPublish(accessToken, mode, postInfo, imageUrls, coverIndex) {
  const payload = {
    post_info: postInfo,
    source_info: {
      source: "PULL_FROM_URL",
      photo_cover_index: coverIndex, // 0 = première photo
      photo_images: imageUrls,
    },
    post_mode: mode === "draft" ? "MEDIA_UPLOAD" : "DIRECT_POST",
    media_type: "PHOTO",
  };

  console.log(
    "[tiktok:photos] init",
    JSON.stringify({
      post_mode: payload.post_mode,
      cover: coverIndex,
      count: imageUrls.length,
      first_url: imageUrls[0],
    })
  );

  return tiktokApi("/v2/post/publish/content/init/", {
    token: accessToken,
    json: payload,
  });
}
