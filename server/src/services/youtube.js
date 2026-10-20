// Service YouTube : API Google, tokens, publication (upload resumable).
//
// Particularité Google : le refresh token est durable et n'est PAS renvoyé
// lors d'un refresh → on ne l'écrase jamais s'il est absent de la réponse.
// invalid_grant = autorisation révoquée / expirée → reconnexion.

import {
  YOUTUBE_CLIENT_ID,
  YOUTUBE_CLIENT_SECRET,
  YOUTUBE_API_BASE,
  YOUTUBE_UPLOAD_URL,
  YOUTUBE_CHUNK_SIZE,
  YOUTUBE_PRIVACY_LEVELS,
  YOUTUBE_TITLE_MAX,
  YOUTUBE_DESCRIPTION_MAX_BYTES,
  GOOGLE_TOKEN_URL,
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
  delay,
  iso,
  isPast,
  dbError,
} from "../lib/utils.js";

// ============================================================
// Appel API Google
// ============================================================

export async function googleRequest(requestUrl, { method = "GET", token, form, json } = {}) {
  const headers = { Accept: "application/json" };
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
    result = await fetchJson(requestUrl, { method, headers, body }, 20_000);
  } catch (error) {
    throw upstreamError("Google", error);
  }

  const { response, data } = result;

  if (!response.ok) {
    const oauthError = typeof data.error === "string" ? data.error : undefined;

    throw new HttpError(
      upstreamStatus(response.status),
      data.error_description ||
        data.error?.message ||
        oauthError ||
        `Google error (HTTP ${response.status})`,
      oauthError
    );
  }

  return data;
}

export async function fetchYouTubeChannel(accessToken) {
  const data = await googleRequest(
    `${YOUTUBE_API_BASE}/channels?part=snippet&mine=true`,
    { token: accessToken }
  );

  const channel = data.items?.[0];
  if (!channel) return null;

  const thumbnails = channel.snippet?.thumbnails || {};

  return {
    id: channel.id,
    title: channel.snippet?.title || null,
    customUrl: channel.snippet?.customUrl || null,
    avatarUrl:
      thumbnails.high?.url ||
      thumbnails.medium?.url ||
      thumbnails.default?.url ||
      null,
  };
}

// ============================================================
// Stockage / refresh des tokens
// ============================================================

function buildYouTubeTokenRow(t) {
  const now = Date.now();
  const accessTtl = Number(t.expires_in) || 3600;

  const row = {
    access_token: encryptSecret(t.access_token),
    access_expires_at: iso(now + accessTtl * 1000),
    updated_at: new Date().toISOString(),
  };

  if (t.refresh_token) row.refresh_token = encryptSecret(t.refresh_token);
  if (t.scope) row.scope = t.scope;

  if (t.refresh_token_expires_in !== undefined) {
    row.refresh_expires_at = t.refresh_token_expires_in
      ? iso(now + Number(t.refresh_token_expires_in) * 1000)
      : null;
  }

  return row;
}

// Connexion initiale : crée ou remplace la ligne.
export async function saveYouTubeTokens(userId, t, extra = {}) {
  const { error } = await supabaseAdmin
    .from("youtube_accounts")
    .upsert(
      { user_id: userId, ...buildYouTubeTokenRow(t), ...extra },
      { onConflict: "user_id" }
    );

  if (error) throw dbError("youtube_accounts upsert", error);
}

export async function getYouTubeAccount(userId) {
  return selectTokenRow("youtube_accounts", userId);
}

const youtubeRefreshExpired = (account) =>
  !account.refresh_token ||
  Boolean(account.refresh_expires_at) && isPast(account.refresh_expires_at);

export async function getValidYouTubeToken(userId) {
  const load = async () => {
    const account = await getYouTubeAccount(userId);

    if (!account) {
      throw new HttpError(
        400,
        "YouTube account not connected",
        "YOUTUBE_NOT_CONNECTED"
      );
    }

    return account;
  };

  const first = await load();
  if (isTokenFresh(first)) return first.access_token;

  return withLock(`youtube-refresh:${userId}`, async () => {
    for (let attempt = 0; attempt < 2; attempt++) {
      // Relecture APRÈS verrou : un autre traitement a pu renouveler.
      const account = await load();

      if (isTokenFresh(account)) return account.access_token;

      if (youtubeRefreshExpired(account)) {
        throw reconnectError("YouTube", "YOUTUBE_REFRESH_EXPIRED");
      }

      let refreshed;

      try {
        refreshed = await googleRequest(GOOGLE_TOKEN_URL, {
          method: "POST",
          form: {
            client_id: YOUTUBE_CLIENT_ID,
            client_secret: YOUTUBE_CLIENT_SECRET,
            grant_type: "refresh_token",
            refresh_token: account.refresh_token,
          },
        });
      } catch (error) {
        if (error instanceof HttpError && error.code === "invalid_grant") {
          throw reconnectError("YouTube", "YOUTUBE_REFRESH_EXPIRED");
        }
        throw error;
      }

      if (!refreshed?.access_token) {
        throw new HttpError(
          502,
          "Google returned an invalid token response",
          "YOUTUBE_BAD_TOKEN_RESPONSE"
        );
      }

      const applied = await updateTokensIfUnchanged(
        "youtube_accounts",
        userId,
        account,
        buildYouTubeTokenRow(refreshed)
      );

      if (applied) return refreshed.access_token;
    }

    throw new HttpError(
      409,
      "YouTube account changed during token refresh, please retry",
      "YOUTUBE_REFRESH_CONFLICT"
    );
  });
}

// ============================================================
// Publication (upload resumable)
// ============================================================

const YOUTUBE_FRIENDLY_ERRORS = {
  quotaExceeded:
    "YouTube daily quota reached for this app. Please try again tomorrow.",
  dailyLimitExceeded:
    "YouTube daily quota reached for this app. Please try again tomorrow.",
  uploadLimitExceeded:
    "This YouTube channel has reached its daily upload limit. Please try again later.",
  youtubeSignupRequired:
    "This Google account has no YouTube channel. Create one on youtube.com, then reconnect.",
  forbidden: "YouTube refused this upload for this channel.",
  invalidTitle: "Invalid YouTube title.",
  invalidDescription: "Invalid YouTube description.",
  invalidTags: "Invalid YouTube tags.",
  invalidPublishAt: "Invalid scheduled date. Pick a date in the future.",
  invalidVideoMetadata: "YouTube rejected the video metadata.",
  mediaBodyRequired: "The video file is empty.",
  videoTooLong:
    "This video is too long for your YouTube account. Verify your channel to upload longer videos.",
};

// Transforme une réponse d'erreur Google en HttpError lisible.
// Ne renvoie JAMAIS un 401 brut (le front le confondrait avec la session Stone).
function youtubeApiError(status, data) {
  const reason =
    data?.error?.errors?.[0]?.reason ||
    (typeof data?.error === "string" ? data.error : undefined) ||
    data?.error?.status;

  console.error(
    "[youtube]",
    JSON.stringify({ status, reason, message: data?.error?.message })
  );

  if (status === 401 || reason === "authError" || reason === "invalid_grant") {
    return reconnectError("YouTube", "YOUTUBE_REFRESH_EXPIRED");
  }

  if (reason === "insufficientPermissions") {
    return new HttpError(
      409,
      "YouTube permission missing, please reconnect your YouTube account.",
      "YOUTUBE_SCOPE_MISSING"
    );
  }

  if (reason === "quotaExceeded" || reason === "dailyLimitExceeded") {
    return new HttpError(429, YOUTUBE_FRIENDLY_ERRORS[reason], reason);
  }

  return new HttpError(
    upstreamStatus(status),
    YOUTUBE_FRIENDLY_ERRORS[reason] ||
      data?.error?.message ||
      `YouTube error (HTTP ${status})`,
    reason
  );
}

function parseYouTubeTags(raw) {
  const text = String(raw || "").trim();
  let list = [];

  if (text) {
    try {
      const parsed = JSON.parse(text);
      list = Array.isArray(parsed) ? parsed : [];
    } catch {
      list = text.split(",");
    }
  }

  // Limite YouTube : 500 caractères au total (guillemets autour des tags
  // contenant un espace + séparateur compris).
  const tags = [];
  let total = 0;

  for (const item of list) {
    const tag = String(item).replace(/[<>,"]/g, "").trim().slice(0, 100);
    if (!tag || tags.includes(tag)) continue;

    const cost = tag.length + (tag.includes(" ") ? 2 : 0) + 1;
    if (total + cost > 500) break;

    tags.push(tag);
    total += cost;
  }

  return tags;
}

// Valide les champs AVANT tout appel à YouTube.
export function buildYouTubeMetadata(fields) {
  const title = String(fields.title || "").replace(/[<>]/g, "").trim();

  if (!title) {
    throw new HttpError(
      400,
      "A title is required for YouTube videos.",
      "YOUTUBE_TITLE_REQUIRED"
    );
  }

  if (title.length > YOUTUBE_TITLE_MAX) {
    throw new HttpError(
      400,
      `The YouTube title must be at most ${YOUTUBE_TITLE_MAX} characters.`,
      "YOUTUBE_TITLE_TOO_LONG"
    );
  }

  const description = String(fields.description || "").replace(/[<>]/g, "").trim();

  if (Buffer.byteLength(description, "utf8") > YOUTUBE_DESCRIPTION_MAX_BYTES) {
    throw new HttpError(
      400,
      "The YouTube description is too long (max 5,000 characters).",
      "YOUTUBE_DESCRIPTION_TOO_LONG"
    );
  }

  // Déclaration « conçue pour les enfants » : choix explicite obligatoire.
  if (fields.made_for_kids !== "true" && fields.made_for_kids !== "false") {
    throw new HttpError(
      400,
      "Tell YouTube if this video is made for kids.",
      "YOUTUBE_MADE_FOR_KIDS_REQUIRED"
    );
  }

  let privacy = YOUTUBE_PRIVACY_LEVELS.has(fields.privacy_level)
    ? fields.privacy_level
    : "private";

  // Programmation : YouTube exige privacyStatus = private + publishAt futur.
  let publishAt = null;

  if (fields.publish_at) {
    const date = new Date(fields.publish_at);

    if (Number.isNaN(date.getTime()) || date.getTime() < Date.now() + 60_000) {
      throw new HttpError(
        400,
        "Pick a date and time in the future.",
        "YOUTUBE_PUBLISH_AT_INVALID"
      );
    }

    publishAt = date.toISOString();
    privacy = "private";
  }

  const tags = parseYouTubeTags(fields.tags);
  const categoryId = /^\d{1,3}$/.test(String(fields.category_id || ""))
    ? String(fields.category_id)
    : "22"; // People & Blogs

  return {
    privacy,
    publishAt,
    metadata: {
      snippet: {
        title,
        description,
        categoryId,
        ...(tags.length > 0 ? { tags } : {}),
      },
      status: {
        privacyStatus: privacy,
        selfDeclaredMadeForKids: fields.made_for_kids === "true",
        embeddable: true,
        ...(publishAt ? { publishAt } : {}),
      },
    },
  };
}

// 1. Ouvre une session d'upload resumable : Google répond avec l'URL
//    d'upload dans l'en-tête Location.
export async function initYouTubeUpload(accessToken, metadata, size, mimeType) {
  let result;

  try {
    result = await fetchJson(
      `${YOUTUBE_UPLOAD_URL}?uploadType=resumable&part=snippet,status`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json; charset=UTF-8",
          "X-Upload-Content-Length": String(size),
          "X-Upload-Content-Type": mimeType,
        },
        body: JSON.stringify(metadata),
      },
      30_000
    );
  } catch (error) {
    throw upstreamError("YouTube", error);
  }

  const { response, data } = result;

  if (!response.ok) throw youtubeApiError(response.status, data);

  const location = response.headers.get("location");

  if (!location || !location.startsWith("https://www.googleapis.com/")) {
    throw new HttpError(
      502,
      "YouTube did not return a valid upload URL",
      "YOUTUBE_NO_UPLOAD_URL"
    );
  }

  return location;
}

// Un PUT sur l'URL resumable.
//   200 / 201 → terminé (corps = ressource vidéo)
//   308       → incomplet (en-tête Range = octets reçus)
async function youtubePut(uploadUrl, headers, body) {
  const { response, data } = await fetchJson(
    uploadUrl,
    { method: "PUT", headers, body, redirect: "manual" },
    120_000
  );

  if (response.status === 200 || response.status === 201) {
    return { done: true, video: data };
  }

  if (response.status === 308) {
    const match = /bytes=0-(\d+)/.exec(response.headers.get("range") || "");
    return { done: false, next: match ? Number(match[1]) + 1 : 0 };
  }

  const error = new Error(`HTTP ${response.status}`);
  error.status = response.status;
  error.data = data;
  throw error;
}

// 2. Envoie le fichier par chunks, avec reprise après erreur réseau / 5xx
//    (on interroge YouTube pour savoir combien d'octets il a reçus).
export async function uploadVideoToYouTube(uploadUrl, buffer, mimeType) {
  const total = buffer.length;
  let offset = 0;
  let failures = 0;

  while (true) {
    try {
      const end = Math.min(offset + YOUTUBE_CHUNK_SIZE, total) - 1;

      const result = await youtubePut(
        uploadUrl,
        {
          "Content-Type": mimeType,
          "Content-Range": `bytes ${offset}-${end}/${total}`,
        },
        buffer.subarray(offset, end + 1)
      );

      if (result.done) return result.video;

      if (result.next <= offset) {
        // Aucun progrès : on compte comme un échec (évite une boucle infinie).
        throw Object.assign(new Error("No progress"), { status: 500 });
      }

      offset = result.next;
    } catch (error) {
      const status = error?.status;

      // Erreur client définitive (hors 429) : inutile de réessayer.
      if (status && status < 500 && status !== 429) {
        throw youtubeApiError(status, error.data);
      }

      failures++;

      if (failures > 5) {
        console.error("YouTube upload failed:", error?.message);
        throw new HttpError(
          502,
          "YouTube upload failed, please retry",
          "YOUTUBE_UPLOAD_FAILED"
        );
      }

      await delay(failures * 1000);

      // Reprise : combien d'octets YouTube a-t-il réellement reçus ?
      try {
        const query = await youtubePut(
          uploadUrl,
          { "Content-Range": `bytes */${total}` },
          undefined
        );

        if (query.done) return query.video;
        offset = query.next;
      } catch {
        // on retentera au prochain tour
      }
    }
  }
}
