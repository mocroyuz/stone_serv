// POST /api/tiktok/webhook  → URL à déclarer dans le portail TikTok for
// Developers (≠ TIKTOK_REDIRECT_URI, qui est l'URL de retour OAuth du FRONTEND).
//
// - En-tête  : TikTok-Signature: t=<timestamp>,s=<signature>
// - Signature: HMAC-SHA256(client_secret, "<timestamp>.<corps brut>"), en hex
// - TikTok exige une réponse 200 ; sinon il réessaie jusqu'à 72 h (livraison
//   "au moins une fois" : le traitement doit être idempotent).

import crypto from "node:crypto";
import {
  TIKTOK_CLIENT_KEY,
  TIKTOK_CLIENT_SECRET,
  TIKTOK_WEBHOOK_TOLERANCE_SEC,
} from "../config/index.js";
import { route } from "../lib/router.js";
import { supabaseAdmin } from "../lib/supabase.js";
import { HttpError, sha256, createSeenCache } from "../lib/utils.js";
import { readBody, sendJson } from "../lib/http.js";
import { clearTikTokProfileThrottle } from "../services/tiktok.js";

const MAX_TIKTOK_WEBHOOK_BODY = 64 * 1024;
const TIKTOK_WEBHOOK_DEDUPE_TTL_MS = 24 * 60 * 60 * 1000;
const TIKTOK_WEBHOOK_DEDUPE_MAX = 5_000;
// Marge (s) appliquée à la date de l'événement pour ne pas supprimer une
// connexion rétablie APRÈS la révocation.
const TIKTOK_REVOKE_SKEW_SEC = 5;

const processedTikTokWebhooks = createSeenCache(
  TIKTOK_WEBHOOK_DEDUPE_MAX,
  TIKTOK_WEBHOOK_DEDUPE_TTL_MS
);

// "t=1633174587,s=<64 hex>" -> { timestamp, signature } ou null.
function parseTikTokSignatureHeader(header) {
  if (typeof header !== "string" || header.length > 512) return null;

  let timestamp = null;
  let signature = null;

  for (const part of header.split(",")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;

    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();

    if (key === "t" && timestamp === null) timestamp = value;
    else if (key === "s" && signature === null) signature = value;
  }

  if (!timestamp || !/^\d{1,12}$/.test(timestamp)) return null;
  if (!signature || !/^[a-f0-9]{64}$/i.test(signature)) return null;

  return { timestamp, signature: signature.toLowerCase() };
}

export function verifyTikTokWebhookSignature(
  rawBody,
  header,
  secret,
  toleranceSec = TIKTOK_WEBHOOK_TOLERANCE_SEC,
  nowMs = Date.now()
) {
  if (!secret) return { ok: false, reason: "secret_missing" };

  const parsed = parseTikTokSignatureHeader(header);
  if (!parsed) return { ok: false, reason: "malformed_header" };

  const expected = crypto
    .createHmac("sha256", secret)
    .update(parsed.timestamp + ".")
    .update(rawBody)
    .digest();

  const received = Buffer.from(parsed.signature, "hex");

  if (
    received.length !== expected.length ||
    !crypto.timingSafeEqual(received, expected)
  ) {
    return { ok: false, reason: "bad_signature" };
  }

  if (toleranceSec > 0) {
    const skewSec = Math.abs(nowMs / 1000 - Number(parsed.timestamp));

    if (skewSec > toleranceSec) {
      return { ok: false, reason: "timestamp_out_of_tolerance" };
    }
  }

  return { ok: true, timestamp: Number(parsed.timestamp) };
}

// Événement "authorization.removed" : l'utilisateur TikTok a retiré l'accès.
// Sécurité / idempotence :
//  - le compte est identifié par open_id, jamais par autre chose
//  - on ne supprime que les lignes dont updated_at est antérieur à l'événement
//  - rejouer l'événement est sans effet (0 ligne supprimée)
async function handleTikTokAuthorizationRemoved(payload, requestId) {
  const openId = payload.user_openid;

  if (typeof openId !== "string" || !/^[A-Za-z0-9._:-]{1,256}$/.test(openId)) {
    throw new HttpError(400, "Invalid user_openid", "INVALID_PAYLOAD");
  }

  const createTime = payload.create_time;

  if (!Number.isSafeInteger(createTime) || createTime <= 0) {
    throw new HttpError(400, "Invalid create_time", "INVALID_PAYLOAD");
  }

  let reason = null;

  if (typeof payload.content === "string") {
    try {
      const content = JSON.parse(payload.content);
      if (content && Number.isInteger(content.reason)) reason = content.reason;
    } catch {
      // content illisible : la déconnexion est traitée quand même
    }
  }

  const cutoff = new Date((createTime + TIKTOK_REVOKE_SKEW_SEC) * 1000).toISOString();

  const { data, error } = await supabaseAdmin
    .from("tiktok_accounts")
    .delete()
    .eq("open_id", openId)
    .lte("updated_at", cutoff)
    .select("user_id");

  if (error) {
    throw new Error("tiktok_accounts cleanup failed: " + error.message);
  }

  if (Array.isArray(data)) {
    for (const row of data) {
      if (row?.user_id) clearTikTokProfileThrottle(row.user_id);
    }
  }

  console.log(
    "[" + requestId + "] [tiktok:webhook] authorization.removed" +
      " openid=" + sha256(openId).slice(0, 10) +
      " reason=" + (reason === null ? "n/a" : reason) +
      " comptes_supprimés=" + (data ? data.length : 0)
  );
}

// Événements documentés mais sans action pour cette application
// (Video Kit / Data Portability) : accusés de réception uniquement.
const TIKTOK_ACK_ONLY_EVENTS = new Set([
  "video.upload.failed",
  "video.publish.completed",
  "portability.download.ready",
]);

route("POST", "/api/tiktok/webhook", async ({ req, res, requestId }) => {
  // 1. Corps BRUT : la signature porte sur les octets exacts reçus.
  const rawBody = await readBody(req, MAX_TIKTOK_WEBHOOK_BODY);

  // 2. Authenticité, AVANT tout parsing JSON.
  const check = verifyTikTokWebhookSignature(
    rawBody,
    req.headers["tiktok-signature"],
    TIKTOK_CLIENT_SECRET
  );

  if (!check.ok) {
    console.warn("[" + requestId + "] [tiktok:webhook] rejeté (" + check.reason + ")");
    throw new HttpError(401, "Invalid webhook signature", "INVALID_SIGNATURE");
  }

  // 3. Structure du message (signé, donc émis par TikTok).
  let payload;

  try {
    payload = JSON.parse(rawBody.toString("utf8"));
  } catch {
    throw new HttpError(400, "Invalid JSON", "INVALID_JSON");
  }

  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new HttpError(400, "Invalid payload", "INVALID_PAYLOAD");
  }

  const eventName = payload.event;

  if (
    typeof eventName !== "string" ||
    eventName.length > 100 ||
    !/^[A-Za-z0-9_.]+$/.test(eventName)
  ) {
    throw new HttpError(400, "Invalid event", "INVALID_PAYLOAD");
  }

  if (typeof payload.client_key === "string" && payload.client_key !== TIKTOK_CLIENT_KEY) {
    // Signé avec notre secret mais destiné à une autre clé : on ignore (200
    // pour éviter des retries inutiles).
    console.warn("[" + requestId + "] [tiktok:webhook] client_key inattendu : ignoré");
    sendJson(res, 200, { received: true, ignored: true });
    return;
  }

  // 4. Événement déjà traité (livraison "au moins une fois").
  const dedupeKey = sha256(rawBody.toString("utf8"));

  if (processedTikTokWebhooks.has(dedupeKey)) {
    sendJson(res, 200, { received: true, duplicate: true });
    return;
  }

  // 5. Traitement. Une exception => 500 => TikTok réessaiera (jusqu'à 72 h).
  if (eventName === "authorization.removed") {
    await handleTikTokAuthorizationRemoved(payload, requestId);
  } else if (TIKTOK_ACK_ONLY_EVENTS.has(eventName)) {
    console.log("[" + requestId + "] [tiktok:webhook] " + eventName + " reçu (aucune action)");
  } else {
    console.warn("[" + requestId + "] [tiktok:webhook] événement inconnu ignoré : " + eventName.slice(0, 60));
  }

  processedTikTokWebhooks.add(dedupeKey);
  sendJson(res, 200, { received: true });
});
