// Configuration YouTube (Google OAuth + upload).

import { env } from "./env.js";
import { APP_URL } from "./app.js";

export const YOUTUBE_CLIENT_ID = env("YOUTUBE_CLIENT_ID");
export const YOUTUBE_CLIENT_SECRET = env("YOUTUBE_CLIENT_SECRET");
export const YOUTUBE_REDIRECT_URI =
  env("YOUTUBE_REDIRECT_URI") || `${APP_URL}/youtube/callback`;

export const YOUTUBE_SCOPES = (
  env("YOUTUBE_SCOPES") ||
  "https://www.googleapis.com/auth/youtube.readonly https://www.googleapis.com/auth/youtube.upload"
)
  .split(/[\s,]+/)
  .filter(Boolean)
  .join(" ");

export const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
export const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
export const GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke";
export const YOUTUBE_API_BASE = "https://www.googleapis.com/youtube/v3";

export const youtubeEnabled = Boolean(YOUTUBE_CLIENT_ID && YOUTUBE_CLIENT_SECRET);

export const YOUTUBE_UPLOAD_URL =
  "https://www.googleapis.com/upload/youtube/v3/videos";
// Les chunks doivent être un multiple de 256 Kio (sauf le dernier).
export const YOUTUBE_CHUNK_SIZE = 8 * 1024 * 1024;
export const YOUTUBE_PRIVACY_LEVELS = new Set(["public", "unlisted", "private"]);
export const YOUTUBE_TITLE_MAX = 100;
export const YOUTUBE_DESCRIPTION_MAX_BYTES = 5000;
export const YOUTUBE_UPLOAD_SCOPE =
  "https://www.googleapis.com/auth/youtube.upload";
