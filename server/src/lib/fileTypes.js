// Validation du type de fichier par MAGIC BYTES (pas le header client).
// SVG volontairement EXCLU pour les avatars (XSS possible).

import { AVATAR_BUCKET } from "../config/index.js";

export const ALLOWED_AVATAR_TYPES = ["image/png", "image/jpeg", "image/webp", "image/gif"];

export const AVATAR_EXTENSIONS = {
  "image/png": "png",
  "image/jpeg": "jpg",
  "image/webp": "webp",
  "image/gif": "gif",
};

export function sniffImageType(buffer) {
  if (!buffer || buffer.length < 12) return null;

  // PNG : 89 50 4E 47
  if (
    buffer[0] === 0x89 &&
    buffer[1] === 0x50 &&
    buffer[2] === 0x4e &&
    buffer[3] === 0x47
  ) {
    return "image/png";
  }

  // JPEG : FF D8 FF
  if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
    return "image/jpeg";
  }

  // GIF : "GIF8"
  if (
    buffer[0] === 0x47 &&
    buffer[1] === 0x49 &&
    buffer[2] === 0x46 &&
    buffer[3] === 0x38
  ) {
    return "image/gif";
  }

  // WebP : "RIFF"...."WEBP"
  if (
    buffer.toString("ascii", 0, 4) === "RIFF" &&
    buffer.toString("ascii", 8, 12) === "WEBP"
  ) {
    return "image/webp";
  }

  return null;
}

export function sniffVideoType(buffer) {
  if (!buffer || buffer.length < 12) return null;

  // MP4 / MOV : "ftyp" aux octets 4-7 ; la marque "qt  " = QuickTime
  if (buffer.toString("ascii", 4, 8) === "ftyp") {
    return buffer.toString("ascii", 8, 12) === "qt  "
      ? "video/quicktime"
      : "video/mp4";
  }

  // WebM / Matroska : 1A 45 DF A3
  if (
    buffer[0] === 0x1a &&
    buffer[1] === 0x45 &&
    buffer[2] === 0xdf &&
    buffer[3] === 0xa3
  ) {
    return "video/webm";
  }

  return null;
}

export function extractAvatarStoragePath(filePathOrUrl) {
  const marker = `/storage/v1/object/public/${AVATAR_BUCKET}/`;
  const markerIndex = filePathOrUrl.indexOf(marker);

  if (markerIndex !== -1) {
    const raw = filePathOrUrl.slice(markerIndex + marker.length).split("?")[0];

    try {
      return decodeURIComponent(raw);
    } catch {
      return null;
    }
  }

  if (!filePathOrUrl.startsWith("http")) {
    return filePathOrUrl;
  }

  return null;
}

export function isOwnedAvatarPath(storagePath, userId) {
  if (typeof storagePath !== "string") return false;
  if (storagePath.includes("..")) return false;
  if (storagePath.startsWith("/")) return false;

  return storagePath.startsWith(`${userId}/`);
}
