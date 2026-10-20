// Routes /api/user/* : profil, mot de passe, avatar.

import crypto from "node:crypto";
import {
  SUPABASE_BASE_URL,
  AVATAR_BUCKET,
  MAX_AVATAR_SIZE,
} from "../config/index.js";
import { route } from "../lib/router.js";
import { supabase, supabaseAdmin } from "../lib/supabase.js";
import { HttpError } from "../lib/utils.js";
import { getJsonBody, sendJson } from "../lib/http.js";
import { parseMultipart } from "../lib/multipart.js";
import { enforce, limiterAccount } from "../lib/rateLimit.js";
import { adminUpdateUser, formatUser } from "../lib/auth.js";
import {
  ALLOWED_AVATAR_TYPES,
  AVATAR_EXTENSIONS,
  sniffImageType,
  extractAvatarStoragePath,
  isOwnedAvatarPath,
} from "../lib/fileTypes.js";

route(
  "GET",
  "/api/user",
  ({ res, user }) => {
    sendJson(res, 200, { success: true, user: formatUser(user) });
  },
  { auth: true }
);

route(
  "GET",
  "/api/user/profile",
  ({ res, user }) => {
    sendJson(res, 200, { success: true, user: formatUser(user) });
  },
  { auth: true }
);

route(
  ["PUT", "PATCH"],
  "/api/user/profile",
  async ({ req, res, user }) => {
    const body = await getJsonBody(req);

    const metadata = { ...(user.user_metadata || {}) };

    // Limitation des longueurs : user_metadata est borné côté Supabase.
    const limitedString = (value, max) => String(value ?? "").slice(0, max);

    if (body.firstName !== undefined || body.first_name !== undefined) {
      metadata.first_name = limitedString(
        body.firstName ?? body.first_name ?? "",
        100
      );
    }

    if (body.lastName !== undefined || body.last_name !== undefined) {
      metadata.last_name = limitedString(
        body.lastName ?? body.last_name ?? "",
        100
      );
    }

    if (body.bio !== undefined) {
      metadata.bio = limitedString(body.bio, 500);
    }

    if (body.avatarUrl !== undefined || body.avatar_url !== undefined) {
      const avatarUrl = limitedString(
        body.avatarUrl ?? body.avatar_url ?? "",
        1000
      );

      // Uniquement une image de NOTRE bucket, dans le dossier de
      // l'utilisateur (ou vide pour retirer l'avatar).
      const ownPrefix = `${SUPABASE_BASE_URL}/storage/v1/object/public/${AVATAR_BUCKET}/${user.id}/`;

      if (avatarUrl && !avatarUrl.startsWith(ownPrefix)) {
        throw new HttpError(400, "Invalid avatar URL");
      }

      metadata.custom_avatar_url = avatarUrl;
    }

    const { data, error } = await adminUpdateUser(user.id, {
      user_metadata: metadata,
    });

    if (error) throw error;

    sendJson(res, 200, { success: true, user: formatUser(data.user) });
  },
  { auth: true }
);

// NOTE : signInWithPassword pour vérifier le mot de passe courant
// crée une session Supabase supplémentaire (impact limité).
route(
  ["PUT", "POST"],
  "/api/user/password",
  async ({ req, res, user }) => {
    const body = await getJsonBody(req);

    const currentPassword = String(
      body.currentPassword ?? body.current_password ?? ""
    );
    const newPassword = String(body.newPassword ?? body.new_password ?? "");

    if (!currentPassword || !newPassword) {
      throw new HttpError(400, "Current and new password are required");
    }

    if (newPassword.length < 8) {
      throw new HttpError(
        400,
        "New password must contain at least 8 characters"
      );
    }

    if (newPassword.length > 128) {
      throw new HttpError(
        400,
        "New password must contain at most 128 characters"
      );
    }

    if (!user.email) {
      throw new HttpError(400, "No email associated with this account");
    }

    // Un token volé ne doit pas permettre de deviner le mot de passe actuel.
    enforce(limiterAccount, `password:${user.id}`);

    const { error: verifyError } = await supabase.auth.signInWithPassword({
      email: user.email,
      password: currentPassword,
    });

    if (verifyError) {
      throw new HttpError(401, "Current password is incorrect");
    }

    const { error } = await adminUpdateUser(user.id, { password: newPassword });

    if (error) throw error;

    sendJson(res, 200, {
      success: true,
      message: "Password updated successfully",
    });
  },
  { auth: true }
);

// Le type est validé par MAGIC BYTES (pas par le Content-Type client).
route(
  "POST",
  "/api/user/avatar",
  async ({ req, res, user }) => {
    enforce(limiterAccount, `avatar:${user.id}`);

    let upload;

    try {
      upload = await parseMultipart(req, {
        fileField: "avatar",
        maxSize: MAX_AVATAR_SIZE,
      });
    } catch (error) {
      if (error?.code === "FILE_TOO_LARGE") {
        throw new HttpError(400, "Avatar is too large. Maximum size is 2 MB.");
      }
      if (error?.code === "NO_FILE") {
        throw new HttpError(400, "No 'avatar' file was provided.");
      }
      throw new HttpError(400, "Could not read the uploaded file.");
    }

    const sniffedType = sniffImageType(upload.buffer);

    if (!sniffedType || !ALLOWED_AVATAR_TYPES.includes(sniffedType)) {
      throw new HttpError(
        400,
        "Unsupported image format. Use PNG, JPEG, WebP or GIF."
      );
    }

    // Extension dérivée du type RÉEL, pas du nom de fichier client.
    const storagePath = `${user.id}/${crypto.randomUUID()}.${AVATAR_EXTENSIONS[sniffedType]}`;

    const { error: storageError } = await supabaseAdmin.storage
      .from(AVATAR_BUCKET)
      .upload(storagePath, upload.buffer, {
        contentType: sniffedType,
        cacheControl: "31536000",
        upsert: false,
      });

    if (storageError) throw storageError;

    const { data: publicUrlData } = supabaseAdmin.storage
      .from(AVATAR_BUCKET)
      .getPublicUrl(storagePath);

    sendJson(res, 200, { success: true, avatar_url: publicUrlData.publicUrl });
  },
  { auth: true }
);

route(
  "DELETE",
  "/api/user/avatar",
  async ({ req, res, user }) => {
    const body = await getJsonBody(req);

    const filePathOrUrl = String(body.filePathOrUrl || "").trim();

    if (!filePathOrUrl) {
      throw new HttpError(400, "Missing filePathOrUrl");
    }

    const storagePath = extractAvatarStoragePath(filePathOrUrl);

    if (!storagePath) {
      sendJson(res, 200, { success: true });
      return;
    }

    if (!isOwnedAvatarPath(storagePath, user.id)) {
      throw new HttpError(403, "You can only delete your own avatar");
    }

    const { error } = await supabaseAdmin.storage
      .from(AVATAR_BUCKET)
      .remove([storagePath]);

    if (error) throw error;

    sendJson(res, 200, { success: true });
  },
  { auth: true }
);
