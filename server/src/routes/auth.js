// Routes /api/auth/* : inscription, connexion, mot de passe oublié,
// OAuth Google / GitHub, refresh, logout.

import { PASSWORD_RESET_REDIRECT_URL } from "../config/index.js";
import { route } from "../lib/router.js";
import { supabase, supabaseAdmin, supabaseOAuth } from "../lib/supabase.js";
import {
  HttpError,
  normalizeEmail,
  EMAIL_REGEX,
} from "../lib/utils.js";
import { getJsonBody, sendJson, sanitizeRedirectTo } from "../lib/http.js";
import {
  enforce,
  limiterAccount,
  limiterPasswordReset,
} from "../lib/rateLimit.js";
import {
  authCacheGet,
  authCacheInvalidateUser,
  adminUpdateUser,
  isRecoverySessionToken,
  formatUser,
  sessionPayload,
} from "../lib/auth.js";
import { dbError } from "../lib/utils.js";

route("POST", "/api/auth/signup", async ({ req, res }) => {
  const body = await getJsonBody(req);

  const email = normalizeEmail(body.email);
  const password = String(body.password || "");

  const firstName = String(body.firstName ?? body.first_name ?? "").trim();
  const lastName = String(body.lastName ?? body.last_name ?? "").trim();

  if (!email || !password) {
    throw new HttpError(400, "Email and password are required");
  }

  if (email.length > 254 || !EMAIL_REGEX.test(email)) {
    throw new HttpError(400, "Invalid email address");
  }

  if (password.length < 8) {
    throw new HttpError(400, "Password must contain at least 8 characters");
  }

  if (password.length > 128) {
    throw new HttpError(400, "Password must contain at most 128 characters");
  }

  enforce(limiterAccount, `signup:${email}`);

  const { data, error } = await supabase.auth.signUp({
    email,
    password,
    options: {
      data: {
        first_name: firstName.slice(0, 100),
        last_name: lastName.slice(0, 100),
      },
    },
  });

  if (error) {
    throw new HttpError(error.status === 429 ? 429 : 400, error.message);
  }

  sendJson(res, 201, {
    success: true,
    user: data.user ? formatUser(data.user) : null,
    session: sessionPayload(data.session),
    message: data.session
      ? "Account created successfully"
      : "Account created. Check your email to confirm your account.",
  });
});

route("POST", "/api/auth/login", async ({ req, res }) => {
  const body = await getJsonBody(req);

  const email = normalizeEmail(body.email);
  const password = String(body.password || "");

  if (!email || !password) {
    throw new HttpError(400, "Email and password are required");
  }

  // Limite par compte en plus de la limite par IP (anti brute-force distribué).
  enforce(limiterAccount, `login:${email}`);

  const { data, error } = await supabase.auth.signInWithPassword({
    email,
    password,
  });

  if (error) {
    if (error.status === 429) {
      throw new HttpError(429, "Too many requests. Please try again later.");
    }

    const notConfirmed =
      error.code === "email_not_confirmed" ||
      error.message.toLowerCase().includes("not confirmed");

    throw new HttpError(
      401,
      notConfirmed ? error.message : "Invalid login credentials",
      notConfirmed ? "EMAIL_NOT_CONFIRMED" : "INVALID_CREDENTIALS"
    );
  }

  sendJson(res, 200, {
    success: true,
    user: data.user ? formatUser(data.user) : null,
    session: sessionPayload(data.session),
  });
});

// Cette route est un oracle de credentials : même limites que le login.
route("POST", "/api/auth/check-verification", async ({ req, res }) => {
  const body = await getJsonBody(req);

  const email = normalizeEmail(body.email);
  const password = String(body.password || "");

  if (!email || !password) {
    throw new HttpError(400, "Email and password are required");
  }

  enforce(limiterAccount, `login:${email}`);

  const { data, error } = await supabase.auth.signInWithPassword({
    email,
    password,
  });

  if (error) {
    const notConfirmed =
      error.code === "email_not_confirmed" ||
      error.message.toLowerCase().includes("not confirmed");

    if (notConfirmed) {
      sendJson(res, 200, { success: true, verified: false });
      return;
    }

    throw new HttpError(401, "Invalid login credentials", "INVALID_CREDENTIALS");
  }

  sendJson(res, 200, {
    success: true,
    verified: Boolean(data.user?.email_confirmed_at),
    session: sessionPayload(data.session),
  });
});

// ------------------------------------------------------------
// MOT DE PASSE OUBLIÉ — étape 1 : envoi de l'email
// POST /api/auth/forgot-password   { email }
//
// - Réponse IDENTIQUE que le compte existe ou non (pas d'énumération).
// - Limites : 10 req / 15 min par IP + 3 demandes / 15 min par email.
// - Le lien reçu redirige vers PASSWORD_RESET_REDIRECT_URL.
// ------------------------------------------------------------
route("POST", "/api/auth/forgot-password", async ({ req, res, requestId }) => {
  const body = await getJsonBody(req);

  const email = normalizeEmail(body.email);

  if (!email || email.length > 254 || !EMAIL_REGEX.test(email)) {
    throw new HttpError(400, "Enter a valid email address.", "INVALID_EMAIL");
  }

  enforce(limiterPasswordReset, `forgot:${email}`);

  const { error } = await supabase.auth.resetPasswordForEmail(email, {
    redirectTo: PASSWORD_RESET_REDIRECT_URL,
  });

  if (error) {
    if (error.status === 429) {
      throw new HttpError(
        429,
        "Too many requests. Please try again later.",
        "RATE_LIMITED"
      );
    }

    // Toute autre erreur est seulement journalisée : répondre différemment
    // révélerait si l'email existe.
    console.error(
      `[${requestId}] forgot-password: ${error.status || ""} ${error.message}`
    );
  }

  sendJson(res, 200, {
    success: true,
    message:
      "If an account exists for this email, a password reset link has been sent.",
  });
});

// ------------------------------------------------------------
// MOT DE PASSE OUBLIÉ — étape 2 : nouveau mot de passe
// POST /api/auth/reset-password
//   { password, access_token }  ou  { password, token_hash }
//
// L'access_token DOIT provenir d'une session de récupération. Après le
// changement, TOUTES les sessions de l'utilisateur sont révoquées.
// ------------------------------------------------------------
route("POST", "/api/auth/reset-password", async ({ req, res, requestId }) => {
  const body = await getJsonBody(req);

  const password = String(
    body.password ?? body.newPassword ?? body.new_password ?? ""
  );
  const accessToken = String(body.accessToken ?? body.access_token ?? "").trim();
  const tokenHash = String(body.tokenHash ?? body.token_hash ?? "").trim();

  if (!password) {
    throw new HttpError(400, "A new password is required");
  }

  if (password.length < 8) {
    throw new HttpError(400, "Password must contain at least 8 characters");
  }

  if (password.length > 128) {
    throw new HttpError(400, "Password must contain at most 128 characters");
  }

  if (!accessToken && !tokenHash) {
    throw new HttpError(
      400,
      "Missing recovery token",
      "RECOVERY_TOKEN_MISSING"
    );
  }

  const invalidLink = () =>
    new HttpError(
      401,
      "This reset link is invalid or has expired. Request a new one.",
      "INVALID_RESET_TOKEN"
    );

  let user = null;
  let sessionToken = null;

  if (tokenHash) {
    if (tokenHash.length > 512) throw invalidLink();

    // verifyOtp consomme le token (usage unique) et ouvre la session.
    const { data, error } = await supabase.auth.verifyOtp({
      token_hash: tokenHash,
      type: "recovery",
    });

    if (error || !data?.user || !data?.session) throw invalidLink();

    user = data.user;
    sessionToken = data.session.access_token;
  } else {
    if (accessToken.length > 4096) throw invalidLink();

    // Un token de connexion ordinaire ne doit pas permettre de changer le
    // mot de passe sans connaître l'ancien.
    if (!isRecoverySessionToken(accessToken)) throw invalidLink();

    const {
      data: { user: found },
      error,
    } = await supabase.auth.getUser(accessToken);

    if (error || !found) throw invalidLink();

    user = found;
    sessionToken = accessToken;
  }

  enforce(limiterAccount, `reset:${user.id}`);

  const { error: updateError } = await adminUpdateUser(user.id, { password });

  if (updateError) {
    if (
      updateError.code === "same_password" ||
      updateError.code === "weak_password"
    ) {
      throw new HttpError(
        400,
        updateError.message || "This password cannot be used.",
        updateError.code
      );
    }

    throw dbError("auth.admin.updateUserById(password)", updateError);
  }

  // Révoque toutes les sessions existantes (le lien de récupération inclus).
  try {
    await supabaseAdmin.auth.admin.signOut(sessionToken, "global");
  } catch (signOutError) {
    console.warn(
      `[${requestId}] reset-password: session revoke failed:`,
      signOutError?.message || signOutError
    );
  }

  authCacheInvalidateUser(user.id);

  sendJson(res, 200, {
    success: true,
    message: "Password updated successfully. You can now sign in.",
  });
});

// Google / GitHub : URL d'autorisation.
// redirectTo est validé avec sanitizeRedirectTo() (origine autorisée).
function registerOAuthLoginRoute(provider, extraOptions) {
  route("POST", `/api/auth/${provider}/url`, async ({ req, res }) => {
    const body = await getJsonBody(req).catch(() => ({}));
    const redirectTo = sanitizeRedirectTo(body.redirectTo);

    const { data, error } = await supabaseOAuth.auth.signInWithOAuth({
      provider,
      options: {
        redirectTo,
        skipBrowserRedirect: true,
        ...extraOptions,
      },
    });

    if (error || !data?.url) {
      throw error || new Error(`${provider}/url: no URL returned`);
    }

    sendJson(res, 200, { success: true, url: data.url });
  });
}

registerOAuthLoginRoute("google", {
  queryParams: { access_type: "offline", prompt: "select_account" },
});

registerOAuthLoginRoute("github", { scopes: "read:user user:email" });

// Révoque réellement la session côté Supabase (et vide le cache).
route("POST", "/api/auth/logout", async ({ req, res }) => {
  const authorization = req.headers.authorization || "";
  const token = authorization.replace(/^Bearer\s+/i, "").trim();

  if (token && token.length <= 4096) {
    const cachedUser = authCacheGet(token);

    try {
      await supabaseAdmin.auth.admin.signOut(token, "local");
    } catch (error) {
      console.warn("Logout revoke failed:", error?.message || error);
    }

    if (cachedUser) authCacheInvalidateUser(cachedUser.id);
  }

  sendJson(res, 200, { success: true });
});

route("POST", "/api/auth/refresh", async ({ req, res }) => {
  const body = await getJsonBody(req);

  const refreshToken = String(body.refreshToken ?? body.refresh_token ?? "");

  if (!refreshToken || refreshToken.length > 4096) {
    throw new HttpError(400, "Missing refresh token");
  }

  const { data, error } = await supabase.auth.refreshSession({
    refresh_token: refreshToken,
  });

  if (error || !data.session) {
    throw new HttpError(
      401,
      "Invalid or expired refresh token",
      "INVALID_REFRESH_TOKEN"
    );
  }

  sendJson(res, 200, {
    success: true,
    session: sessionPayload(data.session),
  });
});

route(
  "POST",
  "/api/auth/resend-verification",
  async ({ res, user }) => {
    if (user.email_confirmed_at) {
      throw new HttpError(400, "This email is already verified");
    }

    if (!user.email) {
      throw new HttpError(400, "No email associated with this account");
    }

    enforce(limiterAccount, `resend:${user.id}`);

    const { error } = await supabase.auth.resend({
      type: "signup",
      email: user.email,
    });

    if (error) throw error;

    sendJson(res, 200, { success: true, message: "Verification email sent" });
  },
  { auth: true }
);
