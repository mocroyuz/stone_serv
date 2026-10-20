import { route } from "../lib/router.js";
import { sendJson } from "../lib/http.js";
import {
  tiktokEnabled,
  tiktokCapabilities,
  pinterestUsable,
  youtubeEnabled,
  canvaEnabled,
} from "../config/index.js";
import { stripe } from "../services/stripe.js";

route("GET", "/api/health", ({ res }) => {
  sendJson(res, 200, {
    success: true,
    server: "Stone",
    supabase: true,
    stripe: Boolean(stripe),
    tiktok: tiktokEnabled
      ? { enabled: true, ...tiktokCapabilities() }
      : { enabled: false },
    pinterest: pinterestUsable,
    youtube: youtubeEnabled,
    canva: canvaEnabled,
  });
});
