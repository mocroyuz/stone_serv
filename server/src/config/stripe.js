// Configuration Stripe : clés, price IDs, plans, URLs de retour.

import { env } from "./env.js";
import { APP_URL } from "./app.js";

export const STRIPE_SECRET_KEY = env("STRIPE_SECRET_KEY");
export const STRIPE_WEBHOOK_SECRET = env("STRIPE_WEBHOOK_SECRET");

export const STRIPE_PRICES = {
  starter: {
    monthly: env("STRIPE_PRICE_STARTER_MONTHLY"),
    annual: env("STRIPE_PRICE_STARTER_ANNUAL"),
  },
  pro: {
    monthly: env("STRIPE_PRICE_PRO_MONTHLY"),
    annual: env("STRIPE_PRICE_PRO_ANNUAL"),
  },
  enterprise: {
    monthly: env("STRIPE_PRICE_ENTERPRISE_MONTHLY"),
    annual: env("STRIPE_PRICE_ENTERPRISE_ANNUAL"),
  },
};

// Correspondance price ID Stripe ↔ plan
export const PLAN_NAMES = {
  starter: "Starter",
  pro: "Professional",
  enterprise: "Enterprise",
};

export const PRICE_TO_PLAN = new Map();

for (const [planKey, periods] of Object.entries(STRIPE_PRICES)) {
  for (const priceId of Object.values(periods)) {
    if (priceId) PRICE_TO_PLAN.set(priceId, planKey);
  }
}

// URLs de retour : le frontend utilise un routage par hash, les URLs
// DOIVENT donc inclure le "#". Les query params viennent APRÈS le hash.
export const STRIPE_SUCCESS_URL = `${APP_URL}/#/account?checkout=success&session_id={CHECKOUT_SESSION_ID}`;
export const STRIPE_CANCEL_URL = `${APP_URL}/#/pricing?checkout=cancel`;
export const STRIPE_PORTAL_RETURN_URL = `${APP_URL}/#/account`;
