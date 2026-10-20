// Routes /api/stripe/* : checkout, portail, abonnement, webhook.
//
// Retour Stripe (hash router) :
//   - checkout success → ${APP_URL}/#/account?checkout=success&session_id=...
//   - checkout cancel  → ${APP_URL}/#/pricing?checkout=cancel
//   - portal return    → ${APP_URL}/#/account

import {
  STRIPE_PRICES,
  STRIPE_WEBHOOK_SECRET,
  STRIPE_SUCCESS_URL,
  STRIPE_CANCEL_URL,
  STRIPE_PORTAL_RETURN_URL,
} from "../config/index.js";
import { route } from "../lib/router.js";
import { HttpError, withLock, createSeenCache } from "../lib/utils.js";
import { getJsonBody, getRawBody, sendJson } from "../lib/http.js";
import {
  stripe,
  requireStripe,
  planDetails,
  getStripeCustomerId,
  subscriptionSnapshot,
  syncSubscriptionToUser,
  processStripeEvent,
} from "../services/stripe.js";

route(
  "POST",
  "/api/stripe/checkout",
  async ({ req, res, user }) => {
    requireStripe();

    const body = await getJsonBody(req);
    const plan = String(body.plan || "").toLowerCase();
    const period = body.period === "annual" ? "annual" : "monthly";

    const priceId = Object.hasOwn(STRIPE_PRICES, plan)
      ? STRIPE_PRICES[plan][period]
      : undefined;

    if (!priceId) {
      const knownPlan = Object.hasOwn(STRIPE_PRICES, plan);
      throw new HttpError(
        400,
        knownPlan
          ? `Plan "${plan}" (${period}) is not configured — missing STRIPE_PRICE_${plan.toUpperCase()}_${period.toUpperCase()}`
          : `Unknown plan or period (plan="${plan.slice(0, 30)}", period="${period}")`
      );
    }

    const customerId = await getStripeCustomerId(user, { create: true });

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      customer: customerId,
      line_items: [{ price: priceId, quantity: 1 }],
      allow_promotion_codes: true,
      client_reference_id: user.id,
      success_url: STRIPE_SUCCESS_URL,
      cancel_url: STRIPE_CANCEL_URL,
      subscription_data: {
        metadata: { supabase_user_id: user.id, plan, period },
      },
    });

    sendJson(res, 200, { success: true, id: session.id, url: session.url });
  },
  { auth: true }
);

route(
  "POST",
  "/api/stripe/portal",
  async ({ res, user }) => {
    requireStripe();

    const customerId = await getStripeCustomerId(user);

    if (!customerId) {
      throw new HttpError(
        400,
        "No Stripe customer associated with this account"
      );
    }

    const session = await stripe.billingPortal.sessions.create({
      customer: customerId,
      return_url: STRIPE_PORTAL_RETURN_URL,
    });

    sendJson(res, 200, { success: true, url: session.url });
  },
  { auth: true }
);

// Interroge Stripe en direct puis resynchronise le compte si besoin :
// l'abonnement apparaît immédiatement après le checkout, même si le webhook
// est en retard.
route(
  "GET",
  "/api/stripe/subscription",
  async ({ res, user }) => {
    requireStripe();

    const customerId = await getStripeCustomerId(user);

    if (!customerId) {
      sendJson(res, 200, { success: true, subscription: null });
      return;
    }

    const list = await stripe.subscriptions.list({
      customer: customerId,
      status: "all",
      limit: 1,
    });

    const sub = list.data[0];

    if (sub) {
      const stored = user.app_metadata?.subscription;
      const fresh = subscriptionSnapshot(sub);

      const changed =
        !stored ||
        stored.id !== fresh.id ||
        stored.status !== fresh.status ||
        stored.price_id !== fresh.price_id ||
        stored.plan_key !== fresh.plan_key ||
        stored.current_period_end !== fresh.current_period_end ||
        stored.cancel_at_period_end !== fresh.cancel_at_period_end;

      if (changed) {
        try {
          await syncSubscriptionToUser(user.id, sub);
        } catch (syncError) {
          console.error("Subscription self-heal failed:", syncError.message);
        }
      }
    }

    const priceId = sub?.items?.data?.[0]?.price?.id || null;

    sendJson(res, 200, {
      success: true,
      subscription: sub
        ? {
            id: sub.id,
            status: sub.status,
            price_id: priceId,
            ...planDetails(priceId, sub.metadata?.plan),
            current_period_end: sub.current_period_end,
            cancel_at_period_end: sub.cancel_at_period_end,
          }
        : null,
    });
  },
  { auth: true }
);

// Idempotence : un événement déjà traité (même id) n'est pas rejoué ; deux
// livraisons simultanées du même événement sont fusionnées.
const processedStripeEvents = createSeenCache(10_000, 24 * 60 * 60 * 1000);

route("POST", "/api/stripe/webhook", async ({ req, res, requestId }) => {
  if (!stripe || !STRIPE_WEBHOOK_SECRET) {
    throw new HttpError(500, "Stripe webhook not configured");
  }

  const signature = req.headers["stripe-signature"];

  if (!signature) {
    throw new HttpError(400, "Missing stripe-signature");
  }

  // Corps BRUT (octets exacts reçus) : indispensable à la signature.
  const rawBody = await getRawBody(req);

  let event;

  try {
    event = stripe.webhooks.constructEvent(
      rawBody,
      signature,
      STRIPE_WEBHOOK_SECRET
    );
  } catch (webhookError) {
    console.warn(
      `[${requestId}] Webhook signature verification failed:`,
      webhookError.message
    );
    throw new HttpError(400, "Webhook signature verification failed");
  }

  if (processedStripeEvents.has(event.id)) {
    sendJson(res, 200, { received: true, duplicate: true });
    return;
  }

  // En cas d'erreur → 500 → Stripe retentera (l'événement n'est marqué
  // « traité » qu'après succès).
  await withLock(`stripe-event:${event.id}`, () => processStripeEvent(event));

  processedStripeEvents.add(event.id);

  sendJson(res, 200, { received: true });
});
