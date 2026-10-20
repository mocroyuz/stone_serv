// Service Stripe : client, plans, clients Stripe ↔ Supabase, synchronisation
// des abonnements, traitement des événements webhook.

import Stripe from "stripe";
import {
  STRIPE_SECRET_KEY,
  PLAN_NAMES,
  PRICE_TO_PLAN,
} from "../config/index.js";
import { HttpError, withLock, idOf } from "../lib/utils.js";
import { getAppMetadata, updateAppMetadata } from "../lib/auth.js";

export const stripe = STRIPE_SECRET_KEY
  ? new Stripe(STRIPE_SECRET_KEY, {
      apiVersion: "2024-06-20",
      maxNetworkRetries: 2,
      timeout: 20_000,
    })
  : null;

export function requireStripe() {
  if (!stripe) throw new HttpError(500, "Stripe is not configured");
}

const isStripeMissing = (error) => error?.code === "resource_missing";

// Source : le price ID de l'abonnement, avec repli sur la metadata `plan`
// posée au checkout.
export function planDetails(priceId, metadataPlan) {
  let key = priceId ? PRICE_TO_PLAN.get(priceId) : undefined;

  if (!key) {
    const fromMetadata = String(metadataPlan || "").toLowerCase();
    if (Object.hasOwn(PLAN_NAMES, fromMetadata)) key = fromMetadata;
  }

  return {
    plan: key || null,
    plan_key: key || null,
    plan_name: key ? PLAN_NAMES[key] : null,
  };
}

// Retourne l'identifiant de client Stripe de l'utilisateur.
// - source de vérité : app_metadata (serveur uniquement)
// - migration : un ancien id dans user_metadata n'est accepté que si le
//   client Stripe correspondant appartient bien à cet utilisateur.
// - création : sous verrou, après relecture d'app_metadata.
export async function getStripeCustomerId(user, { create = false } = {}) {
  const trusted = user.app_metadata?.stripe_customer_id;
  if (trusted) return trusted;

  const legacy = user.user_metadata?.stripe_customer_id;

  if (legacy) {
    try {
      const customer = await stripe.customers.retrieve(legacy);

      if (
        customer &&
        !customer.deleted &&
        customer.metadata?.supabase_user_id === user.id
      ) {
        try {
          await updateAppMetadata(user.id, (current) => ({
            ...current,
            stripe_customer_id: legacy,
          }));
        } catch (saveError) {
          console.error(
            "Legacy Stripe customer migration not saved:",
            saveError.message
          );
        }

        return legacy;
      }
    } catch (error) {
      console.warn("Legacy Stripe customer check failed:", error.message);
    }
  }

  if (!create) return null;

  return withLock(`stripe-customer:${user.id}`, async () => {
    // Un autre appel a pu créer / enregistrer le client entre-temps.
    const fresh = await getAppMetadata(user.id);
    if (fresh.stripe_customer_id) return fresh.stripe_customer_id;

    let customerId = null;

    try {
      const found = await stripe.customers.search({
        query: `metadata['supabase_user_id']:'${user.id}'`,
        limit: 1,
      });

      customerId = found.data[0]?.id || null;
    } catch (searchError) {
      console.warn("Stripe customer search failed:", searchError.message);
    }

    if (!customerId) {
      const customer = await stripe.customers.create({
        email: user.email,
        metadata: { supabase_user_id: user.id },
      });

      customerId = customer.id;
    }

    try {
      await updateAppMetadata(user.id, (current) => ({
        ...current,
        stripe_customer_id: customerId,
      }));
    } catch (saveError) {
      console.error(
        `Stripe customer ${customerId} exists but could not be saved for user ${user.id}:`,
        saveError.message
      );
      throw saveError;
    }

    return customerId;
  });
}

// null UNIQUEMENT si le client est supprimé / inconnu / sans lien utilisateur.
// Une erreur réseau ou API est propagée : le webhook répond 500 et Stripe
// réessaie.
async function resolveUserIdFromCustomer(customerId) {
  if (!customerId) return null;

  const id = typeof customerId === "string" ? customerId : customerId.id;

  try {
    const customer = await stripe.customers.retrieve(id);

    if (customer && !customer.deleted) {
      return customer.metadata?.supabase_user_id || null;
    }

    return null;
  } catch (error) {
    if (isStripeMissing(error)) return null;
    throw error;
  }
}

export function subscriptionSnapshot(subscription) {
  const price = subscription.items?.data?.[0]?.price;

  return {
    id: subscription.id,
    status: subscription.status,
    price_id: price?.id || null,
    product_id: price?.product || null,
    ...planDetails(price?.id, subscription.metadata?.plan),
    current_period_end: subscription.current_period_end,
    cancel_at_period_end: subscription.cancel_at_period_end,
    customer_id:
      typeof subscription.customer === "string"
        ? subscription.customer
        : subscription.customer?.id || null,
  };
}

const TERMINAL_SUBSCRIPTION_STATUSES = new Set([
  "canceled",
  "incomplete_expired",
]);

// Écrit l'état d'abonnement (issu de Stripe) dans app_metadata.
//  - eventCreated : horodatage Stripe (s) de l'événement. Un événement plus
//    ancien que le dernier appliqué est ignoré (livraison dans le désordre).
//  - Un événement terminal d'un ANCIEN abonnement n'écrase pas un
//    abonnement différent encore actif.
//  - overrides : champs forcés dans le snapshot (ex. status "past_due").
// Renvoie true si l'état a été écrit.
export async function syncSubscriptionToUser(
  userId,
  subscription,
  { eventCreated = 0, overrides = {} } = {}
) {
  const snapshot = { ...subscriptionSnapshot(subscription), ...overrides };
  let written = false;

  await updateAppMetadata(userId, (current) => {
    const lastEventAt = Number(current.subscription_event_at || 0);

    if (eventCreated && eventCreated < lastEventAt) return null;

    const stored = current.subscription;

    if (
      stored?.id &&
      stored.id !== snapshot.id &&
      !TERMINAL_SUBSCRIPTION_STATUSES.has(stored.status) &&
      TERMINAL_SUBSCRIPTION_STATUSES.has(snapshot.status)
    ) {
      return null;
    }

    written = true;

    return {
      ...current,
      subscription: snapshot,
      subscription_event_at: Math.max(lastEventAt, eventCreated || 0),
    };
  });

  return written;
}

async function retrieveSubscription(subscriptionId, fallback) {
  try {
    return await stripe.subscriptions.retrieve(subscriptionId);
  } catch (error) {
    if (isStripeMissing(error) && fallback) return fallback;
    throw error;
  }
}

// Traite UN événement Stripe (déjà authentifié par sa signature).
// Toute erreur remonte → 500 → Stripe réessaie. Les handlers sont
// idempotents : l'état est toujours relu depuis Stripe.
export async function processStripeEvent(event) {
  const eventCreated = Number(event.created) || 0;

  try {
    switch (event.type) {
      case "checkout.session.completed": {
        const session = event.data.object;
        const subscriptionId = idOf(session.subscription);

        if (session.mode !== "subscription" || !subscriptionId) break;

        const userId =
          session.client_reference_id ||
          (await resolveUserIdFromCustomer(session.customer));

        if (userId) {
          const subscription = await retrieveSubscription(subscriptionId);
          await syncSubscriptionToUser(userId, subscription, { eventCreated });
        }
        break;
      }

      case "customer.subscription.created":
      case "customer.subscription.updated":
      case "customer.subscription.deleted": {
        const payload = event.data.object;
        const userId = await resolveUserIdFromCustomer(payload.customer);

        if (userId) {
          // Données fraîches de Stripe : un événement en retard ne peut pas
          // réinjecter un ancien état.
          const subscription = await retrieveSubscription(payload.id, payload);
          await syncSubscriptionToUser(userId, subscription, { eventCreated });
        }
        break;
      }

      case "invoice.payment_failed": {
        const invoice = event.data.object;
        const subscriptionId = idOf(invoice.subscription);

        if (!subscriptionId) break; // facture hors abonnement

        const userId = await resolveUserIdFromCustomer(invoice.customer);
        if (!userId) break;

        // Preuve côté Stripe : la facture est-elle TOUJOURS impayée ?
        const [freshInvoice, subscription] = await Promise.all([
          stripe.invoices.retrieve(invoice.id),
          stripe.subscriptions.retrieve(subscriptionId),
        ]);

        const stillUnpaid = freshInvoice.status === "open";
        const liveStatus = subscription.status;

        await syncSubscriptionToUser(userId, subscription, {
          eventCreated,
          overrides:
            stillUnpaid && (liveStatus === "active" || liveStatus === "trialing")
              ? { status: "past_due" }
              : {},
        });
        break;
      }

      // Récupération après un échec de paiement : on relit l'état RÉEL de
      // la subscription puis on synchronise.
      case "invoice.payment_succeeded": {
        const invoice = event.data.object;
        const subscriptionId = idOf(invoice.subscription);

        if (!subscriptionId) break; // facture hors abonnement

        const userId = await resolveUserIdFromCustomer(invoice.customer);
        if (!userId) break;

        const subscription = await retrieveSubscription(subscriptionId);

        await syncSubscriptionToUser(userId, subscription, { eventCreated });
        break;
      }

      default:
        // Événement ignoré
        break;
    }
  } catch (error) {
    if (error instanceof HttpError && error.code === "USER_NOT_FOUND") {
      // Utilisateur supprimé côté Supabase : inutile que Stripe réessaie.
      console.warn(
        `[stripe:webhook] ${event.id} (${event.type}) ignoré : utilisateur introuvable`
      );
      return;
    }

    throw error;
  }
}
