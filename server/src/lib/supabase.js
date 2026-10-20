// Clients Supabase. Pas de session persistée ni d'auto-refresh : ce serveur
// est stateless, un client partagé ne doit jamais mémoriser une session.

import { createClient } from "@supabase/supabase-js";
import {
  SUPABASE_URL,
  SUPABASE_ANON_KEY,
  SUPABASE_SERVICE_ROLE_KEY,
} from "../config/index.js";

const serverAuthOptions = {
  persistSession: false,
  autoRefreshToken: false,
  detectSessionInUrl: false,
};

export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: serverAuthOptions,
});

export const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: serverAuthOptions,
});

export const supabaseOAuth = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: { ...serverAuthOptions, flowType: "implicit" },
});
