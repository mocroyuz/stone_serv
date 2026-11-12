-- Instagram account storage used by server/server.js.
-- Tokens are written/read only by the backend using the Supabase service role.
create table if not exists public.instagram_accounts (
  user_id uuid primary key references auth.users(id) on delete cascade,
  access_token text not null,
  access_expires_at timestamptz,
  account_id text,
  display_name text,
  avatar_url text,
  auth_type text,
  updated_at timestamptz not null default now()
);

alter table public.instagram_accounts enable row level security;

-- The backend uses the service_role key, which bypasses RLS.
-- No client-facing policies are intentionally created because this table
-- contains OAuth credentials.

grant all on table public.instagram_accounts to service_role;

-- Make the new table visible to PostgREST without waiting for a cache refresh.
notify pgrst, 'reload schema';
