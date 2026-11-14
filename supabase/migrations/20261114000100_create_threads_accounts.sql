-- Threads account storage used by server/server.js.
-- OAuth credentials are written/read only by the backend with the service role.
create table if not exists public.threads_accounts (
  user_id uuid primary key references auth.users(id) on delete cascade,
  access_token text not null,
  access_expires_at timestamptz,
  account_id text,
  display_name text,
  avatar_url text,
  updated_at timestamptz not null default now()
);

alter table public.threads_accounts enable row level security;
grant all on table public.threads_accounts to service_role;
notify pgrst, 'reload schema';
