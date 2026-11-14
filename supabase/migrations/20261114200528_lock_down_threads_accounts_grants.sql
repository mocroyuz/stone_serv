-- OAuth tokens in this table are accessed only by the backend service role.
-- Remove the default Data API grants from browser-facing roles.
revoke all privileges on table public.threads_accounts from public, anon, authenticated;
grant all privileges on table public.threads_accounts to service_role;
