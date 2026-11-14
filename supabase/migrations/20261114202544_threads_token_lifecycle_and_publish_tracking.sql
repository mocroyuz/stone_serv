alter table public.threads_accounts
  add column if not exists access_issued_at timestamptz,
  add column if not exists access_refreshed_at timestamptz,
  add column if not exists last_error text;

alter table public.scheduled_posts
  add column if not exists external_id text,
  add column if not exists published_at timestamptz,
  add column if not exists last_error text;

create index if not exists scheduled_posts_threads_due_idx
  on public.scheduled_posts (scheduled_at)
  where network = 'threads' and status = 'external';
