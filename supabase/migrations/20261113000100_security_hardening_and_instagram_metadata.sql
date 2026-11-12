-- Security hardening and OAuth metadata for Stone.
-- Safe to re-run: policies and columns are created idempotently.
begin;

alter table public.instagram_accounts
  add column if not exists scope text,
  add column if not exists token_type text;

revoke all privileges on all tables in schema public from anon;

revoke all privileges on table
  public.mfa_email_codes,
  public.mfa_verified_sessions,
  public.webauthn_challenges,
  public.webauthn_credentials
from anon, authenticated;

do $$
declare t record;
begin
  for t in
    select tablename from pg_tables where schemaname = 'public'
  loop
    execute format('alter table public.%I enable row level security', t.tablename);
  end loop;
end $$;

do $$
declare t text;
begin
  foreach t in array array[
    'instagram_accounts','tiktok_accounts','youtube_accounts',
    'pinterest_accounts','canva_accounts','dropbox_accounts',
    'google_drive_accounts','google_photos_accounts',
    'follower_snapshots','groups','saved_replies',
    'mfa_email_settings','youtube_comment_reads'
  ]
  loop
    execute format('drop policy if exists %I on public.%I', t || '_owner_all', t);
    execute format(
      'create policy %I on public.%I for all to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id)',
      t || '_owner_all', t
    );
  end loop;
end $$;

drop policy if exists "Users can view own tags" on public.tags;
drop policy if exists "Users can insert own tags" on public.tags;
drop policy if exists "Users can update own tags" on public.tags;
drop policy if exists "Users can delete own tags" on public.tags;
create policy "Users can view own tags" on public.tags
  for select to authenticated using ((select auth.uid()) = user_id);
create policy "Users can insert own tags" on public.tags
  for insert to authenticated with check ((select auth.uid()) = user_id);
create policy "Users can update own tags" on public.tags
  for update to authenticated using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);
create policy "Users can delete own tags" on public.tags
  for delete to authenticated using ((select auth.uid()) = user_id);

drop policy if exists "own posts" on public.scheduled_posts;
create policy "own posts" on public.scheduled_posts
  for all to authenticated using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

drop policy if exists "own notifications select" on public.notifications;
drop policy if exists "own notifications update" on public.notifications;
create policy "own notifications select" on public.notifications
  for select to authenticated using ((select auth.uid()) = user_id);
create policy "own notifications update" on public.notifications
  for update to authenticated using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

revoke all on function public.rls_auto_enable() from public, anon, authenticated, service_role;
alter function public.tags_touch_updated_at() set search_path = pg_catalog, public;
alter function public.unread_counts(uuid) set search_path = pg_catalog, public;

create index if not exists webauthn_credentials_user_id_idx
  on public.webauthn_credentials(user_id);

revoke all privileges on table
  public.instagram_accounts,
  public.tiktok_accounts,
  public.youtube_accounts,
  public.pinterest_accounts,
  public.canva_accounts,
  public.dropbox_accounts,
  public.google_drive_accounts,
  public.google_photos_accounts
from anon, authenticated;

grant select, insert, update, delete on table
  public.instagram_accounts,
  public.tiktok_accounts,
  public.youtube_accounts,
  public.pinterest_accounts,
  public.canva_accounts,
  public.dropbox_accounts,
  public.google_drive_accounts,
  public.google_photos_accounts
to service_role;

notify pgrst, 'reload schema';
commit;
