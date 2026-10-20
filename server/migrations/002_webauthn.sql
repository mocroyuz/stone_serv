begin;

create table if not exists public.webauthn_credentials (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  credential_id text not null unique
    check (credential_id ~ '^[A-Za-z0-9_-]{1,2048}$'),
  public_key text not null
    check (public_key ~ '^[A-Za-z0-9_-]{1,8192}$'),
  counter bigint not null default 0 check (counter >= 0),
  transports text[] not null default '{}'
    check (transports <@ array['ble', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb']::text[]),
  name text not null check (length(name) between 1 and 100),
  created_at timestamptz not null default now(),
  last_used_at timestamptz
);

create index if not exists webauthn_credentials_user_idx
  on public.webauthn_credentials (user_id, created_at);

alter table public.webauthn_credentials enable row level security;
revoke all on table public.webauthn_credentials from public, anon, authenticated;
grant all on table public.webauthn_credentials to service_role;

create table if not exists public.webauthn_challenges (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  session_id uuid not null,
  purpose text not null check (purpose in ('register', 'authenticate')),
  challenge text not null check (challenge ~ '^[A-Za-z0-9_-]{16,512}$'),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null check (expires_at > created_at),
  used_at timestamptz
);

create unique index if not exists webauthn_challenges_one_pending_idx
  on public.webauthn_challenges (user_id, session_id, purpose)
  where used_at is null;

create index if not exists webauthn_challenges_expiry_idx
  on public.webauthn_challenges (expires_at);

alter table public.webauthn_challenges enable row level security;
revoke all on table public.webauthn_challenges from public, anon, authenticated;
grant all on table public.webauthn_challenges to service_role;

create or replace function public.webauthn_create_challenge(
  p_user_id uuid,
  p_session_id uuid,
  p_purpose text,
  p_challenge text
)
returns void
language plpgsql
security definer
set search_path = pg_catalog
as $$
declare
  v_now timestamptz := clock_timestamp();
begin
  if p_user_id is null
    or p_session_id is null
    or p_purpose is null
    or p_purpose not in ('register', 'authenticate')
    or p_challenge is null
    or p_challenge !~ '^[A-Za-z0-9_-]{16,512}$'
  then
    raise exception 'Invalid WebAuthn challenge' using errcode = '22023';
  end if;

  perform pg_advisory_xact_lock(
    hashtextextended(p_user_id::text || ':' || p_session_id::text || ':' || p_purpose, 0)
  );

  delete from public.webauthn_challenges
  where expires_at <= v_now
    or (used_at is not null and created_at < v_now - interval '1 day');

  delete from public.webauthn_challenges
  where user_id = p_user_id
    and session_id = p_session_id
    and purpose = p_purpose
    and used_at is null;

  insert into public.webauthn_challenges (
    user_id, session_id, purpose, challenge, created_at, expires_at
  )
  values (
    p_user_id, p_session_id, p_purpose, p_challenge, v_now, v_now + interval '5 minutes'
  );
end;
$$;

create or replace function public.webauthn_consume_challenge(
  p_user_id uuid,
  p_session_id uuid,
  p_purpose text
)
returns table (challenge text)
language plpgsql
security definer
set search_path = pg_catalog
as $$
declare
  v_challenge text;
begin
  if p_user_id is null
    or p_session_id is null
    or p_purpose is null
    or p_purpose not in ('register', 'authenticate')
  then
    raise exception 'Invalid WebAuthn challenge lookup' using errcode = '22023';
  end if;

  update public.webauthn_challenges as pending
  set used_at = clock_timestamp()
  where pending.user_id = p_user_id
    and pending.session_id = p_session_id
    and pending.purpose = p_purpose
    and pending.used_at is null
    and pending.expires_at > clock_timestamp()
  returning pending.challenge into v_challenge;

  if v_challenge is null then
    return;
  end if;

  return query select v_challenge;
end;
$$;

revoke all on function public.webauthn_create_challenge(uuid, uuid, text, text) from public, anon, authenticated;
revoke all on function public.webauthn_consume_challenge(uuid, uuid, text) from public, anon, authenticated;

grant execute on function public.webauthn_create_challenge(uuid, uuid, text, text) to service_role;
grant execute on function public.webauthn_consume_challenge(uuid, uuid, text) to service_role;

commit;
