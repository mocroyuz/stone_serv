begin;

create table if not exists public.mfa_recovery_codes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  code_hash text not null check (code_hash ~ '^[0-9a-f]{64}$'),
  used_at timestamptz,
  batch_id uuid not null,
  created_at timestamptz not null default now(),
  unique (user_id, batch_id, code_hash)
);

create index if not exists mfa_recovery_codes_latest_batch_idx
  on public.mfa_recovery_codes (user_id, created_at desc);

create index if not exists mfa_recovery_codes_unused_batch_idx
  on public.mfa_recovery_codes (user_id, batch_id)
  where used_at is null;

alter table public.mfa_recovery_codes enable row level security;
revoke all on table public.mfa_recovery_codes from public, anon, authenticated;
grant all on table public.mfa_recovery_codes to service_role;

create table if not exists public.mfa_verified_sessions (
  user_id uuid not null references auth.users(id) on delete cascade,
  session_id uuid not null,
  method text not null check (method in ('recovery', 'passkey')),
  verified_at timestamptz not null,
  expires_at timestamptz not null check (expires_at > verified_at),
  primary key (user_id, session_id)
);

create index if not exists mfa_verified_sessions_expiry_idx
  on public.mfa_verified_sessions (expires_at);

alter table public.mfa_verified_sessions enable row level security;
revoke all on table public.mfa_verified_sessions from public, anon, authenticated;
grant all on table public.mfa_verified_sessions to service_role;

create table if not exists public.auth_attempts (
  attempt_key text primary key check (attempt_key ~ '^[0-9a-f]{64}$'),
  failure_count integer not null default 0 check (failure_count between 0 and 4),
  window_started_at timestamptz not null default now(),
  block_count integer not null default 0 check (block_count >= 0),
  blocked_until timestamptz,
  last_failure_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists auth_attempts_updated_at_idx
  on public.auth_attempts (updated_at);

alter table public.auth_attempts enable row level security;
revoke all on table public.auth_attempts from public, anon, authenticated;
grant all on table public.auth_attempts to service_role;

create or replace function public.mfa_recovery_replace_codes(
  p_user_id uuid,
  p_batch_id uuid,
  p_code_hashes text[]
)
returns void
language plpgsql
security definer
set search_path = pg_catalog
as $$
begin
  if p_user_id is null
    or p_batch_id is null
    or coalesce(cardinality(p_code_hashes), 0) <> 10
    or exists (
      select 1
      from unnest(p_code_hashes) as item(code_hash)
      where item.code_hash !~ '^[0-9a-f]{64}$'
    )
  then
    raise exception 'Invalid recovery code batch' using errcode = '22023';
  end if;

  update public.mfa_recovery_codes
  set used_at = coalesce(used_at, clock_timestamp())
  where user_id = p_user_id
    and used_at is null;

  insert into public.mfa_recovery_codes (user_id, code_hash, batch_id)
  select p_user_id, item.code_hash, p_batch_id
  from unnest(p_code_hashes) as item(code_hash);
end;
$$;

create or replace function public.mfa_recovery_consume_code(
  p_user_id uuid,
  p_batch_id uuid,
  p_code_hash text,
  p_session_id uuid,
  p_verified_at timestamptz,
  p_expires_at timestamptz
)
returns table (remaining bigint)
language plpgsql
security definer
set search_path = pg_catalog
as $$
declare
  v_code_id uuid;
begin
  if p_user_id is null
    or p_batch_id is null
    or p_session_id is null
    or p_code_hash !~ '^[0-9a-f]{64}$'
    or p_verified_at is null
    or p_expires_at is null
    or p_expires_at <= p_verified_at
  then
    raise exception 'Invalid recovery verification' using errcode = '22023';
  end if;

  update public.mfa_recovery_codes
  set used_at = p_verified_at
  where user_id = p_user_id
    and batch_id = p_batch_id
    and code_hash = p_code_hash
    and used_at is null
  returning id into v_code_id;

  if v_code_id is null then
    return;
  end if;

  insert into public.mfa_verified_sessions (
    user_id, session_id, method, verified_at, expires_at
  )
  values (p_user_id, p_session_id, 'recovery', p_verified_at, p_expires_at)
  on conflict (user_id, session_id)
  do update set
    method = excluded.method,
    verified_at = excluded.verified_at,
    expires_at = excluded.expires_at;

  return query
  select count(*)
  from public.mfa_recovery_codes
  where user_id = p_user_id
    and batch_id = p_batch_id
    and used_at is null;
end;
$$;

create or replace function public.auth_attempts_check(p_attempt_key text)
returns table (allowed boolean, retry_after integer)
language plpgsql
security definer
set search_path = pg_catalog
as $$
declare
  v_blocked_until timestamptz;
  v_remaining integer;
begin
  if p_attempt_key is null or p_attempt_key !~ '^[0-9a-f]{64}$' then
    raise exception 'Invalid attempt key' using errcode = '22023';
  end if;

  delete from public.auth_attempts
  where updated_at < clock_timestamp() - interval '30 days';

  select attempts.blocked_until
  into v_blocked_until
  from public.auth_attempts as attempts
  where attempts.attempt_key = p_attempt_key;

  if v_blocked_until is not null and v_blocked_until > clock_timestamp() then
    v_remaining := greatest(
      1,
      ceil(extract(epoch from (v_blocked_until - clock_timestamp())))::integer
    );
    return query select false, v_remaining;
    return;
  end if;

  return query select true, null::integer;
end;
$$;

create or replace function public.auth_attempts_record_failure(p_attempt_key text)
returns void
language plpgsql
security definer
set search_path = pg_catalog
as $$
declare
  v_attempt public.auth_attempts%rowtype;
  v_now timestamptz := clock_timestamp();
  v_failure_count integer;
  v_window_started_at timestamptz;
  v_block_count integer;
  v_block_seconds integer;
begin
  if p_attempt_key is null or p_attempt_key !~ '^[0-9a-f]{64}$' then
    raise exception 'Invalid attempt key' using errcode = '22023';
  end if;

  insert into public.auth_attempts (attempt_key, window_started_at)
  values (p_attempt_key, v_now)
  on conflict (attempt_key) do nothing;

  select attempts.*
  into v_attempt
  from public.auth_attempts as attempts
  where attempts.attempt_key = p_attempt_key
  for update;

  if v_attempt.blocked_until is not null and v_attempt.blocked_until > v_now then
    return;
  end if;

  if v_attempt.window_started_at <= v_now - interval '5 minutes' then
    v_failure_count := 1;
    v_window_started_at := v_now;
  else
    v_failure_count := v_attempt.failure_count + 1;
    v_window_started_at := v_attempt.window_started_at;
  end if;

  if v_failure_count >= 5 then
    v_block_count := v_attempt.block_count + 1;
    v_block_seconds := least(
      300 * power(2, least(v_attempt.block_count, 9)),
      86400
    )::integer;

    update public.auth_attempts
    set failure_count = 0,
        window_started_at = v_now,
        block_count = v_block_count,
        blocked_until = v_now + make_interval(secs => v_block_seconds),
        last_failure_at = v_now,
        updated_at = v_now
    where attempt_key = p_attempt_key;
    return;
  end if;

  update public.auth_attempts
  set failure_count = v_failure_count,
      window_started_at = v_window_started_at,
      blocked_until = null,
      last_failure_at = v_now,
      updated_at = v_now
  where attempt_key = p_attempt_key;
end;
$$;

create or replace function public.auth_attempts_reset_success(p_attempt_key text)
returns void
language plpgsql
security definer
set search_path = pg_catalog
as $$
begin
  if p_attempt_key is null or p_attempt_key !~ '^[0-9a-f]{64}$' then
    raise exception 'Invalid attempt key' using errcode = '22023';
  end if;

  update public.auth_attempts
  set failure_count = 0,
      block_count = 0,
      window_started_at = clock_timestamp(),
      blocked_until = null,
      updated_at = clock_timestamp()
  where attempt_key = p_attempt_key;
end;
$$;

revoke all on function public.mfa_recovery_replace_codes(uuid, uuid, text[]) from public, anon, authenticated;
revoke all on function public.mfa_recovery_consume_code(uuid, uuid, text, uuid, timestamptz, timestamptz) from public, anon, authenticated;
revoke all on function public.auth_attempts_check(text) from public, anon, authenticated;
revoke all on function public.auth_attempts_record_failure(text) from public, anon, authenticated;
revoke all on function public.auth_attempts_reset_success(text) from public, anon, authenticated;

grant execute on function public.mfa_recovery_replace_codes(uuid, uuid, text[]) to service_role;
grant execute on function public.mfa_recovery_consume_code(uuid, uuid, text, uuid, timestamptz, timestamptz) to service_role;
grant execute on function public.auth_attempts_check(text) to service_role;
grant execute on function public.auth_attempts_record_failure(text) to service_role;
grant execute on function public.auth_attempts_reset_success(text) to service_role;

commit;
