-- Additive device-envelope foundation. Legacy shared-key RPCs remain usable
-- while vault_state.envelope_status is legacy or preparing.
begin;

alter table public.vault_state
  add column if not exists envelope_status text not null default 'legacy'
    check (envelope_status in ('legacy', 'preparing', 'staging', 'active', 'maintenance')),
  add column if not exists prepared_generation uuid,
  add column if not exists active_migration_id uuid;

create or replace function public.qv_base64url_bytes(p_value text, p_expected_bytes integer default null)
returns bytea
language plpgsql immutable
set search_path = public, pg_temp
as $base64url$
declare
  normalized text;
  decoded bytea;
  canonical text;
begin
  if p_value is null or p_value !~ '^[A-Za-z0-9_-]+$' or length(p_value) % 4 = 1 then return null; end if;
  normalized := replace(replace(p_value, '-', '+'), '_', '/');
  normalized := normalized || repeat('=', (4 - length(normalized) % 4) % 4);
  decoded := decode(normalized, 'base64');
  if p_expected_bytes is not null and octet_length(decoded) <> p_expected_bytes then return null; end if;
  canonical := rtrim(replace(replace(replace(encode(decoded, 'base64'), E'\n', ''), '+', '-'), '/', '_'), '=');
  if canonical <> p_value then return null; end if;
  return decoded;
exception when others then
  return null;
end;
$base64url$;

create or replace function public.qv_valid_public_jwk(p_jwk jsonb)
returns boolean
language plpgsql immutable
set search_path = public, pg_temp
as $jwk$
declare
  modulus bytea;
begin
  if jsonb_typeof(p_jwk) <> 'object' or p_jwk->>'kty' <> 'RSA' or p_jwk->>'e' <> 'AQAB'
     or p_jwk ? 'd' or p_jwk ? 'p' or p_jwk ? 'q' or p_jwk ? 'dp' or p_jwk ? 'dq' or p_jwk ? 'qi' then return false; end if;
  modulus := public.qv_base64url_bytes(p_jwk->>'n', 384);
  return modulus is not null and get_byte(modulus, 0) >= 128;
exception when others then
  return false;
end;
$jwk$;

create or replace function public.qv_public_key_fingerprint(p_jwk jsonb)
returns text
language plpgsql immutable
set search_path = public, pg_temp
as $fingerprint$
declare
  payload bytea;
begin
  if public.qv_valid_public_jwk(p_jwk) is not true then return null; end if;
  payload := convert_to(jsonb_build_array(1, 'RSA-OAEP', 'SHA-256', p_jwk->>'n', p_jwk->>'e')::text, 'UTF8');
  return rtrim(replace(replace(replace(encode(sha256(payload), 'base64'), E'\n', ''), '+', '-'), '/', '_'), '=');
exception when others then
  return null;
end;
$fingerprint$;

create or replace function public.qv_valid_encrypted_bundle(p_bundle jsonb)
returns boolean
language plpgsql immutable
set search_path = public, pg_temp
as $bundle$
declare
  iv bytea;
  data bytea;
begin
  if jsonb_typeof(p_bundle) <> 'object' or p_bundle->>'version' <> '2' then return false; end if;
  iv := decode(p_bundle->>'iv', 'base64');
  data := decode(p_bundle->>'data', 'base64');
  return octet_length(iv) = 12 and octet_length(data) >= 16
    and replace(encode(iv, 'base64'), E'\n', '') = p_bundle->>'iv'
    and replace(encode(data, 'base64'), E'\n', '') = p_bundle->>'data'
    and p_bundle->>'iv' ~ '^[A-Za-z0-9+/]+={0,2}$'
    and p_bundle->>'data' ~ '^[A-Za-z0-9+/]+={0,2}$'
    and octet_length(p_bundle::text) <= 65536;
exception when others then
  return false;
end;
$bundle$;

create or replace function public.qv_valid_migration_copy(p_row jsonb)
returns boolean
language plpgsql immutable
set search_path = public, pg_temp
as $copy$
declare
  key_name text;
  actor uuid;
  generation uuid;
begin
  if jsonb_typeof(p_row) <> 'object' then return false; end if;
  for key_name in select jsonb_object_keys(p_row) loop
    if key_name not in ('id', 'text', 'author', 'context', 'quote_date', 'created_at', 'user_id', 'vault_generation') then return false; end if;
  end loop;
  actor := (p_row->>'user_id')::uuid;
  generation := (p_row->>'vault_generation')::uuid;
  return public.qv_valid_quote(p_row, actor, generation);
exception when others then
  return false;
end;
$copy$;

create table if not exists public.vault_devices (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  status text not null check (status in ('pending', 'active', 'revoked', 'expired')),
  request_kind text not null check (request_kind in ('first', 'additional', 'recovery')),
  expires_at timestamptz,
  enrollment_fingerprint text not null check (enrollment_fingerprint ~ '^[A-Za-z0-9_-]{43}$'),
  public_jwk jsonb not null check (public.qv_valid_public_jwk(public_jwk) and octet_length(public_jwk::text) <= 32768),
  public_key_fingerprint text not null check (public_key_fingerprint ~ '^[A-Za-z0-9_-]{43}$'),
  authorization_token_digest text not null check (authorization_token_digest ~ '^[A-Za-z0-9_-]{43}$'),
  label text not null check (length(label) between 1 and 100),
  protection_mode text not null check (protection_mode in ('passkey-prf', 'remembered')),
  protection jsonb not null check (jsonb_typeof(protection) = 'object' and octet_length(protection::text) <= 32768),
  encrypted_private_bundle jsonb not null check (public.qv_valid_encrypted_bundle(encrypted_private_bundle)),
  approved_by_device_id uuid references public.vault_devices(id) on delete set null,
  created_at timestamptz not null default now(),
  last_sync_at timestamptz,
  lease_expires_at timestamptz,
  revoked_at timestamptz,
  check ((status = 'pending' and expires_at is not null) or status <> 'pending'),
  check (status <> 'revoked' or revoked_at is not null)
);

create table if not exists public.vault_device_wrappers (
  device_id uuid not null references public.vault_devices(id) on delete cascade,
  generation uuid not null,
  purpose text not null check (purpose in ('active', 'conversion_only')),
  wrapped_key text not null check (length(wrapped_key) between 1 and 32768),
  created_by_device_id uuid references public.vault_devices(id) on delete set null,
  created_at timestamptz not null default now(),
  primary key (device_id, generation, purpose)
);

create table if not exists public.vault_recovery_keys (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  status text not null check (status in ('pending', 'active', 'revoked')),
  public_jwk jsonb not null check (public.qv_valid_public_jwk(public_jwk) and octet_length(public_jwk::text) <= 32768),
  public_key_fingerprint text not null check (public_key_fingerprint ~ '^[A-Za-z0-9_-]{43}$'),
  encrypted_private_key jsonb not null check (public.qv_valid_encrypted_bundle(encrypted_private_key)),
  kdf jsonb not null check (jsonb_typeof(kdf) = 'object' and octet_length(kdf::text) <= 32768),
  created_at timestamptz not null default now(),
  confirmed_at timestamptz,
  revoked_at timestamptz,
  check (status <> 'active' or confirmed_at is not null),
  check (status <> 'revoked' or revoked_at is not null)
);

create table if not exists public.vault_recovery_wrappers (
  recovery_key_id uuid not null references public.vault_recovery_keys(id) on delete cascade,
  generation uuid not null,
  wrapped_key text not null check (length(wrapped_key) between 1 and 32768),
  created_by_device_id uuid references public.vault_devices(id) on delete set null,
  created_at timestamptz not null default now(),
  primary key (recovery_key_id, generation)
);

create table if not exists public.vault_recovery_challenges (
  id uuid primary key default gen_random_uuid(),
  recovery_key_id uuid not null references public.vault_recovery_keys(id) on delete cascade,
  expected_digest text not null check (expected_digest ~ '^[A-Za-z0-9_-]{43}$'),
  expires_at timestamptz not null,
  used_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.vault_migrations (
  id uuid primary key default gen_random_uuid(),
  source_generation uuid not null,
  target_generation uuid not null unique,
  target_verifier jsonb not null check (jsonb_typeof(target_verifier) = 'object' and octet_length(target_verifier::text) <= 32768),
  source_revision bigint not null check (source_revision >= 0),
  expected_quote_count integer not null check (expected_quote_count >= 0),
  status text not null check (status in ('prepared', 'staging', 'verified', 'activated', 'rolled_back', 'abandoned')),
  initiating_device_id uuid not null references public.vault_devices(id) on delete restrict,
  prepared_at timestamptz not null default now(),
  activated_at timestamptz,
  rollback_expires_at timestamptz
);

create table if not exists public.vault_migration_quote_copies (
  migration_id uuid not null references public.vault_migrations(id) on delete cascade,
  copy_kind text not null check (copy_kind in ('staged', 'rollback')),
  quote_id uuid not null,
  encrypted_row jsonb not null check (jsonb_typeof(encrypted_row) = 'object' and octet_length(encrypted_row::text) <= 300000 and encrypted_row->>'id' = quote_id::text and encrypted_row->>'vault_generation' = vault_generation::text and public.qv_valid_migration_copy(encrypted_row)),
  vault_generation uuid not null,
  primary key (migration_id, copy_kind, quote_id)
);

create table if not exists public.vault_security_events (
  id bigint generated always as identity primary key,
  event_type text not null check (event_type in ('device_requested', 'device_approved', 'device_completed', 'device_restored', 'device_renamed', 'device_forgotten', 'device_expired', 'device_revoked', 'recovery_created', 'recovery_replaced', 'recovery_used', 'recovery_invalidated', 'member_added', 'member_removed', 'rotation_started', 'rotation_resumed', 'rotation_verified', 'rotation_activated', 'rotation_rolled_back', 'rotation_abandoned', 'migration_started', 'migration_resumed', 'migration_verified', 'migration_activated', 'migration_rolled_back', 'migration_abandoned')),
  actor_id uuid references auth.users(id) on delete set null,
  affected_owner_id uuid references auth.users(id) on delete set null,
  affected_device_id uuid references public.vault_devices(id) on delete set null,
  result text not null check (result in ('ok', 'rejected', 'failed')),
  reason_code text not null check (length(reason_code) between 1 and 100),
  metadata jsonb not null default '{}'::jsonb check (jsonb_typeof(metadata) = 'object' and octet_length(metadata::text) <= 8192),
  created_at timestamptz not null default now()
);

create or replace function public.qv_envelope_legacy_mode()
returns boolean
language sql stable security definer
set search_path = public, pg_temp
as $$
  select envelope_status in ('legacy', 'preparing') from public.vault_state where singleton
$$;

create or replace function public.qv_authorize_device(
  p_device_id uuid,
  p_token text,
  p_generation uuid,
  p_operation text
)
returns jsonb
language plpgsql security definer
set search_path = public, pg_temp
as $authorize$
declare
  state public.vault_state%rowtype;
  device public.vault_devices%rowtype;
  caller uuid := auth.uid();
  token_bytes bytea;
begin
  select * into state from public.vault_state where singleton for update;
  select * into device from public.vault_devices where id = p_device_id for update;
  if not found or caller is null or device.owner_id is distinct from caller
     or public.qv_is_member() is not true
     or device.status <> 'active'
     or p_operation not in ('state', 'sync', 'import', 'edit', 'wrapper', 'lease_renewal', 'complete', 'revoke') then
    return null;
  end if;
  if p_generation is distinct from state.generation
     and not (p_operation = 'complete' and state.envelope_status = 'preparing' and p_generation is not distinct from state.prepared_generation) then return null; end if;
  token_bytes := public.qv_base64url_bytes(p_token, 32);
  if token_bytes is null or rtrim(replace(replace(replace(encode(sha256(token_bytes), 'base64'), E'\n', ''), '+', '-'), '/', '_'), '=') <> device.authorization_token_digest then return null; end if;
  if p_operation <> 'lease_renewal' and (device.lease_expires_at is null or device.lease_expires_at <= now()) then return null; end if;
  return jsonb_build_object('device_id', device.id, 'owner_id', device.owner_id, 'generation', state.generation, 'lease_expires_at', device.lease_expires_at);
exception when others then
  return null;
end;
$authorize$;

create or replace function public.request_device(
  p_device_id uuid, p_owner_id uuid, p_label text, p_public_jwk jsonb, p_enrollment_fingerprint text,
  p_public_key_fingerprint text, p_token_digest text, p_protection_mode text,
  p_protection jsonb, p_encrypted_private_bundle jsonb, p_request_kind text
)
returns jsonb
language plpgsql security definer
set search_path = public, pg_temp
as $request$
declare
  caller uuid := auth.uid();
  device public.vault_devices%rowtype;
begin
  if caller is null or p_owner_id is distinct from caller and public.qv_is_admin() is not true then raise exception 'Device request is not authorized' using errcode = '42501'; end if;
  if public.qv_is_active_profile(p_owner_id) is not true then raise exception 'QuoteVault membership is required' using errcode = '42501'; end if;
  if p_public_jwk is null or octet_length(p_public_jwk::text) > 32768 or public.qv_valid_public_jwk(p_public_jwk) is not true
     or p_device_id is null
     or p_public_key_fingerprint !~ '^[A-Za-z0-9_-]{43}$'
     or public.qv_public_key_fingerprint(p_public_jwk) is distinct from p_public_key_fingerprint
     or p_enrollment_fingerprint !~ '^[A-Za-z0-9_-]{43}$'
     or p_token_digest !~ '^[A-Za-z0-9_-]{43}$'
     or p_protection_mode not in ('passkey-prf', 'remembered')
     or p_request_kind not in ('first', 'additional', 'recovery')
     or public.qv_valid_encrypted_bundle(p_encrypted_private_bundle) is not true then
    raise exception 'Invalid device enrollment metadata' using errcode = '22023';
  end if;
  insert into public.vault_devices(id, owner_id, status, request_kind, expires_at, enrollment_fingerprint, public_jwk, public_key_fingerprint, authorization_token_digest, label, protection_mode, protection, encrypted_private_bundle)
  values (p_device_id, p_owner_id, 'pending', p_request_kind, now() + interval '10 minutes', p_enrollment_fingerprint, p_public_jwk, p_public_key_fingerprint, p_token_digest, left(p_label, 100), p_protection_mode, p_protection, p_encrypted_private_bundle)
  returning * into device;
  insert into public.vault_security_events(event_type, actor_id, affected_owner_id, affected_device_id, result, reason_code)
  values ('device_requested', caller, p_owner_id, device.id, 'ok', p_request_kind);
  return jsonb_build_object('request_id', device.id, 'device_id', device.id, 'enrollment_fingerprint', device.enrollment_fingerprint, 'expires_at', device.expires_at);
end;
$request$;

create or replace function public.get_device_request(p_request_id uuid)
returns jsonb
language plpgsql security definer
set search_path = public, pg_temp
as $get_request$
declare
  request public.vault_devices%rowtype;
begin
  select * into request from public.vault_devices where id = p_request_id and status = 'pending' and expires_at > now();
  if not found or (request.owner_id is distinct from auth.uid() and public.qv_is_admin() is not true) then return null; end if;
  return jsonb_build_object(
    'request_id', request.id, 'owner_id', request.owner_id, 'request_kind', request.request_kind,
    'label', request.label, 'public_jwk', request.public_jwk,
    'public_key_fingerprint', request.public_key_fingerprint,
    'authorization_token_digest', request.authorization_token_digest,
    'enrollment_fingerprint', request.enrollment_fingerprint,
    'protection_mode', request.protection_mode, 'protection', request.protection,
    'expires_at', request.expires_at
  );
end;
$get_request$;

create or replace function public.approve_device(
  p_request_id uuid, p_owner_id uuid, p_public_key_fingerprint text, p_enrollment_fingerprint text,
  p_wrapped_key text, p_generation uuid, p_approver_device_id uuid default null, p_approver_token text default null
)
returns jsonb
language plpgsql security definer
set search_path = public, pg_temp
as $approve$
declare
  state public.vault_state%rowtype;
  pending public.vault_devices%rowtype;
  caller uuid := auth.uid();
begin
  select * into state from public.vault_state where singleton for update;
  if p_approver_device_id is null then
    if public.qv_is_admin() is not true or state.envelope_status not in ('legacy', 'preparing') then raise exception 'Approving device is required' using errcode = '42501'; end if;
  elsif public.qv_authorize_device(p_approver_device_id, p_approver_token, state.generation, 'sync') is null then
    raise exception 'Approving device is not authorized' using errcode = '42501';
  end if;
  select * into pending from public.vault_devices where id = p_request_id for update;
  if not found or pending.owner_id is distinct from p_owner_id or public.qv_is_active_profile(pending.owner_id) is not true
     or pending.status <> 'pending' or pending.expires_at <= now()
     or pending.public_key_fingerprint is distinct from p_public_key_fingerprint
     or pending.enrollment_fingerprint is distinct from p_enrollment_fingerprint
     or p_wrapped_key is null or length(p_wrapped_key) > 32768 then
    raise exception 'Device approval request is invalid or expired' using errcode = '40001';
  end if;
  if caller is distinct from pending.owner_id and public.qv_is_admin() is not true then raise exception 'Device approval is not authorized' using errcode = '42501'; end if;
  if p_generation is distinct from state.generation and not (state.envelope_status = 'preparing' and p_generation is not distinct from state.prepared_generation) then raise exception 'Invalid enrollment generation' using errcode = '40001'; end if;
  update public.vault_devices set status = 'active', expires_at = null, approved_by_device_id = p_approver_device_id, lease_expires_at = now() + interval '30 days' where id = pending.id;
  insert into public.vault_device_wrappers(device_id, generation, purpose, wrapped_key, created_by_device_id)
  values (pending.id, p_generation, 'active', p_wrapped_key, p_approver_device_id);
  insert into public.vault_security_events(event_type, actor_id, affected_owner_id, affected_device_id, result, reason_code)
  values ('device_approved', caller, pending.owner_id, pending.id, 'ok', pending.request_kind);
  return jsonb_build_object('status', 'approved', 'device_id', pending.id, 'generation', p_generation);
end;
$approve$;

create or replace function public.complete_device(p_device_id uuid, p_token text, p_generation uuid)
returns jsonb
language plpgsql security definer
set search_path = public, pg_temp
as $complete$
declare
  authorized jsonb;
  wrapper public.vault_device_wrappers%rowtype;
begin
  authorized := public.qv_authorize_device(p_device_id, p_token, p_generation, 'complete');
  if authorized is null then return null; end if;
  select * into wrapper from public.vault_device_wrappers where device_id = p_device_id and generation = p_generation and purpose = 'active';
  if not found then return null; end if;
  update public.vault_devices set last_sync_at = now() where id = p_device_id;
  insert into public.vault_security_events(event_type, actor_id, affected_owner_id, affected_device_id, result, reason_code)
  values ('device_completed', auth.uid(), auth.uid(), p_device_id, 'ok', 'wrapper-issued');
  return jsonb_build_object('device_id', p_device_id, 'generation', wrapper.generation, 'wrapped_key', wrapper.wrapped_key, 'lease_expires_at', authorized->'lease_expires_at');
end;
$complete$;

create or replace function public.list_own_devices()
returns jsonb
language sql security definer
set search_path = public, pg_temp
as $$
  select coalesce(jsonb_agg(jsonb_build_object('id', d.id, 'status', d.status, 'label', d.label, 'protection_mode', d.protection_mode, 'created_at', d.created_at, 'last_sync_at', d.last_sync_at, 'lease_expires_at', d.lease_expires_at, 'revoked_at', d.revoked_at) order by d.created_at), '[]'::jsonb)
  from public.vault_devices d where d.owner_id = auth.uid() and public.qv_is_member()
$$;

create or replace function public.revoke_own_device(p_device_id uuid, p_token text)
returns jsonb
language plpgsql security definer
set search_path = public, pg_temp
as $revoke$
declare
  state public.vault_state%rowtype;
  authorized jsonb;
begin
  select * into state from public.vault_state where singleton for update;
  authorized := public.qv_authorize_device(p_device_id, p_token, state.generation, 'sync');
  if authorized is null then return null; end if;
  update public.vault_devices set status = 'revoked', revoked_at = now(), lease_expires_at = null where id = p_device_id;
  insert into public.vault_security_events(event_type, actor_id, affected_owner_id, affected_device_id, result, reason_code)
  values ('device_revoked', auth.uid(), auth.uid(), p_device_id, 'ok', 'self');
  return jsonb_build_object('device_id', p_device_id, 'status', 'revoked');
end;
$revoke$;

alter table public.quotes enable row level security;
drop policy if exists qv_member_quotes_select on public.quotes;
create policy qv_member_quotes_select on public.quotes
for select to authenticated using (public.qv_is_member() and public.qv_envelope_legacy_mode());

alter table public.vault_devices enable row level security;
alter table public.vault_device_wrappers enable row level security;
alter table public.vault_recovery_keys enable row level security;
alter table public.vault_recovery_wrappers enable row level security;
alter table public.vault_recovery_challenges enable row level security;
alter table public.vault_migrations enable row level security;
alter table public.vault_migration_quote_copies enable row level security;
alter table public.vault_security_events enable row level security;

drop policy if exists qv_own_devices_select on public.vault_devices;
drop policy if exists qv_own_wrappers_select on public.vault_device_wrappers;
drop policy if exists qv_own_recovery_select on public.vault_recovery_keys;
drop policy if exists qv_own_recovery_wrappers_select on public.vault_recovery_wrappers;

revoke all on table public.vault_devices, public.vault_device_wrappers, public.vault_recovery_keys, public.vault_recovery_wrappers, public.vault_recovery_challenges, public.vault_migrations, public.vault_migration_quote_copies, public.vault_security_events from public, anon, authenticated;

revoke all on function public.qv_envelope_legacy_mode() from public, anon, authenticated;
grant execute on function public.qv_envelope_legacy_mode() to authenticated;
revoke all on function public.qv_authorize_device(uuid, text, uuid, text) from public, anon, authenticated;
revoke all on function public.request_device(uuid, uuid, text, jsonb, text, text, text, text, jsonb, jsonb, text) from public, anon, authenticated;
revoke all on function public.get_device_request(uuid) from public, anon, authenticated;
revoke all on function public.approve_device(uuid, uuid, text, text, text, uuid, uuid, text) from public, anon, authenticated;
revoke all on function public.complete_device(uuid, text, uuid) from public, anon, authenticated;
revoke all on function public.list_own_devices() from public, anon, authenticated;
revoke all on function public.revoke_own_device(uuid, text) from public, anon, authenticated;
grant execute on function public.request_device(uuid, uuid, text, jsonb, text, text, text, text, jsonb, jsonb, text) to authenticated;
grant execute on function public.get_device_request(uuid) to authenticated;
grant execute on function public.approve_device(uuid, uuid, text, text, text, uuid, uuid, text) to authenticated;
grant execute on function public.complete_device(uuid, text, uuid) to authenticated;
grant execute on function public.list_own_devices() to authenticated;
grant execute on function public.revoke_own_device(uuid, text) to authenticated;

commit;
