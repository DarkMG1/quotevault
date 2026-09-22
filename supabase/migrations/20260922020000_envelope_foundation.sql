-- Additive device-envelope foundation. Legacy shared-key RPCs remain usable
-- while vault_state.envelope_status is legacy or preparing.
begin;

alter table public.vault_state
  add column if not exists envelope_status text not null default 'legacy'
    check (envelope_status in ('legacy', 'preparing', 'staging', 'active', 'maintenance')),
  add column if not exists prepared_generation uuid,
  add column if not exists active_migration_id uuid;

create table if not exists public.vault_devices (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  status text not null check (status in ('pending', 'active', 'revoked', 'expired')),
  request_kind text not null check (request_kind in ('first', 'additional', 'recovery')),
  expires_at timestamptz,
  enrollment_fingerprint text not null check (length(enrollment_fingerprint) between 8 and 256),
  public_jwk jsonb not null check (jsonb_typeof(public_jwk) = 'object' and octet_length(public_jwk::text) <= 32768),
  public_key_fingerprint text not null check (length(public_key_fingerprint) between 8 and 256),
  authorization_token_digest text not null check (authorization_token_digest ~ '^[0-9a-f]{64}$'),
  label text not null check (length(label) between 1 and 100),
  protection_mode text not null check (protection_mode in ('passkey-prf', 'remembered')),
  protection jsonb not null check (jsonb_typeof(protection) = 'object' and octet_length(protection::text) <= 32768),
  encrypted_private_bundle jsonb check (encrypted_private_bundle is null or (jsonb_typeof(encrypted_private_bundle) = 'object' and octet_length(encrypted_private_bundle::text) <= 65536)),
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
  purpose text not null check (purpose in ('active', 'conversion-only')),
  wrapped_key text not null check (length(wrapped_key) between 1 and 32768),
  created_by_device_id uuid references public.vault_devices(id) on delete set null,
  created_at timestamptz not null default now(),
  primary key (device_id, generation, purpose)
);

create table if not exists public.vault_recovery_keys (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  status text not null check (status in ('pending', 'active', 'revoked')),
  public_jwk jsonb not null check (jsonb_typeof(public_jwk) = 'object' and octet_length(public_jwk::text) <= 32768),
  public_key_fingerprint text not null check (length(public_key_fingerprint) between 8 and 256),
  encrypted_private_key jsonb not null check (jsonb_typeof(encrypted_private_key) = 'object' and octet_length(encrypted_private_key::text) <= 65536),
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
  expected_digest text not null check (expected_digest ~ '^[0-9a-f]{64}$'),
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
  encrypted_row jsonb not null check (jsonb_typeof(encrypted_row) = 'object' and octet_length(encrypted_row::text) <= 300000),
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
  normalized text;
begin
  select * into state from public.vault_state where singleton for update;
  select * into device from public.vault_devices where id = p_device_id for update;
  if not found or caller is null or device.owner_id is distinct from caller
     or public.qv_is_member() is not true
     or device.status <> 'active'
     or p_generation is distinct from state.generation
     or p_operation is null then
    return null;
  end if;
  if p_token is null or p_token !~ '^[A-Za-z0-9_-]{43}$' then return null; end if;
  normalized := replace(replace(p_token, '-', '+'), '_', '/');
  token_bytes := decode(normalized || '=', 'base64');
  if octet_length(token_bytes) <> 32 or encode(sha256(token_bytes), 'hex') <> device.authorization_token_digest then return null; end if;
  if p_operation not in ('complete', 'lease_renewal') and (device.lease_expires_at is null or device.lease_expires_at <= now()) then return null; end if;
  return jsonb_build_object('device_id', device.id, 'owner_id', device.owner_id, 'generation', state.generation, 'lease_expires_at', device.lease_expires_at);
exception when others then
  return null;
end;
$authorize$;

create or replace function public.request_device(
  p_owner_id uuid, p_label text, p_public_jwk jsonb, p_fingerprint text,
  p_token_digest text, p_protection_mode text, p_protection jsonb, p_request_kind text
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
  if p_public_jwk is null or jsonb_typeof(p_public_jwk) <> 'object' or octet_length(p_public_jwk::text) > 32768
     or p_public_jwk->>'kty' <> 'RSA' or p_public_jwk->>'e' <> 'AQAB'
     or coalesce(length(p_public_jwk->>'n'), 0) < 400
     or p_fingerprint !~ '^[A-Za-z0-9_-]+$' or length(p_fingerprint) not between 8 and 256
     or p_token_digest !~ '^[0-9a-f]{64}$'
     or p_protection_mode not in ('passkey-prf', 'remembered')
     or p_request_kind not in ('first', 'additional', 'recovery') then
    raise exception 'Invalid device enrollment metadata' using errcode = '22023';
  end if;
  insert into public.vault_devices(owner_id, status, request_kind, expires_at, enrollment_fingerprint, public_jwk, public_key_fingerprint, authorization_token_digest, label, protection_mode, protection)
  values (p_owner_id, 'pending', p_request_kind, now() + interval '10 minutes', p_fingerprint, p_public_jwk, p_fingerprint, p_token_digest, left(p_label, 100), p_protection_mode, p_protection)
  returning * into device;
  insert into public.vault_security_events(event_type, actor_id, affected_owner_id, affected_device_id, result, reason_code)
  values ('device_requested', caller, p_owner_id, device.id, 'ok', p_request_kind);
  return jsonb_build_object('request_id', device.id, 'device_id', device.id, 'enrollment_fingerprint', device.enrollment_fingerprint, 'expires_at', device.expires_at);
end;
$request$;

create or replace function public.approve_device(
  p_request_id uuid, p_owner_id uuid, p_fingerprint text, p_wrapped_key text, p_approver_device_id uuid default null
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
  if public.qv_is_admin() is not true and p_approver_device_id is null then raise exception 'Device approval is not authorized' using errcode = '42501'; end if;
  select * into state from public.vault_state where singleton for update;
  select * into pending from public.vault_devices where id = p_request_id for update;
  if not found or pending.owner_id is distinct from p_owner_id or pending.status <> 'pending' or pending.expires_at <= now()
     or pending.enrollment_fingerprint is distinct from p_fingerprint or p_wrapped_key is null or length(p_wrapped_key) > 32768 then
    raise exception 'Device approval request is invalid or expired' using errcode = '40001';
  end if;
  if p_approver_device_id is not null and public.qv_authorize_device(p_approver_device_id, current_setting('request.jwt.claim.device_token', true), state.generation, 'sync') is null then
    raise exception 'Approving device is not authorized' using errcode = '42501';
  end if;
  update public.vault_devices set status = 'active', expires_at = null, approved_by_device_id = p_approver_device_id, lease_expires_at = now() + interval '30 days' where id = pending.id;
  insert into public.vault_device_wrappers(device_id, generation, purpose, wrapped_key, created_by_device_id)
  values (pending.id, state.generation, 'active', p_wrapped_key, p_approver_device_id);
  insert into public.vault_security_events(event_type, actor_id, affected_owner_id, affected_device_id, result, reason_code)
  values ('device_approved', caller, pending.owner_id, pending.id, 'ok', pending.request_kind);
  return jsonb_build_object('status', 'approved', 'device_id', pending.id, 'generation', state.generation);
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
  update public.vault_devices set lease_expires_at = now() + interval '30 days', last_sync_at = now() where id = p_device_id;
  select * into wrapper from public.vault_device_wrappers where device_id = p_device_id and generation = p_generation and purpose = 'active';
  if not found then return null; end if;
  return jsonb_build_object('device_id', p_device_id, 'generation', wrapper.generation, 'wrapped_key', wrapper.wrapped_key, 'lease_expires_at', now() + interval '30 days');
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
create policy qv_own_devices_select on public.vault_devices for select to authenticated using (owner_id = auth.uid());
create policy qv_own_wrappers_select on public.vault_device_wrappers for select to authenticated using (exists (select 1 from public.vault_devices d where d.id = device_id and d.owner_id = auth.uid()));
create policy qv_own_recovery_select on public.vault_recovery_keys for select to authenticated using (owner_id = auth.uid());
create policy qv_own_recovery_wrappers_select on public.vault_recovery_wrappers for select to authenticated using (exists (select 1 from public.vault_recovery_keys r where r.id = recovery_key_id and r.owner_id = auth.uid()));

revoke all on table public.vault_devices, public.vault_device_wrappers, public.vault_recovery_keys, public.vault_recovery_wrappers, public.vault_recovery_challenges, public.vault_migrations, public.vault_migration_quote_copies, public.vault_security_events from public, anon, authenticated;
grant select on table public.vault_devices, public.vault_device_wrappers, public.vault_recovery_keys, public.vault_recovery_wrappers to authenticated;

revoke all on function public.qv_envelope_legacy_mode() from public, anon, authenticated;
grant execute on function public.qv_envelope_legacy_mode() to authenticated;
revoke all on function public.qv_authorize_device(uuid, text, uuid, text) from public, anon, authenticated;
revoke all on function public.request_device(uuid, text, jsonb, text, text, text, jsonb, text) from public, anon, authenticated;
revoke all on function public.approve_device(uuid, uuid, text, text, uuid) from public, anon, authenticated;
revoke all on function public.complete_device(uuid, text, uuid) from public, anon, authenticated;
revoke all on function public.list_own_devices() from public, anon, authenticated;
revoke all on function public.revoke_own_device(uuid, text) from public, anon, authenticated;
grant execute on function public.request_device(uuid, text, jsonb, text, text, text, jsonb, text) to authenticated;
grant execute on function public.approve_device(uuid, uuid, text, text, uuid) to authenticated;
grant execute on function public.complete_device(uuid, text, uuid) to authenticated;
grant execute on function public.list_own_devices() to authenticated;
grant execute on function public.revoke_own_device(uuid, text) to authenticated;

commit;
