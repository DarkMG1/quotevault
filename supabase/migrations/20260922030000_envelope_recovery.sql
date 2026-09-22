-- Recovery proves possession of an encrypted private key; lease signatures remain Edge-only.
begin;

create extension if not exists pgcrypto;

do $roles$
begin
  if not exists (select 1 from pg_roles where rolname = 'service_role') then
    create role service_role noinherit nologin;
  end if;
end;
$roles$;

create or replace function public.qv_valid_recovery_kdf(p_kdf jsonb)
returns boolean
language plpgsql immutable
set search_path = public, pg_temp
as $kdf$
declare
  salt bytea;
begin
  if jsonb_typeof(p_kdf) <> 'object' or p_kdf->>'version' <> '1' or p_kdf->>'iterations' <> '600000'
     or jsonb_typeof(p_kdf->'salt') <> 'string' or p_kdf->>'salt' !~ '^[A-Za-z0-9+/]+={0,2}$' then return false; end if;
  salt := decode(p_kdf->>'salt', 'base64');
  return octet_length(salt) between 16 and 64 and replace(encode(salt, 'base64'), E'\n', '') = p_kdf->>'salt';
exception when others then
  return false;
end;
$kdf$;

create or replace function public.renew_device_lease(p_device_id uuid, p_token text)
returns jsonb
language plpgsql security definer
set search_path = public, pg_temp
as $renew$
declare
  state public.vault_state%rowtype;
  authorized jsonb;
  device public.vault_devices%rowtype;
  issued_at bigint;
  new_expires_at timestamptz;
begin
  select * into state from public.vault_state where singleton for update;
  authorized := public.qv_authorize_device(p_device_id, p_token, state.generation, 'lease_renewal');
  if authorized is null then return null; end if;
  issued_at := floor(extract(epoch from now()) * 1000)::bigint;
  new_expires_at := now() + interval '720 hours';
  update public.vault_devices
  set lease_expires_at = new_expires_at, last_sync_at = now()
  where id = p_device_id
  returning * into device;
  return jsonb_build_array(1, device.id, device.owner_id, state.generation, issued_at,
    floor(extract(epoch from new_expires_at) * 1000)::bigint, device.public_key_fingerprint);
end;
$renew$;

create or replace function public.create_recovery_key(
  p_recovery_key_id uuid, p_public_jwk jsonb, p_public_key_fingerprint text,
  p_encrypted_private_key jsonb, p_kdf jsonb, p_generation uuid, p_wrapped_key text,
  p_device_id uuid, p_token text
)
returns jsonb
language plpgsql security definer
set search_path = public, pg_temp
as $create_recovery$
declare
  state public.vault_state%rowtype;
  authorized jsonb;
begin
  select * into state from public.vault_state where singleton for update;
  authorized := public.qv_authorize_device(p_device_id, p_token, state.generation, 'wrapper');
  if authorized is null or p_generation is distinct from state.generation
     or p_recovery_key_id is null or public.qv_valid_public_jwk(p_public_jwk) is not true
     or public.qv_public_key_fingerprint(p_public_jwk) is distinct from p_public_key_fingerprint
     or public.qv_valid_encrypted_bundle(p_encrypted_private_key) is not true
     or public.qv_valid_recovery_kdf(p_kdf) is not true
     or public.qv_base64url_bytes(p_wrapped_key, 384) is null
     or exists (select 1 from public.vault_recovery_keys where owner_id = auth.uid() and status = 'active') then return null; end if;
  insert into public.vault_recovery_keys(id, owner_id, status, public_jwk, public_key_fingerprint, encrypted_private_key, kdf, confirmed_at)
  values (p_recovery_key_id, auth.uid(), 'active', p_public_jwk, p_public_key_fingerprint, p_encrypted_private_key, p_kdf, now());
  insert into public.vault_recovery_wrappers(recovery_key_id, generation, wrapped_key, created_by_device_id)
  values (p_recovery_key_id, p_generation, p_wrapped_key, p_device_id);
  insert into public.vault_security_events(event_type, actor_id, affected_owner_id, affected_device_id, result, reason_code)
  values ('recovery_created', auth.uid(), auth.uid(), p_device_id, 'ok', 'confirmed');
  return jsonb_build_object('recovery_key_id', p_recovery_key_id, 'generation', p_generation);
end;
$create_recovery$;

create or replace function public.replace_recovery_key(
  p_recovery_key_id uuid, p_public_jwk jsonb, p_public_key_fingerprint text,
  p_encrypted_private_key jsonb, p_kdf jsonb, p_generation uuid, p_wrapped_key text,
  p_device_id uuid, p_token text
)
returns jsonb
language plpgsql security definer
set search_path = public, pg_temp
as $replace_recovery$
declare
  state public.vault_state%rowtype;
  authorized jsonb;
  previous public.vault_recovery_keys%rowtype;
begin
  select * into state from public.vault_state where singleton for update;
  authorized := public.qv_authorize_device(p_device_id, p_token, state.generation, 'wrapper');
  if authorized is null or p_generation is distinct from state.generation
     or p_recovery_key_id is null or public.qv_valid_public_jwk(p_public_jwk) is not true
     or public.qv_public_key_fingerprint(p_public_jwk) is distinct from p_public_key_fingerprint
     or public.qv_valid_encrypted_bundle(p_encrypted_private_key) is not true
     or public.qv_valid_recovery_kdf(p_kdf) is not true
     or public.qv_base64url_bytes(p_wrapped_key, 384) is null then return null; end if;
  select * into previous from public.vault_recovery_keys
  where owner_id = auth.uid() and status = 'active' for update;
  if not found then return null; end if;
  insert into public.vault_recovery_keys(id, owner_id, status, public_jwk, public_key_fingerprint, encrypted_private_key, kdf, confirmed_at)
  values (p_recovery_key_id, auth.uid(), 'active', p_public_jwk, p_public_key_fingerprint, p_encrypted_private_key, p_kdf, now());
  insert into public.vault_recovery_wrappers(recovery_key_id, generation, wrapped_key, created_by_device_id)
  values (p_recovery_key_id, p_generation, p_wrapped_key, p_device_id);
  update public.vault_recovery_keys set status = 'revoked', revoked_at = now() where id = previous.id;
  insert into public.vault_security_events(event_type, actor_id, affected_owner_id, affected_device_id, result, reason_code)
  values ('recovery_replaced', auth.uid(), auth.uid(), p_device_id, 'ok', 'confirmed');
  return jsonb_build_object('recovery_key_id', p_recovery_key_id, 'generation', p_generation);
end;
$replace_recovery$;

-- This function is callable only by the Edge Function's service role. Its raw proof
-- never reaches a normal database role and is encrypted to the recovery key there.
create or replace function public.begin_recovery(p_owner_id uuid)
returns jsonb
language plpgsql security definer
set search_path = public, pg_temp
as $begin_recovery$
declare
  recovery public.vault_recovery_keys%rowtype;
  challenge bytea;
  challenge_id uuid;
begin
  if p_owner_id is null or public.qv_is_active_profile(p_owner_id) is not true then return null; end if;
  select * into recovery from public.vault_recovery_keys
  where owner_id = p_owner_id and status = 'active' for update;
  if not found then return null; end if;
  update public.vault_recovery_challenges set used_at = now()
  where recovery_key_id = recovery.id and used_at is null;
  challenge := gen_random_bytes(32);
  insert into public.vault_recovery_challenges(recovery_key_id, expected_digest, expires_at)
  values (recovery.id,
    rtrim(replace(replace(replace(encode(sha256(challenge), 'base64'), E'\n', ''), '+', '-'), '/', '_'), '='),
    now() + interval '10 minutes')
  returning id into challenge_id;
  return jsonb_build_object('challenge_id', challenge_id,
    'challenge', rtrim(replace(replace(replace(encode(challenge, 'base64'), E'\n', ''), '+', '-'), '/', '_'), '='),
    'public_jwk', recovery.public_jwk);
end;
$begin_recovery$;

create or replace function public.complete_recovery(p_challenge_id uuid, p_response text)
returns jsonb
language plpgsql security definer
set search_path = public, pg_temp
as $complete_recovery$
declare
  state public.vault_state%rowtype;
  challenge public.vault_recovery_challenges%rowtype;
  recovery public.vault_recovery_keys%rowtype;
  wrapper public.vault_recovery_wrappers%rowtype;
  response_bytes bytea;
  response_digest text;
begin
  select * into state from public.vault_state where singleton for update;
  select * into challenge from public.vault_recovery_challenges where id = p_challenge_id;
  if not found then return null; end if;
  select * into recovery from public.vault_recovery_keys where id = challenge.recovery_key_id for update;
  select * into challenge from public.vault_recovery_challenges where id = p_challenge_id for update;
  if not found then return null; end if;
  response_bytes := public.qv_base64url_bytes(p_response, 32);
  if auth.uid() is null or recovery.owner_id is distinct from auth.uid() or public.qv_is_member() is not true
     or recovery.status <> 'active' or challenge.used_at is not null or challenge.expires_at <= now()
     or response_bytes is null then return null; end if;
  response_digest := rtrim(replace(replace(replace(encode(sha256(response_bytes), 'base64'), E'\n', ''), '+', '-'), '/', '_'), '=');
  if response_digest <> challenge.expected_digest then return null; end if;
  select * into wrapper from public.vault_recovery_wrappers
  where recovery_key_id = recovery.id and generation = state.generation;
  if not found then return null; end if;
  update public.vault_recovery_challenges set used_at = now() where id = challenge.id;
  insert into public.vault_security_events(event_type, actor_id, affected_owner_id, result, reason_code)
  values ('recovery_used', auth.uid(), auth.uid(), 'ok', 'challenge-proved');
  return jsonb_build_object('recovery_key_id', recovery.id, 'generation', wrapper.generation, 'wrapped_key', wrapper.wrapped_key);
end;
$complete_recovery$;

revoke all on function public.qv_valid_recovery_kdf(jsonb) from public, anon, authenticated;
revoke all on function public.renew_device_lease(uuid, text) from public, anon, authenticated;
revoke all on function public.create_recovery_key(uuid, jsonb, text, jsonb, jsonb, uuid, text, uuid, text) from public, anon, authenticated;
revoke all on function public.replace_recovery_key(uuid, jsonb, text, jsonb, jsonb, uuid, text, uuid, text) from public, anon, authenticated;
revoke all on function public.begin_recovery(uuid) from public, anon, authenticated;
revoke all on function public.complete_recovery(uuid, text) from public, anon, authenticated;
grant execute on function public.renew_device_lease(uuid, text) to authenticated;
grant execute on function public.create_recovery_key(uuid, jsonb, text, jsonb, jsonb, uuid, text, uuid, text) to authenticated;
grant execute on function public.replace_recovery_key(uuid, jsonb, text, jsonb, jsonb, uuid, text, uuid, text) to authenticated;
grant execute on function public.complete_recovery(uuid, text) to authenticated;
grant execute on function public.begin_recovery(uuid) to service_role;

commit;
