-- Narrow Task 5 bootstrap contracts; device authorization remains token-bound.
begin;

create or replace function public.qv_valid_device_protection(p_mode text, p_protection jsonb)
returns boolean
language plpgsql immutable
set search_path = public, pg_temp
as $protection$
declare
  key_name text;
  credential bytea;
begin
  if jsonb_typeof(p_protection) <> 'object' then return false; end if;
  if p_mode = 'remembered' then
    return p_protection = '{"version":1,"mode":"remembered"}'::jsonb;
  end if;
  if p_mode <> 'passkey-prf' then return false; end if;
  for key_name in select jsonb_object_keys(p_protection) loop
    if key_name not in ('version', 'rpId', 'credentialId', 'prfSalt', 'kdf') then return false; end if;
  end loop;
  if p_protection->'version' <> '1'::jsonb or jsonb_typeof(p_protection->'rpId') <> 'string'
     or jsonb_typeof(p_protection->'credentialId') <> 'string' or jsonb_typeof(p_protection->'prfSalt') <> 'string'
     or p_protection->'kdf' is distinct from '"HKDF-SHA-256"'::jsonb
     or p_protection->>'rpId' <> 'quotes.darkmg1.dev' then return false; end if;
  credential := public.qv_base64url_bytes(p_protection->>'credentialId');
  return credential is not null and octet_length(credential) between 1 and 1024
     and public.qv_base64url_bytes(p_protection->>'prfSalt', 32) is not null;
exception when others then
  return false;
end;
$protection$;

create or replace function public.get_vault_state()
returns jsonb
language plpgsql
stable
security definer
set search_path = public, pg_temp
as $state$
declare
  state public.vault_state%rowtype;
  response jsonb;
begin
  if not public.qv_is_member() then
    raise exception 'QuoteVault membership is required' using errcode = '42501';
  end if;
  select * into state from public.vault_state where singleton;
  response := jsonb_build_object('envelope_status', state.envelope_status, 'generation', state.generation,
    'prepared_generation', state.prepared_generation);
  if state.envelope_status in ('legacy', 'preparing') then
    response := response || jsonb_build_object('kdf', state.kdf, 'verifier', state.verifier,
      'legacy_generation', state.legacy_generation);
  end if;
  return response;
end;
$state$;

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
     or public.qv_base64url_bytes(p_public_key_fingerprint, 32) is null
     or public.qv_public_key_fingerprint(p_public_jwk) is distinct from p_public_key_fingerprint
     or public.qv_base64url_bytes(p_enrollment_fingerprint, 32) is null
     or public.qv_base64url_bytes(p_token_digest, 32) is null
     or p_protection_mode not in ('passkey-prf', 'remembered')
     or public.qv_valid_device_protection(p_protection_mode, p_protection) is not true
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

create or replace function public.get_passkey_restore_devices()
returns jsonb
language plpgsql security definer
set search_path = public, pg_temp
as $restore$
declare
  state public.vault_state%rowtype;
  device public.vault_devices%rowtype;
  devices jsonb := '[]'::jsonb;
begin
  if auth.uid() is null or public.qv_is_member() is not true then return null; end if;
  select * into state from public.vault_state where singleton for share;
  for device in select * from public.vault_devices d
    where d.owner_id = auth.uid() and d.status = 'active' and d.protection_mode = 'passkey-prf'
    order by d.created_at for share
  loop
    devices := devices || jsonb_build_array(jsonb_build_object(
      'device_id', device.id, 'protection_mode', device.protection_mode, 'protection', device.protection,
      'public_key_fingerprint', device.public_key_fingerprint, 'encrypted_private_bundle', device.encrypted_private_bundle
    ));
  end loop;
  return jsonb_build_object('generation', state.generation, 'devices', devices);
end;
$restore$;

revoke all on function public.qv_valid_device_protection(text, jsonb) from public, anon, authenticated;
revoke all on function public.get_passkey_restore_devices() from public, anon, authenticated;
grant execute on function public.get_passkey_restore_devices() to authenticated;

commit;
