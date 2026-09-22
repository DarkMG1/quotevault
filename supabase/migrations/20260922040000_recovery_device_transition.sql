-- Bind recovery proof to a single pending-device activation without persisting its bearer token.
begin;

alter table public.vault_recovery_challenges
  add column if not exists recovery_transition_digest text,
  add column if not exists recovery_transition_expires_at timestamptz,
  add column if not exists recovery_transition_used_at timestamptz;

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
  if not found or public.qv_valid_encrypted_bundle(recovery.encrypted_private_key) is not true
     or public.qv_valid_recovery_kdf(recovery.kdf) is not true then return null; end if;
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
    'public_jwk', recovery.public_jwk,
    'encrypted_private_key', recovery.encrypted_private_key,
    'kdf', recovery.kdf);
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
  transition_bytes bytea;
  transition_token text;
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
  transition_bytes := gen_random_bytes(32);
  transition_token := rtrim(replace(replace(replace(encode(transition_bytes, 'base64'), E'\n', ''), '+', '-'), '/', '_'), '=');
  update public.vault_recovery_challenges
  set used_at = now(),
      recovery_transition_digest = rtrim(replace(replace(replace(encode(sha256(transition_bytes), 'base64'), E'\n', ''), '+', '-'), '/', '_'), '='),
      recovery_transition_expires_at = now() + interval '10 minutes',
      recovery_transition_used_at = null
  where id = challenge.id;
  insert into public.vault_security_events(event_type, actor_id, affected_owner_id, result, reason_code)
  values ('recovery_used', auth.uid(), auth.uid(), 'ok', 'challenge-proved');
  return jsonb_build_object('recovery_key_id', recovery.id, 'generation', wrapper.generation,
    'wrapped_key', wrapper.wrapped_key, 'transition_token', transition_token);
end;
$complete_recovery$;

-- Lock order is vault state, pending device, recovery key, then challenge.
create or replace function public.activate_recovered_device(
  p_challenge_id uuid, p_transition_token text, p_request_id uuid,
  p_enrollment_fingerprint text, p_generation uuid, p_wrapped_key text
)
returns jsonb
language plpgsql security definer
set search_path = public, pg_temp
as $activate_recovered_device$
declare
  state public.vault_state%rowtype;
  device public.vault_devices%rowtype;
  challenge public.vault_recovery_challenges%rowtype;
  recovery public.vault_recovery_keys%rowtype;
  transition_bytes bytea;
  transition_digest text;
begin
  select * into state from public.vault_state where singleton for update;
  select * into device from public.vault_devices where id = p_request_id for update;
  if not found then return null; end if;
  select * into challenge from public.vault_recovery_challenges where id = p_challenge_id;
  if not found then return null; end if;
  select * into recovery from public.vault_recovery_keys where id = challenge.recovery_key_id for update;
  select * into challenge from public.vault_recovery_challenges where id = p_challenge_id for update;
  if not found then return null; end if;
  transition_bytes := public.qv_base64url_bytes(p_transition_token, 32);
  if auth.uid() is null or public.qv_is_member() is not true
     or device.owner_id is distinct from auth.uid() or recovery.owner_id is distinct from auth.uid()
     or device.status <> 'pending' or device.request_kind <> 'recovery' or device.expires_at <= now()
     or device.enrollment_fingerprint is distinct from p_enrollment_fingerprint
     or p_generation is distinct from state.generation or public.qv_base64url_bytes(p_enrollment_fingerprint, 32) is null
     or public.qv_base64url_bytes(p_wrapped_key, 384) is null
     or recovery.status <> 'active' or challenge.used_at is null or transition_bytes is null
     or challenge.recovery_transition_used_at is not null or challenge.recovery_transition_expires_at <= now() then return null; end if;
  transition_digest := rtrim(replace(replace(replace(encode(sha256(transition_bytes), 'base64'), E'\n', ''), '+', '-'), '/', '_'), '=');
  if challenge.recovery_transition_digest is distinct from transition_digest then return null; end if;
  update public.vault_recovery_challenges set recovery_transition_used_at = now() where id = challenge.id;
  update public.vault_devices set status = 'active', expires_at = null, approved_by_device_id = null, lease_expires_at = null where id = device.id;
  insert into public.vault_device_wrappers(device_id, generation, purpose, wrapped_key, created_by_device_id)
  values (device.id, state.generation, 'active', p_wrapped_key, null);
  insert into public.vault_security_events(event_type, actor_id, affected_owner_id, affected_device_id, result, reason_code)
  values ('device_restored', auth.uid(), auth.uid(), device.id, 'ok', 'recovery-transition');
  return jsonb_build_object('device_id', device.id, 'generation', state.generation);
end;
$activate_recovered_device$;

revoke all on function public.begin_recovery(uuid) from public, anon, authenticated;
revoke all on function public.complete_recovery(uuid, text) from public, anon, authenticated;
revoke all on function public.activate_recovered_device(uuid, text, uuid, text, uuid, text) from public, anon, authenticated;
grant execute on function public.begin_recovery(uuid) to service_role;
grant execute on function public.complete_recovery(uuid, text) to authenticated;
grant execute on function public.activate_recovered_device(uuid, text, uuid, text, uuid, text) to authenticated;

commit;
