-- Service-only metadata lets a cleared client authenticate its recovery-key bundle.
begin;

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
    'recovery_key_id', recovery.id,
    'public_key_fingerprint', recovery.public_key_fingerprint,
    'encrypted_private_key', recovery.encrypted_private_key,
    'kdf', recovery.kdf);
end;
$begin_recovery$;

revoke all on function public.begin_recovery(uuid) from public, anon, authenticated;
grant execute on function public.begin_recovery(uuid) to service_role;

commit;
