-- Replacing a recovery phrase must work during preparation exactly as creating one does:
-- the new key is wrapped for the prepared generation by a device that holds it.
-- Safe to reapply after itself.
begin;

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
  if state.envelope_status='preparing' and p_generation is not distinct from state.prepared_generation then
    authorized := public.qv_authorize_device(p_device_id,p_token,p_generation,'complete');
    if authorized is null or not exists(select 1 from public.vault_device_wrappers where device_id=p_device_id and generation=p_generation and purpose='active') then return null; end if;
  else
    authorized := public.qv_authorize_device(p_device_id,p_token,state.generation,'wrapper');
    if authorized is null or p_generation is distinct from state.generation then return null; end if;
  end if;
  if p_recovery_key_id is null or public.qv_valid_public_jwk(p_public_jwk) is not true
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

commit;
