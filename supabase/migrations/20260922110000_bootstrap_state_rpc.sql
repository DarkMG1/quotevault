-- Bootstrap needs public derivation metadata before a device can be unlocked.
-- Keep the ciphertext-bearing vault state RPC device-gated.
begin;

create or replace function public.get_vault_bootstrap_state()
returns jsonb
language plpgsql stable security definer
set search_path = public, pg_temp
as $bootstrap$
declare state public.vault_state%rowtype; response jsonb;
begin
  if not public.qv_is_member() then
    raise exception 'QuoteVault membership is required' using errcode = '42501';
  end if;
  select * into state from public.vault_state where singleton;
  response := jsonb_build_object('envelope_status', state.envelope_status,
    'generation', state.generation, 'prepared_generation', state.prepared_generation);
  if state.envelope_status in ('legacy', 'preparing') then
    response := response || jsonb_build_object('kdf', state.kdf, 'verifier', state.verifier,
      'legacy_generation', state.legacy_generation);
  end if;
  return response;
end;
$bootstrap$;

revoke all on function public.get_vault_bootstrap_state() from public, anon, authenticated;
grant execute on function public.get_vault_bootstrap_state() to authenticated;

create or replace function public.remove_member_access(p_member_id uuid, p_device_id uuid default null, p_device_token text default null)
returns jsonb language plpgsql security definer set search_path = public, pg_temp
as $remove$
declare state public.vault_state%rowtype; member_email text; member_owner_id uuid;
begin
  if public.qv_is_admin() is not true or public.qv_is_member() is not true then raise exception 'QuoteVault administrator membership is required' using errcode = '42501'; end if;
  select * into state from public.vault_state where singleton for update;
  if state.envelope_status not in ('legacy', 'preparing') and public.qv_authorize_device(p_device_id, p_device_token, state.generation, 'state') is null then return null; end if;
  select email into member_email from public.allowlist where id = p_member_id for update;
  if not found then return null; end if;
  select id into member_owner_id from auth.users where lower(email) = lower(member_email) for update;
  if member_owner_id is not null then
    perform 1 from public.vault_devices where owner_id = member_owner_id for update;
    delete from public.vault_device_wrappers w using public.vault_devices d where w.device_id = d.id and d.owner_id = member_owner_id;
    delete from public.vault_recovery_wrappers w using public.vault_recovery_keys k where w.recovery_key_id = k.id and k.owner_id = member_owner_id;
    delete from public.vault_recovery_challenges c using public.vault_recovery_keys k where c.recovery_key_id = k.id and k.owner_id = member_owner_id;
    update public.vault_recovery_keys set status = 'revoked', revoked_at = now() where owner_id = member_owner_id and status <> 'revoked';
    update public.vault_devices set status = 'revoked', revoked_at = now(), lease_expires_at = null where owner_id = member_owner_id and status <> 'revoked';
  end if;
  delete from public.allowlist where id = p_member_id;
  insert into public.vault_security_events(event_type, actor_id, affected_owner_id, affected_device_id, result, reason_code)
    values ('member_removed', auth.uid(), member_owner_id, p_device_id, 'ok', 'access-only');
  return jsonb_build_object('id', p_member_id, 'owner_id', member_owner_id, 'status', 'removed');
end;
$remove$;

revoke all on function public.remove_member_access(uuid, uuid, text) from public, anon, authenticated;
grant execute on function public.remove_member_access(uuid, uuid, text) to authenticated;

commit;
