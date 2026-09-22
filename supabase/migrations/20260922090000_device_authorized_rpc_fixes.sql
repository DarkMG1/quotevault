-- Close active-mode legacy mutation and map allowlist rows to auth identities.
begin;

alter function public.rotate_vault(uuid, jsonb, jsonb) rename to qv_rotate_vault_legacy;

create or replace function public.rotate_vault(p_expected_generation uuid, p_kdf jsonb, p_verifier jsonb)
returns jsonb
language plpgsql security definer
set search_path = public, pg_temp
as $rotate$
declare state public.vault_state%rowtype;
begin
  if public.qv_is_admin() is not true then raise exception 'QuoteVault administrator access is required' using errcode = '42501'; end if;
  select * into state from public.vault_state where singleton for update;
  if state.envelope_status not in ('legacy', 'preparing') then
    raise exception 'Legacy vault rotation is unavailable after envelope cutover begins' using errcode = '42501';
  end if;
  return public.qv_rotate_vault_legacy(p_expected_generation, p_kdf, p_verifier);
end;
$rotate$;

create or replace function public.list_members(p_device_id uuid default null, p_device_token text default null)
returns jsonb language plpgsql security definer set search_path = public, pg_temp
as $members$
declare state public.vault_state%rowtype;
begin
  if public.qv_is_admin() is not true or public.qv_is_member() is not true then raise exception 'QuoteVault administrator membership is required' using errcode = '42501'; end if;
  select * into state from public.vault_state where singleton for update;
  if state.envelope_status not in ('legacy', 'preparing') and public.qv_authorize_device(p_device_id, p_device_token, state.generation, 'state') is null then return null; end if;
  return (select coalesce(jsonb_agg(jsonb_build_object('id', a.id, 'email', a.email, 'first_name', p.first_name, 'last_name', p.last_name) order by a.email), '[]'::jsonb)
    from public.allowlist a
    left join auth.users u on lower(u.email) = lower(a.email)
    left join public.profiles p on p.id = u.id);
end;
$members$;

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
  -- Supabase sessions require service-role auth.admin.signOut(owner_id, 'global') after this RPC commits.
  delete from public.allowlist where id = p_member_id;
  insert into public.vault_security_events(event_type, actor_id, affected_owner_id, affected_device_id, result, reason_code)
    values ('member_removed', auth.uid(), member_owner_id, p_device_id, 'ok', 'access-only');
  return jsonb_build_object('id', p_member_id, 'status', 'removed');
end;
$remove$;

revoke all on function public.qv_rotate_vault_legacy(uuid, jsonb, jsonb) from public, anon, authenticated;
revoke all on function public.rotate_vault(uuid, jsonb, jsonb) from public, anon, authenticated;
grant execute on function public.rotate_vault(uuid, jsonb, jsonb) to authenticated;

commit;
