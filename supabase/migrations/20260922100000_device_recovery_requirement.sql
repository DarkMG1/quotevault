-- Recovery setup is an owner property, not a browser enrollment hint.
begin;

create or replace function public.complete_device(p_device_id uuid, p_token text, p_generation uuid)
returns jsonb
language plpgsql security definer
set search_path = public, pg_temp
as $complete$
declare
  authorized jsonb;
  wrapper public.vault_device_wrappers%rowtype;
  recovery_setup_required boolean;
begin
  authorized := public.qv_authorize_device(p_device_id, p_token, p_generation, 'complete');
  if authorized is null then return null; end if;
  select * into wrapper from public.vault_device_wrappers where device_id = p_device_id and generation = p_generation and purpose = 'active';
  if not found then return null; end if;
  select not exists (
    select 1 from public.vault_recovery_keys where owner_id = auth.uid() and status = 'active'
  ) into recovery_setup_required;
  update public.vault_devices set last_sync_at = now() where id = p_device_id;
  insert into public.vault_security_events(event_type, actor_id, affected_owner_id, affected_device_id, result, reason_code)
  values ('device_completed', auth.uid(), auth.uid(), p_device_id, 'ok', 'wrapper-issued');
  return jsonb_build_object(
    'device_id', p_device_id, 'generation', wrapper.generation, 'wrapped_key', wrapper.wrapped_key,
    'lease_expires_at', authorized->'lease_expires_at', 'recovery_setup_required', recovery_setup_required
  );
end;
$complete$;

commit;
