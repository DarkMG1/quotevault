-- Reject malformed pre-bootstrap rows before exposing or activating them.
begin;

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
      and public.qv_valid_device_protection(d.protection_mode, d.protection) is true
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
     or public.qv_valid_device_protection(pending.protection_mode, pending.protection) is not true
     or pending.public_key_fingerprint is distinct from p_public_key_fingerprint
     or pending.enrollment_fingerprint is distinct from p_enrollment_fingerprint
     or public.qv_base64url_bytes(p_wrapped_key, 384) is null then
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

commit;
