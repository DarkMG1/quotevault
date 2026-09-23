-- Audit fixes. Additive: every statement is safe to reapply after itself.
begin;

-- Hosted Supabase installs pgcrypto in the extensions schema.
alter function public.begin_recovery(uuid) set search_path = public, extensions, pg_temp;
alter function public.complete_recovery(uuid, text) set search_path = public, extensions, pg_temp;

-- initialize_vault and legacy rotate_vault clear legacy_generation, so it cannot
-- identify the initial migration; the migration's recorded source state does.
create or replace function public.qv_envelope_legacy_mode()
returns boolean language sql stable security definer set search_path = public, pg_temp as $legacy$
  select state.envelope_status='legacy' or (
    state.envelope_status='preparing' and exists(
      select 1 from public.vault_migrations m where m.id=state.active_migration_id
        and m.status in ('staging','ready','activated') and m.source_generation=state.generation
        and m.source_state->>'envelope_status'='legacy'
    )
  ) from public.vault_state state where state.singleton
$legacy$;

-- A key is wrapped for a new generation only after a holder of the previous
-- generation's key authenticates the record's public-key fingerprint.
alter table public.vault_device_wrappers add column if not exists attestation jsonb;
alter table public.vault_recovery_wrappers add column if not exists attestation jsonb;

create or replace function public.attest_vault_keys(p_device_id uuid,p_token text,p_generation uuid,p_devices jsonb,p_recoveries jsonb)
returns void language plpgsql security definer set search_path = public, pg_temp as $attest$
declare state public.vault_state%rowtype; item jsonb; admin boolean:=public.qv_is_admin() is true;
begin
  if jsonb_typeof(p_devices)<>'array' or jsonb_typeof(p_recoveries)<>'array' or jsonb_array_length(p_devices)+jsonb_array_length(p_recoveries)>400 then raise exception 'Invalid key attestation' using errcode='22023'; end if;
  select * into state from public.vault_state where singleton for update;
  if (p_generation is distinct from state.generation and p_generation is distinct from state.prepared_generation) or public.qv_authorize_device(p_device_id,p_token,state.generation,'state') is null then raise exception 'Key attestation is not authorized' using errcode='42501'; end if;
  for item in select value from jsonb_array_elements(p_devices) loop
    if public.qv_valid_verifier(item->'attestation') is not true then raise exception 'Invalid key attestation' using errcode='22023'; end if;
    update public.vault_device_wrappers w set attestation=item->'attestation' from public.vault_devices d
      where d.id=w.device_id and w.device_id=(item->>'device_id')::uuid and w.generation=p_generation and w.purpose='active' and (admin or d.owner_id=auth.uid());
  end loop;
  for item in select value from jsonb_array_elements(p_recoveries) loop
    if public.qv_valid_verifier(item->'attestation') is not true then raise exception 'Invalid key attestation' using errcode='22023'; end if;
    update public.vault_recovery_wrappers w set attestation=item->'attestation' from public.vault_recovery_keys k
      where k.id=w.recovery_key_id and w.recovery_key_id=(item->>'recovery_key_id')::uuid and w.generation=p_generation and (admin or k.owner_id=auth.uid());
  end loop;
end $attest$;
revoke all on function public.attest_vault_keys(uuid,text,uuid,jsonb,jsonb) from public, anon, authenticated;
grant execute on function public.attest_vault_keys(uuid,text,uuid,jsonb,jsonb) to authenticated;

create or replace function public.get_envelope_migration_coverage(p_migration_id uuid,p_device_id uuid,p_token text)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $coverage$
declare state public.vault_state%rowtype; migration public.vault_migrations%rowtype; member record; members jsonb:='[]'::jsonb; devices jsonb; recoveries jsonb; blockers jsonb; ready boolean;
begin
  if public.qv_is_admin() is not true or public.qv_is_member() is not true then raise exception 'QuoteVault administrator membership is required' using errcode='42501'; end if;
  select * into state from public.vault_state where singleton for share;
  select * into migration from public.vault_migrations where id=p_migration_id for share;
  if migration.id is null or migration.status not in ('staging','ready','activated') or state.active_migration_id is distinct from migration.id or state.envelope_status not in ('preparing','maintenance') or public.qv_migration_device_ok(p_device_id,p_token,state) is not true then raise exception 'Migration coverage is unavailable' using errcode='40001'; end if;
  ready:=migration.status in ('staging','ready') and public.qv_migration_ready(migration);
  for member in select lower(a.email) email,u.id owner_id from public.allowlist a left join auth.users u on lower(u.email)=lower(a.email) order by a.id loop
    select coalesce(jsonb_agg(jsonb_build_object('device_id',d.id,'public_jwk',d.public_jwk,'public_key_fingerprint',d.public_key_fingerprint,'attestation',sw.attestation,'wrapper_staged',w.device_id is not null,'last_sync_at',d.last_sync_at,'empty_queue_reported_at',r.reported_at,'reported_revision',r.reported_revision) order by d.id),'[]'::jsonb) into devices from public.vault_devices d left join public.vault_device_wrappers w on w.device_id=d.id and w.generation=migration.target_generation and w.purpose='active' left join public.vault_device_wrappers sw on sw.device_id=d.id and sw.generation=migration.source_generation and sw.purpose='active' left join public.vault_migration_queue_reports r on r.migration_id=migration.id and r.device_id=d.id where d.owner_id=member.owner_id and d.status='active';
    select coalesce(jsonb_agg(jsonb_build_object('recovery_key_id',k.id,'public_jwk',k.public_jwk,'public_key_fingerprint',k.public_key_fingerprint,'attestation',sw.attestation,'wrapper_staged',w.recovery_key_id is not null) order by k.id),'[]'::jsonb) into recoveries from public.vault_recovery_keys k left join public.vault_recovery_wrappers w on w.recovery_key_id=k.id and w.generation=migration.target_generation left join public.vault_recovery_wrappers sw on sw.recovery_key_id=k.id and sw.generation=migration.source_generation where k.owner_id=member.owner_id and k.status='active';
    blockers := (case when member.owner_id is null then jsonb_build_array('no_account') else '[]'::jsonb end)||(case when member.owner_id is not null and devices='[]'::jsonb then jsonb_build_array('no_active_device') else '[]'::jsonb end)||(case when member.owner_id is not null and recoveries='[]'::jsonb then jsonb_build_array('no_active_recovery') else '[]'::jsonb end)||(case when member.owner_id is not null and exists(select 1 from public.vault_devices d left join public.vault_device_wrappers w on w.device_id=d.id and w.generation=migration.target_generation and w.purpose='active' where d.owner_id=member.owner_id and d.status='active' and w.device_id is null) then jsonb_build_array('missing_device_wrapper') else '[]'::jsonb end)||(case when member.owner_id is not null and exists(select 1 from public.vault_recovery_keys k left join public.vault_recovery_wrappers w on w.recovery_key_id=k.id and w.generation=migration.target_generation where k.owner_id=member.owner_id and k.status='active' and w.recovery_key_id is null) then jsonb_build_array('missing_recovery_wrapper') else '[]'::jsonb end)||(case when member.owner_id is not null and exists(select 1 from public.vault_devices d left join public.vault_migration_queue_reports r on r.migration_id=migration.id and r.device_id=d.id where d.owner_id=member.owner_id and d.status='active' and (d.last_sync_at is null or d.last_sync_at<migration.prepared_at or d.last_sync_at<=now()-interval '5 minutes' or r.reported_at is null or r.reported_at<=now()-interval '5 minutes' or r.reported_revision is distinct from migration.source_revision)) then jsonb_build_array('no_recent_empty_queue') else '[]'::jsonb end);
    members:=members||jsonb_build_array(jsonb_build_object('email',member.email,'member_id',member.owner_id,'devices',devices,'recovery_keys',recoveries,'blockers',blockers));
  end loop;
  return jsonb_build_object('migration_id',migration.id,'status',case when migration.status='activated' then 'activated' when ready then 'ready' else 'staging' end,'ready',ready,'source_generation',migration.source_generation,'target_generation',migration.target_generation,'expected_quote_count',migration.expected_quote_count,'staged_quote_count',(select count(*) from public.vault_migration_quote_copies where migration_id=migration.id and copy_kind='staged'),'queue_report_max_age_seconds',300,'members',members);
end $coverage$;

-- A member who may already hold the prepared key cannot be removed while that
-- key can still become active.
create or replace function public.remove_member_access(p_member_id uuid,p_device_id uuid default null,p_device_token text default null,p_rotate boolean default false,p_target_generation uuid default null,p_target_verifier jsonb default null)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $remove$
declare state public.vault_state%rowtype;
begin
  if public.qv_is_admin() is not true or public.qv_is_member() is not true then raise exception 'QuoteVault administrator membership is required' using errcode='42501'; end if;
  select * into state from public.vault_state where singleton for update;
  if public.qv_envelope_legacy_mode() is not true and public.qv_authorize_device(p_device_id,p_device_token,state.generation,'state') is null then return null; end if;
  if state.envelope_status='preparing' and exists(select 1 from public.allowlist a join auth.users u on lower(u.email)=lower(a.email) where a.id=p_member_id and (
       exists(select 1 from public.vault_devices d join public.vault_device_wrappers w on w.device_id=d.id where d.owner_id=u.id and w.generation=state.prepared_generation)
       or exists(select 1 from public.vault_recovery_keys k join public.vault_recovery_wrappers w on w.recovery_key_id=k.id where k.owner_id=u.id and w.generation=state.prepared_generation))) then
    raise exception 'Cancel the prepared migration before removing a member who holds its key' using errcode='40001';
  end if;
  return public.qv_remove_member_preparing_gate(p_member_id,p_device_id,p_device_token,p_rotate,p_target_generation,p_target_verifier);
end $remove$;

-- Lease renewal also records last_sync_at; both stay writable in maintenance.
create or replace function public.qv_reject_maintenance_device_mutation()
returns trigger language plpgsql security definer set search_path = public, pg_temp as $$
begin
  if exists(select 1 from public.vault_state where singleton and envelope_status='maintenance') then
    if tg_table_name='vault_devices' and tg_op='UPDATE'
       and (to_jsonb(new)-'lease_expires_at'-'last_sync_at') is not distinct from (to_jsonb(old)-'lease_expires_at'-'last_sync_at') then return new; end if;
    raise exception 'Vault migration verification is in progress' using errcode='40001';
  end if;
  return coalesce(new,old);
end $$;

-- Queue-report freshness must come from the device's own authorized sync.
create or replace function public.sync_quotes(p_generation uuid,p_revision bigint,p_operations jsonb,p_device_id uuid default null,p_device_token text default null)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $sync$
declare state public.vault_state%rowtype; response jsonb;
begin
  if public.qv_is_member() is not true then raise exception 'QuoteVault membership is required' using errcode='42501'; end if;
  select * into state from public.vault_state where singleton for update;
  if public.qv_envelope_legacy_mode() is not true and public.qv_authorize_device(p_device_id,p_device_token,p_generation,'sync') is null then return null; end if;
  response:=public.qv_sync_quotes_legacy(p_generation,p_revision,p_operations);
  if state.envelope_status='preparing' and response is not null and p_device_id is not null
     and public.qv_authorize_device(p_device_id,p_device_token,p_generation,'sync') is not null then update public.vault_devices set last_sync_at=now() where id=p_device_id; end if;
  return response;
end $sync$;

-- Writes during preparation advance the revision; abandoning must not reuse it.
create or replace function public.abandon_envelope_migration(p_migration_id uuid,p_device_id uuid,p_token text)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $abandon$
declare state public.vault_state%rowtype; migration public.vault_migrations%rowtype;
begin
  if public.qv_is_admin() is not true or public.qv_is_member() is not true then raise exception 'QuoteVault administrator membership is required' using errcode='42501'; end if;
  select * into state from public.vault_state where singleton for update;
  select * into migration from public.vault_migrations where id=p_migration_id for update;
  if p_device_id is null and p_token is null then
    if public.qv_is_member() is not true or state.envelope_status<>'preparing' or migration.source_state->>'envelope_status'<>'legacy' then raise exception 'Migration device is not authorized' using errcode='42501'; end if;
  elsif public.qv_authorize_device(p_device_id,p_token,state.generation,'state') is null then raise exception 'Migration device is not authorized' using errcode='42501';
  end if;
  if migration.id is null or migration.status not in ('staging','ready') or state.envelope_status<>'preparing' or state.active_migration_id is distinct from migration.id then raise exception 'Migration cannot be abandoned' using errcode='40001'; end if;
  delete from public.vault_device_wrappers where generation=migration.target_generation;
  delete from public.vault_recovery_wrappers where generation=migration.target_generation;
  delete from public.vault_migration_quote_copies where migration_id=migration.id;
  update public.vault_migrations set status='abandoned' where id=migration.id;
  update public.vault_state set generation=(migration.source_state->>'generation')::uuid,revision=greatest(state.revision,(migration.source_state->>'revision')::bigint)+1,envelope_status=migration.source_state->>'envelope_status',prepared_generation=nullif(migration.source_state->>'prepared_generation','')::uuid,active_migration_id=nullif(migration.source_state->>'active_migration_id','')::uuid where singleton;
  return jsonb_build_object('migration_id',migration.id,'status','abandoned');
end $abandon$;

-- The acting device proves authorization; the target may be any device of the same member.
drop function if exists public.revoke_own_device(uuid, text);
create or replace function public.revoke_own_device(p_device_id uuid, p_token text, p_target_device_id uuid default null)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $revoke$
declare state public.vault_state%rowtype; target uuid:=coalesce(p_target_device_id,p_device_id);
begin
  select * into state from public.vault_state where singleton for update;
  if public.qv_authorize_device(p_device_id,p_token,state.generation,'revoke') is null then return null; end if;
  perform 1 from public.vault_devices where id=target and owner_id=auth.uid() for update;
  if not found then return null; end if;
  delete from public.vault_device_wrappers where device_id=target and purpose='conversion_only';
  update public.vault_devices set status='revoked',revoked_at=now(),lease_expires_at=null where id=target;
  insert into public.vault_security_events(event_type,actor_id,affected_owner_id,affected_device_id,result,reason_code)
    values('device_revoked',auth.uid(),auth.uid(),target,'ok',case when target=p_device_id then 'self' else 'owner' end);
  return jsonb_build_object('device_id',target,'status','revoked');
end $revoke$;
revoke all on function public.revoke_own_device(uuid,text,uuid) from public, anon, authenticated;
grant execute on function public.revoke_own_device(uuid,text,uuid) to authenticated;

-- Reapplying an older migration recreates device-less RPC overloads. Rerunning
-- this migration afterwards closes them again.
do $guard$
declare signature text;
begin
  foreach signature in array array['public.sync_quotes(uuid,bigint,jsonb)','public.checked_import(uuid,bigint,jsonb)','public.edit_quote(uuid,uuid,text,text,date)','public.edit_quotes(uuid,jsonb)','public.get_vault_state()'] loop
    if to_regprocedure(signature) is not null then execute format('revoke all on function %s from public, anon, authenticated', signature); end if;
  end loop;
end $guard$;

commit;
