-- Verified ciphertext-only generation cutover. Staged copies remain inaccessible
-- to normal users; the server validates envelope structure, never plaintext.
begin;

alter table public.vault_migrations add column if not exists source_state jsonb;
alter table public.vault_migrations drop constraint if exists vault_migrations_source_state_check;
alter table public.vault_migrations add constraint vault_migrations_source_state_check
  check (source_state is null or (jsonb_typeof(source_state)='object' and octet_length(source_state::text)<=65536));
alter table public.vault_migrations drop constraint if exists vault_migrations_status_check;
alter table public.vault_migrations add constraint vault_migrations_status_check
  check (status in ('prepared', 'staging', 'ready', 'activated', 'rolled_back', 'finalized', 'abandoned'));
alter table public.vault_migrations alter column initiating_device_id drop not null;
create table if not exists public.vault_migration_queue_reports (
  migration_id uuid not null references public.vault_migrations(id) on delete cascade,
  device_id uuid not null references public.vault_devices(id) on delete cascade,
  reported_at timestamptz not null default now(),
  reported_revision bigint not null,
  primary key (migration_id,device_id)
);
alter table public.vault_migration_queue_reports add column if not exists reported_revision bigint;

create or replace function public.qv_valid_migration_v2_quote(p_row jsonb, p_generation uuid)
returns boolean language plpgsql immutable set search_path = public, pg_temp as $v$
declare key text; cipher jsonb;
begin
  if jsonb_typeof(p_row) <> 'object' then return false; end if;
  for key in select jsonb_object_keys(p_row) loop
    if key not in ('id','text','author','context','quote_date','created_at','user_id','vault_generation') then return false; end if;
  end loop;
  if p_row ?& array['id','text','author','context','quote_date','created_at','user_id','vault_generation'] is not true
     or jsonb_typeof(p_row->'author') <> 'string' or jsonb_typeof(p_row->'context') <> 'string' or jsonb_typeof(p_row->'vault_generation') <> 'string'
     or p_row->>'author' <> 'ENCRYPTED' or p_row->>'context' <> 'ENCRYPTED'
     or p_row->>'vault_generation' <> p_generation::text or left(p_row->>'text', 7) <> '$$E2E$$'
     or jsonb_typeof(p_row->'id') <> 'string' or jsonb_typeof(p_row->'text') <> 'string'
     or jsonb_typeof(p_row->'user_id') <> 'string' or jsonb_typeof(p_row->'created_at') <> 'string'
     or jsonb_typeof(p_row->'quote_date') not in ('string','null') then return false; end if;
  cipher := substring(p_row->>'text' from 8)::jsonb;
  if public.qv_valid_encrypted_bundle(cipher) is not true
     or exists (select 1 from jsonb_object_keys(cipher) k where k not in ('version','iv','data'))
     or p_row->>'id' !~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'
     or p_row->>'user_id' !~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'
     or p_row->>'created_at' !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.[0-9]{6}Z$' then return false; end if;
  if p_row->>'quote_date' is not null then perform (p_row->>'quote_date')::date; end if;
  perform (p_row->>'created_at')::timestamptz;
  return true;
exception when others then return false;
end $v$;

create or replace function public.qv_valid_migration_copy(p_row jsonb)
returns boolean language plpgsql immutable set search_path = public, pg_temp as $copy$
declare generation uuid;
begin
  generation := (p_row->>'vault_generation')::uuid;
  return public.qv_valid_quote(p_row, (p_row->>'user_id')::uuid, generation)
      or public.qv_valid_migration_v2_quote(p_row, generation);
exception when others then return false;
end $copy$;

create or replace function public.qv_migration_enrollment_ready(p_migration public.vault_migrations)
returns boolean language sql stable security definer set search_path = public, pg_temp as $$
  select not exists (select 1 from public.allowlist a where not exists (select 1 from auth.users u join public.vault_devices d on d.owner_id=u.id and d.status='active' where lower(u.email)=lower(a.email)))
    and not exists (select 1 from public.allowlist a where not exists (select 1 from auth.users u join public.vault_recovery_keys k on k.owner_id=u.id and k.status='active' where lower(u.email)=lower(a.email)))
    and not exists (select 1 from public.vault_devices d left join public.vault_device_wrappers w on w.device_id=d.id and w.generation=p_migration.target_generation and w.purpose='active' where d.status='active' and w.device_id is null)
    and not exists (select 1 from public.vault_recovery_keys k left join public.vault_recovery_wrappers w on w.recovery_key_id=k.id and w.generation=p_migration.target_generation where k.status='active' and w.recovery_key_id is null)
    and not exists (select 1 from public.vault_devices d left join public.vault_migration_queue_reports r on r.migration_id=p_migration.id and r.device_id=d.id where d.status='active' and (d.last_sync_at is null or d.last_sync_at<p_migration.prepared_at or d.last_sync_at<=now()-interval '5 minutes' or r.reported_at is null or r.reported_at<=now()-interval '5 minutes' or r.reported_revision is distinct from p_migration.source_revision))
$$;

create or replace function public.qv_migration_ready(p_migration public.vault_migrations)
returns boolean language sql stable security definer set search_path = public, pg_temp as $$
  select (select count(*) from public.vault_migration_quote_copies where migration_id=p_migration.id and copy_kind='staged')=p_migration.expected_quote_count
    and public.qv_migration_enrollment_ready(p_migration)
$$;

drop function if exists public.prepare_envelope_migration(uuid,text,uuid,jsonb);
create or replace function public.prepare_envelope_migration(p_source_generation uuid, p_source_revision bigint, p_device_id uuid, p_token text, p_target_generation uuid, p_target_verifier jsonb)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $prepare$
declare state public.vault_state%rowtype; authorized jsonb; migration public.vault_migrations%rowtype;
begin
  if public.qv_is_admin() is not true or public.qv_is_member() is not true then raise exception 'QuoteVault administrator membership is required' using errcode='42501'; end if;
  if p_source_generation is null or p_source_revision is null or p_target_generation is null or p_target_generation=p_source_generation or public.qv_valid_verifier(p_target_verifier) is not true then raise exception 'Invalid migration request' using errcode='22023'; end if;
  select * into state from public.vault_state where singleton for update;
  if state.envelope_status not in ('legacy','active') or state.active_migration_id is not null or state.generation is distinct from p_source_generation or state.revision is distinct from p_source_revision then raise exception 'Migration source changed; reload before staging' using errcode='40001'; end if;
  if exists(select 1 from public.quotes where vault_generation=p_target_generation)
     or exists(select 1 from public.vault_device_wrappers where generation=p_target_generation)
     or exists(select 1 from public.vault_recovery_wrappers where generation=p_target_generation)
     or exists(select 1 from public.vault_migrations where source_generation=p_target_generation or target_generation=p_target_generation) then raise exception 'Target generation was previously used' using errcode='22023'; end if;
  if state.envelope_status='legacy' then
    if p_device_id is not null or p_token is not null then raise exception 'Legacy preparation does not use a device token' using errcode='42501'; end if;
  else
    authorized := public.qv_authorize_device(p_device_id,p_token,state.generation,'state');
    if authorized is null then raise exception 'Migration device is not authorized' using errcode='42501'; end if;
  end if;
  insert into public.vault_migrations(source_generation,target_generation,target_verifier,source_revision,expected_quote_count,status,initiating_device_id,source_state)
  values(state.generation,p_target_generation,p_target_verifier,state.revision,(select count(*) from public.quotes where vault_generation=state.generation),'staging',p_device_id,to_jsonb(state))
  returning * into migration;
  update public.vault_state set envelope_status='preparing',prepared_generation=p_target_generation,active_migration_id=migration.id where singleton;
  return jsonb_build_object('migration_id',migration.id,'status',migration.status,'source_generation',migration.source_generation,'target_generation',migration.target_generation,'expected_quote_count',migration.expected_quote_count,'source_revision',migration.source_revision);
end $prepare$;

create or replace function public.stage_envelope_quotes(p_migration_id uuid, p_device_id uuid, p_token text, p_rows jsonb)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $stage$
declare state public.vault_state%rowtype; migration public.vault_migrations%rowtype; authorized jsonb; row jsonb; row_id uuid; existing jsonb;
begin
  -- Mutating migration RPCs lock state, migration, then qv_authorize_device's device row.
  if public.qv_is_admin() is not true or jsonb_typeof(p_rows) <> 'array' or jsonb_array_length(p_rows) not between 1 and 50 or octet_length(p_rows::text)>921600 then raise exception 'Invalid migration staging request' using errcode='22023'; end if;
  select * into state from public.vault_state where singleton for update;
  select * into migration from public.vault_migrations where id=p_migration_id for update;
  if not found or migration.status not in ('staging','ready') or state.envelope_status<>'preparing' or state.active_migration_id is distinct from migration.id then raise exception 'Migration is not staging' using errcode='40001'; end if;
  authorized:=public.qv_authorize_device(p_device_id,p_token,state.generation,'state');
  if authorized is null then raise exception 'Migration device is not authorized' using errcode='42501'; end if;
  for row in select value from jsonb_array_elements(p_rows) loop
    if public.qv_valid_migration_v2_quote(row,migration.target_generation) is not true then raise exception 'Invalid target envelope' using errcode='22023'; end if;
  end loop;
  if public.qv_migration_enrollment_ready(migration) is not true then raise exception 'Migration enrollment is incomplete' using errcode='40001'; end if;
  for row in select value from jsonb_array_elements(p_rows) loop
    row_id:=(row->>'id')::uuid;
    select encrypted_row into existing from public.vault_migration_quote_copies where migration_id=migration.id and copy_kind='staged' and quote_id=row_id for update;
    if found then if existing is distinct from row then raise exception 'Staged quote replay changed' using errcode='40001'; end if;
    else insert into public.vault_migration_quote_copies(migration_id,copy_kind,quote_id,encrypted_row,vault_generation) values(migration.id,'staged',row_id,row,migration.target_generation); end if;
  end loop;
  if public.qv_migration_ready(migration) then update public.vault_migrations set status='ready' where id=migration.id; migration.status:='ready'; else update public.vault_migrations set status='staging' where id=migration.id; migration.status:='staging'; end if;
  return jsonb_build_object('migration_id',migration.id,'status',migration.status,'staged_quote_count',(select count(*) from public.vault_migration_quote_copies where migration_id=migration.id and copy_kind='staged'));
end $stage$;

create or replace function public.stage_envelope_wrappers(p_migration_id uuid, p_device_id uuid, p_token text, p_devices jsonb, p_recoveries jsonb)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $wrappers$
declare state public.vault_state%rowtype; migration public.vault_migrations%rowtype; authorized jsonb; item jsonb; target_id uuid; key text;
begin
  if public.qv_is_admin() is not true or jsonb_typeof(p_devices)<>'array' or jsonb_typeof(p_recoveries)<>'array' or jsonb_array_length(p_devices)>200 or jsonb_array_length(p_recoveries)>200 or octet_length((p_devices||p_recoveries)::text)>500000 then raise exception 'Invalid migration wrapper request' using errcode='22023'; end if;
  select * into state from public.vault_state where singleton for update;
  select * into migration from public.vault_migrations where id=p_migration_id for update;
  if not found or migration.status not in ('staging','ready') or state.envelope_status<>'preparing' or state.active_migration_id is distinct from migration.id then raise exception 'Migration is not staging' using errcode='40001'; end if;
  authorized:=public.qv_authorize_device(p_device_id,p_token,state.generation,'state');
  if authorized is null then raise exception 'Migration device is not authorized' using errcode='42501'; end if;
  for item in select value from jsonb_array_elements(p_devices) loop
    if jsonb_typeof(item)<>'object' or item ?& array['device_id','wrapped_key'] is not true or exists(select 1 from jsonb_object_keys(item) k where k not in ('device_id','wrapped_key')) or public.qv_base64url_bytes(item->>'wrapped_key',384) is null then raise exception 'Invalid migration wrapper' using errcode='22023'; end if;
    target_id:=(item->>'device_id')::uuid; if not exists(select 1 from public.vault_devices where id=target_id and status='active') then raise exception 'Invalid migration wrapper' using errcode='22023'; end if;
    select wrapped_key into key from public.vault_device_wrappers where device_id=target_id and generation=migration.target_generation and purpose='active' for update;
    if found and key is distinct from item->>'wrapped_key' then raise exception 'Staged wrapper replay changed' using errcode='40001'; end if;
    insert into public.vault_device_wrappers(device_id,generation,purpose,wrapped_key,created_by_device_id) values(target_id,migration.target_generation,'active',item->>'wrapped_key',p_device_id) on conflict (device_id,generation,purpose) do nothing;
  end loop;
  for item in select value from jsonb_array_elements(p_recoveries) loop
    if jsonb_typeof(item)<>'object' or item ?& array['recovery_key_id','wrapped_key'] is not true or exists(select 1 from jsonb_object_keys(item) k where k not in ('recovery_key_id','wrapped_key')) or public.qv_base64url_bytes(item->>'wrapped_key',384) is null then raise exception 'Invalid migration wrapper' using errcode='22023'; end if;
    target_id:=(item->>'recovery_key_id')::uuid; if not exists(select 1 from public.vault_recovery_keys where id=target_id and status='active') then raise exception 'Invalid migration wrapper' using errcode='22023'; end if;
    select wrapped_key into key from public.vault_recovery_wrappers where recovery_key_id=target_id and generation=migration.target_generation for update;
    if found and key is distinct from item->>'wrapped_key' then raise exception 'Staged wrapper replay changed' using errcode='40001'; end if;
    insert into public.vault_recovery_wrappers(recovery_key_id,generation,wrapped_key,created_by_device_id) values(target_id,migration.target_generation,item->>'wrapped_key',p_device_id) on conflict (recovery_key_id,generation) do nothing;
  end loop;
  if public.qv_migration_ready(migration) then update public.vault_migrations set status='ready' where id=migration.id; migration.status:='ready'; else update public.vault_migrations set status='staging' where id=migration.id; migration.status:='staging'; end if;
  return jsonb_build_object('migration_id',migration.id,'status',migration.status);
end $wrappers$;

create or replace function public.get_pending_envelope_migration(p_device_id uuid,p_token text)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $pending$
declare state public.vault_state%rowtype; migration public.vault_migrations%rowtype;
begin
  if public.qv_is_admin() is not true or public.qv_is_member() is not true then raise exception 'QuoteVault administrator membership is required' using errcode='42501'; end if;
  select * into state from public.vault_state where singleton;
  if state.envelope_status not in ('preparing','maintenance') or state.active_migration_id is null then return null; end if;
  select * into migration from public.vault_migrations where id=state.active_migration_id and status in ('staging','ready','activated');
  if migration.id is null then return null; end if;
  if p_device_id is null and p_token is null then
    if public.qv_is_member() is not true or state.envelope_status<>'preparing' or migration.source_state->>'envelope_status'<>'legacy' then return null; end if;
  elsif public.qv_migration_device_ok(p_device_id,p_token,state) is not true then return null;
  end if;
  select * into state from public.vault_state where singleton for share;
  if state.envelope_status not in ('preparing','maintenance') or state.active_migration_id is null then return null; end if;
  select * into migration from public.vault_migrations where id=state.active_migration_id and status in ('staging','ready','activated') for share;
  if migration.id is null then return null; end if;
  return jsonb_build_object('migration_id',migration.id,'status',migration.status,'source_generation',migration.source_generation,'target_generation',migration.target_generation,'source_revision',migration.source_revision,'expected_quote_count',migration.expected_quote_count,'staged_quote_count',(select count(*) from public.vault_migration_quote_copies where migration_id=migration.id and copy_kind='staged'),'rollback_expires_at',migration.rollback_expires_at);
end $pending$;

drop function if exists public.report_envelope_migration_empty_queue(uuid,uuid,text);
create or replace function public.report_envelope_migration_empty_queue(p_migration_id uuid,p_source_revision bigint,p_device_id uuid,p_token text)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $report$
declare state public.vault_state%rowtype; migration public.vault_migrations%rowtype; reported_at timestamptz;
begin
  select * into state from public.vault_state where singleton for update;
  select * into migration from public.vault_migrations where id=p_migration_id for update;
  if migration.id is null or migration.status not in ('staging','ready') or state.envelope_status<>'preparing' or state.active_migration_id is distinct from migration.id then raise exception 'Migration is not staging' using errcode='40001'; end if;
  if public.qv_authorize_device(p_device_id,p_token,state.generation,'state') is null then raise exception 'Migration device is not authorized' using errcode='40001'; end if;
  if p_source_revision is distinct from state.revision or p_source_revision is distinct from migration.source_revision or not exists(select 1 from public.vault_devices where id=p_device_id and last_sync_at>=migration.prepared_at and last_sync_at>now()-interval '5 minutes') then raise exception 'Migration queue report is stale' using errcode='40001'; end if;
  insert into public.vault_migration_queue_reports(migration_id,device_id,reported_at,reported_revision) values(migration.id,p_device_id,now(),p_source_revision)
  on conflict (migration_id,device_id) do update set reported_at=excluded.reported_at,reported_revision=excluded.reported_revision returning public.vault_migration_queue_reports.reported_at into reported_at;
  if public.qv_migration_ready(migration) then update public.vault_migrations set status='ready' where id=migration.id; migration.status:='ready'; else update public.vault_migrations set status='staging' where id=migration.id; migration.status:='staging'; end if;
  return jsonb_build_object('migration_id',migration.id,'source_revision',migration.source_revision,'status',migration.status,'device_id',p_device_id,'reported_at',reported_at,'ready',migration.status='ready');
end $report$;

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
    select coalesce(jsonb_agg(jsonb_build_object('device_id',d.id,'public_jwk',d.public_jwk,'public_key_fingerprint',d.public_key_fingerprint,'wrapper_staged',w.device_id is not null,'last_sync_at',d.last_sync_at,'empty_queue_reported_at',r.reported_at,'reported_revision',r.reported_revision) order by d.id),'[]'::jsonb) into devices from public.vault_devices d left join public.vault_device_wrappers w on w.device_id=d.id and w.generation=migration.target_generation and w.purpose='active' left join public.vault_migration_queue_reports r on r.migration_id=migration.id and r.device_id=d.id where d.owner_id=member.owner_id and d.status='active';
    select coalesce(jsonb_agg(jsonb_build_object('recovery_key_id',k.id,'public_jwk',k.public_jwk,'public_key_fingerprint',k.public_key_fingerprint,'wrapper_staged',w.recovery_key_id is not null) order by k.id),'[]'::jsonb) into recoveries from public.vault_recovery_keys k left join public.vault_recovery_wrappers w on w.recovery_key_id=k.id and w.generation=migration.target_generation where k.owner_id=member.owner_id and k.status='active';
    blockers := (case when member.owner_id is null then jsonb_build_array('no_account') else '[]'::jsonb end)||(case when member.owner_id is not null and devices='[]'::jsonb then jsonb_build_array('no_active_device') else '[]'::jsonb end)||(case when member.owner_id is not null and recoveries='[]'::jsonb then jsonb_build_array('no_active_recovery') else '[]'::jsonb end)||(case when member.owner_id is not null and exists(select 1 from public.vault_devices d left join public.vault_device_wrappers w on w.device_id=d.id and w.generation=migration.target_generation and w.purpose='active' where d.owner_id=member.owner_id and d.status='active' and w.device_id is null) then jsonb_build_array('missing_device_wrapper') else '[]'::jsonb end)||(case when member.owner_id is not null and exists(select 1 from public.vault_recovery_keys k left join public.vault_recovery_wrappers w on w.recovery_key_id=k.id and w.generation=migration.target_generation where k.owner_id=member.owner_id and k.status='active' and w.recovery_key_id is null) then jsonb_build_array('missing_recovery_wrapper') else '[]'::jsonb end)||(case when member.owner_id is not null and exists(select 1 from public.vault_devices d left join public.vault_migration_queue_reports r on r.migration_id=migration.id and r.device_id=d.id where d.owner_id=member.owner_id and d.status='active' and (d.last_sync_at is null or d.last_sync_at<migration.prepared_at or d.last_sync_at<=now()-interval '5 minutes' or r.reported_at is null or r.reported_at<=now()-interval '5 minutes' or r.reported_revision is distinct from migration.source_revision)) then jsonb_build_array('no_recent_empty_queue') else '[]'::jsonb end);
    members:=members||jsonb_build_array(jsonb_build_object('email',member.email,'member_id',member.owner_id,'devices',devices,'recovery_keys',recoveries,'blockers',blockers));
  end loop;
  return jsonb_build_object('migration_id',migration.id,'status',case when migration.status='activated' then 'activated' when ready then 'ready' else 'staging' end,'ready',ready,'source_generation',migration.source_generation,'target_generation',migration.target_generation,'expected_quote_count',migration.expected_quote_count,'staged_quote_count',(select count(*) from public.vault_migration_quote_copies where migration_id=migration.id and copy_kind='staged'),'queue_report_max_age_seconds',300,'members',members);
end $coverage$;

-- Preparing-mode queue reports are tied to the server result of a legacy sync.
create or replace function public.sync_quotes(p_generation uuid,p_revision bigint,p_operations jsonb,p_device_id uuid default null,p_device_token text default null)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $sync$
declare state public.vault_state%rowtype; response jsonb;
begin
  if public.qv_is_member() is not true then raise exception 'QuoteVault membership is required' using errcode='42501'; end if;
  select * into state from public.vault_state where singleton for update;
  if state.envelope_status='preparing' then
    if p_device_id is null and p_device_token is null then return public.qv_sync_quotes_legacy(p_generation,p_revision,p_operations); end if;
    if public.qv_authorize_device(p_device_id,p_device_token,p_generation,'sync') is null then return null; end if;
    response:=public.qv_sync_quotes_legacy(p_generation,p_revision,p_operations);
    if response is not null then update public.vault_devices set last_sync_at=now() where id=p_device_id; end if;
    return response;
  end if;
  if state.envelope_status not in ('legacy','preparing') and public.qv_authorize_device(p_device_id,p_device_token,p_generation,'sync') is null then return null; end if;
  return public.qv_sync_quotes_legacy(p_generation,p_revision,p_operations);
end $sync$;

create or replace function public.refresh_envelope_migration_source(p_migration_id uuid,p_source_revision bigint,p_device_id uuid,p_token text)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $refresh$
declare state public.vault_state%rowtype; migration public.vault_migrations%rowtype; quote public.quotes%rowtype;
begin
  if public.qv_is_admin() is not true or public.qv_is_member() is not true then raise exception 'QuoteVault administrator membership is required' using errcode='42501'; end if;
  select * into state from public.vault_state where singleton for update;
  select * into migration from public.vault_migrations where id=p_migration_id for update;
  if migration.id is null or migration.status not in ('staging','ready') or state.envelope_status<>'preparing' or state.active_migration_id is distinct from migration.id or state.generation is distinct from migration.source_generation or p_source_revision is distinct from state.revision then raise exception 'Migration source changed; reload before staging' using errcode='40001'; end if;
  if public.qv_authorize_device(p_device_id,p_token,state.generation,'state') is null then raise exception 'Migration device is not authorized' using errcode='42501'; end if;
  for quote in select * from public.quotes where vault_generation=migration.source_generation order by id for update loop null; end loop;
  if migration.source_revision=p_source_revision and migration.expected_quote_count=(select count(*) from public.quotes where vault_generation=migration.source_generation) then
    return jsonb_build_object('migration_id',migration.id,'status',migration.status,'source_generation',migration.source_generation,'source_revision',migration.source_revision,'expected_quote_count',migration.expected_quote_count,'reset',false);
  end if;
  delete from public.vault_migration_quote_copies where migration_id=migration.id and copy_kind='staged';
  delete from public.vault_migration_queue_reports where migration_id=migration.id;
  update public.vault_migrations set source_revision=p_source_revision,expected_quote_count=(select count(*) from public.quotes where vault_generation=migration.source_generation),source_state=jsonb_set(source_state,'{revision}',to_jsonb(p_source_revision),true),status='staging' where id=migration.id returning * into migration;
  return jsonb_build_object('migration_id',migration.id,'status',migration.status,'source_generation',migration.source_generation,'source_revision',migration.source_revision,'expected_quote_count',migration.expected_quote_count,'reset',true);
end $refresh$;

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
  update public.vault_state set generation=(migration.source_state->>'generation')::uuid,revision=(migration.source_state->>'revision')::bigint,envelope_status=migration.source_state->>'envelope_status',prepared_generation=nullif(migration.source_state->>'prepared_generation','')::uuid,active_migration_id=nullif(migration.source_state->>'active_migration_id','')::uuid where singleton;
  return jsonb_build_object('migration_id',migration.id,'status','abandoned');
end $abandon$;

create or replace function public.qv_migration_device_ok(p_device_id uuid,p_token text,p_state public.vault_state)
returns boolean language plpgsql stable security definer set search_path = public, pg_temp as $ok$
declare d public.vault_devices%rowtype; b bytea;
begin
  select * into d from public.vault_devices where id=p_device_id;
  b:=public.qv_base64url_bytes(p_token,32);
  return auth.uid() is not null and public.qv_is_member() is true and p_state.generation is not null and p_state.envelope_status in ('preparing','maintenance') and d.owner_id=auth.uid() and d.status='active' and d.lease_expires_at>now() and b is not null and rtrim(replace(replace(replace(encode(sha256(b),'base64'),E'\n',''),'+','-'),'/','_'),'=')=d.authorization_token_digest;
exception when others then return false;
end $ok$;

-- A freshly approved target-wrapped device may establish its owner's first
-- recovery key while preparation is open; normal active-vault behavior stays
-- on the established wrapper authorization path.
create or replace function public.create_recovery_key(
  p_recovery_key_id uuid, p_public_jwk jsonb, p_public_key_fingerprint text,
  p_encrypted_private_key jsonb, p_kdf jsonb, p_generation uuid, p_wrapped_key text,
  p_device_id uuid, p_token text
)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $create_recovery$
declare state public.vault_state%rowtype; authorized jsonb;
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
     or public.qv_base64url_bytes(p_wrapped_key,384) is null
     or exists(select 1 from public.vault_recovery_keys where owner_id=auth.uid() and status='active') then return null; end if;
  insert into public.vault_recovery_keys(id,owner_id,status,public_jwk,public_key_fingerprint,encrypted_private_key,kdf,confirmed_at)
  values(p_recovery_key_id,auth.uid(),'active',p_public_jwk,p_public_key_fingerprint,p_encrypted_private_key,p_kdf,now());
  insert into public.vault_recovery_wrappers(recovery_key_id,generation,wrapped_key,created_by_device_id)
  values(p_recovery_key_id,p_generation,p_wrapped_key,p_device_id);
  insert into public.vault_security_events(event_type,actor_id,affected_owner_id,affected_device_id,result,reason_code)
  values('recovery_created',auth.uid(),auth.uid(),p_device_id,'ok','confirmed');
  return jsonb_build_object('recovery_key_id',p_recovery_key_id,'generation',p_generation);
end $create_recovery$;

create or replace function public.activate_envelope_migration(p_migration_id uuid,p_device_id uuid,p_token text)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $activate$
declare state public.vault_state%rowtype; migration public.vault_migrations%rowtype; d public.vault_devices%rowtype; recovery public.vault_recovery_keys%rowtype; source_quote public.quotes%rowtype; staged public.vault_migration_quote_copies%rowtype;
begin
  if public.qv_is_admin() is not true then raise exception 'QuoteVault administrator membership is required' using errcode='42501'; end if;
  select * into state from public.vault_state where singleton for update;
  select * into migration from public.vault_migrations where id=p_migration_id for update;
  -- Lock every device deterministically after state and migration, before quotes.
  for d in select * from public.vault_devices order by id for update loop null; end loop;
  for recovery in select * from public.vault_recovery_keys order by id for update loop null; end loop;
  if migration.id is null or migration.status<>'ready' or state.envelope_status<>'preparing' or state.active_migration_id is distinct from migration.id or public.qv_migration_device_ok(p_device_id,p_token,state) is not true then raise exception 'Migration is not ready or authorized' using errcode='40001'; end if;
  for source_quote in select * from public.quotes where vault_generation=migration.source_generation order by id for update loop null; end loop;
  if state.generation is distinct from migration.source_generation or state.revision is distinct from migration.source_revision
     or (select count(*) from public.quotes where vault_generation=migration.source_generation)<>migration.expected_quote_count or exists(select 1 from public.quotes where vault_generation<>migration.source_generation)
     or exists((select id from public.quotes where vault_generation=migration.source_generation) except (select quote_id from public.vault_migration_quote_copies where migration_id=migration.id and copy_kind='staged'))
     or exists((select quote_id from public.vault_migration_quote_copies where migration_id=migration.id and copy_kind='staged') except (select id from public.quotes where vault_generation=migration.source_generation))
     or exists(select 1 from public.vault_migration_quote_copies c join public.quotes source on source.id=c.quote_id where c.migration_id=migration.id and c.copy_kind='staged' and ((c.encrypted_row->>'user_id') is distinct from source.user_id::text or (c.encrypted_row->>'created_at') is distinct from to_char(source.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') or c.encrypted_row->'quote_date' is distinct from coalesce(to_jsonb(source.quote_date),'null'::jsonb)))
     or public.qv_migration_ready(migration) is not true then raise exception 'Migration source, staged rows, or wrappers changed' using errcode='40001'; end if;
  insert into public.vault_migration_quote_copies(migration_id,copy_kind,quote_id,encrypted_row,vault_generation)
    select migration.id,'rollback',src.id,jsonb_build_object('id',src.id,'text',src.text,'author',src.author,'context',src.context,'quote_date',src.quote_date,'created_at',to_char(src.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'user_id',src.user_id,'vault_generation',src.vault_generation),src.vault_generation from public.quotes src where src.vault_generation=migration.source_generation order by src.id;
  delete from public.quotes where vault_generation=migration.source_generation;
  for staged in select * from public.vault_migration_quote_copies where migration_id=migration.id and copy_kind='staged' order by quote_id loop
    insert into public.quotes(id,text,author,context,quote_date,created_at,user_id,vault_generation) values(staged.quote_id,staged.encrypted_row->>'text',staged.encrypted_row->>'author',staged.encrypted_row->>'context',nullif(staged.encrypted_row->>'quote_date','')::date,(staged.encrypted_row->>'created_at')::timestamptz,(staged.encrypted_row->>'user_id')::uuid,migration.target_generation);
  end loop;
  update public.vault_state set generation=migration.target_generation,revision=migration.source_revision+1,envelope_status='maintenance',prepared_generation=migration.target_generation,active_migration_id=migration.id where singleton;
  update public.vault_migrations set status='activated',activated_at=now(),rollback_expires_at=now()+interval '7 days' where id=migration.id;
  return jsonb_build_object('migration_id',migration.id,'status','activated','generation',migration.target_generation,'revision',migration.source_revision+1);
end $activate$;

create or replace function public.rollback_envelope_migration(p_migration_id uuid,p_device_id uuid,p_token text)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $rollback$
declare state public.vault_state%rowtype; migration public.vault_migrations%rowtype; d public.vault_devices%rowtype; recovery public.vault_recovery_keys%rowtype; target_quote public.quotes%rowtype; copy public.vault_migration_quote_copies%rowtype;
begin
  if public.qv_is_admin() is not true then raise exception 'QuoteVault administrator membership is required' using errcode='42501'; end if;
  select * into state from public.vault_state where singleton for update; select * into migration from public.vault_migrations where id=p_migration_id for update;
  for d in select * from public.vault_devices order by id for update loop null; end loop; for recovery in select * from public.vault_recovery_keys order by id for update loop null; end loop; for target_quote in select * from public.quotes where vault_generation=migration.target_generation order by id for update loop null; end loop;
  if migration.id is null or migration.status<>'activated' or state.active_migration_id is distinct from migration.id or state.envelope_status<>'maintenance' or migration.rollback_expires_at<=now() or public.qv_migration_device_ok(p_device_id,p_token,state) is not true
     or (select count(*) from public.vault_migration_quote_copies where migration_id=migration.id and copy_kind='rollback')<>migration.expected_quote_count
     or exists((select quote_id from public.vault_migration_quote_copies where migration_id=migration.id and copy_kind='rollback') except (select id from public.quotes where vault_generation=migration.target_generation))
     or exists((select id from public.quotes where vault_generation=migration.target_generation) except (select quote_id from public.vault_migration_quote_copies where migration_id=migration.id and copy_kind='rollback'))
     or exists(select 1 from public.vault_migration_quote_copies where migration_id=migration.id and copy_kind='rollback' and vault_generation is distinct from migration.source_generation) then raise exception 'Migration rollback is unavailable' using errcode='40001'; end if;
  delete from public.quotes where vault_generation=migration.target_generation;
  for copy in select * from public.vault_migration_quote_copies where migration_id=migration.id and copy_kind='rollback' order by quote_id loop
    insert into public.quotes(id,text,author,context,quote_date,created_at,user_id,vault_generation) values(copy.quote_id,copy.encrypted_row->>'text',copy.encrypted_row->>'author',copy.encrypted_row->>'context',nullif(copy.encrypted_row->>'quote_date','')::date,(copy.encrypted_row->>'created_at')::timestamptz,(copy.encrypted_row->>'user_id')::uuid,migration.source_generation);
  end loop;
  update public.vault_state set generation=(migration.source_state->>'generation')::uuid,revision=(migration.source_state->>'revision')::bigint,envelope_status=migration.source_state->>'envelope_status',prepared_generation=nullif(migration.source_state->>'prepared_generation','')::uuid,active_migration_id=nullif(migration.source_state->>'active_migration_id','')::uuid where singleton;
  delete from public.vault_device_wrappers where generation=migration.target_generation;
  delete from public.vault_recovery_wrappers where generation=migration.target_generation;
  delete from public.vault_migration_quote_copies where migration_id=migration.id;
  update public.vault_migrations set status='rolled_back' where id=migration.id;
  return jsonb_build_object('migration_id',migration.id,'status','rolled_back','generation',migration.source_generation);
end $rollback$;

create or replace function public.finalize_envelope_migration(p_migration_id uuid,p_device_id uuid,p_token text)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $finalize$
declare state public.vault_state%rowtype; migration public.vault_migrations%rowtype; d public.vault_devices%rowtype; recovery public.vault_recovery_keys%rowtype;
begin
  if public.qv_is_admin() is not true then raise exception 'QuoteVault administrator membership is required' using errcode='42501'; end if;
  select * into state from public.vault_state where singleton for update; select * into migration from public.vault_migrations where id=p_migration_id for update;
  for d in select * from public.vault_devices order by id for update loop null; end loop; for recovery in select * from public.vault_recovery_keys order by id for update loop null; end loop;
  if migration.id is null or migration.status<>'activated' or state.envelope_status<>'maintenance' or state.active_migration_id is distinct from migration.id or state.generation is distinct from migration.target_generation or state.revision is distinct from migration.source_revision+1 or state.prepared_generation is distinct from migration.target_generation or public.qv_migration_device_ok(p_device_id,p_token,state) is not true
     or exists((select id from public.quotes where vault_generation=migration.target_generation) except (select quote_id from public.vault_migration_quote_copies where migration_id=migration.id and copy_kind='staged'))
     or exists((select quote_id from public.vault_migration_quote_copies where migration_id=migration.id and copy_kind='staged') except (select id from public.quotes where vault_generation=migration.target_generation))
     or exists(select 1 from public.quotes q join public.vault_migration_quote_copies c on c.migration_id=migration.id and c.copy_kind='staged' and c.quote_id=q.id where q.vault_generation=migration.target_generation and c.encrypted_row is distinct from jsonb_build_object('id',q.id,'text',q.text,'author',q.author,'context',q.context,'quote_date',q.quote_date,'created_at',to_char(q.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'user_id',q.user_id,'vault_generation',q.vault_generation)) then raise exception 'Migration target verification failed' using errcode='40001'; end if;
  delete from public.vault_migration_quote_copies where migration_id=migration.id;
  update public.vault_migrations set status='finalized' where id=migration.id;
  update public.vault_state set envelope_status='active',prepared_generation=null,active_migration_id=null where singleton;
  return jsonb_build_object('migration_id',migration.id,'status','finalized','generation',migration.target_generation);
end $finalize$;

create or replace function public.purge_expired_vault_rollback()
returns integer language plpgsql security definer set search_path = public, pg_temp as $purge$
declare n integer:=0; state public.vault_state%rowtype; expired_id uuid;
begin
  select * into state from public.vault_state where singleton for update;
  for expired_id in select id from public.vault_migrations where status='activated' and rollback_expires_at<=now() order by id for update skip locked loop
    delete from public.vault_migration_quote_copies c where c.migration_id=expired_id;
    update public.vault_migrations set status='finalized' where id=expired_id;
    if state.active_migration_id is not distinct from expired_id then update public.vault_state set envelope_status='active',prepared_generation=null,active_migration_id=null where singleton; end if;
    n:=n+1;
  end loop;
  delete from public.vault_migration_quote_copies c using public.vault_migrations m where c.migration_id=m.id and m.status='finalized';
  update public.vault_state set envelope_status='active',prepared_generation=null,active_migration_id=null where active_migration_id in (select id from public.vault_migrations where status='finalized');
  return n;
end $purge$;

create or replace function public.get_envelope_migration_snapshot(p_migration_id uuid,p_device_id uuid,p_token text)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $snapshot$
declare state public.vault_state%rowtype; migration public.vault_migrations%rowtype;
begin
  if public.qv_is_admin() is not true then raise exception 'QuoteVault administrator membership is required' using errcode='42501'; end if;
  select * into state from public.vault_state where singleton for share; select * into migration from public.vault_migrations where id=p_migration_id for share;
  if migration.id is null or migration.status<>'activated' or state.envelope_status<>'maintenance' or state.active_migration_id is distinct from migration.id or public.qv_migration_device_ok(p_device_id,p_token,state) is not true then raise exception 'Migration snapshot is unavailable' using errcode='40001'; end if;
  return jsonb_build_object('migration_id',migration.id,'generation',state.generation,'revision',state.revision,'quotes',(select coalesce(jsonb_agg(jsonb_build_object('id',q.id,'text',q.text,'author',q.author,'context',q.context,'quote_date',q.quote_date,'created_at',to_char(q.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'user_id',q.user_id,'vault_generation',q.vault_generation) order by q.id),'[]'::jsonb) from public.quotes q where q.vault_generation=migration.target_generation));
end $snapshot$;

create or replace function public.qv_reject_maintenance_device_mutation()
returns trigger language plpgsql security definer set search_path = public, pg_temp as $$
begin
  if exists(select 1 from public.vault_state where singleton and envelope_status='maintenance') then
    if tg_table_name='vault_devices' and tg_op='UPDATE'
       and (to_jsonb(new)-'lease_expires_at') is not distinct from (to_jsonb(old)-'lease_expires_at') then return new; end if;
    raise exception 'Vault migration verification is in progress' using errcode='40001';
  end if;
  return coalesce(new,old);
end $$;
drop trigger if exists qv_no_device_mutation_in_maintenance on public.vault_devices;
create trigger qv_no_device_mutation_in_maintenance before insert or update or delete on public.vault_devices
for each row execute function public.qv_reject_maintenance_device_mutation();
drop trigger if exists qv_no_device_wrapper_mutation_in_maintenance on public.vault_device_wrappers;
create trigger qv_no_device_wrapper_mutation_in_maintenance before insert or update or delete on public.vault_device_wrappers
for each row execute function public.qv_reject_maintenance_device_mutation();
drop trigger if exists qv_no_recovery_key_mutation_in_maintenance on public.vault_recovery_keys;
create trigger qv_no_recovery_key_mutation_in_maintenance before insert or update or delete on public.vault_recovery_keys
for each row execute function public.qv_reject_maintenance_device_mutation();
drop trigger if exists qv_no_recovery_wrapper_mutation_in_maintenance on public.vault_recovery_wrappers;
create trigger qv_no_recovery_wrapper_mutation_in_maintenance before insert or update or delete on public.vault_recovery_wrappers
for each row execute function public.qv_reject_maintenance_device_mutation();

-- A device completion is not evidence that its local legacy queue was synced.
create or replace function public.complete_device(p_device_id uuid,p_token text,p_generation uuid)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $complete$
declare authorized jsonb; wrapper public.vault_device_wrappers%rowtype; active_recovery_key_id uuid;
begin
  authorized:=public.qv_authorize_device(p_device_id,p_token,p_generation,'complete');
  if authorized is null then return null; end if;
  select * into wrapper from public.vault_device_wrappers where device_id=p_device_id and generation=p_generation and purpose='active';
  if wrapper.device_id is null then return null; end if;
  select id into active_recovery_key_id from public.vault_recovery_keys where owner_id=auth.uid() and status='active';
  insert into public.vault_security_events(event_type,actor_id,affected_owner_id,affected_device_id,result,reason_code)
  values('device_completed',auth.uid(),auth.uid(),p_device_id,'ok','wrapper-issued');
  return jsonb_build_object('device_id',p_device_id,'generation',wrapper.generation,'wrapped_key',wrapper.wrapped_key,'lease_expires_at',authorized->'lease_expires_at','recovery_setup_required',active_recovery_key_id is null,'active_recovery_key_id',active_recovery_key_id);
end $complete$;

-- Bootstrap may start without an approver device, but only for the admin's own
-- first target device.  A legacy administrator cannot strand another member.
create or replace function public.approve_device(
  p_request_id uuid,p_owner_id uuid,p_public_key_fingerprint text,p_enrollment_fingerprint text,
  p_wrapped_key text,p_generation uuid,p_approver_device_id uuid default null,p_approver_token text default null
)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $approve$
declare state public.vault_state%rowtype; pending public.vault_devices%rowtype; caller uuid:=auth.uid();
begin
  select * into state from public.vault_state where singleton for update;
  if p_approver_device_id is null then
    if public.qv_is_admin() is not true or state.envelope_status<>'preparing' then raise exception 'Approving device is required' using errcode='42501'; end if;
  elsif public.qv_authorize_device(p_approver_device_id,p_approver_token,state.generation,'sync') is null then
    raise exception 'Approving device is not authorized' using errcode='42501';
  end if;
  select * into pending from public.vault_devices where id=p_request_id for update;
  if pending.id is null or pending.owner_id is distinct from p_owner_id or public.qv_is_active_profile(pending.owner_id) is not true
     or pending.status<>'pending' or pending.expires_at<=now() or public.qv_valid_device_protection(pending.protection_mode,pending.protection) is not true
     or pending.public_key_fingerprint is distinct from p_public_key_fingerprint or pending.enrollment_fingerprint is distinct from p_enrollment_fingerprint
     or public.qv_base64url_bytes(p_wrapped_key,384) is null then raise exception 'Device approval request is invalid or expired' using errcode='40001'; end if;
  if p_approver_device_id is null and state.envelope_status='preparing' and (pending.owner_id is distinct from caller or pending.request_kind<>'first') then
    raise exception 'Bootstrap approval must be the administrator first device' using errcode='42501';
  end if;
  if p_approver_device_id is null and p_generation is distinct from state.prepared_generation then
    raise exception 'Bootstrap approval must use the prepared generation' using errcode='42501';
  end if;
  if caller is distinct from pending.owner_id and public.qv_is_admin() is not true then raise exception 'Device approval is not authorized' using errcode='42501'; end if;
  if p_generation is distinct from state.generation and not(state.envelope_status='preparing' and p_generation is not distinct from state.prepared_generation) then raise exception 'Invalid enrollment generation' using errcode='40001'; end if;
  update public.vault_devices set status='active',expires_at=null,approved_by_device_id=p_approver_device_id,lease_expires_at=now()+interval '30 days' where id=pending.id;
  insert into public.vault_device_wrappers(device_id,generation,purpose,wrapped_key,created_by_device_id) values(pending.id,p_generation,'active',p_wrapped_key,p_approver_device_id);
  insert into public.vault_security_events(event_type,actor_id,affected_owner_id,affected_device_id,result,reason_code) values('device_approved',caller,pending.owner_id,pending.id,'ok',pending.request_kind);
  return jsonb_build_object('status','approved','device_id',pending.id,'generation',p_generation);
end $approve$;

-- Maintenance blocks every active mutation path; reads remain available for verification.
create or replace function public.qv_authorize_device(p_device_id uuid,p_token text,p_generation uuid,p_operation text)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $auth$
declare state public.vault_state%rowtype; device public.vault_devices%rowtype; caller uuid:=auth.uid(); token_bytes bytea;
begin
  select * into state from public.vault_state where singleton for update; select * into device from public.vault_devices where id=p_device_id for update;
  if not found or caller is null or device.owner_id is distinct from caller or public.qv_is_member() is not true or device.status<>'active' or p_operation not in ('state','sync','import','edit','wrapper','lease_renewal','complete','revoke')
     or (state.envelope_status='maintenance' and p_operation not in ('state','lease_renewal','complete')) then return null; end if;
  if p_generation is distinct from state.generation and not(p_operation='complete' and state.envelope_status='preparing' and p_generation is not distinct from state.prepared_generation) then return null; end if;
  token_bytes:=public.qv_base64url_bytes(p_token,32); if token_bytes is null or rtrim(replace(replace(replace(encode(sha256(token_bytes),'base64'),E'\n',''),'+','-'),'/','_'),'=')<>device.authorization_token_digest or (p_operation<>'lease_renewal' and (device.lease_expires_at is null or device.lease_expires_at<=now())) then return null; end if;
  return jsonb_build_object('device_id',device.id,'owner_id',device.owner_id,'generation',state.generation,'lease_expires_at',device.lease_expires_at);
exception when others then return null;
end $auth$;

-- A cleared browser may restore only devices that already have a wrapper for
-- the generation it must unlock, including the prepared generation.
create or replace function public.get_passkey_restore_devices()
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $restore$
declare state public.vault_state%rowtype; target_generation uuid; devices jsonb;
begin
  if auth.uid() is null or public.qv_is_member() is not true then return null; end if;
  select * into state from public.vault_state where singleton for share;
  target_generation:=case when state.envelope_status='preparing' then state.prepared_generation else state.generation end;
  select coalesce(jsonb_agg(jsonb_build_object('device_id',d.id,'protection_mode',d.protection_mode,'protection',d.protection,'public_key_fingerprint',d.public_key_fingerprint,'encrypted_private_bundle',d.encrypted_private_bundle) order by d.created_at),'[]'::jsonb)
    into devices from public.vault_devices d join public.vault_device_wrappers w on w.device_id=d.id and w.generation=target_generation and w.purpose='active'
    where d.owner_id=auth.uid() and d.status='active' and d.protection_mode='passkey-prf' and public.qv_valid_device_protection(d.protection_mode,d.protection) is true;
  return jsonb_build_object('generation',target_generation,'devices',devices);
end $restore$;

revoke all on function public.qv_valid_migration_v2_quote(jsonb,uuid), public.qv_migration_enrollment_ready(public.vault_migrations), public.qv_migration_ready(public.vault_migrations), public.qv_migration_device_ok(uuid,text,public.vault_state) from public,anon,authenticated;
revoke all on table public.vault_migration_queue_reports from public,anon,authenticated;
revoke all on function public.prepare_envelope_migration(uuid, bigint, uuid,text,uuid,jsonb), public.stage_envelope_quotes(uuid,uuid,text,jsonb), public.stage_envelope_wrappers(uuid,uuid,text,jsonb,jsonb), public.get_pending_envelope_migration(uuid,text), public.get_envelope_migration_coverage(uuid,uuid,text), public.report_envelope_migration_empty_queue(uuid,bigint,uuid,text), public.refresh_envelope_migration_source(uuid,bigint,uuid,text), public.abandon_envelope_migration(uuid,uuid,text), public.activate_envelope_migration(uuid,uuid,text), public.rollback_envelope_migration(uuid,uuid,text), public.finalize_envelope_migration(uuid,uuid,text), public.get_envelope_migration_snapshot(uuid,uuid,text), public.purge_expired_vault_rollback() from public,anon,authenticated;
grant execute on function public.prepare_envelope_migration(uuid, bigint, uuid,text,uuid,jsonb), public.stage_envelope_quotes(uuid,uuid,text,jsonb), public.stage_envelope_wrappers(uuid,uuid,text,jsonb,jsonb), public.get_pending_envelope_migration(uuid,text), public.get_envelope_migration_coverage(uuid,uuid,text), public.report_envelope_migration_empty_queue(uuid,bigint,uuid,text), public.refresh_envelope_migration_source(uuid,bigint,uuid,text), public.abandon_envelope_migration(uuid,uuid,text), public.activate_envelope_migration(uuid,uuid,text), public.rollback_envelope_migration(uuid,uuid,text), public.finalize_envelope_migration(uuid,uuid,text), public.get_envelope_migration_snapshot(uuid,uuid,text) to authenticated;
grant execute on function public.purge_expired_vault_rollback() to service_role;

-- Production requires pg_cron. Disposable and hosted projects without it keep
-- the service-only RPC available for an operator/Edge scheduled invocation.
do $cron$
declare scheduled boolean;
begin
  if exists(select 1 from pg_extension where extname='pg_cron') and to_regnamespace('cron') is not null then
    execute $$select exists(select 1 from cron.job where jobname='quotevault-purge-expired-vault-rollback')$$ into scheduled;
    if not scheduled then
      execute 'select cron.schedule(''quotevault-purge-expired-vault-rollback'', ''0 * * * *'', ''select public.purge_expired_vault_rollback()'')';
    end if;
  end if;
exception when invalid_schema_name or undefined_table or undefined_function or insufficient_privilege then
  raise notice 'pg_cron is required in production to schedule rollback purge';
end $cron$;
commit;
