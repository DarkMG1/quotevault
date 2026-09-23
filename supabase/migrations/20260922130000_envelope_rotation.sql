begin;

-- Legacy authorization exists only before cutover and during the one initial
-- shared-key migration; retained-history rotations remain device-gated.
create or replace function public.qv_envelope_legacy_mode()
returns boolean language sql stable security definer set search_path = public, pg_temp as $legacy$
  select state.envelope_status='legacy' or (
    state.envelope_status='preparing' and state.legacy_generation is not distinct from state.generation and exists(
      select 1 from public.vault_migrations m where m.id=state.active_migration_id
        and m.status in ('staging','ready','activated') and m.source_generation=state.generation
        and m.source_state->>'envelope_status'='legacy'
    )
  ) from public.vault_state state where state.singleton
$legacy$;

-- An old wrapper is read-only conversion material. It is never an authorization
-- path for an obsolete generation's state or writes.
create or replace function public.qv_conversion_source_in_lineage(p_source_generation uuid, p_current_generation uuid)
returns boolean language sql stable security definer set search_path = public, pg_temp as $lineage$
  with recursive lineage(source_generation,target_generation) as (
    select m.source_generation,m.target_generation from public.vault_migrations m
      where m.target_generation=p_current_generation and m.status in ('activated','finalized')
    union
    select m.source_generation,m.target_generation from public.vault_migrations m
      join lineage l on l.source_generation=m.target_generation
      where m.status in ('activated','finalized')
  )
  select exists(select 1 from lineage where source_generation=p_source_generation)
$lineage$;

create or replace function public.get_conversion_wrapper(p_source_generation uuid, p_device_id uuid, p_token text)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $wrapper$
declare state public.vault_state%rowtype; wrapper public.vault_device_wrappers%rowtype;
begin
  if public.qv_is_member() is not true then raise exception 'QuoteVault membership is required' using errcode='42501'; end if;
  select * into state from public.vault_state where singleton for update;
  if state.envelope_status not in ('active','preparing') or public.qv_authorize_device(p_device_id,p_token,state.generation,'wrapper') is null
     or not exists(select 1 from public.vault_device_wrappers where device_id=p_device_id and generation=state.generation and purpose='active')
     or public.qv_conversion_source_in_lineage(p_source_generation,state.generation) is not true then return null; end if;
  select * into wrapper from public.vault_device_wrappers where device_id=p_device_id and generation=p_source_generation and purpose='conversion_only';
  if not found then return null; end if;
  return jsonb_build_object('device_id',p_device_id,'generation',p_source_generation,'wrapped_key',wrapper.wrapped_key,'purpose','conversion_only');
end $wrapper$;

create or replace function public.ack_conversion_queue(p_source_generation uuid, p_device_id uuid, p_token text)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $ack$
declare state public.vault_state%rowtype; removed boolean:=false;
begin
  if public.qv_is_member() is not true then raise exception 'QuoteVault membership is required' using errcode='42501'; end if;
  select * into state from public.vault_state where singleton for update;
  if state.envelope_status not in ('active','preparing') or public.qv_authorize_device(p_device_id,p_token,state.generation,'wrapper') is null
     or not exists(select 1 from public.vault_device_wrappers where device_id=p_device_id and generation=state.generation and purpose='active')
     or public.qv_conversion_source_in_lineage(p_source_generation,state.generation) is not true then return null; end if;
  delete from public.vault_device_wrappers where device_id=p_device_id and generation=p_source_generation and purpose='conversion_only' returning true into removed;
  return jsonb_build_object('status','acknowledged','removed',removed);
end $ack$;

create or replace function public.revoke_own_device(p_device_id uuid, p_token text)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $revoke$
declare state public.vault_state%rowtype; authorized jsonb;
begin
  select * into state from public.vault_state where singleton for update;
  authorized:=public.qv_authorize_device(p_device_id,p_token,state.generation,'revoke');
  if authorized is null then return null; end if;
  delete from public.vault_device_wrappers where device_id=p_device_id and purpose='conversion_only';
  update public.vault_devices set status='revoked',revoked_at=now(),lease_expires_at=null where id=p_device_id;
  insert into public.vault_security_events(event_type,actor_id,affected_owner_id,affected_device_id,result,reason_code)
    values('device_revoked',auth.uid(),auth.uid(),p_device_id,'ok','self');
  return jsonb_build_object('device_id',p_device_id,'status','revoked');
end $revoke$;

-- State is locked before every device. Global Supabase session invalidation is
-- performed by the supported Edge auth.admin.signOut path after this RPC.
drop function if exists public.remove_member_access(uuid,uuid,text);
drop function if exists public.remove_member_access(uuid,uuid,text,boolean,uuid,jsonb);
create function public.remove_member_access(
  p_member_id uuid, p_device_id uuid default null, p_device_token text default null,
  p_rotate boolean default false, p_target_generation uuid default null, p_target_verifier jsonb default null
)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $remove$
declare state public.vault_state%rowtype; member_email text; member_owner_id uuid; device public.vault_devices%rowtype; recovery public.vault_recovery_keys%rowtype; migration jsonb;
begin
  if public.qv_is_admin() is not true or public.qv_is_member() is not true then raise exception 'QuoteVault administrator membership is required' using errcode='42501'; end if;
  select * into state from public.vault_state where singleton for update;
  if state.envelope_status not in ('legacy','preparing') and public.qv_authorize_device(p_device_id,p_device_token,state.generation,'state') is null then return null; end if;
  if p_rotate and (state.envelope_status<>'active' or p_target_generation is null or p_target_verifier is null) then raise exception 'Rotation requires an active vault and target key metadata' using errcode='22023'; end if;
  select email into member_email from public.allowlist where id=p_member_id for update;
  if not found then return null; end if;
  select id into member_owner_id from auth.users where lower(email)=lower(member_email) for update;
  if member_owner_id is not null then
    for device in select * from public.vault_devices where owner_id=member_owner_id order by id for update loop null; end loop;
    for recovery in select * from public.vault_recovery_keys where owner_id=member_owner_id order by id for update loop null; end loop;
    delete from public.vault_device_wrappers w using public.vault_devices d where w.device_id=d.id and d.owner_id=member_owner_id;
    delete from public.vault_recovery_wrappers w using public.vault_recovery_keys k where w.recovery_key_id=k.id and k.owner_id=member_owner_id;
    delete from public.vault_recovery_challenges c using public.vault_recovery_keys k where c.recovery_key_id=k.id and k.owner_id=member_owner_id;
    update public.vault_recovery_keys set status='revoked',revoked_at=now() where owner_id=member_owner_id and status<>'revoked';
    update public.vault_devices set status='revoked',revoked_at=now(),lease_expires_at=null where owner_id=member_owner_id and status<>'revoked';
  end if;
  delete from public.allowlist where id=p_member_id;
  insert into public.vault_security_events(event_type,actor_id,affected_owner_id,affected_device_id,result,reason_code)
    values('member_removed',auth.uid(),member_owner_id,p_device_id,'ok',case when p_rotate then 'remove-and-rotate' else 'access-only' end);
  if not p_rotate then return jsonb_build_object('id',p_member_id,'owner_id',member_owner_id,'status','removed'); end if;
  migration:=public.prepare_envelope_migration(state.generation,state.revision,p_device_id,p_device_token,p_target_generation,p_target_verifier);
  return jsonb_build_object('id',p_member_id,'owner_id',member_owner_id,'status','removed_and_preparing_rotation','migration_id',migration->>'migration_id','target_generation',migration->>'target_generation');
end $remove$;

create or replace function public.get_vault_bootstrap_state()
returns jsonb language plpgsql stable security definer set search_path = public, pg_temp as $bootstrap$
declare state public.vault_state%rowtype; response jsonb;
begin
  if public.qv_is_member() is not true then raise exception 'QuoteVault membership is required' using errcode='42501'; end if;
  select * into state from public.vault_state where singleton;
  response:=jsonb_build_object('envelope_status',state.envelope_status,'generation',state.generation,'prepared_generation',state.prepared_generation);
  if public.qv_envelope_legacy_mode() then
    response:=response||jsonb_build_object('kdf',state.kdf,'verifier',state.verifier,'legacy_generation',state.legacy_generation);
  end if;
  return response;
end $bootstrap$;

create or replace function public.get_vault_state(p_device_id uuid default null,p_device_token text default null)
returns jsonb language plpgsql volatile security definer set search_path = public, pg_temp as $state$
declare state public.vault_state%rowtype;
begin
  if public.qv_is_member() is not true then raise exception 'QuoteVault membership is required' using errcode='42501'; end if;
  select * into state from public.vault_state where singleton for update;
  if public.qv_envelope_legacy_mode() is not true and public.qv_authorize_device(p_device_id,p_device_token,state.generation,'state') is null then return null; end if;
  return public.qv_get_vault_state_legacy();
end $state$;

create or replace function public.sync_quotes(p_generation uuid,p_revision bigint,p_operations jsonb,p_device_id uuid default null,p_device_token text default null)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $sync$
declare state public.vault_state%rowtype; response jsonb;
begin
  if public.qv_is_member() is not true then raise exception 'QuoteVault membership is required' using errcode='42501'; end if;
  select * into state from public.vault_state where singleton for update;
  if public.qv_envelope_legacy_mode() is not true and public.qv_authorize_device(p_device_id,p_device_token,p_generation,'sync') is null then return null; end if;
  response:=public.qv_sync_quotes_legacy(p_generation,p_revision,p_operations);
  if state.envelope_status='preparing' and response is not null and p_device_id is not null then update public.vault_devices set last_sync_at=now() where id=p_device_id; end if;
  return response;
end $sync$;

create or replace function public.rotate_vault(p_expected_generation uuid,p_kdf jsonb,p_verifier jsonb)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $rotate$
begin
  if public.qv_is_admin() is not true then raise exception 'QuoteVault administrator access is required' using errcode='42501'; end if;
  if public.qv_envelope_legacy_mode() is not true then raise exception 'Legacy vault rotation is unavailable after envelope cutover begins' using errcode='42501'; end if;
  return public.qv_rotate_vault_legacy(p_expected_generation,p_kdf,p_verifier);
end $rotate$;

do $gates$
begin
  if to_regprocedure('public.qv_checked_import_preparing_gate(uuid,bigint,jsonb,uuid,text)') is null then execute 'alter function public.checked_import(uuid,bigint,jsonb,uuid,text) rename to qv_checked_import_preparing_gate'; end if;
  if to_regprocedure('public.qv_edit_quote_preparing_gate(uuid,uuid,text,text,date,uuid,text)') is null then execute 'alter function public.edit_quote(uuid,uuid,text,text,date,uuid,text) rename to qv_edit_quote_preparing_gate'; end if;
  if to_regprocedure('public.qv_edit_quotes_preparing_gate(uuid,jsonb,uuid,text)') is null then execute 'alter function public.edit_quotes(uuid,jsonb,uuid,text) rename to qv_edit_quotes_preparing_gate'; end if;
  if to_regprocedure('public.qv_list_members_preparing_gate(uuid,text)') is null then execute 'alter function public.list_members(uuid,text) rename to qv_list_members_preparing_gate'; end if;
  if to_regprocedure('public.qv_add_member_preparing_gate(text,uuid,text)') is null then execute 'alter function public.add_member(text,uuid,text) rename to qv_add_member_preparing_gate'; end if;
  if to_regprocedure('public.qv_remove_member_preparing_gate(uuid,uuid,text,boolean,uuid,jsonb)') is null then execute 'alter function public.remove_member_access(uuid,uuid,text,boolean,uuid,jsonb) rename to qv_remove_member_preparing_gate'; end if;
  if to_regprocedure('public.qv_approve_device_preparing_gate(uuid,uuid,text,text,text,uuid,uuid,text)') is null then execute 'alter function public.approve_device(uuid,uuid,text,text,text,uuid,uuid,text) rename to qv_approve_device_preparing_gate'; end if;
end $gates$;

create or replace function public.checked_import(p_generation uuid,p_revision bigint,p_operations jsonb,p_device_id uuid default null,p_device_token text default null)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $import$
declare state public.vault_state%rowtype;
begin
  if public.qv_is_member() is not true then raise exception 'QuoteVault membership is required' using errcode='42501'; end if;
  select * into state from public.vault_state where singleton for update;
  if public.qv_envelope_legacy_mode() is not true and public.qv_authorize_device(p_device_id,p_device_token,p_generation,'import') is null then return null; end if;
  return public.qv_checked_import_preparing_gate(p_generation,p_revision,p_operations,p_device_id,p_device_token);
end $import$;

create or replace function public.edit_quote(p_generation uuid,p_quote_id uuid,p_expected_text text,p_text text,p_quote_date date,p_device_id uuid default null,p_device_token text default null)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $edit$
declare state public.vault_state%rowtype;
begin
  if public.qv_is_admin() is not true or public.qv_is_member() is not true then raise exception 'QuoteVault administrator membership is required' using errcode='42501'; end if;
  select * into state from public.vault_state where singleton for update;
  if public.qv_envelope_legacy_mode() is not true and public.qv_authorize_device(p_device_id,p_device_token,p_generation,'edit') is null then return null; end if;
  return public.qv_edit_quote_preparing_gate(p_generation,p_quote_id,p_expected_text,p_text,p_quote_date,p_device_id,p_device_token);
end $edit$;

create or replace function public.edit_quotes(p_generation uuid,p_edits jsonb,p_device_id uuid default null,p_device_token text default null)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $edits$
declare state public.vault_state%rowtype;
begin
  if public.qv_is_admin() is not true or public.qv_is_member() is not true then raise exception 'QuoteVault administrator membership is required' using errcode='42501'; end if;
  select * into state from public.vault_state where singleton for update;
  if public.qv_envelope_legacy_mode() is not true and public.qv_authorize_device(p_device_id,p_device_token,p_generation,'edit') is null then return null; end if;
  return public.qv_edit_quotes_preparing_gate(p_generation,p_edits,p_device_id,p_device_token);
end $edits$;

create or replace function public.list_members(p_device_id uuid default null,p_device_token text default null)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $members$
declare state public.vault_state%rowtype;
begin
  if public.qv_is_admin() is not true or public.qv_is_member() is not true then raise exception 'QuoteVault administrator membership is required' using errcode='42501'; end if;
  select * into state from public.vault_state where singleton for update;
  if public.qv_envelope_legacy_mode() is not true and public.qv_authorize_device(p_device_id,p_device_token,state.generation,'state') is null then return null; end if;
  return public.qv_list_members_preparing_gate(p_device_id,p_device_token);
end $members$;

create or replace function public.add_member(p_email text,p_device_id uuid default null,p_device_token text default null)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $add$
declare state public.vault_state%rowtype;
begin
  if public.qv_is_admin() is not true or public.qv_is_member() is not true then raise exception 'QuoteVault administrator membership is required' using errcode='42501'; end if;
  select * into state from public.vault_state where singleton for update;
  if public.qv_envelope_legacy_mode() is not true and public.qv_authorize_device(p_device_id,p_device_token,state.generation,'state') is null then return null; end if;
  return public.qv_add_member_preparing_gate(p_email,p_device_id,p_device_token);
end $add$;

create or replace function public.remove_member_access(p_member_id uuid,p_device_id uuid default null,p_device_token text default null,p_rotate boolean default false,p_target_generation uuid default null,p_target_verifier jsonb default null)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $remove$
declare state public.vault_state%rowtype;
begin
  if public.qv_is_admin() is not true or public.qv_is_member() is not true then raise exception 'QuoteVault administrator membership is required' using errcode='42501'; end if;
  select * into state from public.vault_state where singleton for update;
  if public.qv_envelope_legacy_mode() is not true and public.qv_authorize_device(p_device_id,p_device_token,state.generation,'state') is null then return null; end if;
  return public.qv_remove_member_preparing_gate(p_member_id,p_device_id,p_device_token,p_rotate,p_target_generation,p_target_verifier);
end $remove$;

create or replace function public.approve_device(p_request_id uuid,p_owner_id uuid,p_public_key_fingerprint text,p_enrollment_fingerprint text,p_wrapped_key text,p_generation uuid,p_approver_device_id uuid default null,p_approver_token text default null)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $approve$
declare state public.vault_state%rowtype;
begin
  select * into state from public.vault_state where singleton for update;
  if p_approver_device_id is null and public.qv_envelope_legacy_mode() is not true then raise exception 'Approving device is required' using errcode='42501'; end if;
  return public.qv_approve_device_preparing_gate(p_request_id,p_owner_id,p_public_key_fingerprint,p_enrollment_fingerprint,p_wrapped_key,p_generation,p_approver_device_id,p_approver_token);
end $approve$;

-- The existing staged activation remains the sole rotation engine. This copy
-- changes only old active device wrappers into conversion-only wrappers.
create or replace function public.activate_envelope_migration(p_migration_id uuid,p_device_id uuid,p_token text)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $activate$
declare state public.vault_state%rowtype; migration public.vault_migrations%rowtype; d public.vault_devices%rowtype; recovery public.vault_recovery_keys%rowtype; source_quote public.quotes%rowtype; staged public.vault_migration_quote_copies%rowtype;
begin
  if public.qv_is_admin() is not true then raise exception 'QuoteVault administrator membership is required' using errcode='42501'; end if;
  select * into state from public.vault_state where singleton for update;
  select * into migration from public.vault_migrations where id=p_migration_id for update;
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
  delete from public.vault_device_wrappers w using public.vault_devices device_row where w.device_id=device_row.id and w.generation=migration.source_generation and w.purpose='active' and device_row.status<>'active';
  update public.vault_device_wrappers w set purpose='conversion_only'
    from public.vault_devices device_row where w.device_id=device_row.id and w.generation=migration.source_generation and w.purpose='active' and device_row.status='active';
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
  update public.vault_device_wrappers set purpose='active' where generation=migration.source_generation and purpose='conversion_only';
  delete from public.vault_device_wrappers where generation=migration.target_generation;
  delete from public.vault_recovery_wrappers where generation=migration.target_generation;
  delete from public.vault_migration_quote_copies where migration_id=migration.id;
  update public.vault_migrations set status='rolled_back' where id=migration.id;
  return jsonb_build_object('migration_id',migration.id,'status','rolled_back','generation',migration.source_generation);
end $rollback$;

-- A retained rotation can restore an existing passkey device from its source
-- wrapper until its target wrapper is staged. Initial legacy preparation keeps
-- the original target-only rule because it has no device-authorized source.
create or replace function public.get_passkey_restore_devices()
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $restore$
declare state public.vault_state%rowtype; target_generation uuid; devices jsonb;
begin
  if auth.uid() is null or public.qv_is_member() is not true then return null; end if;
  select * into state from public.vault_state where singleton for share;
  if state.envelope_status='preparing' and public.qv_envelope_legacy_mode() is not true then
    select coalesce(jsonb_agg(jsonb_build_object('device_id',d.id,'protection_mode',d.protection_mode,'protection',d.protection,'public_key_fingerprint',d.public_key_fingerprint,'encrypted_private_bundle',d.encrypted_private_bundle,'generation',coalesce(target.generation,source.generation)) order by d.created_at),'[]'::jsonb)
      into devices from public.vault_devices d
      left join public.vault_device_wrappers target on target.device_id=d.id and target.generation=state.prepared_generation and target.purpose='active'
      left join public.vault_device_wrappers source on source.device_id=d.id and source.generation=state.generation and source.purpose='active'
      where d.owner_id=auth.uid() and d.status='active' and d.protection_mode='passkey-prf' and public.qv_valid_device_protection(d.protection_mode,d.protection) is true
        and (target.device_id is not null or source.device_id is not null);
    return jsonb_build_object('generation',state.generation,'devices',devices);
  end if;
  target_generation:=case when state.envelope_status='preparing' then state.prepared_generation else state.generation end;
  select coalesce(jsonb_agg(jsonb_build_object('device_id',d.id,'protection_mode',d.protection_mode,'protection',d.protection,'public_key_fingerprint',d.public_key_fingerprint,'encrypted_private_bundle',d.encrypted_private_bundle,'generation',target_generation) order by d.created_at),'[]'::jsonb)
    into devices from public.vault_devices d join public.vault_device_wrappers w on w.device_id=d.id and w.generation=target_generation and w.purpose='active'
    where d.owner_id=auth.uid() and d.status='active' and d.protection_mode='passkey-prf' and public.qv_valid_device_protection(d.protection_mode,d.protection) is true;
  return jsonb_build_object('generation',target_generation,'devices',devices);
end $restore$;

revoke all on function public.qv_conversion_source_in_lineage(uuid,uuid), public.qv_checked_import_preparing_gate(uuid,bigint,jsonb,uuid,text), public.qv_edit_quote_preparing_gate(uuid,uuid,text,text,date,uuid,text), public.qv_edit_quotes_preparing_gate(uuid,jsonb,uuid,text), public.qv_list_members_preparing_gate(uuid,text), public.qv_add_member_preparing_gate(text,uuid,text), public.qv_remove_member_preparing_gate(uuid,uuid,text,boolean,uuid,jsonb), public.qv_approve_device_preparing_gate(uuid,uuid,text,text,text,uuid,uuid,text) from public,anon,authenticated;
revoke all on function public.qv_envelope_legacy_mode(), public.get_vault_bootstrap_state(), public.get_vault_state(uuid,text), public.sync_quotes(uuid,bigint,jsonb,uuid,text), public.checked_import(uuid,bigint,jsonb,uuid,text), public.edit_quote(uuid,uuid,text,text,date,uuid,text), public.edit_quotes(uuid,jsonb,uuid,text), public.list_members(uuid,text), public.add_member(text,uuid,text), public.remove_member_access(uuid,uuid,text,boolean,uuid,jsonb), public.approve_device(uuid,uuid,text,text,text,uuid,uuid,text), public.rotate_vault(uuid,jsonb,jsonb), public.get_conversion_wrapper(uuid,uuid,text), public.ack_conversion_queue(uuid,uuid,text), public.revoke_own_device(uuid,text), public.activate_envelope_migration(uuid,uuid,text), public.rollback_envelope_migration(uuid,uuid,text) from public,anon,authenticated;
grant execute on function public.qv_envelope_legacy_mode(), public.get_vault_bootstrap_state(), public.get_vault_state(uuid,text), public.sync_quotes(uuid,bigint,jsonb,uuid,text), public.checked_import(uuid,bigint,jsonb,uuid,text), public.edit_quote(uuid,uuid,text,text,date,uuid,text), public.edit_quotes(uuid,jsonb,uuid,text), public.list_members(uuid,text), public.add_member(text,uuid,text), public.remove_member_access(uuid,uuid,text,boolean,uuid,jsonb), public.approve_device(uuid,uuid,text,text,text,uuid,uuid,text), public.rotate_vault(uuid,jsonb,jsonb), public.get_conversion_wrapper(uuid,uuid,text), public.ack_conversion_queue(uuid,uuid,text), public.revoke_own_device(uuid,text), public.activate_envelope_migration(uuid,uuid,text), public.rollback_envelope_migration(uuid,uuid,text) to authenticated;

commit;
