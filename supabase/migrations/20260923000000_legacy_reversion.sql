-- Return an envelope or legacy vault to a shared passphrase in the pre-envelope
-- v1 format. The client re-encrypts; the server swaps rows atomically after
-- proving the staged set equals the stored set. Safe to reapply after itself.
begin;

create table if not exists public.vault_legacy_reversions (
  id uuid primary key default gen_random_uuid(),
  source_generation uuid not null,
  source_revision bigint not null,
  source_status text not null check (source_status in ('legacy','active')),
  target_generation uuid not null unique,
  expected_quote_count integer not null check (expected_quote_count >= 0),
  status text not null default 'staging' check (status in ('staging','committed','abandoned')),
  created_by uuid not null,
  created_at timestamptz not null default now(),
  committed_at timestamptz
);
create table if not exists public.vault_legacy_reversion_rows (
  reversion_id uuid not null references public.vault_legacy_reversions(id) on delete cascade,
  quote_id uuid not null,
  row_kind text not null check (row_kind in ('staged','source')),
  text text not null,
  primary key (reversion_id, quote_id, row_kind)
);
alter table public.vault_legacy_reversions enable row level security;
alter table public.vault_legacy_reversion_rows enable row level security;
revoke all on table public.vault_legacy_reversions, public.vault_legacy_reversion_rows from public, anon, authenticated;

create or replace function public.qv_reversion_authorized(p_state public.vault_state, p_device_id uuid, p_token text)
returns boolean language plpgsql security definer set search_path = public, pg_temp as $auth$
begin
  if public.qv_is_admin() is not true or public.qv_is_member() is not true then return false; end if;
  if p_state.envelope_status='legacy' then return true; end if;
  return public.qv_authorize_device(p_device_id,p_token,p_state.generation,'state') is not null;
end $auth$;

create or replace function public.qv_legacy_v1_text(p_text text)
returns boolean language plpgsql immutable set search_path = public, pg_temp as $v1$
declare cipher jsonb;
begin
  if left(p_text,7)<>'$$E2E$$' then return false; end if;
  cipher := substring(p_text from 8)::jsonb;
  return jsonb_typeof(cipher)='object' and not cipher ? 'version' and (select count(*) from jsonb_object_keys(cipher))=2
    and public.qv_valid_verifier(cipher) is true and length(cipher->>'data')<=262144;
exception when others then return false;
end $v1$;

create or replace function public.begin_legacy_reversion(p_source_generation uuid,p_source_revision bigint,p_device_id uuid,p_token text)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $begin$
declare state public.vault_state%rowtype; reversion public.vault_legacy_reversions%rowtype;
begin
  select * into state from public.vault_state where singleton for update;
  if public.qv_reversion_authorized(state,p_device_id,p_token) is not true then raise exception 'Administrator device authorization is required' using errcode='42501'; end if;
  if state.envelope_status not in ('legacy','active') then raise exception 'Finish or cancel the open migration first' using errcode='40001'; end if;
  if state.generation is distinct from p_source_generation or state.revision is distinct from p_source_revision then raise exception 'Vault changed; reload and start again' using errcode='40001'; end if;
  delete from public.vault_legacy_reversion_rows where reversion_id in (select id from public.vault_legacy_reversions where status='staging');
  update public.vault_legacy_reversions set status='abandoned' where status='staging';
  insert into public.vault_legacy_reversions(source_generation,source_revision,source_status,target_generation,expected_quote_count,created_by)
    values(state.generation,state.revision,state.envelope_status,gen_random_uuid(),(select count(*) from public.quotes where vault_generation=state.generation),auth.uid())
    returning * into reversion;
  return jsonb_build_object('reversion_id',reversion.id,'target_generation',reversion.target_generation,'expected_quote_count',reversion.expected_quote_count);
end $begin$;

create or replace function public.stage_legacy_reversion(p_reversion_id uuid,p_rows jsonb,p_device_id uuid,p_token text)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $stage$
declare state public.vault_state%rowtype; reversion public.vault_legacy_reversions%rowtype; item jsonb;
begin
  if jsonb_typeof(p_rows)<>'array' or jsonb_array_length(p_rows)>50 then raise exception 'Invalid reversion batch' using errcode='22023'; end if;
  select * into state from public.vault_state where singleton for update;
  if public.qv_reversion_authorized(state,p_device_id,p_token) is not true then raise exception 'Administrator device authorization is required' using errcode='42501'; end if;
  select * into reversion from public.vault_legacy_reversions where id=p_reversion_id for update;
  if not found or reversion.status<>'staging' or state.generation<>reversion.source_generation or state.revision<>reversion.source_revision then raise exception 'Vault changed; reload and start again' using errcode='40001'; end if;
  for item in select value from jsonb_array_elements(p_rows) loop
    if jsonb_typeof(item)<>'object' or (select count(*) from jsonb_object_keys(item))<>2 or item ?& array['quote_id','text'] is not true
       or public.qv_legacy_v1_text(item->>'text') is not true
       or not exists(select 1 from public.quotes where id=(item->>'quote_id')::uuid and vault_generation=reversion.source_generation) then
      raise exception 'Invalid reversion row' using errcode='22023';
    end if;
    insert into public.vault_legacy_reversion_rows(reversion_id,quote_id,row_kind,text) values(reversion.id,(item->>'quote_id')::uuid,'staged',item->>'text')
      on conflict (reversion_id,quote_id,row_kind) do update set text=excluded.text;
  end loop;
  return jsonb_build_object('reversion_id',reversion.id,'staged_quote_count',(select count(*) from public.vault_legacy_reversion_rows where reversion_id=reversion.id and row_kind='staged'));
exception when invalid_text_representation then raise exception 'Invalid reversion row' using errcode='22023';
end $stage$;

create or replace function public.commit_legacy_reversion(p_reversion_id uuid,p_kdf jsonb,p_verifier jsonb,p_device_id uuid,p_token text)
returns jsonb language plpgsql security definer set search_path = public, pg_temp as $commit$
declare state public.vault_state%rowtype; reversion public.vault_legacy_reversions%rowtype; quote_count integer;
begin
  if public.qv_valid_kdf(p_kdf) is not true or public.qv_valid_verifier(p_verifier) is not true then raise exception 'Invalid vault cryptography metadata' using errcode='22023'; end if;
  select * into state from public.vault_state where singleton for update;
  if public.qv_reversion_authorized(state,p_device_id,p_token) is not true then raise exception 'Administrator device authorization is required' using errcode='42501'; end if;
  select * into reversion from public.vault_legacy_reversions where id=p_reversion_id for update;
  if not found or reversion.status<>'staging' or state.envelope_status<>reversion.source_status or state.generation<>reversion.source_generation or state.revision<>reversion.source_revision then raise exception 'Vault changed; reload and start again' using errcode='40001'; end if;
  perform 1 from public.quotes for update;
  select count(*) into quote_count from public.quotes;
  if quote_count<>reversion.expected_quote_count
     or exists(select 1 from public.quotes where vault_generation<>reversion.source_generation)
     or exists(select 1 from public.quotes q where not exists(select 1 from public.vault_legacy_reversion_rows s where s.reversion_id=reversion.id and s.row_kind='staged' and s.quote_id=q.id))
     or exists(select 1 from public.vault_legacy_reversion_rows s where s.reversion_id=reversion.id and s.row_kind='staged' and not exists(select 1 from public.quotes q where q.id=s.quote_id)) then
    raise exception 'Staged quotes do not match the vault; nothing was changed' using errcode='40001';
  end if;
  insert into public.vault_legacy_reversion_rows(reversion_id,quote_id,row_kind,text) select reversion.id,q.id,'source',q.text from public.quotes q;
  update public.quotes q set text=s.text,author='ENCRYPTED',context='ENCRYPTED',vault_generation=reversion.target_generation
    from public.vault_legacy_reversion_rows s where s.reversion_id=reversion.id and s.row_kind='staged' and s.quote_id=q.id;
  delete from public.vault_legacy_reversion_rows where reversion_id=reversion.id and row_kind='staged';
  update public.vault_state set generation=reversion.target_generation,revision=state.revision+1,
    kdf=jsonb_build_object('salt',p_kdf->>'salt','iterations',(p_kdf->>'iterations')::integer),
    verifier=jsonb_build_object('iv',p_verifier->>'iv','data',p_verifier->>'data'),
    envelope_status='legacy',legacy_generation=null,prepared_generation=null,active_migration_id=null
    where singleton returning * into state;
  update public.vault_legacy_reversions set status='committed',committed_at=now() where id=reversion.id;
  insert into public.vault_security_events(event_type,actor_id,affected_owner_id,affected_device_id,result,reason_code)
    values('rotation_activated',auth.uid(),auth.uid(),p_device_id,'ok','legacy-reversion');
  if to_regprocedure('realtime.send(jsonb,text,text,boolean)') is not null then
    perform realtime.send(jsonb_build_object('generation',state.generation),'vault-generation','quotevault-sync',true);
  end if;
  return jsonb_build_object('generation',state.generation,'revision',state.revision,'envelope_status','legacy','quote_count',quote_count);
end $commit$;

revoke all on function public.qv_reversion_authorized(public.vault_state,uuid,text), public.qv_legacy_v1_text(text),
  public.begin_legacy_reversion(uuid,bigint,uuid,text), public.stage_legacy_reversion(uuid,jsonb,uuid,text),
  public.commit_legacy_reversion(uuid,jsonb,jsonb,uuid,text) from public, anon, authenticated;
grant execute on function public.begin_legacy_reversion(uuid,bigint,uuid,text), public.stage_legacy_reversion(uuid,jsonb,uuid,text),
  public.commit_legacy_reversion(uuid,jsonb,jsonb,uuid,text) to authenticated;

commit;
