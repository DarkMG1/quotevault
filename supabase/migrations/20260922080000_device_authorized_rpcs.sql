-- Device-bound access for all ciphertext-bearing RPCs. The renamed functions
-- retain the proven legacy implementations and have no client grants.
begin;

alter function public.sync_quotes(uuid, bigint, jsonb) rename to qv_sync_quotes_legacy;
alter function public.checked_import(uuid, bigint, jsonb) rename to qv_checked_import_legacy;
alter function public.edit_quote(uuid, uuid, text, text, date) rename to qv_edit_quote_legacy;
alter function public.edit_quotes(uuid, jsonb) rename to qv_edit_quotes_legacy;
alter function public.get_vault_state() rename to qv_get_vault_state_legacy;

create or replace function public.get_vault_state(
  p_device_id uuid default null, p_device_token text default null
)
returns jsonb
language plpgsql stable security definer
set search_path = public, pg_temp
as $state$
declare
  state public.vault_state%rowtype;
begin
  if public.qv_is_member() is not true then raise exception 'QuoteVault membership is required' using errcode = '42501'; end if;
  select * into state from public.vault_state where singleton;
  if state.envelope_status not in ('legacy', 'preparing')
     and public.qv_authorize_device(p_device_id, p_device_token, state.generation, 'state') is null then return null; end if;
  return public.qv_get_vault_state_legacy();
end;
$state$;

create or replace function public.sync_quotes(
  p_generation uuid, p_revision bigint, p_operations jsonb,
  p_device_id uuid default null, p_device_token text default null
)
returns jsonb
language plpgsql security definer
set search_path = public, pg_temp
as $sync$
declare state public.vault_state%rowtype;
begin
  if public.qv_is_member() is not true then raise exception 'QuoteVault membership is required' using errcode = '42501'; end if;
  select * into state from public.vault_state where singleton for update;
  if state.envelope_status not in ('legacy', 'preparing')
     and public.qv_authorize_device(p_device_id, p_device_token, p_generation, 'sync') is null then return null; end if;
  return public.qv_sync_quotes_legacy(p_generation, p_revision, p_operations);
end;
$sync$;

create or replace function public.checked_import(
  p_generation uuid, p_revision bigint, p_operations jsonb,
  p_device_id uuid default null, p_device_token text default null
)
returns jsonb
language plpgsql security definer
set search_path = public, pg_temp
as $import$
declare
  state public.vault_state%rowtype;
  authorized jsonb;
  receipt public.vault_operation_receipts%rowtype;
  op jsonb;
  batch jsonb;
  response jsonb;
  results jsonb := '[]'::jsonb;
  caller_id uuid := auth.uid();
  operation_id text;
  quote_id text;
  digest_text text;
  seen_operations text[] := array[]::text[];
  seen_quotes text[] := array[]::text[];
  all_receipted boolean := true;
  batch_offset integer;
  operation_count integer;
begin
  if public.qv_is_member() is not true then raise exception 'QuoteVault membership is required' using errcode = '42501'; end if;
  select * into state from public.vault_state where singleton for update;
  if state.envelope_status not in ('legacy', 'preparing') then
    authorized := public.qv_authorize_device(p_device_id, p_device_token, p_generation, 'import');
    if authorized is null then return null; end if;
  end if;
  if p_revision is null or p_revision < 0 or jsonb_typeof(p_operations) is distinct from 'array' then
    raise exception 'Invalid import request' using errcode = '22023';
  end if;
  operation_count := jsonb_array_length(p_operations);
  if operation_count not between 1 and 500 or octet_length(p_operations::text) > 921600 then
    raise exception 'Invalid import request' using errcode = '22023';
  end if;
  for op in select value from jsonb_array_elements(p_operations) loop
    operation_id := lower(op->>'operation_id'); quote_id := lower(op->>'quote_id');
    if (jsonb_typeof(op) = 'object' and operation_id ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'
        and quote_id ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'
        and op->>'action' = 'INSERT' and op->>'actor_id' = caller_id::text and op->>'vault_generation' = p_generation::text
        and not operation_id = any(seen_operations) and not quote_id = any(seen_quotes)) is not true then
      raise exception 'Invalid import request' using errcode = '22023';
    end if;
    seen_operations := array_append(seen_operations, operation_id); seen_quotes := array_append(seen_quotes, quote_id);
  end loop;
  if p_generation is distinct from state.generation then raise exception 'Vault generation changed; refresh before importing' using errcode = '40001'; end if;
  for op in select value from jsonb_array_elements(p_operations) loop
    digest_text := encode(sha256(convert_to(op::text, 'UTF8')), 'hex');
    select * into receipt from public.vault_operation_receipts
      where operation_id = (op->>'operation_id')::uuid and actor_id = caller_id;
    if not found or receipt.generation <> state.generation or receipt.request_digest <> digest_text or receipt.result->>'status' is distinct from 'ok' then all_receipted := false; exit; end if;
  end loop;
  if p_revision is distinct from state.revision and not all_receipted then raise exception 'Vault changed; refresh and review the import again' using errcode = '40001'; end if;
  for batch_offset in 0..((operation_count - 1) / 50) loop
    select jsonb_agg(value order by ordinal) into batch from jsonb_array_elements(p_operations) with ordinality as entries(value, ordinal)
      where ordinal > batch_offset * 50 and ordinal <= (batch_offset + 1) * 50;
    response := public.qv_sync_quotes_legacy(p_generation, null, batch);
    if jsonb_typeof(response->'results') is distinct from 'array' or jsonb_array_length(response->'results') <> jsonb_array_length(batch)
       or exists (select 1 from jsonb_array_elements(response->'results') result where result->>'status' is distinct from 'ok') then
      raise exception 'Import rejected; no quotes were added' using errcode = '22023';
    end if;
    results := results || response->'results';
  end loop;
  return jsonb_build_object('generation', response->'generation', 'revision', response->'revision', 'results', results, 'quotes', response->'quotes');
end;
$import$;

create or replace function public.edit_quote(
  p_generation uuid, p_quote_id uuid, p_expected_text text, p_text text, p_quote_date date,
  p_device_id uuid default null, p_device_token text default null
)
returns jsonb
language plpgsql security definer
set search_path = public, pg_temp
as $edit$
declare state public.vault_state%rowtype;
begin
  if public.qv_is_admin() is not true or public.qv_is_member() is not true then
    raise exception 'QuoteVault administrator membership is required' using errcode = '42501';
  end if;
  select * into state from public.vault_state where singleton for update;
  if state.envelope_status not in ('legacy', 'preparing')
     and public.qv_authorize_device(p_device_id, p_device_token, p_generation, 'edit') is null then return null; end if;
  return public.qv_edit_quote_legacy(p_generation, p_quote_id, p_expected_text, p_text, p_quote_date);
end;
$edit$;

create or replace function public.edit_quotes(
  p_generation uuid, p_edits jsonb, p_device_id uuid default null, p_device_token text default null
)
returns jsonb
language plpgsql security definer
set search_path = public, pg_temp
as $edits$
declare
  state public.vault_state%rowtype;
  edit jsonb;
  quote_id_text text;
  seen_quote_ids text[] := array[]::text[];
begin
  if public.qv_is_admin() is not true or public.qv_is_member() is not true then raise exception 'QuoteVault administrator membership is required' using errcode = '42501'; end if;
  select * into state from public.vault_state where singleton for update;
  if state.envelope_status not in ('legacy', 'preparing')
     and public.qv_authorize_device(p_device_id, p_device_token, p_generation, 'edit') is null then return null; end if;
  if jsonb_typeof(p_edits) is distinct from 'array' or jsonb_array_length(p_edits) not between 1 and 500 or octet_length(p_edits::text) > 921600 then
    raise exception 'Invalid edit batch' using errcode = '22023';
  end if;
  for edit in select value from jsonb_array_elements(p_edits) loop
    if jsonb_typeof(edit) is distinct from 'object' or not edit ?& array['quote_id', 'expected_text', 'text', 'quote_date']
       or exists (select 1 from jsonb_object_keys(edit) key where key not in ('quote_id', 'expected_text', 'text', 'quote_date'))
       or jsonb_typeof(edit->'quote_id') <> 'string' or jsonb_typeof(edit->'expected_text') <> 'string'
       or jsonb_typeof(edit->'text') <> 'string' or jsonb_typeof(edit->'quote_date') not in ('string', 'null') then
      raise exception 'Invalid edit batch' using errcode = '22023';
    end if;
    quote_id_text := edit->>'quote_id';
    if quote_id_text !~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$' or lower(quote_id_text) = any(seen_quote_ids) then
      raise exception 'Invalid edit batch' using errcode = '22023';
    end if;
    begin if edit->>'quote_date' is not null then perform (edit->>'quote_date')::date; end if;
    exception when invalid_text_representation or invalid_datetime_format or datetime_field_overflow then raise exception 'Invalid edit batch' using errcode = '22023'; end;
    seen_quote_ids := array_append(seen_quote_ids, lower(quote_id_text));
  end loop;
  for edit in select value from jsonb_array_elements(p_edits) loop
    perform public.qv_edit_quote_legacy(p_generation, (edit->>'quote_id')::uuid, edit->>'expected_text', edit->>'text', (edit->>'quote_date')::date);
  end loop;
  return jsonb_build_object('updated', jsonb_array_length(p_edits));
end;
$edits$;

create or replace function public.list_members(p_device_id uuid default null, p_device_token text default null)
returns jsonb language plpgsql security definer set search_path = public, pg_temp
as $members$
declare state public.vault_state%rowtype;
begin
  if public.qv_is_admin() is not true or public.qv_is_member() is not true then raise exception 'QuoteVault administrator membership is required' using errcode = '42501'; end if;
  select * into state from public.vault_state where singleton for update;
  if state.envelope_status not in ('legacy', 'preparing') and public.qv_authorize_device(p_device_id, p_device_token, state.generation, 'state') is null then return null; end if;
  return (select coalesce(jsonb_agg(jsonb_build_object('id', a.id, 'email', a.email, 'first_name', p.first_name, 'last_name', p.last_name) order by a.email), '[]'::jsonb)
    from public.allowlist a left join public.profiles p on p.id = a.id);
end;
$members$;

create or replace function public.add_member(p_email text, p_device_id uuid default null, p_device_token text default null)
returns jsonb language plpgsql security definer set search_path = public, pg_temp
as $add$
declare state public.vault_state%rowtype; email text := lower(trim(p_email)); member_id uuid := gen_random_uuid();
begin
  if public.qv_is_admin() is not true or public.qv_is_member() is not true then raise exception 'QuoteVault administrator membership is required' using errcode = '42501'; end if;
  select * into state from public.vault_state where singleton for update;
  if state.envelope_status not in ('legacy', 'preparing') and public.qv_authorize_device(p_device_id, p_device_token, state.generation, 'state') is null then return null; end if;
  if email is null or length(email) > 320 or email !~ '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$' then raise exception 'Invalid member email' using errcode = '22023'; end if;
  insert into public.allowlist(id, email, created_at) values(member_id, email, now());
  insert into public.vault_security_events(event_type, actor_id, affected_owner_id, affected_device_id, result, reason_code)
    values ('member_added', auth.uid(), null, p_device_id, 'ok', 'allowlist');
  return jsonb_build_object('id', member_id, 'email', email);
end;
$add$;

create or replace function public.remove_member_access(p_member_id uuid, p_device_id uuid default null, p_device_token text default null)
returns jsonb language plpgsql security definer set search_path = public, pg_temp
as $remove$
declare state public.vault_state%rowtype;
begin
  if public.qv_is_admin() is not true or public.qv_is_member() is not true then raise exception 'QuoteVault administrator membership is required' using errcode = '42501'; end if;
  select * into state from public.vault_state where singleton for update;
  if state.envelope_status not in ('legacy', 'preparing') and public.qv_authorize_device(p_device_id, p_device_token, state.generation, 'state') is null then return null; end if;
  if p_member_id is null or not exists(select 1 from public.allowlist where id = p_member_id) then return null; end if;
  perform 1 from public.vault_devices where owner_id = p_member_id for update;
  delete from public.vault_device_wrappers w using public.vault_devices d where w.device_id = d.id and d.owner_id = p_member_id;
  delete from public.vault_recovery_wrappers w using public.vault_recovery_keys k where w.recovery_key_id = k.id and k.owner_id = p_member_id;
  update public.vault_recovery_keys set status = 'revoked', revoked_at = now() where owner_id = p_member_id and status <> 'revoked';
  update public.vault_devices set status = 'revoked', revoked_at = now(), lease_expires_at = null where owner_id = p_member_id and status <> 'revoked';
  -- auth.sessions is managed by Supabase Auth; service-role admin.signOut is the supported session-revocation path.
  delete from public.allowlist where id = p_member_id;
  insert into public.vault_security_events(event_type, actor_id, affected_owner_id, affected_device_id, result, reason_code)
    values ('member_removed', auth.uid(), case when exists(select 1 from auth.users where id = p_member_id) then p_member_id end, p_device_id, 'ok', 'access-only');
  return jsonb_build_object('id', p_member_id, 'status', 'removed');
end;
$remove$;

alter table public.quotes enable row level security;
drop policy if exists qv_member_quotes_select on public.quotes;
create policy qv_member_quotes_select on public.quotes for select to authenticated using (public.qv_is_member() and public.qv_envelope_legacy_mode());
drop policy if exists qv_admin_allowlist_select on public.allowlist;
drop policy if exists qv_admin_allowlist_insert on public.allowlist;
drop policy if exists qv_admin_allowlist_update on public.allowlist;
drop policy if exists qv_admin_allowlist_delete on public.allowlist;
create policy qv_admin_allowlist_select on public.allowlist for select to authenticated using (public.qv_is_admin() and public.qv_envelope_legacy_mode());
create policy qv_admin_allowlist_insert on public.allowlist for insert to authenticated with check (public.qv_is_admin() and public.qv_envelope_legacy_mode());
create policy qv_admin_allowlist_update on public.allowlist for update to authenticated using (public.qv_is_admin() and public.qv_envelope_legacy_mode()) with check (public.qv_is_admin() and public.qv_envelope_legacy_mode());
create policy qv_admin_allowlist_delete on public.allowlist for delete to authenticated using (public.qv_is_admin() and public.qv_envelope_legacy_mode());

do $realtime$
begin
  if exists(select 1 from pg_publication where pubname = 'supabase_realtime')
     and exists(select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'quotes') then
    alter publication supabase_realtime drop table public.quotes;
  end if;
end;
$realtime$;

revoke all on function public.qv_sync_quotes_legacy(uuid, bigint, jsonb), public.qv_checked_import_legacy(uuid, bigint, jsonb), public.qv_edit_quote_legacy(uuid, uuid, text, text, date), public.qv_edit_quotes_legacy(uuid, jsonb), public.qv_get_vault_state_legacy() from public, anon, authenticated;
revoke all on function public.get_vault_state(uuid, text), public.sync_quotes(uuid, bigint, jsonb, uuid, text), public.checked_import(uuid, bigint, jsonb, uuid, text), public.edit_quote(uuid, uuid, text, text, date, uuid, text), public.edit_quotes(uuid, jsonb, uuid, text), public.list_members(uuid, text), public.add_member(text, uuid, text), public.remove_member_access(uuid, uuid, text) from public, anon, authenticated;
grant execute on function public.get_vault_state(uuid, text), public.sync_quotes(uuid, bigint, jsonb, uuid, text), public.checked_import(uuid, bigint, jsonb, uuid, text), public.edit_quote(uuid, uuid, text, text, date, uuid, text), public.edit_quotes(uuid, jsonb, uuid, text), public.list_members(uuid, text), public.add_member(text, uuid, text), public.remove_member_access(uuid, uuid, text) to authenticated;

commit;
