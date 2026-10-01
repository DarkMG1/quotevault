-- Remove device-envelope encryption and return the database to the shared-key schema
-- that existed after 20260922010000_admin_quote_edit.sql.
--
-- Generated from the catalogs of two local databases and verified so that applying
-- every migration plus this one yields a public schema identical to the pre-envelope
-- one (tables, columns, constraints, indexes, functions, privileges, RLS policies,
-- triggers, realtime publication). No quote, profile, allowlist or vault_state row is
-- modified. Device, recovery, migration, rollback and reversion records are deleted.
--
-- Deliberately untouched: pgcrypto (pre-existing in production), service_role grants,
-- and objects outside public (auth triggers and realtime policies depend only on
-- functions this file replaces in place, never drops). Safe to reapply after itself.
begin;

-- 1. Stop the rollback purge job created for envelope migrations.
do $cron$ begin if to_regnamespace('cron') is not null and exists(select 1 from pg_extension where extname='pg_cron') then
  perform cron.unschedule(jobid) from cron.job where jobname = 'quotevault-purge-expired-vault-rollback';
end if; end $cron$;
-- 2. Policies on pre-envelope tables that the envelope migrations added or changed.
drop policy if exists qv_admin_allowlist_delete on public.allowlist;
drop policy if exists qv_admin_allowlist_insert on public.allowlist;
drop policy if exists qv_admin_allowlist_select on public.allowlist;
drop policy if exists qv_admin_allowlist_update on public.allowlist;
drop policy if exists qv_member_quotes_select on public.quotes;
-- 3. Triggers on pre-envelope tables that the envelope migrations added or changed.
-- 4. Envelope tables (device, recovery, migration, rollback and reversion records).
drop table if exists public.vault_device_wrappers cascade;
drop table if exists public.vault_devices cascade;
drop table if exists public.vault_legacy_reversion_rows cascade;
drop table if exists public.vault_legacy_reversions cascade;
drop table if exists public.vault_migration_queue_reports cascade;
drop table if exists public.vault_migration_quote_copies cascade;
drop table if exists public.vault_migrations cascade;
drop table if exists public.vault_recovery_challenges cascade;
drop table if exists public.vault_recovery_keys cascade;
drop table if exists public.vault_recovery_wrappers cascade;
drop table if exists public.vault_security_events cascade;
-- 5. Envelope columns and constraints on pre-envelope tables.
alter table public.vault_state drop column if exists active_migration_id;
alter table public.vault_state drop column if exists envelope_status;
alter table public.vault_state drop column if exists prepared_generation;
alter table public.vault_state drop constraint if exists vault_state_active_migration_id_fkey;
alter table public.vault_state drop constraint if exists vault_state_envelope_status_check;
-- 6. Envelope-only functions (exact signatures; nothing outside public depends on them).
drop function if exists public.abandon_envelope_migration(uuid,uuid,text);
drop function if exists public.ack_conversion_queue(uuid,uuid,text);
drop function if exists public.activate_envelope_migration(uuid,uuid,text);
drop function if exists public.activate_recovered_device(uuid,text,uuid,text,uuid,text);
drop function if exists public.add_member(text,uuid,text);
drop function if exists public.approve_device(uuid,uuid,text,text,text,uuid,uuid,text);
drop function if exists public.attest_vault_keys(uuid,text,uuid,jsonb,jsonb);
drop function if exists public.begin_legacy_reversion(uuid,bigint,uuid,text);
drop function if exists public.begin_recovery(uuid);
drop function if exists public.checked_import(uuid,bigint,jsonb,uuid,text);
drop function if exists public.commit_legacy_reversion(uuid,jsonb,jsonb,uuid,text);
drop function if exists public.complete_device(uuid,text,uuid);
drop function if exists public.complete_recovery(uuid,text);
drop function if exists public.create_recovery_key(uuid,jsonb,text,jsonb,jsonb,uuid,text,uuid,text);
drop function if exists public.edit_quote(uuid,uuid,text,text,date,uuid,text);
drop function if exists public.edit_quotes(uuid,jsonb,uuid,text);
drop function if exists public.finalize_envelope_migration(uuid,uuid,text);
drop function if exists public.get_conversion_wrapper(uuid,uuid,text);
drop function if exists public.get_device_request(uuid);
drop function if exists public.get_envelope_migration_coverage(uuid,uuid,text);
drop function if exists public.get_envelope_migration_snapshot(uuid,uuid,text);
drop function if exists public.get_passkey_restore_devices();
drop function if exists public.get_pending_envelope_migration(uuid,text);
drop function if exists public.get_vault_bootstrap_state();
drop function if exists public.get_vault_state(uuid,text);
drop function if exists public.list_members(uuid,text);
drop function if exists public.list_own_devices();
drop function if exists public.prepare_envelope_migration(uuid,bigint,uuid,text,uuid,jsonb);
drop function if exists public.purge_expired_vault_rollback();
drop function if exists public.qv_add_member_preparing_gate(text,uuid,text);
drop function if exists public.qv_approve_device_preparing_gate(uuid,uuid,text,text,text,uuid,uuid,text);
drop function if exists public.qv_authorize_device(uuid,text,uuid,text);
drop function if exists public.qv_base64url_bytes(text,integer);
drop function if exists public.qv_checked_import_legacy(uuid,bigint,jsonb);
drop function if exists public.qv_checked_import_preparing_gate(uuid,bigint,jsonb,uuid,text);
drop function if exists public.qv_conversion_source_in_lineage(uuid,uuid);
drop function if exists public.qv_edit_quote_legacy(uuid,uuid,text,text,date);
drop function if exists public.qv_edit_quote_preparing_gate(uuid,uuid,text,text,date,uuid,text);
drop function if exists public.qv_edit_quotes_legacy(uuid,jsonb);
drop function if exists public.qv_edit_quotes_preparing_gate(uuid,jsonb,uuid,text);
drop function if exists public.qv_envelope_legacy_mode();
drop function if exists public.qv_get_vault_state_legacy();
drop function if exists public.qv_legacy_v1_text(text);
drop function if exists public.qv_list_members_preparing_gate(uuid,text);
drop function if exists public.qv_migration_device_ok(uuid,text,vault_state);
drop function if exists public.qv_migration_enrollment_ready(vault_migrations);
drop function if exists public.qv_migration_ready(vault_migrations);
drop function if exists public.qv_public_key_fingerprint(jsonb);
drop function if exists public.qv_reject_maintenance_device_mutation();
drop function if exists public.qv_remove_member_preparing_gate(uuid,uuid,text,boolean,uuid,jsonb);
drop function if exists public.qv_reversion_authorized(vault_state,uuid,text);
drop function if exists public.qv_rotate_vault_legacy(uuid,jsonb,jsonb);
drop function if exists public.qv_sync_quotes_legacy(uuid,bigint,jsonb);
drop function if exists public.qv_valid_device_protection(text,jsonb);
drop function if exists public.qv_valid_encrypted_bundle(jsonb);
drop function if exists public.qv_valid_migration_copy(jsonb);
drop function if exists public.qv_valid_migration_v2_quote(jsonb,uuid);
drop function if exists public.qv_valid_public_jwk(jsonb);
drop function if exists public.qv_valid_recovery_kdf(jsonb);
drop function if exists public.refresh_envelope_migration_source(uuid,bigint,uuid,text);
drop function if exists public.remove_member_access(uuid,uuid,text,boolean,uuid,jsonb);
drop function if exists public.renew_device_lease(uuid,text);
drop function if exists public.replace_recovery_key(uuid,jsonb,text,jsonb,jsonb,uuid,text,uuid,text);
drop function if exists public.report_envelope_migration_empty_queue(uuid,bigint,uuid,text);
drop function if exists public.request_device(uuid,uuid,text,jsonb,text,text,text,text,jsonb,jsonb,text);
drop function if exists public.revoke_own_device(uuid,text,uuid);
drop function if exists public.rollback_envelope_migration(uuid,uuid,text);
drop function if exists public.stage_envelope_quotes(uuid,uuid,text,jsonb);
drop function if exists public.stage_envelope_wrappers(uuid,uuid,text,jsonb,jsonb);
drop function if exists public.stage_legacy_reversion(uuid,jsonb,uuid,text);
drop function if exists public.sync_quotes(uuid,bigint,jsonb,uuid,text);
drop function if exists public.verify_member_session_invalidation(uuid);
-- 7. Restore pre-envelope function definitions (create or replace keeps dependents such as auth triggers and realtime policies).
CREATE OR REPLACE FUNCTION public.checked_import(p_generation uuid, p_revision bigint, p_operations jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
declare
  state public.vault_state%rowtype;
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
  if public.qv_is_member() is not true then
    raise exception 'QuoteVault membership is required' using errcode = '42501';
  end if;
  if p_revision is null or p_revision < 0 then
    raise exception 'Invalid import request' using errcode = '22023';
  end if;
  if jsonb_typeof(p_operations) is distinct from 'array' then
    raise exception 'Invalid import request' using errcode = '22023';
  end if;
  operation_count := jsonb_array_length(p_operations);
  if operation_count not between 1 and 500 or octet_length(p_operations::text) > 921600 then
    raise exception 'Invalid import request' using errcode = '22023';
  end if;

  for op in select value from jsonb_array_elements(p_operations) loop
    operation_id := lower(op->>'operation_id');
    quote_id := lower(op->>'quote_id');
    if (jsonb_typeof(op) = 'object'
        and operation_id ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'
        and quote_id ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'
        and op->>'action' = 'INSERT'
        and op->>'actor_id' = caller_id::text
        and op->>'vault_generation' = p_generation::text
        and not operation_id = any(seen_operations)
        and not quote_id = any(seen_quotes)) is not true then
      raise exception 'Invalid import request' using errcode = '22023';
    end if;
    seen_operations := array_append(seen_operations, operation_id);
    seen_quotes := array_append(seen_quotes, quote_id);
  end loop;

  -- This is the same row lock used by sync_quotes. It serializes an import
  -- against ordinary sync without another lock primitive or schema object.
  select * into state from public.vault_state where singleton for update;
  if p_generation is distinct from state.generation then
    raise exception 'Vault generation changed; refresh before importing' using errcode = '40001';
  end if;

  for op in select value from jsonb_array_elements(p_operations) loop
    digest_text := encode(sha256(convert_to(op::text, 'UTF8')), 'hex');
    select * into receipt
    from public.vault_operation_receipts
    where vault_operation_receipts.operation_id = (op->>'operation_id')::uuid
      and vault_operation_receipts.actor_id = caller_id;
    if not found or receipt.generation <> state.generation
       or receipt.request_digest <> digest_text or receipt.result->>'status' is distinct from 'ok' then
      all_receipted := false;
      exit;
    end if;
  end loop;
  if p_revision is distinct from state.revision and not all_receipted then
    raise exception 'Vault changed; refresh and review the import again' using errcode = '40001';
  end if;

  for batch_offset in 0..((operation_count - 1) / 50) loop
    select jsonb_agg(value order by ordinal) into batch
    from jsonb_array_elements(p_operations) with ordinality as entries(value, ordinal)
    where ordinal > batch_offset * 50 and ordinal <= (batch_offset + 1) * 50;
    response := public.sync_quotes(p_generation, null, batch);
    if jsonb_typeof(response->'results') is distinct from 'array'
       or jsonb_array_length(response->'results') <> jsonb_array_length(batch)
       or exists (
         select 1 from jsonb_array_elements(response->'results') result
         where result->>'status' is distinct from 'ok'
       ) then
      raise exception 'Import rejected; no quotes were added' using errcode = '22023';
    end if;
    results := results || (response->'results');
  end loop;

  return jsonb_build_object(
    'generation', response->'generation',
    'revision', response->'revision',
    'results', results,
    'quotes', response->'quotes'
  );
end;
$function$;
CREATE OR REPLACE FUNCTION public.edit_quote(p_generation uuid, p_quote_id uuid, p_expected_text text, p_text text, p_quote_date date)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
declare
  state public.vault_state%rowtype;
  quote public.quotes%rowtype;
  payload jsonb;
begin
  if public.qv_is_admin() is not true or public.qv_is_member() is not true then
    raise exception 'QuoteVault administrator membership is required' using errcode = '42501';
  end if;

  select * into state from public.vault_state where singleton for update;
  if p_generation is null or p_generation is distinct from state.generation then
    raise exception 'Vault generation changed; reload before editing' using errcode = '40001';
  end if;

  select * into quote
  from public.quotes
  where id = p_quote_id and vault_generation = state.generation
  for update;
  if not found then
    raise exception 'Quote not found in the current vault generation' using errcode = 'P0002';
  end if;
  if p_expected_text is distinct from quote.text then
    raise exception 'Quote changed; reload before editing' using errcode = '40001';
  end if;

  payload := jsonb_build_object(
    'id', quote.id,
    'text', p_text,
    'author', quote.author,
    'context', quote.context,
    'quote_date', p_quote_date,
    'created_at', to_char(quote.created_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'user_id', quote.user_id,
    'vault_generation', quote.vault_generation
  );
  if public.qv_valid_quote(payload, quote.user_id, state.generation) is not true then
    raise exception 'Invalid encrypted quote' using errcode = '22023';
  end if;

  update public.quotes
  set text = p_text,
      quote_date = p_quote_date
  where id = quote.id
  returning to_jsonb(public.quotes.*) into payload;
  return payload;
end;
$function$;
CREATE OR REPLACE FUNCTION public.edit_quotes(p_generation uuid, p_edits jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
declare
  edit jsonb;
  quote_id_text text;
  seen_quote_ids text[] := array[]::text[];
begin
  if public.qv_is_admin() is not true or public.qv_is_member() is not true then
    raise exception 'QuoteVault administrator membership is required' using errcode = '42501';
  end if;
  if jsonb_typeof(p_edits) is distinct from 'array' then
    raise exception 'Invalid edit batch' using errcode = '22023';
  end if;
  if jsonb_array_length(p_edits) not between 1 and 500
     or octet_length(p_edits::text) > 921600 then
    raise exception 'Invalid edit batch' using errcode = '22023';
  end if;

  for edit in select value from jsonb_array_elements(p_edits) loop
    if jsonb_typeof(edit) is distinct from 'object' then
      raise exception 'Invalid edit batch' using errcode = '22023';
    end if;
    if not edit ?& array['quote_id', 'expected_text', 'text', 'quote_date']
       or exists (
         select 1 from jsonb_object_keys(edit) key
         where key not in ('quote_id', 'expected_text', 'text', 'quote_date')
       ) then
      raise exception 'Invalid edit batch' using errcode = '22023';
    end if;
    if jsonb_typeof(edit->'quote_id') <> 'string'
       or jsonb_typeof(edit->'expected_text') <> 'string'
       or jsonb_typeof(edit->'text') <> 'string'
       or jsonb_typeof(edit->'quote_date') not in ('string', 'null') then
      raise exception 'Invalid edit batch' using errcode = '22023';
    end if;
    quote_id_text := edit->>'quote_id';
    if quote_id_text !~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'
       or lower(quote_id_text) = any(seen_quote_ids) then
      raise exception 'Invalid edit batch' using errcode = '22023';
    end if;
    begin
      if edit->>'quote_date' is not null then
        perform (edit->>'quote_date')::date;
      end if;
    exception when invalid_text_representation or invalid_datetime_format or datetime_field_overflow then
      raise exception 'Invalid edit batch' using errcode = '22023';
    end;
    seen_quote_ids := array_append(seen_quote_ids, lower(quote_id_text));
  end loop;

  -- The same singleton lock used by sync/import is held for the whole batch.
  perform 1 from public.vault_state where singleton for update;
  for edit in select value from jsonb_array_elements(p_edits) loop
    perform public.edit_quote(
      p_generation,
      (edit->>'quote_id')::uuid,
      edit->>'expected_text',
      edit->>'text',
      (edit->>'quote_date')::date
    );
  end loop;
  return jsonb_build_object('updated', jsonb_array_length(p_edits));
end;
$function$;
CREATE OR REPLACE FUNCTION public.get_vault_state()
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
declare
  state public.vault_state%rowtype;
begin
  if not public.qv_is_member() then
    raise exception 'QuoteVault membership is required' using errcode = '42501';
  end if;
  select * into state from public.vault_state where singleton;
  return jsonb_build_object(
    'generation', state.generation,
    'kdf', state.kdf,
    'verifier', state.verifier,
    'legacy_generation', state.legacy_generation
  );
end;
$function$;
CREATE OR REPLACE FUNCTION public.rotate_vault(p_expected_generation uuid, p_kdf jsonb, p_verifier jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
declare
  state public.vault_state%rowtype;
begin
  if public.qv_is_admin() is not true then
    raise exception 'QuoteVault administrator access is required' using errcode = '42501';
  end if;
  if public.qv_valid_kdf(p_kdf) is not true or public.qv_valid_verifier(p_verifier) is not true then
    raise exception 'Invalid vault cryptography metadata' using errcode = '22023';
  end if;
  select * into state from public.vault_state where singleton for update;
  if p_expected_generation is null or state.generation is distinct from p_expected_generation then
    raise exception 'Vault generation changed; reload before rotating' using errcode = '40001';
  end if;
  delete from public.vault_operation_receipts;
  delete from public.quotes;
  update public.vault_state
  set generation = gen_random_uuid(),
      revision = revision + 1,
      kdf = jsonb_build_object('salt', p_kdf->>'salt', 'iterations', (p_kdf->>'iterations')::integer),
      verifier = jsonb_build_object('iv', p_verifier->>'iv', 'data', p_verifier->>'data'),
      legacy_generation = null
  where singleton
  returning * into state;
  -- A private Broadcast tells active members to refresh. It contains only the
  -- generation UUID; get_vault_state remains the metadata authority.
  if to_regprocedure('realtime.send(jsonb,text,text,boolean)') is not null then
    perform realtime.send(
      jsonb_build_object('generation', state.generation),
      'vault-generation',
      'quotevault-sync',
      true
    );
  end if;
  return jsonb_build_object(
    'generation', state.generation, 'revision', state.revision,
    'kdf', state.kdf, 'verifier', state.verifier, 'legacy_generation', state.legacy_generation
  );
end;
$function$;
CREATE OR REPLACE FUNCTION public.sync_quotes(p_generation uuid, p_revision bigint, p_operations jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
declare
  state public.vault_state%rowtype;
  op jsonb;
  op_id uuid;
  quote_id uuid;
  op_id_text text;
  quote_id_text text;
  action text;
  caller_id uuid := auth.uid();
  owner_id uuid;
  digest_text text;
  receipt public.vault_operation_receipts%rowtype;
  result jsonb;
  results jsonb := '[]'::jsonb;
  changed boolean := false;
  valid_operation boolean;
  rows_deleted integer;
begin
  if not public.qv_is_member() then
    raise exception 'QuoteVault membership is required' using errcode = '42501';
  end if;
  if ((p_revision is null or p_revision >= 0)
      and jsonb_typeof(p_operations) = 'array'
      and jsonb_array_length(p_operations) <= 50
      and octet_length(p_operations::text) <= 1048576) is not true then
    raise exception 'Invalid sync request' using errcode = '22023';
  end if;

  select * into state from public.vault_state where singleton for update;
  if p_generation is distinct from state.generation then
    for op in select value from jsonb_array_elements(p_operations) loop
      results := results || jsonb_build_array(jsonb_build_object(
        'operation_id', op->>'operation_id', 'status', 'rejected', 'error', 'stale vault generation'
      ));
    end loop;
    return jsonb_build_object(
      'generation', state.generation,
      'revision', state.revision,
      'results', results,
      'quotes', (select coalesce(jsonb_agg(to_jsonb(q) order by q.created_at, q.id), '[]'::jsonb) from public.quotes q)
    );
  end if;

  for op in select value from jsonb_array_elements(p_operations) loop
    op_id_text := op->>'operation_id';
    quote_id_text := op->>'quote_id';
    action := op->>'action';
    valid_operation := jsonb_typeof(op) = 'object'
      and op_id_text ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'
      and quote_id_text ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'
      and action in ('INSERT', 'DELETE')
      and op->>'actor_id' = caller_id::text
      and op->>'vault_generation' = state.generation::text;

    if valid_operation is not true then
      results := results || jsonb_build_array(jsonb_build_object(
        'operation_id', op_id_text, 'status', 'rejected', 'error', 'invalid operation'
      ));
      continue;
    end if;

    op_id := op_id_text::uuid;
    quote_id := quote_id_text::uuid;
    digest_text := encode(sha256(convert_to(op::text, 'UTF8')), 'hex');
    select * into receipt
    from public.vault_operation_receipts
    where vault_operation_receipts.operation_id = op_id
      and vault_operation_receipts.actor_id = caller_id;

    if found then
      if receipt.generation = state.generation and receipt.request_digest = digest_text then
        results := results || jsonb_build_array(receipt.result);
      else
        results := results || jsonb_build_array(jsonb_build_object(
          'operation_id', op_id, 'status', 'rejected', 'error', 'operation id already used'
        ));
      end if;
      continue;
    end if;

    result := null;
    begin
      if action = 'INSERT' then
        if (op->>'quote_id' = op->'payload'->>'id') is not true
           or public.qv_valid_quote(op->'payload', caller_id, state.generation) is not true then
          result := jsonb_build_object('operation_id', op_id, 'status', 'rejected', 'error', 'invalid encrypted quote');
        else
          insert into public.quotes (id, text, author, context, quote_date, created_at, user_id, vault_generation)
          values (
            quote_id,
            op->'payload'->>'text',
            op->'payload'->>'author',
            op->'payload'->>'context',
            (op->'payload'->>'quote_date')::date,
            (op->'payload'->>'created_at')::timestamptz,
            caller_id,
            state.generation
          );
          result := jsonb_build_object('operation_id', op_id, 'status', 'ok');
          changed := true;
        end if;
      else
        select user_id into owner_id from public.quotes where id = quote_id for update;
        if found and owner_id is distinct from caller_id and public.qv_is_admin() is not true then
          result := jsonb_build_object('operation_id', op_id, 'status', 'rejected', 'error', 'only the creator or admin may delete this quote');
        else
          delete from public.quotes where id = quote_id;
          get diagnostics rows_deleted = row_count;
          result := jsonb_build_object('operation_id', op_id, 'status', 'ok');
          changed := changed or rows_deleted > 0;
        end if;
      end if;
    exception
      when unique_violation or check_violation or not_null_violation or foreign_key_violation or string_data_right_truncation then
        result := jsonb_build_object('operation_id', op_id, 'status', 'rejected', 'error', 'operation violates vault data constraints');
    end;

    insert into public.vault_operation_receipts (operation_id, actor_id, generation, request_digest, result)
    values (op_id, caller_id, state.generation, digest_text, result);
    results := results || jsonb_build_array(result);
  end loop;

  select * into state from public.vault_state where singleton;
  return jsonb_build_object(
    'generation', state.generation,
    'revision', state.revision,
    'results', results,
    'quotes', case when changed or p_revision is distinct from state.revision then
      (select coalesce(jsonb_agg(to_jsonb(q) order by q.created_at, q.id), '[]'::jsonb) from public.quotes q)
    else null end
  );
end;
$function$;
-- 8. Function privileges for anon, authenticated and PUBLIC exactly as before.
revoke all on function public.checked_import(uuid,bigint,jsonb) from public, anon, authenticated;
grant execute on function public.checked_import(uuid,bigint,jsonb) to authenticated;
revoke all on function public.edit_quote(uuid,uuid,text,text,date) from public, anon, authenticated;
grant execute on function public.edit_quote(uuid,uuid,text,text,date) to authenticated;
revoke all on function public.edit_quotes(uuid,jsonb) from public, anon, authenticated;
grant execute on function public.edit_quotes(uuid,jsonb) to authenticated;
revoke all on function public.get_vault_state() from public, anon, authenticated;
grant execute on function public.get_vault_state() to authenticated;
revoke all on function public.rotate_vault(uuid,jsonb,jsonb) from public, anon, authenticated;
grant execute on function public.rotate_vault(uuid,jsonb,jsonb) to authenticated;
revoke all on function public.sync_quotes(uuid,bigint,jsonb) from public, anon, authenticated;
grant execute on function public.sync_quotes(uuid,bigint,jsonb) to authenticated;
-- 9. Pre-envelope policies, triggers, RLS flags and table privileges.
drop policy if exists qv_admin_allowlist_delete on public.allowlist;
create policy qv_admin_allowlist_delete on public.allowlist as permissive for delete to authenticated using (qv_is_admin());
drop policy if exists qv_admin_allowlist_insert on public.allowlist;
create policy qv_admin_allowlist_insert on public.allowlist as permissive for insert to authenticated with check (qv_is_admin());
drop policy if exists qv_admin_allowlist_select on public.allowlist;
create policy qv_admin_allowlist_select on public.allowlist as permissive for select to authenticated using (qv_is_admin());
drop policy if exists qv_admin_allowlist_update on public.allowlist;
create policy qv_admin_allowlist_update on public.allowlist as permissive for update to authenticated using (qv_is_admin()) with check (qv_is_admin());
drop policy if exists qv_member_quotes_select on public.quotes;
create policy qv_member_quotes_select on public.quotes as permissive for select to authenticated using (qv_is_member());
-- 10. Instant cross-device updates for the shared-key client.
do $publication$ begin if exists(select 1 from pg_publication where pubname = 'supabase_realtime')
  and not exists(select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'quotes') then
  execute 'alter publication supabase_realtime add table public.quotes';
end if; end $publication$;

commit;
