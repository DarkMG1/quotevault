-- Additive hardening for the deployed secure-vault migration.
-- Apply as one transaction, after 20260920000000_secure_vault.sql.

begin;

-- The administrator must remain a member so the vault gate cannot hide the
-- only administration UI. Other allowlist rows retain the existing RLS rules.
create or replace function public.qv_protect_administrator_allowlist()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $hardening$
begin
  if lower(old.email) = 'darkmgdevelopment@gmail.com' and tg_op = 'DELETE' then
    raise exception 'The configured administrator must remain allowlisted' using errcode = '23514';
  end if;
  if lower(old.email) = 'darkmgdevelopment@gmail.com'
     and lower(new.email) is distinct from lower(old.email) then
    raise exception 'The configured administrator must remain allowlisted' using errcode = '23514';
  end if;
  return coalesce(new, old);
end;
$hardening$;

drop trigger if exists qv_protect_administrator_allowlist on public.allowlist;
create trigger qv_protect_administrator_allowlist
before update or delete on public.allowlist
for each row execute function public.qv_protect_administrator_allowlist();

-- Legacy verifier discovery keeps its 10 MiB compatibility ceiling. New quote
-- ciphertext is limited to 256 KiB base64, and a sync request to 1 MiB total.
create or replace function public.qv_valid_quote(p_quote jsonb, p_actor uuid, p_generation uuid)
returns boolean
language plpgsql
immutable
set search_path = public, pg_temp
as $quote_validator$
declare
  cipher jsonb;
  created_at_value timestamptz;
begin
  if (jsonb_typeof(p_quote) = 'object'
      and jsonb_typeof(p_quote->'id') = 'string'
      and jsonb_typeof(p_quote->'text') = 'string'
      and jsonb_typeof(p_quote->'author') = 'string'
      and jsonb_typeof(p_quote->'created_at') = 'string'
      and jsonb_typeof(p_quote->'user_id') = 'string'
      and jsonb_typeof(p_quote->'vault_generation') = 'string'
      and (jsonb_typeof(p_quote->'context') in ('string', 'null') or not p_quote ? 'context')
      and (jsonb_typeof(p_quote->'quote_date') = 'null'
           or not p_quote ? 'quote_date'
           or (jsonb_typeof(p_quote->'quote_date') = 'string'
               and p_quote->>'quote_date' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'))
      and p_quote->>'id' ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'
      and p_quote->>'user_id' = p_actor::text
      and p_quote->>'vault_generation' = p_generation::text
      and p_quote->>'author' = 'ENCRYPTED'
      and (p_quote->>'context' = 'ENCRYPTED' or p_quote->>'context' is null)
      and left(p_quote->>'text', 7) = '$$E2E$$'
      -- Browser-created quotes use Date.prototype.toISOString().
      and p_quote->>'created_at' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,3})?Z$') is not true then
    return false;
  end if;

  cipher := substring(p_quote->>'text' from 8)::jsonb;
  if public.qv_valid_verifier(cipher) is not true
     or length(cipher->>'data') > 262144 then
    return false;
  end if;
  if p_quote->>'quote_date' is not null then
    perform (p_quote->>'quote_date')::date;
  end if;
  created_at_value := (p_quote->>'created_at')::timestamptz;
  return isfinite(created_at_value);
exception when invalid_text_representation or invalid_datetime_format or datetime_field_overflow then
  return false;
end;
$quote_validator$;

create or replace function public.sync_quotes(
  p_generation uuid,
  p_revision bigint,
  p_operations jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $sync$
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
$sync$;

create or replace function public.rotate_vault(
  p_expected_generation uuid,
  p_kdf jsonb,
  p_verifier jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $rotate$
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
$rotate$;

revoke all on function public.qv_protect_administrator_allowlist() from public, anon, authenticated;

-- Private-channel authorization is evaluated against this SELECT policy on
-- connection. No INSERT policy is granted, so clients cannot forge a reset.
do $realtime_auth$
begin
  if to_regclass('realtime.messages') is not null then
    execute 'drop policy if exists qv_member_vault_generation_broadcast on realtime.messages';
    execute $policy$
      create policy qv_member_vault_generation_broadcast on realtime.messages
      for select to authenticated
      using (
        realtime.messages.extension = 'broadcast'
        and realtime.messages.topic = 'quotevault-sync'
        and (select realtime.topic()) = 'quotevault-sync'
        and (select public.qv_is_member())
      )
    $policy$;
  end if;
end;
$realtime_auth$;

commit;
