-- Atomic, revision-checked encrypted imports. Source identifiers remain inside
-- the encrypted quote payload; this RPC persists only normal quote ciphertext
-- and existing operation receipts.
begin;

create or replace function public.checked_import(
  p_generation uuid,
  p_revision bigint,
  p_operations jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $import$
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
$import$;

revoke all on function public.checked_import(uuid, bigint, jsonb) from public, anon, authenticated;
grant execute on function public.checked_import(uuid, bigint, jsonb) to authenticated;

commit;
