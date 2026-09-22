-- Administrative corrections are serialized with sync/import and preserve all
-- quote metadata other than its encrypted text and visible date.
begin;

create or replace function public.edit_quote(
  p_generation uuid,
  p_quote_id uuid,
  p_expected_text text,
  p_text text,
  p_quote_date date
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $edit$
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
$edit$;

create or replace function public.edit_quotes(
  p_generation uuid,
  p_edits jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $edits$
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
$edits$;

revoke all on function public.edit_quote(uuid, uuid, text, text, date) from public, anon, authenticated;
grant execute on function public.edit_quote(uuid, uuid, text, text, date) to authenticated;
revoke all on function public.edit_quotes(uuid, jsonb) from public, anon, authenticated;
grant execute on function public.edit_quotes(uuid, jsonb) to authenticated;

commit;
