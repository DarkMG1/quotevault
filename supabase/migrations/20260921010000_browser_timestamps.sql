-- PostgreSQL normalizes leap seconds; JavaScript dates reject them.
-- Keep this additive: the earlier hardening migration is already deployed.
begin;

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
      and p_quote->>'created_at' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]{1,3})?Z$') is not true then
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

commit;
