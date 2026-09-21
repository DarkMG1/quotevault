-- Checked encrypted imports run only against a disposable local database.
begin;

insert into public.allowlist(id,email,created_at) values
 ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','darkmgdevelopment@gmail.com',now()),
 ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','import-member@example.invalid',now());
insert into auth.users(instance_id,id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at) values
 ('00000000-0000-0000-0000-000000000000','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','authenticated','authenticated','darkmgdevelopment@gmail.com','not-used',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000000','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','authenticated','authenticated','import-member@example.invalid','not-used',now(),'{}','{}',now(),now());

-- Owner access lets this test inspect receipts; checked_import itself still
-- authenticates through auth.uid(), which is set to the member below.
set local role none;
select set_config('request.jwt.claim.sub','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',true);

do $test$
declare
  actor uuid := 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  generation uuid := (select generation from public.vault_state where singleton);
  revision bigint := (select vault_state.revision from public.vault_state where singleton);
  operations jsonb := '[]'::jsonb;
  late_operations jsonb := '[]'::jsonb;
  replay_op jsonb;
  fresh_op jsonb;
  response jsonb;
  i integer;
  operation_uuid uuid;
  quote_uuid uuid;
  stale_generation uuid;
  created text := to_char(clock_timestamp(), 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  prior_quotes integer;
  prior_receipts integer;
begin
  -- The wrapper must bridge sync_quotes' 50-operation cap atomically.
  for i in 1..51 loop
    operation_uuid := gen_random_uuid();
    quote_uuid := gen_random_uuid();
    operations := operations || jsonb_build_array(jsonb_build_object(
      'operation_id', operation_uuid, 'action', 'INSERT', 'quote_id', quote_uuid,
      'actor_id', actor, 'vault_generation', generation,
      'payload', jsonb_build_object('id', quote_uuid,
        'text', '$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}',
        'author', 'ENCRYPTED', 'context', 'ENCRYPTED', 'quote_date', null,
        'created_at', created, 'user_id', actor, 'vault_generation', generation)
    ));
  end loop;
  response := public.checked_import(generation, revision, operations);
  if jsonb_array_length(response->'results') <> 51
     or (select count(*) from public.quotes) <> 51
     or (select count(*) from public.vault_operation_receipts) <> 51 then
    raise exception 'checked import did not commit all 51 encrypted rows';
  end if;

  -- A failing second internal batch rolls back the first batch and its receipts.
  revision := (select vault_state.revision from public.vault_state where singleton);
  prior_quotes := (select count(*) from public.quotes);
  prior_receipts := (select count(*) from public.vault_operation_receipts);
  for i in 1..51 loop
    operation_uuid := gen_random_uuid();
    quote_uuid := gen_random_uuid();
    late_operations := late_operations || jsonb_build_array(jsonb_build_object(
      'operation_id', operation_uuid, 'action', 'INSERT', 'quote_id', quote_uuid,
      'actor_id', actor, 'vault_generation', generation,
      'payload', jsonb_build_object('id', quote_uuid,
        'text', case when i = 51 then 'not encrypted' else '$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}' end,
        'author', 'ENCRYPTED', 'context', 'ENCRYPTED', 'quote_date', null,
        'created_at', created, 'user_id', actor, 'vault_generation', generation)
    ));
  end loop;
  begin
    perform public.checked_import(generation, revision, late_operations);
    raise exception 'late invalid encrypted operation was accepted';
  exception when invalid_parameter_value then null;
  end;
  if (select count(*) from public.quotes) <> prior_quotes
     or (select count(*) from public.vault_operation_receipts) <> prior_receipts then
    raise exception 'failed import left partial quotes or receipts';
  end if;

  begin
    perform public.checked_import(generation, (select vault_state.revision from public.vault_state where singleton),
      jsonb_build_array(operations->0, operations->0));
    raise exception 'duplicate operation IDs were accepted';
  exception when invalid_parameter_value then null;
  end;
  begin
    perform public.checked_import(generation, (select vault_state.revision from public.vault_state where singleton), null);
    raise exception 'NULL import operations were accepted';
  exception when invalid_parameter_value then null;
  end;

  replay_op := jsonb_build_object(
    'operation_id', gen_random_uuid(), 'action', 'INSERT', 'quote_id', gen_random_uuid(),
    'actor_id', actor, 'vault_generation', generation,
    'payload', jsonb_build_object('id', gen_random_uuid(),
      'text', '$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}',
      'author', 'ENCRYPTED', 'context', 'ENCRYPTED', 'quote_date', null,
      'created_at', created, 'user_id', actor, 'vault_generation', generation)
  );
  replay_op := jsonb_set(replay_op, '{payload,id}', replay_op->'quote_id');
  revision := (select vault_state.revision from public.vault_state where singleton);
  response := public.checked_import(generation, revision, jsonb_build_array(replay_op));
  if response->'results'->0->>'status' <> 'ok' then raise exception 'valid import was rejected'; end if;
  -- A lost response can be retried after the revision changed only with the exact body.
  response := public.checked_import(generation, revision, jsonb_build_array(replay_op));
  if response->'results'->0->>'status' <> 'ok' or (select count(*) from public.quotes) <> prior_quotes + 1 then
    raise exception 'exact receipt retry was not idempotent';
  end if;
  begin
    perform public.checked_import(generation, revision,
      jsonb_build_array(jsonb_set(replay_op, '{payload,text}',
        to_jsonb('$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"BBBBBBBBBBBBBBBBBBBBBB=="}'::text))));
    raise exception 'changed receipt body was accepted';
  exception when serialization_failure then null;
  end;

  stale_generation := gen_random_uuid();
  begin
    perform public.checked_import(stale_generation, (select vault_state.revision from public.vault_state where singleton),
      jsonb_build_array(jsonb_set(operations->0, '{vault_generation}', to_jsonb(stale_generation::text))));
    raise exception 'stale generation import was accepted';
  exception when serialization_failure then null;
  end;
  fresh_op := jsonb_build_object(
    'operation_id', gen_random_uuid(), 'action', 'INSERT', 'quote_id', gen_random_uuid(),
    'actor_id', actor, 'vault_generation', generation,
    'payload', jsonb_build_object('id', gen_random_uuid(),
      'text', '$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}',
      'author', 'ENCRYPTED', 'context', 'ENCRYPTED', 'quote_date', null,
      'created_at', created, 'user_id', actor, 'vault_generation', generation)
  );
  fresh_op := jsonb_set(fresh_op, '{payload,id}', fresh_op->'quote_id');
  begin
    perform public.checked_import(generation, 0, jsonb_build_array(fresh_op));
    raise exception 'stale revision import was accepted';
  exception when serialization_failure then null;
  end;
  if exists (select 1 from public.quotes where left(text, 7) <> '$$E2E$$')
     or exists (select 1 from public.vault_operation_receipts where request_digest !~ '^[0-9a-f]{64}$') then
    raise exception 'import stored plaintext request data';
  end if;
end;
$test$;

reset role;
set local role authenticated;
select set_config('request.jwt.claim.sub','cccccccc-cccc-4ccc-8ccc-cccccccccccc',true);
do $auth$
begin
  begin
    perform public.checked_import(gen_random_uuid(), 0, '[]'::jsonb);
    raise exception 'non-member import was accepted';
  exception when insufficient_privilege then null;
  end;
end;
$auth$;
reset role;

do $grants$
begin
  if has_function_privilege('anon', 'public.checked_import(uuid,bigint,jsonb)', 'EXECUTE') then
    raise exception 'anonymous checked import execution was granted';
  end if;
end;
$grants$;

rollback;
