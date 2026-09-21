-- Disposable empty database only; all fixture data and DDL roll back.
begin;
do $$ begin
  if exists(select 1 from pg_proc p join pg_namespace n on n.oid=p.pronamespace
      where n.nspname='public' and (p.proname like 'qv_%' or p.proname in ('get_vault_state','sync_quotes','rotate_vault','initialize_vault'))
        and has_function_privilege('anon',p.oid,'EXECUTE')) then
    raise exception 'Supabase default function grants still permit anonymous execution';
  end if;
  if exists (select 1 from public.quotes) or exists (select 1 from auth.users) then
    raise exception 'Use an empty disposable database for this test';
  end if;
end $$;

insert into public.allowlist(id,email,created_at) values
 ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','darkmgdevelopment@gmail.com',now()),
 ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','member@example.invalid',now());
insert into auth.users(instance_id,id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at) values
 ('00000000-0000-0000-0000-000000000000','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','authenticated','authenticated','darkmgdevelopment@gmail.com','not-used',now(),'{}','{"first_name":"Admin"}',now(),now()),
 ('00000000-0000-0000-0000-000000000000','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','authenticated','authenticated','member@example.invalid','not-used',now(),'{}','{"first_name":"Member"}',now(),now());

-- A constraint deliberately fails the final reset write, after its deletes.
alter table public.vault_state add constraint test_failed_reset
 check (kdf->>'salt' <> 'YmJiYmJiYmJiYmJiYmJiYg==');

do $test$
declare
  admin_id uuid := 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  member_id uuid := 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  quote_id uuid := gen_random_uuid();
  generation uuid;
  next_generation uuid;
  config jsonb := '{"salt":"MDEyMzQ1Njc4OWFiY2RlZg==","iterations":600000}';
  verifier jsonb := '{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}';
  state jsonb;
  response jsonb;
  insert_op jsonb;
  delete_op jsonb;
begin
  if public.qv_valid_kdf(null) is true
     or public.qv_valid_verifier(null) is true
     or public.qv_valid_verifier('{"iv":"AA==","data":"AAAAAAAAAAAAAAAAAAAAAA=="}') is true
     or public.qv_valid_quote('{}',member_id,gen_random_uuid()) is true then
    raise exception 'Malformed cryptography/quote metadata was accepted';
  end if;
  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  generation := (public.get_vault_state()->>'generation')::uuid;
  insert into public.quotes(id,text,author,context,quote_date,created_at,user_id,vault_generation)
    values(quote_id,'Legacy plaintext','Legacy author',null,null,now(),admin_id,generation);
  response := public.sync_quotes(generation,null,'[]');
  if jsonb_array_length(response->'quotes') is distinct from 1 then
    raise exception 'Null revision did not return the complete initial snapshot';
  end if;

  -- Initialization preserves legacy plaintext while invalidating the previous KDF generation.
  state := public.initialize_vault(generation,config,verifier);
  next_generation := (state->>'generation')::uuid;
  if next_generation = generation or state->'kdf' is distinct from config
     or state->'verifier' is distinct from verifier or state->'legacy_generation' is distinct from 'null'::jsonb
     or not exists(select 1 from public.quotes where id=quote_id and vault_generation=next_generation) then
    raise exception 'Initialization contract or preservation failed';
  end if;
  generation := next_generation;
  begin
    perform public.initialize_vault(generation,config,verifier);
    raise exception 'Repeated initialization was accepted';
  exception when unique_violation then null;
  end;
  begin
    perform public.rotate_vault(null,config,verifier);
    raise exception 'Null expected generation was accepted';
  exception when serialization_failure then null;
  end;
  begin
    perform public.rotate_vault(generation,null,verifier);
    raise exception 'Null cryptography metadata was accepted';
  exception when invalid_parameter_value then null;
  end;

  perform set_config('request.jwt.claim.sub',member_id::text,true);
  response := public.sync_quotes(generation,null,'[{}]');
  if response->'results'->0->>'status' is distinct from 'rejected' then
    raise exception 'Missing operation fields bypassed validation';
  end if;
  delete_op := jsonb_build_object('operation_id',gen_random_uuid(),'action','DELETE','quote_id',quote_id,
    'actor_id',member_id,'vault_generation',generation);
  response := public.sync_quotes(generation,null,jsonb_build_array(delete_op));
  if response->'results'->0->>'status' is distinct from 'rejected' then
    raise exception 'Member deleted another creator quote';
  end if;
  begin
    perform public.rotate_vault(generation,config,verifier);
    raise exception 'Member rotation was accepted';
  exception when insufficient_privilege then null;
  end;

  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  begin
    perform public.rotate_vault(generation,jsonb_set(config,'{salt}','"YmJiYmJiYmJiYmJiYmJiYg=="'),verifier);
    raise exception 'Expected reset constraint failure';
  exception when check_violation then null;
  end;
  if (public.get_vault_state()->>'generation')::uuid <> generation
     or not exists(select 1 from public.quotes where id=quote_id) then
    raise exception 'Failed reset did not roll back its quote deletion';
  end if;

  state := public.rotate_vault(generation,config,verifier);
  next_generation := (state->>'generation')::uuid;
  if next_generation = generation or state->'kdf' is distinct from config
     or state->'verifier' is distinct from verifier or state->'legacy_generation' is distinct from 'null'::jsonb
     or exists(select 1 from public.quotes) or exists(select 1 from public.vault_operation_receipts) then
    raise exception 'Successful rotation contract or cleanup failed';
  end if;
  response := public.sync_quotes(generation,null,jsonb_build_array(delete_op));
  if response->'results'->0->>'status' is distinct from 'rejected'
     or response->>'generation' is distinct from next_generation::text then
    raise exception 'Old generation mutated the rotated vault';
  end if;
  generation := next_generation;

  insert_op := jsonb_build_object('operation_id',gen_random_uuid(),'action','INSERT','quote_id',quote_id,
    'actor_id',admin_id,'vault_generation',generation,'payload',jsonb_build_object(
      'id',quote_id,'text','$$E2E$$'||verifier::text,'author','ENCRYPTED','context','ENCRYPTED',
      'quote_date',null,'created_at',now(),'user_id',admin_id,'vault_generation',generation));
  response := public.sync_quotes(generation,null,jsonb_build_array(insert_op));
  if response->'results'->0->>'status' is distinct from 'ok' then raise exception 'Valid encrypted insertion failed'; end if;
  response := public.sync_quotes(generation,(response->>'revision')::bigint,jsonb_build_array(insert_op));
  if response->'results'->0->>'status' is distinct from 'ok' or response->'quotes' is distinct from 'null'::jsonb then
    raise exception 'Lost-response retry duplicated the insertion or downloaded an unchanged snapshot';
  end if;
  delete_op := jsonb_build_object('operation_id',gen_random_uuid(),'action','DELETE','quote_id',quote_id,
    'actor_id',admin_id,'vault_generation',generation);
  response := public.sync_quotes(generation,null,jsonb_build_array(delete_op));
  if response->'results'->0->>'status' is distinct from 'ok' then raise exception 'Creator deletion failed'; end if;
  response := public.sync_quotes(generation,null,jsonb_build_array(insert_op));
  if response->'results'->0->>'status' is distinct from 'ok' or jsonb_array_length(response->'quotes') is distinct from 0 then
    raise exception 'Replayed insertion resurrected a deleted quote';
  end if;
  response := public.sync_quotes(generation,null,jsonb_build_array(jsonb_set(insert_op,'{payload,quote_date}','"2026-09-20"')));
  if response->'results'->0->>'status' is distinct from 'rejected' then
    raise exception 'Reused operation ID accepted changed content';
  end if;
end;
$test$;

-- Exercise actual grants/RLS with an authenticated non-admin role.
set local role authenticated;
select set_config('request.jwt.claim.sub','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',true);
do $$ begin
  if exists(select 1 from public.allowlist) then raise exception 'Member enumerated allowlist'; end if;
  begin
    delete from public.quotes;
    raise exception 'Direct quote writes were allowed';
  exception when insufficient_privilege then null;
  end;
  begin
    insert into public.allowlist(id,email,created_at) values(gen_random_uuid(),'intruder@example.invalid',now());
    raise exception 'Member changed allowlist';
  exception when insufficient_privilege then null;
  end;
end $$;
set local role none;
rollback;
