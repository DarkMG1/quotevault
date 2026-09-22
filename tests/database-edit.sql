-- Administrative encrypted quote edits run only against a disposable database.
begin;

insert into public.allowlist(id,email,created_at) values
 ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','darkmgdevelopment@gmail.com',now()),
 ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','edit-member@example.invalid',now());
insert into auth.users(instance_id,id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at) values
 ('00000000-0000-0000-0000-000000000000','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','authenticated','authenticated','darkmgdevelopment@gmail.com','not-used',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000000','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','authenticated','authenticated','edit-member@example.invalid','not-used',now(),'{}','{}',now(),now());

do $seed$
declare
  member_id uuid := 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  quote_id uuid := '11111111-1111-4111-8111-111111111111';
  generation uuid := (select generation from public.vault_state where singleton);
begin
  insert into public.quotes(id,text,author,context,quote_date,created_at,user_id,vault_generation)
  values (
    quote_id,
    '$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}',
    'ENCRYPTED', 'ENCRYPTED', date '2026-09-20', '2026-09-20T12:34:56.789Z', member_id, generation
  );
  insert into public.quotes(id,text,author,context,quote_date,created_at,user_id,vault_generation)
  values (
    '22222222-2222-4222-8222-222222222222',
    '$$E2E$${"iv":"DDDDDDDDDDDDDDDD","data":"AAAAAAAAAAAAAAAAAAAAAA=="}',
    'ENCRYPTED', 'ENCRYPTED', date '2026-09-20', '2026-09-20T12:34:57.789Z', member_id, generation
  );
end;
$seed$;

select set_config('qv.edit.generation', (select generation::text from public.vault_state where singleton), true);
select set_config('qv.edit.revision', (select revision::text from public.vault_state where singleton), true);
set local role authenticated;
select set_config('request.jwt.claim.sub','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',true);
do $member_denied$
declare
  generation uuid := current_setting('qv.edit.generation')::uuid;
begin
  begin
    perform public.edit_quote(
      generation, '11111111-1111-4111-8111-111111111111',
      '$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}',
      '$$E2E$${"iv":"BBBBBBBBBBBBBBBB","data":"AAAAAAAAAAAAAAAAAAAAAA=="}', date '2026-09-21'
    );
    raise exception 'member edited its own quote';
  exception when insufficient_privilege then null;
  end;
end;
$member_denied$;

select set_config('request.jwt.claim.sub','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',true);
do $admin_edit$
declare
  quote_id uuid := '11111111-1111-4111-8111-111111111111';
  generation uuid := current_setting('qv.edit.generation')::uuid;
  old_text text := '$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}';
  new_text text := '$$E2E$${"iv":"BBBBBBBBBBBBBBBB","data":"AAAAAAAAAAAAAAAAAAAAAA=="}';
  response jsonb;
begin
  response := public.edit_quote(generation, quote_id, old_text, new_text, date '2026-09-21');
  if response->>'text' is distinct from new_text
     or response->>'user_id' is distinct from 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
     or (response->>'created_at')::timestamptz is distinct from '2026-09-20T12:34:56.789Z'::timestamptz then
    raise exception 'admin edit did not preserve returned quote identity';
  end if;
  begin
    perform public.edit_quote(generation, quote_id, old_text, new_text, date '2026-09-21');
    raise exception 'stale quote text was accepted';
  exception when serialization_failure then null;
  end;
  begin
    perform public.edit_quote(generation, gen_random_uuid(), new_text, new_text, date '2026-09-21');
    raise exception 'missing quote was accepted';
  exception when no_data_found then null;
  end;
  begin
    perform public.edit_quote(null, quote_id, new_text, new_text, date '2026-09-21');
    raise exception 'missing vault generation was accepted';
  exception when serialization_failure then null;
  end;
  begin
    perform public.edit_quote(gen_random_uuid(), quote_id, new_text, new_text, date '2026-09-21');
    raise exception 'stale vault generation was accepted';
  exception when serialization_failure then null;
  end;
  begin
    perform public.edit_quote(generation, quote_id, new_text, 'plaintext', date '2026-09-21');
    raise exception 'plaintext quote edit was accepted';
  exception when invalid_parameter_value then null;
  end;
  if (select text from public.quotes where id = quote_id) is distinct from new_text then
    raise exception 'rejected quote edit changed ciphertext';
  end if;
end;
$admin_edit$;
reset role;

do $preservation$
begin
  if not exists (
    select 1 from public.quotes
    where id = '11111111-1111-4111-8111-111111111111'
      and text = '$$E2E$${"iv":"BBBBBBBBBBBBBBBB","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'
      and user_id = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
      and created_at = '2026-09-20T12:34:56.789Z'::timestamptz
      and author = 'ENCRYPTED' and context = 'ENCRYPTED'
  ) or (select revision from public.vault_state where singleton) <> current_setting('qv.edit.revision')::bigint + 1 then
    raise exception 'admin edit changed immutable metadata or missed the revision increment';
  end if;
end;
$preservation$;

select set_config('qv.edit.batch_revision', (select revision::text from public.vault_state where singleton), true);
set local role authenticated;
select set_config('request.jwt.claim.sub','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',true);
do $admin_batch$
declare
  generation uuid := current_setting('qv.edit.generation')::uuid;
  first_old text := '$$E2E$${"iv":"BBBBBBBBBBBBBBBB","data":"AAAAAAAAAAAAAAAAAAAAAA=="}';
  first_new text := '$$E2E$${"iv":"CCCCCCCCCCCCCCCC","data":"AAAAAAAAAAAAAAAAAAAAAA=="}';
  second_old text := '$$E2E$${"iv":"DDDDDDDDDDDDDDDD","data":"AAAAAAAAAAAAAAAAAAAAAA=="}';
  second_new text := '$$E2E$${"iv":"EEEEEEEEEEEEEEEE","data":"AAAAAAAAAAAAAAAAAAAAAA=="}';
  response jsonb;
begin
  response := public.edit_quotes(generation, jsonb_build_array(
    jsonb_build_object('quote_id', '11111111-1111-4111-8111-111111111111',
      'expected_text', first_old, 'text', first_new, 'quote_date', 'null'::jsonb),
    jsonb_build_object('quote_id', '22222222-2222-4222-8222-222222222222',
      'expected_text', second_old, 'text', second_new, 'quote_date', '2026-09-22')
  ));
  if response->>'updated' is distinct from '2' then
    raise exception 'admin batch did not report both edits';
  end if;
  begin
    perform public.edit_quotes(generation, jsonb_build_array(
      jsonb_build_object('quote_id', '11111111-1111-4111-8111-111111111111',
        'expected_text', first_new, 'text', '$$E2E$${"iv":"FFFFFFFFFFFFFFFF","data":"AAAAAAAAAAAAAAAAAAAAAA=="}', 'quote_date', '2026-09-23'),
      jsonb_build_object('quote_id', '22222222-2222-4222-8222-222222222222',
        'expected_text', second_old, 'text', first_new, 'quote_date', '2026-09-23')
    ));
    raise exception 'late stale batch edit was accepted';
  exception when serialization_failure then null;
  end;
  begin
    perform public.edit_quotes(generation, jsonb_build_array(jsonb_build_object(
      'quote_id', '11111111-1111-4111-8111-111111111111',
      'expected_text', first_new, 'text', first_new, 'quote_date', jsonb_build_array('2026-09-23')
    )));
    raise exception 'array quote date was accepted';
  exception when invalid_parameter_value then null;
  end;
  begin
    perform public.edit_quotes(generation, jsonb_build_array(jsonb_build_object(
      'quote_id', '11111111-1111-4111-8111-111111111111',
      'expected_text', first_new, 'text', first_new, 'quote_date', jsonb_build_object('date', '2026-09-23')
    )));
    raise exception 'object quote date was accepted';
  exception when invalid_parameter_value then null;
  end;
end;
$admin_batch$;
reset role;

do $batch_preservation$
begin
  if not exists (
    select 1 from public.quotes
    where id = '11111111-1111-4111-8111-111111111111'
      and text = '$$E2E$${"iv":"CCCCCCCCCCCCCCCC","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'
      and quote_date is null
      and user_id = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
      and created_at = '2026-09-20T12:34:56.789Z'::timestamptz
      and author = 'ENCRYPTED' and context = 'ENCRYPTED'
  ) or not exists (
    select 1 from public.quotes
    where id = '22222222-2222-4222-8222-222222222222'
      and text = '$$E2E$${"iv":"EEEEEEEEEEEEEEEE","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'
      and quote_date = date '2026-09-22'
  ) or (select revision from public.vault_state where singleton) <> current_setting('qv.edit.batch_revision')::bigint + 2 then
    raise exception 'failed batch changed quotes or revision';
  end if;
end;
$batch_preservation$;

set local role authenticated;
select set_config('request.jwt.claim.sub','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',true);
do $member_batch_denied$
begin
  begin
    perform public.edit_quotes(current_setting('qv.edit.generation')::uuid, '[]'::jsonb);
    raise exception 'member batch edit was accepted';
  exception when insufficient_privilege then null;
  end;
end;
$member_batch_denied$;
reset role;

do $grants$
begin
  if has_function_privilege('anon', 'public.edit_quote(uuid,uuid,text,text,date)', 'EXECUTE') then
    raise exception 'anonymous quote edit execution was granted';
  end if;
  if has_function_privilege('anon', 'public.edit_quotes(uuid,jsonb)', 'EXECUTE') then
    raise exception 'anonymous batch quote edit execution was granted';
  end if;
end;
$grants$;

rollback;
