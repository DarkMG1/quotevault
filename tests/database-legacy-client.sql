-- The a1bb840 frontend must keep working on the final schema while the vault is legacy.
begin;
insert into public.allowlist(id,email,created_at) values
 ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','darkmgdevelopment@gmail.com',now()),
 ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','legacy-client@example.invalid',now());
insert into auth.users(instance_id,id,aud,role,email,encrypted_password,email_confirmed_at) values
 (gen_random_uuid(),'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','authenticated','authenticated','darkmgdevelopment@gmail.com','x',now()),
 (gen_random_uuid(),'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','authenticated','authenticated','legacy-client@example.invalid','x',now());
update public.vault_state set envelope_status='legacy',prepared_generation=null,active_migration_id=null,
  verifier='{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}' where singleton;
select set_config('qv.g',(select generation::text from public.vault_state where singleton),true);
set local role authenticated;
select set_config('request.jwt.claim.sub','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',true);
do $client$
declare
  g uuid := current_setting('qv.g')::uuid;
  quote_id uuid := gen_random_uuid();
  response jsonb;
  cipher text := '$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}';
begin
  response := public.get_vault_state();
  if response->>'generation' is distinct from g::text or response->'kdf' is null then raise exception 'old get_vault_state() contract broke: %', response; end if;
  response := public.sync_quotes(g, 0, jsonb_build_array(jsonb_build_object(
    'operation_id', gen_random_uuid(), 'action', 'INSERT', 'quote_id', quote_id,
    'actor_id', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'vault_generation', g,
    'payload', jsonb_build_object('id', quote_id, 'text', cipher, 'author', 'ENCRYPTED', 'context', 'ENCRYPTED',
      'quote_date', '2026-09-23', 'created_at', '2026-09-23T12:00:00.000Z',
      'user_id', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'vault_generation', g))));
  if response->'results'->0->>'status' is distinct from 'ok' then raise exception 'old 3-argument sync_quotes insert broke: %', response; end if;
  response := public.sync_quotes(g, null, '[]'::jsonb);
  if jsonb_array_length(response->'quotes') <> 1 then raise exception 'old full snapshot broke: %', response; end if;
  perform 1 from public.profiles limit 1;
end $client$;
select set_config('request.jwt.claim.sub','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',true);
do $admin$
declare
  g uuid := current_setting('qv.g')::uuid;
  q record;
begin
  select id, text into q from public.quotes limit 1;
  perform public.edit_quote(g, q.id, q.text, '$$E2E$${"iv":"BBBBBBBBBBBBBBBB","data":"AAAAAAAAAAAAAAAAAAAAAA=="}', date '2026-09-23');
  perform public.edit_quotes(g, jsonb_build_array(jsonb_build_object('quote_id', q.id::text,
    'expected_text', (select text from public.quotes where id = q.id),
    'text', '$$E2E$${"iv":"CCCCCCCCCCCCCCCC","data":"AAAAAAAAAAAAAAAAAAAAAA=="}', 'quote_date', '2026-09-23')));
  insert into public.allowlist(id,email,created_at) values (gen_random_uuid(),'added-by-old-admin@example.invalid',now());
  delete from public.allowlist where email='added-by-old-admin@example.invalid';
end $admin$;
reset role;
rollback;
