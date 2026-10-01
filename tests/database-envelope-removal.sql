-- After removing device-envelope encryption: data intact, envelope objects gone, shared-key client works.
begin;
do $verify$
declare expected record;
begin
  select * into expected from qv_removal_check.expected;
  if (select md5(string_agg(q::text, ',' order by q.id)) from public.quotes q) is distinct from expected.quotes then raise exception 'quotes changed'; end if;
  if (select md5(row(s.singleton,s.generation,s.revision,s.kdf,s.verifier,s.legacy_generation)::text) from public.vault_state s) is distinct from expected.vault_state then raise exception 'vault settings changed'; end if;
  if (select md5(string_agg(a::text, ',' order by a.id)) from public.allowlist a) is distinct from expected.allowlist then raise exception 'allowlist changed'; end if;
  if (select md5(coalesce(string_agg(p::text, ',' order by p.id), '')) from public.profiles p) is distinct from expected.profiles then raise exception 'profiles changed'; end if;
  if to_regclass('public.vault_devices') is not null or to_regclass('public.vault_migrations') is not null or to_regprocedure('public.request_device(uuid,text,text,jsonb,text,text,text,jsonb,text,jsonb)') is not null then raise exception 'envelope objects remain'; end if;
  if exists(select 1 from information_schema.columns where table_schema='public' and table_name='vault_state' and column_name in ('envelope_status','prepared_generation','active_migration_id')) then raise exception 'envelope columns remain'; end if;
end $verify$;
select set_config('qv.g',(select generation::text from public.vault_state where singleton),true);
set local role authenticated;
select set_config('request.jwt.claim.sub','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',true);
do $client$
declare
  g uuid := current_setting('qv.g')::uuid;
  quote_id uuid := gen_random_uuid();
  response jsonb;
begin
  response := public.get_vault_state();
  if response->>'generation' is distinct from g::text then raise exception 'get_vault_state() broke: %', response; end if;
  response := public.sync_quotes(g, 0, jsonb_build_array(jsonb_build_object('operation_id', gen_random_uuid(), 'action', 'INSERT', 'quote_id', quote_id,
    'actor_id', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'vault_generation', g, 'payload', jsonb_build_object('id', quote_id,
    'text', '$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}', 'author', 'ENCRYPTED', 'context', 'ENCRYPTED',
    'quote_date', '2026-10-02', 'created_at', '2026-10-02T12:00:00.000Z', 'user_id', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'vault_generation', g))));
  if response->'results'->0->>'status' is distinct from 'ok' then raise exception 'shared-key sync insert broke: %', response; end if;
  if jsonb_array_length(public.sync_quotes(g, null, '[]'::jsonb)->'quotes') <> 26 then raise exception 'full snapshot broke'; end if;
  if (select count(*) from public.quotes) <> 26 then raise exception 'members cannot read quotes'; end if;
  perform 1 from public.profiles limit 1;
end $client$;
select set_config('request.jwt.claim.sub','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',true);
do $admin$
declare g uuid := current_setting('qv.g')::uuid; q record;
begin
  select id, text into q from public.quotes order by id limit 1;
  perform public.edit_quote(g, q.id, q.text, '$$E2E$${"iv":"BBBBBBBBBBBBBBBB","data":"AAAAAAAAAAAAAAAAAAAAAA=="}', date '2026-10-02');
  insert into public.allowlist(id,email,created_at) values (gen_random_uuid(),'added-after-removal@example.invalid',now());
  delete from public.allowlist where email='added-after-removal@example.invalid';
end $admin$;
reset role;
rollback;
