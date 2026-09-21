-- Run in a new empty disposable PostgreSQL/Supabase-shaped database as owner:
-- psql -d quotevault_hardening -v ON_ERROR_STOP=1 -f tests/database-hardening.sql
-- This installs both migrations, proves the pre-hardening regressions, then
-- verifies the additive migration and safe reapplication.

\ir database-fixture.sql
create schema realtime;
create table realtime.messages (
  payload jsonb not null,
  event text not null,
  topic text not null,
  private boolean not null,
  extension text not null
);
create function realtime.topic()
returns text language sql stable
as $$ select current_setting('realtime.topic', true) $$;
create function realtime.send(p_payload jsonb, p_event text, p_topic text, p_private boolean)
returns void language plpgsql security definer set search_path = realtime, pg_temp
as $send$
begin
  insert into realtime.messages(payload, event, topic, private, extension)
  values (p_payload, p_event, p_topic, p_private, 'broadcast');
end;
$send$;
alter table realtime.messages enable row level security;
grant usage on schema realtime to authenticated;
grant select on realtime.messages to authenticated;
\ir ../supabase/migrations/20260920000000_secure_vault.sql

insert into public.allowlist (id, email, created_at) values
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'darkmgdevelopment@gmail.com', now()),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'member@example.invalid', now());
insert into auth.users (
  instance_id, id, aud, role, email, encrypted_password, email_confirmed_at,
  raw_app_meta_data, raw_user_meta_data, created_at, updated_at
) values
  ('00000000-0000-0000-0000-000000000000', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'authenticated', 'authenticated',
   'darkmgdevelopment@gmail.com', 'not-used', now(), '{}'::jsonb, '{}'::jsonb, now(), now()),
  ('00000000-0000-0000-0000-000000000000', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'authenticated', 'authenticated',
   'member@example.invalid', 'not-used', now(), '{}'::jsonb, '{}'::jsonb, now(), now());

-- Before hardening, the configured administrator can rename its own allowlist
-- entry and PostgreSQL accepts infinity as a quote timestamp.
set role authenticated;
select set_config('request.jwt.claim.sub', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', false);
update public.allowlist set email = 'admin-before-hardening@example.invalid'
where email = 'darkmgdevelopment@gmail.com';
update public.allowlist set email = 'darkmgdevelopment@gmail.com'
where email = 'admin-before-hardening@example.invalid';
reset role;

do $old_behavior$
declare
  generation uuid := (select generation from public.vault_state where singleton);
  payload jsonb;
begin
  payload := jsonb_build_object(
    'id', '11111111-1111-4111-8111-111111111111',
    'text', '$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}',
    'author', 'ENCRYPTED', 'context', 'ENCRYPTED', 'created_at', 'infinity',
    'user_id', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'vault_generation', generation
  );
  if public.qv_valid_quote(payload, 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', generation) is not true then
    raise exception 'pre-hardening fixture did not accept infinity';
  end if;
end;
$old_behavior$;

\ir ../supabase/migrations/20260921000000_vault_hardening.sql

select set_config(
  'qv.hardening.generation',
  (select generation::text from public.vault_state where singleton),
  false
);

set role authenticated;
select set_config('request.jwt.claim.sub', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', false);
do $administrator_guard$
begin
  begin
    update public.allowlist set email = 'admin-renamed@example.invalid'
    where email = 'darkmgdevelopment@gmail.com';
    raise exception 'administrator allowlist rename was accepted';
  exception when check_violation then
    if sqlerrm <> 'The configured administrator must remain allowlisted' then raise; end if;
  end;
  begin
    delete from public.allowlist where email = 'darkmgdevelopment@gmail.com';
    raise exception 'administrator allowlist deletion was accepted';
  exception when check_violation then
    if sqlerrm <> 'The configured administrator must remain allowlisted' then raise; end if;
  end;
  update public.allowlist set email = 'renamed-member@example.invalid'
  where email = 'member@example.invalid';
  update public.allowlist set email = 'member@example.invalid'
  where email = 'renamed-member@example.invalid';
end;
$administrator_guard$;
reset role;

do $validators$
declare
  actor uuid := 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  generation uuid := (select generation from public.vault_state where singleton);
  payload jsonb;
begin
  payload := jsonb_build_object(
    'id', '11111111-1111-4111-8111-111111111111',
    'text', '$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}',
    'author', 'ENCRYPTED', 'context', 'ENCRYPTED', 'created_at', 'infinity',
    'user_id', actor, 'vault_generation', generation
  );
  if public.qv_valid_quote(payload, actor, generation) is not false then
    raise exception 'infinite created_at was accepted';
  end if;
  payload := jsonb_set(payload, '{created_at}', '"2026-09-21T12:34:56.789Z"');
  if public.qv_valid_quote(payload, actor, generation) is not true then
    raise exception 'browser ISO created_at was rejected';
  end if;
  payload := jsonb_set(payload, '{text}', to_jsonb('$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"' || repeat('A', 262148) || '"}'));
  if public.qv_valid_verifier(jsonb_build_object('iv', 'AAAAAAAAAAAAAAAA', 'data', repeat('A', 262148))) is not true then
    raise exception 'hardening changed legacy verifier acceptance';
  end if;
  if public.qv_valid_quote(payload, actor, generation) is not false then
    raise exception 'oversized quote ciphertext was accepted';
  end if;
end;
$validators$;

set role authenticated;
select set_config('request.jwt.claim.sub', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', false);
do $request_cap$
begin
  begin
    perform public.sync_quotes(
      current_setting('qv.hardening.generation')::uuid,
      null,
      jsonb_build_array(jsonb_build_object('ignored', repeat('x', 1048576)))
    );
    raise exception 'oversized sync request was accepted';
  exception when invalid_parameter_value then
    null;
  end;
end;
$request_cap$;

select set_config('request.jwt.claim.sub', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', false);
create temp table qv_hardening_rotation as
select public.rotate_vault(
  current_setting('qv.hardening.generation')::uuid,
  '{"salt":"MDEyMzQ1Njc4OWFiY2RlZg==","iterations":600000}',
  '{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'
) as state;
select set_config('realtime.topic', 'quotevault-sync', false);

do $generation_event$
declare
  rotated_generation uuid := (select (state->>'generation')::uuid from qv_hardening_rotation);
begin
  if not exists (
    select 1 from realtime.messages
    where payload = jsonb_build_object('generation', rotated_generation)
      and event = 'vault-generation' and topic = 'quotevault-sync'
      and private and extension = 'broadcast'
  ) then
    raise exception 'rotation did not emit a private generation broadcast';
  end if;
  begin
    insert into realtime.messages(payload, event, topic, private, extension)
    values ('{}', 'vault-generation', 'quotevault-sync', true, 'broadcast');
    raise exception 'authenticated client forged a generation broadcast';
  exception when insufficient_privilege then
    null;
  end;
end;
$generation_event$;
reset role;

set role authenticated;
select set_config('request.jwt.claim.sub', 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', false);
select set_config('realtime.topic', 'quotevault-sync', false);
do $broadcast_membership$
begin
  if exists (select 1 from realtime.messages where event = 'vault-generation') then
    raise exception 'non-member received generation broadcasts';
  end if;
end;
$broadcast_membership$;
reset role;

-- Reapplication preserves the current event and recreates all hardening rules.
\ir ../supabase/migrations/20260921000000_vault_hardening.sql

set role authenticated;
select set_config('request.jwt.claim.sub', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', false);
do $reapplication$
begin
  perform set_config('realtime.topic', 'quotevault-sync', true);
  if not exists (select 1 from realtime.messages where event = 'vault-generation') then
    raise exception 'hardening reapplication lost the generation broadcast';
  end if;
  begin
    delete from public.allowlist where email = 'darkmgdevelopment@gmail.com';
    raise exception 'hardening reapplication lost administrator guard';
  exception when check_violation then
    null;
  end;
end;
$reapplication$;
reset role;

-- PostgreSQL normalizes seconds=60, but browsers display Invalid Date.
\ir ../supabase/migrations/20260921010000_browser_timestamps.sql
do $browser_dates$
declare
  actor uuid := 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  generation uuid := (select generation from public.vault_state where singleton);
  payload jsonb;
begin
  payload := jsonb_build_object('id','11111111-1111-4111-8111-111111111111',
    'text','$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}',
    'author','ENCRYPTED','context','ENCRYPTED','created_at','2026-09-21T12:34:60Z',
    'user_id',actor,'vault_generation',generation);
  if public.qv_valid_quote(payload,actor,generation) is not false then
    raise exception 'browser-invalid leap second was accepted';
  end if;
  payload := jsonb_set(payload,'{created_at}','"2026-09-21T23:59:59.999Z"');
  if public.qv_valid_quote(payload,actor,generation) is not true then
    raise exception 'valid browser timestamp was rejected';
  end if;
end;
$browser_dates$;
