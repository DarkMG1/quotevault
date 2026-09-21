-- Run as the database owner after the migration.  This file creates no durable data.
-- In psql, use: psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f tests/database.sql

begin;

create temp table qv_test (
  member_id uuid not null default gen_random_uuid(),
  admin_id uuid not null default gen_random_uuid(),
  quote_id uuid not null default gen_random_uuid(),
  insert_operation_id uuid not null default gen_random_uuid(),
  delete_operation_id uuid not null default gen_random_uuid(),
  quote_created_at timestamptz not null default now(),
  generation uuid,
  prior_generation uuid,
  first_response jsonb,
  kdf jsonb not null default '{"salt":"MDEyMzQ1Njc4OWFiY2RlZg==","iterations":600000}'::jsonb,
  verifier jsonb not null default '{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb
);
insert into qv_test default values;
grant select, update on qv_test to authenticated;

insert into public.allowlist (id, email, created_at)
select gen_random_uuid(), 'sql-test-' || member_id || '@example.invalid', now() from qv_test
union all
select gen_random_uuid(), 'darkmgdevelopment@gmail.com', now() from qv_test;

insert into auth.users (
  instance_id, id, aud, role, email, encrypted_password, email_confirmed_at,
  raw_app_meta_data, raw_user_meta_data, created_at, updated_at
)
select
  '00000000-0000-0000-0000-000000000000', member_id, 'authenticated', 'authenticated',
  'sql-test-' || member_id || '@example.invalid', 'not-used', now(),
  '{}'::jsonb, '{"first_name":"SQL","last_name":"Verifier"}'::jsonb, now(), now()
from qv_test;

insert into auth.users (
  instance_id, id, aud, role, email, encrypted_password, email_confirmed_at,
  raw_app_meta_data, raw_user_meta_data, created_at, updated_at
)
select
  '00000000-0000-0000-0000-000000000000', admin_id, 'authenticated', 'authenticated',
  'darkmgdevelopment@gmail.com', 'not-used', now(),
  '{}'::jsonb, '{"first_name":"SQL","last_name":"Admin"}'::jsonb, now(), now()
from qv_test;

-- The auth trigger rejects a synthetic email that was never allowlisted.
do $$
begin
  insert into auth.users (
    instance_id, id, aud, role, email, encrypted_password, email_confirmed_at,
    raw_app_meta_data, raw_user_meta_data, created_at, updated_at
  ) values (
    '00000000-0000-0000-0000-000000000000', gen_random_uuid(), 'authenticated', 'authenticated',
    'unapproved-sql-test@example.invalid', 'not-used', now(), '{}'::jsonb, '{}'::jsonb, now(), now()
  );
  raise exception 'unapproved signup was accepted';
exception when insufficient_privilege then
  null;
end;
$$;

set local role authenticated;
select set_config('request.jwt.claim.sub', (select member_id::text from qv_test), true);
select set_config('request.jwt.claim.role', 'authenticated', true);

-- Authenticated members cannot enumerate the allowlist.
do $$
begin
  if exists (select 1 from public.allowlist) then
    raise exception 'allowlist was readable by a member';
  end if;
end;
$$;

set local role anon;
do $$
begin
  if exists (select 1 from public.quotes) then
    raise exception 'quotes were readable anonymously';
  end if;
exception when insufficient_privilege then
  null;
end;
$$;
set local role authenticated;

-- The auth metadata trigger populates and refreshes the member-visible profile.
set local role none;
update auth.users
set raw_user_meta_data = '{"first_name":"Updated","last_name":"Profile"}'::jsonb
where id = (select member_id from qv_test);
set local role authenticated;

do $$
begin
  if not exists (
    select 1 from public.profiles
    where id = (select member_id from qv_test)
      and first_name = 'Updated' and last_name = 'Profile'
  ) then
    raise exception 'profile trigger did not synchronize auth metadata';
  end if;
end;
$$;

update qv_test set prior_generation = (public.get_vault_state()->>'generation')::uuid;

select set_config('request.jwt.claim.sub', (select admin_id::text from qv_test), true);
update qv_test
set first_response = public.initialize_vault(prior_generation, kdf, verifier);

do $$
begin
  if (select first_response->>'generation' from qv_test) = (select prior_generation::text from qv_test)
     or (select first_response->'kdf' from qv_test) <> (select kdf from qv_test)
     or (select first_response->'verifier' from qv_test) <> (select verifier from qv_test)
     or (select first_response->'legacy_generation' from qv_test) <> 'null'::jsonb then
    raise exception 'initialize did not return the complete rotated vault state';
  end if;
end;
$$;

update qv_test set generation = (first_response->>'generation')::uuid;
select set_config('request.jwt.claim.sub', (select member_id::text from qv_test), true);

do $$
declare
  response jsonb;
begin
  select public.sync_quotes((select generation from qv_test), null, '[]'::jsonb) into response;
  if response->'quotes' <> '[]'::jsonb then
    raise exception 'a null revision did not return the initial full snapshot';
  end if;
end;
$$;

do $$
declare
  response jsonb;
begin
  select public.sync_quotes(
    (select generation from qv_test), null,
    jsonb_build_array(jsonb_build_object(
      'operation_id', gen_random_uuid(), 'action', 'INSERT', 'quote_id', gen_random_uuid(),
      'actor_id', (select member_id from qv_test), 'vault_generation', (select generation from qv_test)
    ))
  ) into response;
  if response->'results'->0->>'status' <> 'rejected'
     or response->'quotes' <> '[]'::jsonb then
    raise exception 'missing payload bypassed quote validation';
  end if;
end;
$$;

update qv_test
set first_response = public.sync_quotes(
  generation,
  0,
  jsonb_build_array(jsonb_build_object(
    'operation_id', insert_operation_id,
    'action', 'INSERT',
    'quote_id', quote_id,
    'actor_id', member_id,
    'vault_generation', generation,
    'payload', jsonb_build_object(
      'id', quote_id,
      'text', '$$E2E$$' || verifier::text,
      'author', 'ENCRYPTED',
      'context', 'ENCRYPTED',
      'quote_date', current_date::text,
      'created_at', quote_created_at::text,
      'user_id', member_id,
      'vault_generation', generation
    )
  ))
);

do $insert_replay$
declare
  response jsonb;
begin
  if (select first_response->'results'->0->>'status' from qv_test) <> 'ok' then
    raise exception 'insert operation was not accepted';
  end if;
  select public.sync_quotes(
    (select generation from qv_test),
    (select (first_response->>'revision')::bigint from qv_test),
    jsonb_build_array(jsonb_build_object(
      'operation_id', (select insert_operation_id from qv_test),
      'action', 'INSERT',
      'quote_id', (select quote_id from qv_test),
      'actor_id', (select member_id from qv_test),
      'vault_generation', (select generation from qv_test),
      'payload', jsonb_build_object(
        'id', (select quote_id from qv_test),
        'text', '$$E2E$$' || (select verifier::text from qv_test),
        'author', 'ENCRYPTED', 'context', 'ENCRYPTED',
        'quote_date', current_date::text, 'created_at', (select quote_created_at::text from qv_test),
        'user_id', (select member_id from qv_test), 'vault_generation', (select generation from qv_test)
      )
    ))
  ) into response;
  if response->'results'->0->>'status' <> 'ok' or response->'quotes' <> 'null'::jsonb then
    raise exception 'insert replay was not receipt-backed';
  end if;
end;
$insert_replay$;

-- A non-admin rotation fails before changing a quote or its generation.
do $$
declare
  before_generation uuid := (select generation from qv_test);
begin
  begin
    perform public.rotate_vault(before_generation, (select kdf from qv_test), (select verifier from qv_test));
    raise exception 'non-admin rotation was accepted';
  exception when insufficient_privilege then
    null;
  end;
  if (select (public.get_vault_state()->>'generation')::uuid) <> before_generation then
    raise exception 'failed rotation changed the generation';
  end if;
  if jsonb_array_length(public.sync_quotes(before_generation, 0, '[]'::jsonb)->'quotes') <> 1 then
    raise exception 'failed rotation changed quotes';
  end if;
end;
$$;

-- A stale generation returns a rejection and leaves the quote intact.
do $$
declare
  response jsonb;
begin
  select public.sync_quotes(
    gen_random_uuid(), 0,
    jsonb_build_array(jsonb_build_object(
      'operation_id', gen_random_uuid(), 'action', 'DELETE',
      'quote_id', (select quote_id from qv_test),
      'actor_id', (select member_id from qv_test),
      'vault_generation', gen_random_uuid()
    ))
  ) into response;
  if response->'results'->0->>'error' <> 'stale vault generation'
     or jsonb_array_length(response->'quotes') <> 1 then
    raise exception 'stale generation was not rejected safely';
  end if;
end;
$$;

-- DELETE is receipt-backed too: replay stays successful and cannot restore the row.
update qv_test
set first_response = public.sync_quotes(
  generation,
  (first_response->>'revision')::bigint,
  jsonb_build_array(jsonb_build_object(
    'operation_id', delete_operation_id,
    'action', 'DELETE',
    'quote_id', quote_id,
    'actor_id', member_id,
    'vault_generation', generation
  ))
);

do $$
declare
  response jsonb;
begin
  select public.sync_quotes(
    (select generation from qv_test),
    (select (first_response->>'revision')::bigint from qv_test),
    jsonb_build_array(jsonb_build_object(
      'operation_id', (select delete_operation_id from qv_test),
      'action', 'DELETE',
      'quote_id', (select quote_id from qv_test),
      'actor_id', (select member_id from qv_test),
      'vault_generation', (select generation from qv_test)
    ))
  ) into response;
  if response->'results'->0->>'status' <> 'ok'
     or response->'quotes' <> 'null'::jsonb then
    raise exception 'delete replay was not idempotent';
  end if;
end;
$$;

set local role none;
rollback;
