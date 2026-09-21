-- QuoteVault's existing public tables are deliberately migrated in place.
-- Run docs/database-prerequisites.md against the target project before applying this file.

begin;

do $$
begin
  if to_regclass('public.quotes') is null
     or to_regclass('public.profiles') is null
     or to_regclass('public.allowlist') is null
     or to_regclass('public.app_settings') is null then
    raise exception 'QuoteVault requires public.quotes, profiles, allowlist, and app_settings';
  end if;
end;
$$;

create table if not exists public.vault_state (
  singleton boolean primary key default true check (singleton),
  generation uuid not null,
  revision bigint not null default 0 check (revision >= 0),
  kdf jsonb not null,
  verifier jsonb,
  legacy_generation uuid
);

create table if not exists public.vault_operation_receipts (
  operation_id uuid not null,
  actor_id uuid not null,
  generation uuid not null,
  request_digest text not null,
  result jsonb not null,
  created_at timestamptz not null default now(),
  primary key (operation_id, actor_id)
);

create or replace function public.qv_valid_kdf(p_kdf jsonb)
returns boolean
language plpgsql
immutable
set search_path = public, pg_temp
as $legacy$
declare
  iterations integer;
  salt_bytes integer;
begin
  if jsonb_typeof(p_kdf) <> 'object'
     or jsonb_typeof(p_kdf->'salt') <> 'string'
     or jsonb_typeof(p_kdf->'iterations') <> 'number'
     or coalesce(p_kdf->>'salt', '') !~ '^[A-Za-z0-9+/]+={0,2}$'
     or length(p_kdf->>'salt') not between 24 and 88
     or coalesce(p_kdf->>'iterations', '') !~ '^[1-9][0-9]{5,6}$' then
    return false;
  end if;
  iterations := (p_kdf->>'iterations')::integer;
  salt_bytes := octet_length(decode(p_kdf->>'salt', 'base64'));
  return salt_bytes between 16 and 64 and iterations between 600000 and 2000000;
exception when others then
  return false;
end;
$legacy$;

create or replace function public.qv_valid_verifier(p_verifier jsonb)
returns boolean
language plpgsql
immutable
set search_path = public, pg_temp
as $quote$
declare
  iv_bytes integer;
  data_bytes integer;
begin
  if (jsonb_typeof(p_verifier) = 'object'
      and jsonb_typeof(p_verifier->'iv') = 'string'
      and jsonb_typeof(p_verifier->'data') = 'string'
      and length(p_verifier->>'iv') = 16
      and coalesce(p_verifier->>'iv', '') ~ '^[A-Za-z0-9+/]+={0,2}$'
      and coalesce(p_verifier->>'data', '') ~ '^[A-Za-z0-9+/]+={0,2}$'
      and length(p_verifier->>'data') <= 10485760) is not true then
    return false;
  end if;
  iv_bytes := octet_length(decode(p_verifier->>'iv', 'base64'));
  data_bytes := octet_length(decode(p_verifier->>'data', 'base64'));
  return iv_bytes = 12 and data_bytes >= 16;
exception when others then
  return false;
end;
$quote$;

-- The old verifier is a normal encrypted quote.  No plaintext is decrypted here.
create or replace function public.qv_legacy_verifier()
returns jsonb
language plpgsql
stable
set search_path = public, pg_temp
as $legacy$
declare
  candidate text;
  parsed jsonb;
begin
  for candidate in
    select substring(q.text from 8)
    from public.quotes q
    where q.text like '$$E2E$$%'
  loop
    begin
      parsed := candidate::jsonb;
      if public.qv_valid_verifier(parsed) then
        return jsonb_build_object('iv', parsed->>'iv', 'data', parsed->>'data');
      end if;
    exception when others then
      -- A malformed legacy row is not a valid verifier; keep looking.
      null;
    end;
  end loop;
  return null;
end;
$legacy$;

insert into public.vault_state (singleton, generation, revision, kdf, verifier, legacy_generation)
select true,
       initial.generation,
       0,
       jsonb_build_object(
         'salt', encode(convert_to('QuoteVault-FixedSalt-2026', 'UTF8'), 'base64'),
         'iterations', 100000
       ),
       public.qv_legacy_verifier(),
       initial.generation
from (select gen_random_uuid() as generation) initial
where not exists (select 1 from public.vault_state where singleton);

do $$
declare
  initial_generation uuid;
begin
  select generation into initial_generation from public.vault_state where singleton;
  if not exists (
    select 1
    from information_schema.columns
    where table_schema = 'public' and table_name = 'quotes' and column_name = 'vault_generation'
  ) then
    -- This constant default exists only while PostgreSQL backfills existing rows.
    execute format('alter table public.quotes add column vault_generation uuid default %L::uuid', initial_generation);
  end if;
  update public.quotes set vault_generation = initial_generation where vault_generation is null;
end;
$$;

alter table public.quotes alter column vault_generation set not null;
alter table public.quotes alter column vault_generation drop default;
alter table public.quotes alter column context drop not null;
alter table public.quotes alter column quote_date drop not null;
-- The original deployed schema used text; valid calendar dates keep the same JSON value.
alter table public.quotes alter column quote_date type date using nullif(quote_date::text, '')::date;

-- A valid encrypted quote supplies an equivalent slow-verification payload.
-- Leave the old hash in the locked table when initialization is still required.
delete from public.app_settings
where key = 'vault_key_hash'
  and exists (select 1 from public.vault_state where singleton and verifier is not null);

create or replace function public.qv_is_member()
returns boolean
language sql
stable
security definer
set search_path = public, auth, pg_temp
as $$
  select exists (
    select 1
    from auth.users u
    join public.allowlist a on lower(a.email) = lower(u.email)
    where u.id = auth.uid()
      and u.email_confirmed_at is not null
  )
$$;

create or replace function public.qv_is_admin()
returns boolean
language sql
stable
security definer
set search_path = public, auth, pg_temp
as $$
  select exists (
    select 1
    from auth.users u
    where u.id = auth.uid()
      and lower(u.email) = 'darkmgdevelopment@gmail.com'
      and u.email_confirmed_at is not null
  )
$$;

create or replace function public.qv_is_active_profile(p_profile_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public, auth, pg_temp
as $$
  select exists (
    select 1
    from auth.users u
    join public.allowlist a on lower(a.email) = lower(u.email)
    where u.id = p_profile_id and u.email_confirmed_at is not null
  )
$$;

create or replace function public.qv_allow_signup()
returns trigger
language plpgsql
security definer
set search_path = public, auth, pg_temp
as $$
begin
  if new.email is null or not exists (
    select 1 from public.allowlist where lower(email) = lower(new.email)
  ) then
    raise exception 'This email is not approved for QuoteVault' using errcode = '42501';
  end if;
  return new;
end;
$$;

create or replace function public.qv_sync_profile()
returns trigger
language plpgsql
security definer
set search_path = public, auth, pg_temp
as $$
begin
  insert into public.profiles (id, first_name, last_name)
  values (
    new.id,
    left(coalesce(new.raw_user_meta_data->>'first_name', ''), 100),
    left(coalesce(new.raw_user_meta_data->>'last_name', ''), 100)
  )
  on conflict (id) do update
  set first_name = excluded.first_name,
      last_name = excluded.last_name;
  return new;
end;
$$;

-- Replace the inspected legacy QuoteVault profile hooks, preserving unrelated auth triggers.
do $$
begin
  if exists (select 1 from pg_trigger where tgrelid = 'auth.users'::regclass
      and tgname = 'on_auth_user_created' and tgfoid = to_regprocedure('public.handle_new_user()')) then
    drop trigger on_auth_user_created on auth.users;
  end if;
  if exists (select 1 from pg_trigger where tgrelid = 'auth.users'::regclass
      and tgname = 'on_auth_user_updated' and tgfoid = to_regprocedure('public.handle_user_update()')) then
    drop trigger on_auth_user_updated on auth.users;
  end if;
end;
$$;

drop trigger if exists qv_allow_signup_before_insert on auth.users;
create trigger qv_allow_signup_before_insert
before insert on auth.users
for each row execute function public.qv_allow_signup();

drop trigger if exists qv_sync_profile_after_change on auth.users;
create trigger qv_sync_profile_after_change
after insert or update of raw_user_meta_data on auth.users
for each row execute function public.qv_sync_profile();

-- Bring existing auth users into profiles without requiring metadata edits.
insert into public.profiles (id, first_name, last_name)
select u.id,
       left(coalesce(u.raw_user_meta_data->>'first_name', ''), 100),
       left(coalesce(u.raw_user_meta_data->>'last_name', ''), 100)
from auth.users u
on conflict (id) do update
set first_name = case when excluded.first_name <> '' then excluded.first_name else public.profiles.first_name end,
    last_name = case when excluded.last_name <> '' then excluded.last_name else public.profiles.last_name end;

create or replace function public.qv_bump_revision()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  update public.vault_state set revision = revision + 1 where singleton;
  return coalesce(new, old);
end;
$$;

drop trigger if exists qv_quotes_bump_revision on public.quotes;
create trigger qv_quotes_bump_revision
after insert or update or delete on public.quotes
for each row execute function public.qv_bump_revision();

create or replace function public.qv_valid_quote(p_quote jsonb, p_actor uuid, p_generation uuid)
returns boolean
language plpgsql
immutable
set search_path = public, pg_temp
as $quote_validator$
declare
  cipher jsonb;
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
      and left(p_quote->>'text', 7) = '$$E2E$$') is not true then
    return false;
  end if;

  cipher := substring(p_quote->>'text' from 8)::jsonb;
  if public.qv_valid_verifier(cipher) is not true then
    return false;
  end if;
  if p_quote->>'quote_date' is not null then
    perform (p_quote->>'quote_date')::date;
  end if;
  perform (p_quote->>'created_at')::timestamptz;
  return true;
exception when invalid_text_representation or invalid_datetime_format or datetime_field_overflow then
  return false;
end;
$quote_validator$;

create or replace function public.get_vault_state()
returns jsonb
language plpgsql
stable
security definer
set search_path = public, pg_temp
as $$
declare
  state public.vault_state%rowtype;
begin
  if not public.qv_is_member() then
    raise exception 'QuoteVault membership is required' using errcode = '42501';
  end if;
  select * into state from public.vault_state where singleton;
  return jsonb_build_object(
    'generation', state.generation,
    'kdf', state.kdf,
    'verifier', state.verifier,
    'legacy_generation', state.legacy_generation
  );
end;
$$;

create or replace function public.sync_quotes(
  p_generation uuid,
  p_revision bigint,
  p_operations jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  state public.vault_state%rowtype;
  op jsonb;
  op_id uuid;
  quote_id uuid;
  op_id_text text;
  quote_id_text text;
  action text;
  caller_id uuid := auth.uid();
  owner_id uuid;
  digest_text text;
  receipt public.vault_operation_receipts%rowtype;
  result jsonb;
  results jsonb := '[]'::jsonb;
  changed boolean := false;
  valid_operation boolean;
  rows_deleted integer;
begin
  if not public.qv_is_member() then
    raise exception 'QuoteVault membership is required' using errcode = '42501';
  end if;
  if ((p_revision is null or p_revision >= 0)
      and jsonb_typeof(p_operations) = 'array'
      and jsonb_array_length(p_operations) <= 50) is not true then
    raise exception 'Invalid sync request' using errcode = '22023';
  end if;

  select * into state from public.vault_state where singleton for update;
  if p_generation is distinct from state.generation then
    for op in select value from jsonb_array_elements(p_operations) loop
      results := results || jsonb_build_array(jsonb_build_object(
        'operation_id', op->>'operation_id', 'status', 'rejected', 'error', 'stale vault generation'
      ));
    end loop;
    return jsonb_build_object(
      'generation', state.generation,
      'revision', state.revision,
      'results', results,
      'quotes', (select coalesce(jsonb_agg(to_jsonb(q) order by q.created_at, q.id), '[]'::jsonb) from public.quotes q)
    );
  end if;

  for op in select value from jsonb_array_elements(p_operations) loop
    op_id_text := op->>'operation_id';
    quote_id_text := op->>'quote_id';
    action := op->>'action';
    valid_operation := jsonb_typeof(op) = 'object'
      and op_id_text ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'
      and quote_id_text ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'
      and action in ('INSERT', 'DELETE')
      and op->>'actor_id' = caller_id::text
      and op->>'vault_generation' = state.generation::text;

    if valid_operation is not true then
      results := results || jsonb_build_array(jsonb_build_object(
        'operation_id', op_id_text, 'status', 'rejected', 'error', 'invalid operation'
      ));
      continue;
    end if;

    op_id := op_id_text::uuid;
    quote_id := quote_id_text::uuid;
    digest_text := encode(sha256(convert_to(op::text, 'UTF8')), 'hex');
    select * into receipt
    from public.vault_operation_receipts
    where vault_operation_receipts.operation_id = op_id
      and vault_operation_receipts.actor_id = caller_id;

    if found then
      if receipt.generation = state.generation and receipt.request_digest = digest_text then
        results := results || jsonb_build_array(receipt.result);
      else
        results := results || jsonb_build_array(jsonb_build_object(
          'operation_id', op_id, 'status', 'rejected', 'error', 'operation id already used'
        ));
      end if;
      continue;
    end if;

    result := null;
    begin
      if action = 'INSERT' then
        if (op->>'quote_id' = op->'payload'->>'id') is not true
           or public.qv_valid_quote(op->'payload', caller_id, state.generation) is not true then
          result := jsonb_build_object('operation_id', op_id, 'status', 'rejected', 'error', 'invalid encrypted quote');
        else
          insert into public.quotes (id, text, author, context, quote_date, created_at, user_id, vault_generation)
          values (
            quote_id,
            op->'payload'->>'text',
            op->'payload'->>'author',
            op->'payload'->>'context',
            (op->'payload'->>'quote_date')::date,
            (op->'payload'->>'created_at')::timestamptz,
            caller_id,
            state.generation
          );
          result := jsonb_build_object('operation_id', op_id, 'status', 'ok');
          changed := true;
        end if;
      else
        select user_id into owner_id from public.quotes where id = quote_id for update;
        if found and owner_id is distinct from caller_id and public.qv_is_admin() is not true then
          result := jsonb_build_object('operation_id', op_id, 'status', 'rejected', 'error', 'only the creator or admin may delete this quote');
        else
          delete from public.quotes where id = quote_id;
          get diagnostics rows_deleted = row_count;
          result := jsonb_build_object('operation_id', op_id, 'status', 'ok');
          changed := changed or rows_deleted > 0;
        end if;
      end if;
    exception
      when unique_violation or check_violation or not_null_violation or foreign_key_violation or string_data_right_truncation then
        result := jsonb_build_object('operation_id', op_id, 'status', 'rejected', 'error', 'operation violates vault data constraints');
    end;

    insert into public.vault_operation_receipts (operation_id, actor_id, generation, request_digest, result)
    values (op_id, caller_id, state.generation, digest_text, result);
    results := results || jsonb_build_array(result);
  end loop;

  select * into state from public.vault_state where singleton;
  return jsonb_build_object(
    'generation', state.generation,
    'revision', state.revision,
    'results', results,
    'quotes', case when changed or p_revision is distinct from state.revision then
      (select coalesce(jsonb_agg(to_jsonb(q) order by q.created_at, q.id), '[]'::jsonb) from public.quotes q)
    else null end
  );
end;
$$;

create or replace function public.rotate_vault(
  p_expected_generation uuid,
  p_kdf jsonb,
  p_verifier jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $init$
declare
  state public.vault_state%rowtype;
begin
  if public.qv_is_admin() is not true then
    raise exception 'QuoteVault administrator access is required' using errcode = '42501';
  end if;
  if public.qv_valid_kdf(p_kdf) is not true or public.qv_valid_verifier(p_verifier) is not true then
    raise exception 'Invalid vault cryptography metadata' using errcode = '22023';
  end if;
  select * into state from public.vault_state where singleton for update;
  if p_expected_generation is null or state.generation is distinct from p_expected_generation then
    raise exception 'Vault generation changed; reload before rotating' using errcode = '40001';
  end if;
  delete from public.vault_operation_receipts;
  delete from public.quotes;
  update public.vault_state
  set generation = gen_random_uuid(),
      revision = revision + 1,
      kdf = jsonb_build_object('salt', p_kdf->>'salt', 'iterations', (p_kdf->>'iterations')::integer),
      verifier = jsonb_build_object('iv', p_verifier->>'iv', 'data', p_verifier->>'data'),
      legacy_generation = null
  where singleton
  returning * into state;
  return jsonb_build_object(
    'generation', state.generation, 'revision', state.revision,
    'kdf', state.kdf, 'verifier', state.verifier, 'legacy_generation', state.legacy_generation
  );
end;
$init$;

create or replace function public.initialize_vault(
  p_expected_generation uuid,
  p_kdf jsonb,
  p_verifier jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $initializer$
declare
  state public.vault_state%rowtype;
begin
  if public.qv_is_admin() is not true then
    raise exception 'QuoteVault administrator access is required' using errcode = '42501';
  end if;
  if public.qv_valid_kdf(p_kdf) is not true or public.qv_valid_verifier(p_verifier) is not true then
    raise exception 'Invalid vault cryptography metadata' using errcode = '22023';
  end if;
  select * into state from public.vault_state where singleton for update;
  if p_expected_generation is null or state.generation is distinct from p_expected_generation then
    raise exception 'Vault generation changed; reload before initializing' using errcode = '40001';
  end if;
  if state.verifier is not null then
    raise exception 'Vault is already initialized' using errcode = '23505';
  end if;
  if exists (select 1 from public.quotes where text like '$$E2E$$%') then
    raise exception 'Encrypted quotes exist; initialize would not be safe' using errcode = '23514';
  end if;
  update public.vault_state
  set generation = gen_random_uuid(),
      revision = revision + 1,
      kdf = jsonb_build_object('salt', p_kdf->>'salt', 'iterations', (p_kdf->>'iterations')::integer),
      verifier = jsonb_build_object('iv', p_verifier->>'iv', 'data', p_verifier->>'data'),
      legacy_generation = null
  where singleton
  returning * into state;
  update public.quotes set vault_generation = state.generation;
  select * into state from public.vault_state where singleton;
  delete from public.app_settings where key = 'vault_key_hash';
  return jsonb_build_object(
    'generation', state.generation, 'revision', state.revision,
    'kdf', state.kdf, 'verifier', state.verifier, 'legacy_generation', state.legacy_generation
  );
end;
$initializer$;

alter table public.quotes enable row level security;
alter table public.profiles enable row level security;
alter table public.allowlist enable row level security;
alter table public.app_settings enable row level security;
alter table public.vault_state enable row level security;
alter table public.vault_operation_receipts enable row level security;

do $$
declare
  policy_record record;
begin
  for policy_record in
    select schemaname, tablename, policyname
    from pg_policies
    where schemaname = 'public'
      and tablename in ('quotes', 'profiles', 'allowlist', 'app_settings', 'vault_state', 'vault_operation_receipts')
  loop
    execute format('drop policy if exists %I on %I.%I', policy_record.policyname, policy_record.schemaname, policy_record.tablename);
  end loop;
end;
$$;

create policy qv_member_profiles_select on public.profiles
for select to authenticated using (public.qv_is_member() and public.qv_is_active_profile(id));

create policy qv_member_quotes_select on public.quotes
for select to authenticated using (public.qv_is_member());

create policy qv_admin_allowlist_select on public.allowlist
for select to authenticated using (public.qv_is_admin());
create policy qv_admin_allowlist_insert on public.allowlist
for insert to authenticated with check (public.qv_is_admin());
create policy qv_admin_allowlist_update on public.allowlist
for update to authenticated using (public.qv_is_admin()) with check (public.qv_is_admin());
create policy qv_admin_allowlist_delete on public.allowlist
for delete to authenticated using (public.qv_is_admin());

revoke all on table public.quotes, public.app_settings, public.vault_state, public.vault_operation_receipts from public, anon, authenticated;
revoke all on table public.profiles from public, anon, authenticated;
revoke all on table public.allowlist from public, anon, authenticated;
grant select on table public.profiles to authenticated;
grant select on table public.quotes to authenticated;
grant select, insert, update, delete on table public.allowlist to authenticated;

revoke all on function public.qv_valid_kdf(jsonb) from public;
revoke all on function public.qv_valid_verifier(jsonb) from public;
revoke all on function public.qv_legacy_verifier() from public;
revoke all on function public.qv_is_member() from public;
revoke all on function public.qv_is_admin() from public;
revoke all on function public.qv_is_active_profile(uuid) from public;
revoke all on function public.qv_allow_signup() from public;
revoke all on function public.qv_sync_profile() from public;
revoke all on function public.qv_bump_revision() from public;
revoke all on function public.qv_valid_quote(jsonb, uuid, uuid) from public;
revoke all on function public.get_vault_state() from public;
revoke all on function public.sync_quotes(uuid, bigint, jsonb) from public;
revoke all on function public.rotate_vault(uuid, jsonb, jsonb) from public;
revoke all on function public.initialize_vault(uuid, jsonb, jsonb) from public;
grant execute on function public.get_vault_state() to authenticated;
grant execute on function public.sync_quotes(uuid, bigint, jsonb) to authenticated;
grant execute on function public.rotate_vault(uuid, jsonb, jsonb) to authenticated;
grant execute on function public.initialize_vault(uuid, jsonb, jsonb) to authenticated;
grant execute on function public.qv_is_member() to authenticated;
grant execute on function public.qv_is_admin() to authenticated;
grant execute on function public.qv_is_active_profile(uuid) to authenticated;

do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (
       select 1 from pg_publication_tables
       where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'quotes'
     ) then
    alter publication supabase_realtime add table public.quotes;
  end if;
end;
$$;

commit;
