-- Disposable PostgreSQL/Supabase-shaped baseline for tests/database.sql.
-- Run only in an empty test database as its owner.

do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then create role anon; end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then create role authenticated; end if;
end;
$$;

create schema auth;
create function auth.uid()
returns uuid language sql stable
as $$ select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;

create table auth.users (
  instance_id uuid not null,
  id uuid primary key,
  aud text not null,
  role text not null,
  email text not null unique,
  encrypted_password text not null,
  email_confirmed_at timestamptz,
  raw_app_meta_data jsonb not null default '{}'::jsonb,
  raw_user_meta_data jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.quotes (
  id uuid primary key,
  text text not null,
  author text not null,
  context text not null,
  quote_date date not null,
  created_at timestamptz not null,
  user_id uuid
);
create table public.profiles (id uuid primary key, first_name text not null, last_name text not null);
create table public.allowlist (id uuid primary key, email text not null unique, created_at timestamptz not null);
create table public.app_settings (key text primary key, value text not null);

-- Proves the migration removes pre-existing permissive RLS policies.
alter table public.quotes enable row level security;
create policy legacy_allow_all on public.quotes for select using (true);

grant usage on schema public, auth to authenticated;
grant execute on function auth.uid() to authenticated;
