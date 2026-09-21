-- Run with psql in a NEW EMPTY DISPOSABLE DATABASE. This creates test fixtures.
\ir database-fixture.sql
insert into auth.users(instance_id,id,aud,role,email,encrypted_password,email_confirmed_at,raw_user_meta_data) values
 ('00000000-0000-0000-0000-000000000000','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','authenticated','authenticated','darkmgdevelopment@gmail.com','not-used',now(),'{}');
insert into public.allowlist values('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','darkmgdevelopment@gmail.com',now());
insert into public.profiles values('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','Existing','Name');
insert into public.app_settings values('vault_key_hash','legacy-test-hash');
insert into public.quotes values
 ('11111111-1111-4111-8111-111111111111','$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}','ENCRYPTED','ENCRYPTED',current_date,now(),'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'),
 ('22222222-2222-4222-8222-222222222222','Legacy plaintext','Existing Name','Legacy context',current_date,now(),'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa');
create temp table original_quotes as select id,text,author,context,quote_date,created_at,user_id from public.quotes;
\ir ../supabase/migrations/20260920000000_secure_vault.sql

do $test$ begin
  if (select count(*) from public.quotes) <> 2
     or exists(select * from original_quotes except select id,text,author,context,quote_date,created_at,user_id from public.quotes)
     or exists(select 1 from public.app_settings where key='vault_key_hash')
     or not exists(select 1 from public.vault_state where legacy_generation=generation and kdf->>'iterations'='100000'
        and verifier='{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb)
     or not exists(select 1 from public.profiles where first_name='Existing' and last_name='Name')
     or exists(select 1 from pg_policies where policyname='legacy_allow_all') then
    raise exception 'Legacy migration lost data, names, derivation, or permission safety';
  end if;
end $test$;
select set_config('request.jwt.claim.sub','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',false);
create temp table rotated_state as select public.rotate_vault(
 (select generation from public.vault_state),
 '{"salt":"MDEyMzQ1Njc4OWFiY2RlZg==","iterations":600000}',
 '{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}') as state;
\ir ../supabase/migrations/20260920000000_secure_vault.sql

do $$ begin
 if not exists(select 1 from public.vault_state v, rotated_state r
     where v.generation=(r.state->>'generation')::uuid and v.legacy_generation is null
       and v.kdf=r.state->'kdf' and v.verifier=r.state->'verifier') then
   raise exception 'Migration rerun re-enabled legacy adoption or changed rotated cryptography';
 end if;
end $$;
