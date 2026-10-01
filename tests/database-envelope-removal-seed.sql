-- Committed fixture for the envelope removal test: shared-key data plus device records.
begin;
insert into public.allowlist(id,email,created_at) values
 ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','darkmgdevelopment@gmail.com',now()),
 ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','removal-member@example.invalid',now());
insert into auth.users(instance_id,id,aud,role,email,encrypted_password,email_confirmed_at) values
 (gen_random_uuid(),'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','authenticated','authenticated','darkmgdevelopment@gmail.com','x',now()),
 (gen_random_uuid(),'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','authenticated','authenticated','removal-member@example.invalid','x',now());
update public.vault_state set envelope_status='legacy',prepared_generation=null,active_migration_id=null,
  verifier='{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}' where singleton;
insert into public.quotes(id,text,author,context,quote_date,created_at,user_id,vault_generation)
select gen_random_uuid(),'$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"'||lpad(i::text,22,'A')||'"}','ENCRYPTED','ENCRYPTED',date '2026-09-20',now(),
  'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',(select generation from public.vault_state where singleton) from generate_series(1,25) i;
insert into public.vault_devices(id,owner_id,status,request_kind,enrollment_fingerprint,public_jwk,public_key_fingerprint,authorization_token_digest,label,protection_mode,protection,encrypted_private_bundle,lease_expires_at)
select '11111111-1111-4111-8111-111111111111','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','active','first',d,j,public.qv_public_key_fingerprint(j),d,'removal','remembered','{"version":1,"mode":"remembered"}'::jsonb,'{"version":2,"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb,now()+interval '1 day'
from (select 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'::text d,
             jsonb_build_object('kty','RSA','n',rtrim(replace(replace(replace(encode(decode('80'||repeat('00',383),'hex'),'base64'),E'\n',''),'+','-'),'/','_'),'='),'e','AQAB') j) x;
create schema qv_removal_check;
create table qv_removal_check.expected as select
  (select md5(string_agg(q::text, ',' order by q.id)) from public.quotes q) as quotes,
  (select md5(row(s.singleton,s.generation,s.revision,s.kdf,s.verifier,s.legacy_generation)::text) from public.vault_state s) as vault_state,
  (select md5(string_agg(a::text, ',' order by a.id)) from public.allowlist a) as allowlist,
  (select md5(coalesce(string_agg(p::text, ',' order by p.id), '')) from public.profiles p) as profiles;
commit;
