-- Regressions for the 2026-09-23 audit fixes.
begin;

do $test$
declare
  admin_id uuid := 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  member_id uuid := 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  other_id uuid := 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  admin_device uuid := '11111111-1111-4111-8111-111111111111';
  member_device uuid := '22222222-2222-4222-8222-222222222222';
  other_device uuid := '33333333-3333-4333-8333-333333333333';
  member_recovery uuid := '55555555-5555-4555-8555-555555555555';
  target uuid := '77777777-7777-4777-8777-777777777777';
  g uuid := (select generation from public.vault_state where singleton);
  token text := 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
  digest text := rtrim(replace(replace(replace(encode(sha256(decode(token || '=', 'base64')), 'base64'), E'\n', ''), '+', '-'), '/', '_'), '=');
  jwk jsonb := jsonb_build_object('kty', 'RSA', 'n', rtrim(replace(replace(replace(encode(decode('80' || repeat('00', 383), 'hex'), 'base64'), E'\n', ''), '+', '-'), '/', '_'), '='), 'e', 'AQAB');
  bundle jsonb := jsonb_build_object('version', 2, 'iv', 'AAAAAAAAAAAAAAAA', 'data', 'AAAAAAAAAAAAAAAAAAAAAA==');
  verifier jsonb := '{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}';
  migration jsonb;
  r0 bigint;
begin
  insert into public.allowlist(id,email,created_at) values
    (admin_id,'darkmgdevelopment@gmail.com',now()),(member_id,'member@example.invalid',now()),(other_id,'other@example.invalid',now());
  insert into auth.users(instance_id,id,aud,role,email,encrypted_password,email_confirmed_at) values
    (gen_random_uuid(),admin_id,'authenticated','authenticated','darkmgdevelopment@gmail.com','x',now()),
    (gen_random_uuid(),member_id,'authenticated','authenticated','member@example.invalid','x',now()),
    (gen_random_uuid(),other_id,'authenticated','authenticated','other@example.invalid','x',now());
  insert into public.vault_devices(id,owner_id,status,request_kind,enrollment_fingerprint,public_jwk,public_key_fingerprint,authorization_token_digest,label,protection_mode,protection,encrypted_private_bundle,lease_expires_at,last_sync_at)
  select id,owner_id,'active','first',digest,jwk,public.qv_public_key_fingerprint(jwk),digest,'audit','remembered','{"version":1,"mode":"remembered"}'::jsonb,bundle,now()+interval '1 day',now()-interval '2 hours'
  from (values(admin_device,admin_id),(member_device,member_id),(other_device,other_id)) d(id,owner_id);
  insert into public.vault_recovery_keys(id,owner_id,status,public_jwk,public_key_fingerprint,encrypted_private_key,kdf,confirmed_at)
  values(member_recovery,member_id,'active',jwk,public.qv_public_key_fingerprint(jwk),bundle,'{"version":1,"salt":"MDEyMzQ1Njc4OWFiY2RlZg==","iterations":600000}'::jsonb,now());

  -- A legacy vault that was initialized or rotated has no legacy_generation.
  update public.vault_state set legacy_generation=null where singleton;
  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  migration := public.prepare_envelope_migration(g,(select revision from public.vault_state),null,null,target,verifier);
  if public.qv_envelope_legacy_mode() is not true or public.sync_quotes(g,null,'[]',null,null) is null or public.get_vault_state(null,null) is null then
    raise exception 'initial migration of an initialized legacy vault lost legacy access';
  end if;

  -- Another member cannot refresh a device's sync time without its token.
  perform set_config('request.jwt.claim.sub',member_id::text,true);
  perform public.sync_quotes(g,null,'[]',admin_device,'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB');
  if (select last_sync_at > now()-interval '1 minute' from public.vault_devices where id=admin_device) then
    raise exception 'a member refreshed another device''s sync time';
  end if;
  perform public.sync_quotes(g,null,'[]',member_device,token);
  if (select last_sync_at < now()-interval '1 minute' from public.vault_devices where id=member_device) then
    raise exception 'an authorized device sync did not refresh its sync time';
  end if;

  -- Attestations: owners attest their own records, admins any; others are ignored.
  insert into public.vault_device_wrappers(device_id,generation,purpose,wrapped_key) values
    (member_device,target,'active',repeat('A',512)),(other_device,target,'active',repeat('A',512));
  insert into public.vault_recovery_wrappers(recovery_key_id,generation,wrapped_key) values(member_recovery,target,repeat('A',512));
  perform public.attest_vault_keys(member_device,token,target,jsonb_build_array(jsonb_build_object('device_id',member_device,'attestation',verifier),jsonb_build_object('device_id',other_device,'attestation',verifier)),jsonb_build_array(jsonb_build_object('recovery_key_id',member_recovery,'attestation',verifier)));
  if (select attestation from public.vault_device_wrappers where device_id=member_device and generation=target) is distinct from verifier
     or (select attestation from public.vault_recovery_wrappers where recovery_key_id=member_recovery and generation=target) is distinct from verifier
     or (select attestation from public.vault_device_wrappers where device_id=other_device and generation=target) is not null then
    raise exception 'attestation ownership was not enforced';
  end if;
  begin
    perform public.attest_vault_keys(member_device,'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',target,'[]','[]');
    raise exception 'attestation accepted a wrong device token';
  exception when sqlstate '42501' then null; end;
  begin
    perform public.attest_vault_keys(member_device,token,target,jsonb_build_array(jsonb_build_object('device_id',member_device,'attestation','{"iv":"x"}'::jsonb)),'[]');
    raise exception 'attestation accepted a malformed value';
  exception when sqlstate '22023' then null; end;
  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  perform public.attest_vault_keys(admin_device,token,target,jsonb_build_array(jsonb_build_object('device_id',other_device,'attestation',verifier)),'[]');
  if (select attestation from public.vault_device_wrappers where device_id=other_device and generation=target) is distinct from verifier then
    raise exception 'an administrator could not attest a staged wrapper';
  end if;

  -- A member holding the prepared key cannot be removed while it can activate.
  begin
    perform public.remove_member_access(member_id,admin_device,token);
    raise exception 'member holding the prepared key was removed during preparation';
  exception when sqlstate '40001' then null; end;

  -- Abandon never reuses a revision observed during preparation.
  update public.vault_state set revision=revision+1 where singleton;
  r0 := (select revision from public.vault_state);
  perform public.abandon_envelope_migration((select active_migration_id from public.vault_state),null,null);
  if (select revision from public.vault_state) <= r0 then
    raise exception 'abandon moved the revision backwards';
  end if;
  if public.remove_member_access(member_id,admin_device,token)->>'status' <> 'removed' then
    raise exception 'member removal failed after abandon';
  end if;

  -- Lease renewal keeps working in maintenance, including its sync timestamp.
  update public.vault_devices set last_sync_at=now()-interval '1 hour' where id=admin_device;
  update public.vault_state set envelope_status='maintenance' where singleton;
  if public.renew_device_lease(admin_device,token) is null then
    raise exception 'maintenance blocked lease renewal';
  end if;
end $test$;

rollback;

-- Recovery runs where hosted Supabase installs pgcrypto.
begin;
create schema if not exists extensions;
alter extension pgcrypto set schema extensions;
do $test$
declare
  owner_id uuid := 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  jwk jsonb := jsonb_build_object('kty','RSA','n',rtrim(replace(replace(replace(encode(decode('80'||repeat('00',383),'hex'),'base64'),E'\n',''),'+','-'),'/','_'),'='),'e','AQAB');
begin
  insert into public.allowlist(id,email,created_at) values (owner_id,'darkmgdevelopment@gmail.com',now());
  insert into auth.users(instance_id,id,aud,role,email,encrypted_password,email_confirmed_at) values (gen_random_uuid(),owner_id,'authenticated','authenticated','darkmgdevelopment@gmail.com','x',now());
  insert into public.vault_recovery_keys(id,owner_id,status,public_jwk,public_key_fingerprint,encrypted_private_key,kdf,confirmed_at)
    values (gen_random_uuid(),owner_id,'active',jwk,public.qv_public_key_fingerprint(jwk),jsonb_build_object('version',2,'iv','AAAAAAAAAAAAAAAA','data','AAAAAAAAAAAAAAAAAAAAAA=='),'{"version":1,"salt":"MDEyMzQ1Njc4OWFiY2RlZg==","iterations":600000}'::jsonb,now());
  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  if public.begin_recovery(owner_id) is null then raise exception 'recovery challenge was not issued'; end if;
end $test$;
rollback;

-- A member revokes another of their devices with the acting device's own token.
begin;
do $test$
declare
  owner uuid := 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  stranger uuid := 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  acting uuid := '11111111-1111-4111-8111-111111111111';
  target uuid := '22222222-2222-4222-8222-222222222222';
  foreign_device uuid := '33333333-3333-4333-8333-333333333333';
  acting_token text := rtrim(replace(replace(encode(decode(repeat('00',32),'hex'),'base64'),'+','-'),'/','_'),'=');
  jwk jsonb := jsonb_build_object('kty','RSA','n',rtrim(replace(replace(replace(encode(decode('80'||repeat('00',383),'hex'),'base64'),E'\n',''),'+','-'),'/','_'),'='),'e','AQAB');
begin
  insert into public.allowlist(id,email,created_at) values(owner,'revoke-test@example.invalid',now()),(stranger,'stranger@example.invalid',now());
  insert into auth.users(instance_id,id,aud,role,email,encrypted_password,email_confirmed_at) values
    (gen_random_uuid(),owner,'authenticated','authenticated','revoke-test@example.invalid','x',now()),
    (gen_random_uuid(),stranger,'authenticated','authenticated','stranger@example.invalid','x',now());
  insert into public.vault_devices(id,owner_id,status,request_kind,enrollment_fingerprint,public_jwk,public_key_fingerprint,authorization_token_digest,label,protection_mode,protection,encrypted_private_bundle,lease_expires_at)
  select id,device_owner,'active','first',rtrim(replace(replace(encode(sha256(decode(repeat(byte,32),'hex')),'base64'),'+','-'),'/','_'),'='),jwk,public.qv_public_key_fingerprint(jwk),
    rtrim(replace(replace(encode(sha256(decode(repeat(byte,32),'hex')),'base64'),'+','-'),'/','_'),'='),
    'audit','remembered','{"version":1,"mode":"remembered"}'::jsonb,'{"version":2,"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb,now()+interval '1 day'
  from (values(acting,owner,'00'),(target,owner,'01'),(foreign_device,stranger,'02')) d(id,device_owner,byte);
  update public.vault_state set envelope_status='active' where singleton;
  perform set_config('request.jwt.claim.sub',owner::text,true);
  if public.revoke_own_device(acting,acting_token,foreign_device) is not null then
    raise exception 'a member revoked another member''s device';
  end if;
  if (select status from public.vault_devices where id=foreign_device)<>'active' then
    raise exception 'a member revoked another member''s device';
  end if;
  if public.revoke_own_device(target,acting_token) is not null then
    raise exception 'a device token authorized a different device';
  end if;
  if public.revoke_own_device(acting,acting_token,target)->>'status'<>'revoked' then
    raise exception 'a member could not revoke their other device';
  end if;
  if (select status from public.vault_devices where id=target)<>'revoked' then
    raise exception 'a member could not revoke their other device';
  end if;
  if public.revoke_own_device(acting,acting_token)->>'status'<>'revoked' then
    raise exception 'self-revocation no longer works';
  end if;
end $test$;
rollback;
