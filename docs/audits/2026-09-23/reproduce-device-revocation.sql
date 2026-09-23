-- Run only after the fixture and all migrations in a disposable local database.
-- Checks the Profile > Devices > Revoke request for a second device (fixed by 20260922140000_audit_fixes.sql).
begin;
do $test$
declare
  owner uuid := 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  current_device uuid := '11111111-1111-4111-8111-111111111111';
  target_device uuid := '22222222-2222-4222-8222-222222222222';
  token text := 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
  jwk jsonb := jsonb_build_object('kty','RSA','n',rtrim(replace(replace(replace(encode(decode('80'||repeat('00',383),'hex'),'base64'),E'\n',''),'+','-'),'/','_'),'='),'e','AQAB');
  bundle jsonb := '{"version":2,"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}';
  g uuid := (select generation from public.vault_state where singleton);
  response jsonb;
begin
  insert into public.allowlist(id,email,created_at) values(owner,'revoke-test@example.invalid',now());
  insert into auth.users(instance_id,id,aud,role,email,encrypted_password,email_confirmed_at)
    values(gen_random_uuid(),owner,'authenticated','authenticated','revoke-test@example.invalid','synthetic',now());
  insert into public.vault_devices(id,owner_id,status,request_kind,enrollment_fingerprint,public_jwk,public_key_fingerprint,authorization_token_digest,label,protection_mode,protection,encrypted_private_bundle,lease_expires_at)
    select id,owner,'active','first',token,jwk,public.qv_public_key_fingerprint(jwk),
      rtrim(replace(replace(encode(sha256(decode(repeat(case when id=current_device then '00' else '01' end,32),'hex')),'base64'),'+','-'),'/','_'),'='),
      'Synthetic device','remembered','{"version":1,"mode":"remembered"}'::jsonb,bundle,now()+interval '1 day'
    from (values(current_device),(target_device)) devices(id);
  update public.vault_state set envelope_status='active' where singleton;
  perform set_config('request.jwt.claim.sub',owner::text,true);
  if public.qv_authorize_device(current_device,token,g,'revoke') is null then
    raise exception 'Fixture current device is not authorized';
  end if;
  if public.revoke_own_device(target_device,token) is not null then
    raise exception 'A device token authorized a different device';
  end if;
  response := public.revoke_own_device(current_device,token,target_device);
  if response->>'status' is distinct from 'revoked' then
    raise exception 'QV3 still present: the acting device cannot revoke another owned device';
  end if;
  if (select status from public.vault_devices where id=target_device)<>'revoked' then
    raise exception 'QV3 still present: target remains active';
  end if;
  raise notice 'QV3 fixed: the acting device revoked another owned device';
end $test$;
rollback;
