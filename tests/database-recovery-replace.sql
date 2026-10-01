-- A member can replace an unrecorded recovery phrase while the initial migration is preparing.
begin;
do $test$
declare
  owner_id uuid := 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  device_id uuid := '11111111-1111-4111-8111-111111111111';
  old_recovery uuid := '55555555-5555-4555-8555-555555555555';
  new_recovery uuid := '66666666-6666-4666-8666-666666666666';
  target uuid := '77777777-7777-4777-8777-777777777777';
  g uuid := (select generation from public.vault_state where singleton);
  token text := 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
  digest text := rtrim(replace(replace(replace(encode(sha256(decode(token || '=', 'base64')), 'base64'), E'\n', ''), '+', '-'), '/', '_'), '=');
  jwk jsonb := jsonb_build_object('kty','RSA','n',rtrim(replace(replace(replace(encode(decode('80'||repeat('00',383),'hex'),'base64'),E'\n',''),'+','-'),'/','_'),'='),'e','AQAB');
  bundle jsonb := '{"version":2,"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}';
  kdf jsonb := '{"version":1,"salt":"MDEyMzQ1Njc4OWFiY2RlZg==","iterations":600000}';
  response jsonb;
begin
  insert into public.allowlist(id,email,created_at) values (owner_id,'darkmgdevelopment@gmail.com',now());
  insert into auth.users(instance_id,id,aud,role,email,encrypted_password,email_confirmed_at) values (gen_random_uuid(),owner_id,'authenticated','authenticated','darkmgdevelopment@gmail.com','x',now());
  update public.vault_state set legacy_generation=generation where singleton;
  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  perform public.prepare_envelope_migration(g,(select revision from public.vault_state),null,null,target,'{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb);
  insert into public.vault_devices(id,owner_id,status,request_kind,enrollment_fingerprint,public_jwk,public_key_fingerprint,authorization_token_digest,label,protection_mode,protection,encrypted_private_bundle,lease_expires_at)
    values(device_id,owner_id,'active','first',digest,jwk,public.qv_public_key_fingerprint(jwk),digest,'t','remembered','{"version":1,"mode":"remembered"}'::jsonb,bundle,now()+interval '1 day');
  insert into public.vault_device_wrappers(device_id,generation,purpose,wrapped_key) values(device_id,target,'active',repeat('A',512));
  insert into public.vault_recovery_keys(id,owner_id,status,public_jwk,public_key_fingerprint,encrypted_private_key,kdf,confirmed_at)
    values(old_recovery,owner_id,'active',jwk,public.qv_public_key_fingerprint(jwk),bundle,kdf,now());
  insert into public.vault_recovery_wrappers(recovery_key_id,generation,wrapped_key) values(old_recovery,target,repeat('A',512));

  response := public.replace_recovery_key(new_recovery,jwk,public.qv_public_key_fingerprint(jwk),bundle,kdf,target,repeat('B',512),device_id,token);
  if response is null then raise exception 'recovery replacement refused during legacy preparation'; end if;
  if (select status from public.vault_recovery_keys where id=old_recovery)<>'revoked' then raise exception 'old recovery key still active'; end if;
  if (select status from public.vault_recovery_keys where id=new_recovery)<>'active'
     or not exists(select 1 from public.vault_recovery_wrappers where recovery_key_id=new_recovery and generation=target) then
    raise exception 'new recovery key not active with a prepared wrapper';
  end if;

  -- A wrong token or a generation other than the prepared one is still refused.
  if public.replace_recovery_key(gen_random_uuid(),jwk,public.qv_public_key_fingerprint(jwk),bundle,kdf,target,repeat('C',512),device_id,'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB') is not null then raise exception 'wrong token accepted'; end if;
  if public.replace_recovery_key(gen_random_uuid(),jwk,public.qv_public_key_fingerprint(jwk),bundle,kdf,gen_random_uuid(),repeat('C',512),device_id,token) is not null then raise exception 'foreign generation accepted'; end if;
end $test$;
rollback;
