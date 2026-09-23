-- Conversion wrappers and removal must not preserve old-generation writes.
begin;

do $test$
declare
  admin_id uuid := 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  member_id uuid := 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  rotating_member_id uuid := 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  admin_device uuid := '11111111-1111-4111-8111-111111111111';
  member_device uuid := '22222222-2222-4222-8222-222222222222';
  member_pending uuid := '23232323-2323-4232-8232-232323232323';
  admin_pending uuid := '24242424-2424-4242-8242-242424242424';
  rotating_device uuid := '33333333-3333-4333-8333-333333333333';
  admin_recovery uuid := '44444444-4444-4444-8444-444444444444';
  member_recovery uuid := '55555555-5555-4555-8555-555555555555';
  rotating_recovery uuid := '56565656-5656-4656-8656-565656565656';
  old_generation uuid := '66666666-6666-4666-8666-666666666666';
  rotation_generation uuid := '77777777-7777-4777-8777-777777777777';
  cutover_generation uuid := '88888888-8888-4888-8888-888888888888';
  source_generation uuid := (select generation from public.vault_state where singleton);
  active_generation uuid := '99999999-9999-4999-8999-999999999999';
  token text := 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
  digest text := rtrim(replace(replace(replace(encode(sha256(decode(token || '=', 'base64')), 'base64'), E'\n', ''), '+', '-'), '/', '_'), '=');
  jwk jsonb := jsonb_build_object('kty', 'RSA', 'n', rtrim(replace(replace(replace(encode(decode('80' || repeat('00', 383), 'hex'), 'base64'), E'\n', ''), '+', '-'), '/', '_'), '='), 'e', 'AQAB');
  bundle jsonb := jsonb_build_object('version', 2, 'iv', 'AAAAAAAAAAAAAAAA', 'data', 'AAAAAAAAAAAAAAAAAAAAAA==');
  verifier jsonb := jsonb_build_object('iv', 'AAAAAAAAAAAAAAAA', 'data', 'AAAAAAAAAAAAAAAAAAAAAA==');
  passkey_protection jsonb := jsonb_build_object('version',1,'rpId','quotes.darkmg1.dev','credentialId',token,'prfSalt',token,'kdf','HKDF-SHA-256');
  response jsonb;
  migration_id uuid;
  legacy_migration_id uuid;
  cutover_migration uuid;
begin
  insert into public.allowlist(id,email,created_at) values
    (admin_id,'darkmgdevelopment@gmail.com',now()),(member_id,'member@example.invalid',now()),(rotating_member_id,'rotate@example.invalid',now());
  insert into auth.users(instance_id,id,aud,role,email,encrypted_password,email_confirmed_at) values
    (gen_random_uuid(),admin_id,'authenticated','authenticated','darkmgdevelopment@gmail.com','x',now()),
    (gen_random_uuid(),member_id,'authenticated','authenticated','member@example.invalid','x',now()),
    (gen_random_uuid(),rotating_member_id,'authenticated','authenticated','rotate@example.invalid','x',now());
  insert into public.vault_devices(id,owner_id,status,request_kind,expires_at,enrollment_fingerprint,public_jwk,public_key_fingerprint,authorization_token_digest,label,protection_mode,protection,encrypted_private_bundle,lease_expires_at)
  select id,owner_id,status,'first',case when status='pending' then now()+interval '10 minutes' else null end,digest,jwk,public.qv_public_key_fingerprint(jwk),digest,'rotation test',case when id=admin_device then 'passkey-prf' else 'remembered' end,case when id=admin_device then passkey_protection else '{"version":1,"mode":"remembered"}'::jsonb end,bundle,case when status='active' then now()+interval '1 day' else null end
  from (values(admin_device,admin_id,'active'::text),(member_device,member_id,'active'::text),(member_pending,member_id,'pending'::text),(admin_pending,admin_id,'pending'::text),(rotating_device,rotating_member_id,'active'::text)) as d(id,owner_id,status);
  insert into public.vault_recovery_keys(id,owner_id,status,public_jwk,public_key_fingerprint,encrypted_private_key,kdf,confirmed_at)
  select id,owner_id,'active',jwk,public.qv_public_key_fingerprint(jwk),bundle,'{"version":1,"salt":"MDEyMzQ1Njc4OWFiY2RlZg==","iterations":600000}'::jsonb,now()
  from (values(admin_recovery,admin_id),(member_recovery,member_id),(rotating_recovery,rotating_member_id)) as r(id,owner_id);
  insert into public.vault_device_wrappers(device_id,generation,purpose,wrapped_key) values
    (admin_device,source_generation,'active',repeat('A',512)),
    (member_device,source_generation,'active',repeat('A',512)),
    (rotating_device,source_generation,'active',repeat('A',512)),
    (admin_device,old_generation,'conversion_only',repeat('A',512)),
    (member_device,old_generation,'conversion_only',repeat('A',512));
  insert into public.vault_recovery_wrappers(recovery_key_id,generation,wrapped_key) values
    (admin_recovery,source_generation,repeat('A',512)),(member_recovery,source_generation,repeat('A',512)),(rotating_recovery,source_generation,repeat('A',512));
  insert into public.vault_migrations(source_generation,target_generation,target_verifier,source_revision,expected_quote_count,status,initiating_device_id,source_state)
  values(old_generation,source_generation,verifier,0,0,'finalized',admin_device,'{}');
  insert into public.vault_migrations(source_generation,target_generation,target_verifier,source_revision,expected_quote_count,status,initiating_device_id,source_state)
  values(source_generation,active_generation,verifier,0,0,'finalized',admin_device,jsonb_build_object('envelope_status','legacy')) returning id into legacy_migration_id;
  insert into public.vault_device_wrappers(device_id,generation,purpose,wrapped_key) values
    (admin_device,active_generation,'active',repeat('A',512)),(member_device,active_generation,'active',repeat('A',512)),(rotating_device,active_generation,'active',repeat('A',512));
  insert into public.vault_recovery_wrappers(recovery_key_id,generation,wrapped_key) values
    (admin_recovery,active_generation,repeat('A',512)),(member_recovery,active_generation,repeat('A',512)),(rotating_recovery,active_generation,repeat('A',512));
  update public.vault_state set generation=active_generation,envelope_status='active' where singleton;
  insert into public.vault_recovery_challenges(recovery_key_id,expected_digest,expires_at) values(member_recovery,digest,now()+interval '1 day');

  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  if public.sync_quotes(old_generation,null,'[]'::jsonb,admin_device,token) is not null then
    raise exception 'conversion wrapper authorized an old-generation write';
  end if;
  response := public.get_conversion_wrapper(old_generation,admin_device,token);
  if (response->>'wrapped_key') is distinct from repeat('A',512) or (response->>'generation') is distinct from old_generation::text then
    raise exception 'multi-hop conversion wrapper was not available to its active device';
  end if;
  update public.vault_state set envelope_status='preparing',prepared_generation=cutover_generation where singleton;
  response := public.get_passkey_restore_devices();
  if response->>'generation' <> active_generation::text
     or response->'devices' <> jsonb_build_array(jsonb_build_object('device_id',admin_device,'protection_mode','passkey-prf','protection',passkey_protection,'public_key_fingerprint',public.qv_public_key_fingerprint(jwk),'encrypted_private_bundle',bundle,'generation',active_generation)) then
    raise exception 'retained preparation did not offer the source wrapper to a passkey device: %', response;
  end if;
  insert into public.vault_device_wrappers(device_id,generation,purpose,wrapped_key) values(admin_device,cutover_generation,'active',repeat('A',512));
  response := public.get_passkey_restore_devices();
  if response->'devices'->0->>'generation' <> cutover_generation::text then
    raise exception 'retained preparation did not prefer the staged target wrapper: %', response;
  end if;
  delete from public.vault_device_wrappers where device_id=admin_device and generation=cutover_generation and purpose='active';
  if public.get_vault_state(null,null) is not null or public.sync_quotes(active_generation,null,'[]'::jsonb,null,null) is not null
     or public.checked_import(active_generation,0,'[]'::jsonb,null,null) is not null
     or public.edit_quote(active_generation,'34343434-3434-4434-8434-343434343434','x','x',current_date,null,null) is not null
     or public.edit_quotes(active_generation,'[]'::jsonb,null,null) is not null
     or public.list_members(null,null) is not null or public.add_member('blocked@example.invalid',null,null) is not null
     or public.remove_member_access(rotating_member_id,null,null) is not null then
    raise exception 'retained preparation accepted a no-device vault or admin request';
  end if;
  begin
    perform public.rotate_vault(active_generation,'{}'::jsonb,'{}'::jsonb);
    raise exception 'retained preparation accepted legacy rotation';
  exception when sqlstate '42501' then null;
  end;
  begin
    perform public.approve_device(admin_pending,admin_id,public.qv_public_key_fingerprint(jwk),digest,repeat('A',512),cutover_generation,null,null);
    raise exception 'retained preparation accepted self bootstrap approval';
  exception when sqlstate '42501' then null;
  end;
  response := public.approve_device(admin_pending,admin_id,public.qv_public_key_fingerprint(jwk),digest,repeat('A',512),active_generation,admin_device,token);
  if response->>'status' <> 'approved' or response->>'generation' <> active_generation::text then
    raise exception 'authorized retained enrollment did not approve the source generation: %', response;
  end if;
  delete from public.vault_device_wrappers where device_id=admin_pending;
  delete from public.vault_devices where id=admin_pending;
  response := public.get_vault_bootstrap_state();
  if response ? 'kdf' or response ? 'verifier' or response ? 'legacy_generation' then
    raise exception 'retained rotation exposed a legacy bootstrap contract';
  end if;
  response := public.get_conversion_wrapper(old_generation,admin_device,token);
  if (response->>'wrapped_key') is distinct from repeat('A',512) then
    raise exception 'preparing conversion wrapper was unavailable';
  end if;
  response := public.ack_conversion_queue(old_generation,admin_device,token);
  if response->>'status' <> 'acknowledged'
     or exists(select 1 from public.vault_device_wrappers where device_id=admin_device and generation=old_generation and purpose='conversion_only') then
    raise exception 'preparing conversion queue did not remove old wrapper: %, %', response, exists(select 1 from public.vault_device_wrappers where device_id=admin_device and generation=old_generation and purpose='conversion_only');
  end if;
  insert into public.vault_device_wrappers(device_id,generation,purpose,wrapped_key) values(admin_device,old_generation,'conversion_only',repeat('A',512));
  update public.vault_state set envelope_status='active',prepared_generation=null where singleton;
  perform set_config('request.jwt.claim.sub',member_id::text,true);
  response := public.revoke_own_device(member_device,token);
  if response->>'status'<>'revoked'
     or exists(select 1 from public.vault_device_wrappers where device_id=member_device and generation=old_generation and purpose='conversion_only') then
    raise exception 'device revocation left a conversion wrapper: %, %', response, exists(select 1 from public.vault_device_wrappers where device_id=member_device and generation=old_generation and purpose='conversion_only');
  end if;
  update public.vault_devices set status='active',revoked_at=null,lease_expires_at=now()+interval '1 day' where id=member_device;
  insert into public.vault_device_wrappers(device_id,generation,purpose,wrapped_key) values(member_device,old_generation,'conversion_only',repeat('A',512));
  perform set_config('request.jwt.claim.sub',admin_id::text,true);

  insert into public.vault_migrations(source_generation,target_generation,target_verifier,source_revision,expected_quote_count,status,initiating_device_id,source_state)
  values(active_generation,cutover_generation,verifier,(select revision from public.vault_state where singleton),0,'ready',admin_device,to_jsonb((select v from public.vault_state v where singleton))) returning id into cutover_migration;
  insert into public.vault_device_wrappers(device_id,generation,purpose,wrapped_key) values
    (admin_device,cutover_generation,'active',repeat('A',512)),(member_device,cutover_generation,'active',repeat('A',512)),(rotating_device,cutover_generation,'active',repeat('A',512));
  insert into public.vault_recovery_wrappers(recovery_key_id,generation,wrapped_key) values
    (admin_recovery,cutover_generation,repeat('A',512)),(member_recovery,cutover_generation,repeat('A',512)),(rotating_recovery,cutover_generation,repeat('A',512));
  update public.vault_devices set last_sync_at=now() where status='active';
  insert into public.vault_migration_queue_reports(migration_id,device_id,reported_revision)
    select cutover_migration,id,(select revision from public.vault_state where singleton) from public.vault_devices where status='active';
  update public.vault_state set envelope_status='preparing',prepared_generation=cutover_generation,active_migration_id=cutover_migration where singleton;
  response := public.activate_envelope_migration(cutover_migration,admin_device,token);
  if response->>'status'<>'activated'
     or exists(select 1 from public.vault_device_wrappers where generation=active_generation and purpose='active')
     or (select count(*) from public.vault_device_wrappers where generation=active_generation and purpose='conversion_only')<>3 then
    raise exception 'activation did not convert every retained device wrapper: %, %, %', response, exists(select 1 from public.vault_device_wrappers where generation=active_generation and purpose='active'), (select count(*) from public.vault_device_wrappers where generation=active_generation and purpose='conversion_only');
  end if;
  response := public.rollback_envelope_migration(cutover_migration,admin_device,token);
  if response->>'status'<>'rolled_back'
     or exists(select 1 from public.vault_device_wrappers where generation=active_generation and purpose='conversion_only')
     or (select count(*) from public.vault_device_wrappers where generation=active_generation and purpose='active')<>3
     or exists(select 1 from public.vault_device_wrappers where generation=cutover_generation) then
    raise exception 'rollback did not restore active wrappers after conversion: %, %, %, %', response, exists(select 1 from public.vault_device_wrappers where generation=active_generation and purpose='conversion_only'), (select count(*) from public.vault_device_wrappers where generation=active_generation and purpose='active'), exists(select 1 from public.vault_device_wrappers where generation=cutover_generation);
  end if;

  update public.vault_migrations set status='staging' where id=legacy_migration_id;
  update public.vault_state set generation=source_generation,legacy_generation=source_generation,envelope_status='preparing',prepared_generation=active_generation,active_migration_id=legacy_migration_id where singleton;
  response := public.get_vault_bootstrap_state();
  if response ? 'kdf' is not true or response ? 'verifier' is not true or response->>'legacy_generation' <> source_generation::text then
    raise exception 'initial legacy migration lost its bootstrap contract';
  end if;
  response := public.get_passkey_restore_devices();
  if response->>'generation' <> active_generation::text or response->'devices'->0->>'generation' <> active_generation::text then
    raise exception 'initial legacy preparation did not require its staged target wrapper: %', response;
  end if;
  if public.get_vault_state(null,null) is null or public.sync_quotes(source_generation,null,'[]'::jsonb,null,null) is null or public.list_members(null,null) is null then
    raise exception 'initial legacy migration lost no-device compatibility';
  end if;
  update public.vault_migrations set status='finalized' where id=legacy_migration_id;
  update public.vault_state set generation=active_generation,envelope_status='active',prepared_generation=null,active_migration_id=null where singleton;

  response := public.remove_member_access(member_id,admin_device,token);
  if response->>'status' <> 'removed' or (select generation from public.vault_state where singleton) is distinct from active_generation
     or exists(select 1 from public.allowlist where id=member_id)
     or exists(select 1 from public.vault_devices where owner_id=member_id and status<>'revoked')
     or exists(select 1 from public.vault_device_wrappers w join public.vault_devices d on d.id=w.device_id where d.owner_id=member_id)
     or exists(select 1 from public.vault_recovery_keys where owner_id=member_id and status<>'revoked')
     or exists(select 1 from public.vault_recovery_wrappers w join public.vault_recovery_keys k on k.id=w.recovery_key_id where k.owner_id=member_id)
     or exists(select 1 from public.vault_recovery_challenges c join public.vault_recovery_keys k on k.id=c.recovery_key_id where k.owner_id=member_id) then
    raise exception 'member removal left access material or changed generation';
  end if;
  perform set_config('request.jwt.claim.sub',member_id::text,true);
  begin
    perform public.sync_quotes(active_generation,null,'[]'::jsonb,member_device,token);
    raise exception 'removed member work reached the vault';
  exception when sqlstate '42501' then null;
  end;

  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  response := public.remove_member_access(rotating_member_id,admin_device,token,true,rotation_generation,verifier);
  migration_id := (response->>'migration_id')::uuid;
  if response->>'status' <> 'removed_and_preparing_rotation'
     or migration_id is null
     or (select envelope_status from public.vault_state where singleton) <> 'preparing'
     or not exists(select 1 from public.vault_migrations m where m.id=migration_id and m.source_generation=active_generation and m.target_generation=rotation_generation) then
    raise exception 'remove-and-rotate did not reuse staged migration preparation';
  end if;
  insert into public.quotes(id,text,author,context,quote_date,created_at,user_id,vault_generation)
  values('34343434-3434-4434-8434-343434343434','$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}','ENCRYPTED','ENCRYPTED',current_date,now(),admin_id,active_generation);
end;
$test$;

set local role authenticated;
select set_config('request.jwt.claim.sub','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',true);
do $$ begin
  if exists(select 1 from public.quotes) or exists(select 1 from public.allowlist) then
    raise exception 'retained preparation direct-table RLS bypassed device authorization';
  end if;
end $$;
reset role;

rollback;
