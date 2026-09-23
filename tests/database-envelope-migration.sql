-- The migration state machine is deliberately exercised through its RPC boundary.
begin;

do $test$
declare
  admin_id uuid := 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  admin_device uuid := '11111111-1111-4111-8111-111111111111';
  member_id uuid := 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  member_device uuid := '22222222-2222-4222-8222-222222222222';
  recovery_id uuid := '55555555-5555-4555-8555-555555555555';
  admin_recovery_id uuid := '44444444-4444-4444-8444-444444444444';
  token text := 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
  source_generation uuid := (select generation from public.vault_state where singleton);
  target_generation uuid := '99999999-9999-4999-8999-999999999999';
  quote_id uuid := '66666666-6666-4666-8666-666666666666';
  migration jsonb;
  staged jsonb;
  response jsonb;
  snapshot jsonb;
  retry jsonb;
  abandoned jsonb;
  legacy_migration jsonb;
  row jsonb;
  source_revision bigint;
  cipher text := '$$E2E$${"version":2,"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}';
  bootstrap_jwk jsonb := jsonb_build_object('kty','RSA','n',rtrim(replace(replace(replace(encode(decode('80'||repeat('00',383),'hex'),'base64'),E'\n',''),'+','-'),'/','_'),'='),'e','AQAB');
  bootstrap_bundle jsonb := jsonb_build_object('version',2,'iv','AAAAAAAAAAAAAAAA','data','AAAAAAAAAAAAAAAAAAAAAA==');
  bootstrap_fingerprint text;
begin
  insert into public.allowlist(id,email,created_at) values
    (admin_id,'darkmgdevelopment@gmail.com',now()), (member_id,'member@example.invalid',now())
  on conflict do nothing;
  insert into auth.users(instance_id,id,aud,role,email,encrypted_password,email_confirmed_at) values
    (gen_random_uuid(),admin_id,'authenticated','authenticated','darkmgdevelopment@gmail.com','x',now()),
    (gen_random_uuid(),member_id,'authenticated','authenticated','member@example.invalid','x',now())
  on conflict do nothing;
  source_revision := (select revision from public.vault_state where singleton);
  bootstrap_fingerprint:=public.qv_public_key_fingerprint(bootstrap_jwk);
  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  legacy_migration := public.prepare_envelope_migration(source_generation,source_revision,null,null,'33333333-3333-4333-8333-333333333333','{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb);
  if legacy_migration->>'status'<>'staging' or (select initiating_device_id from public.vault_migrations where id=(legacy_migration->>'migration_id')::uuid) is not null
     or (select envelope_status from public.vault_state where singleton)<>'preparing' then raise exception 'legacy prepare required a device or did not prepare'; end if;
  if public.get_pending_envelope_migration(null,null)->>'migration_id'<>legacy_migration->>'migration_id' then raise exception 'device-less legacy pending status was unavailable'; end if;
  if public.sync_quotes(source_generation,source_revision,'[]'::jsonb,null,null) is null then raise exception 'preparing blocked legacy device-less sync'; end if;
  response:=public.request_device('23232323-2323-4232-8232-232323232323',member_id,'member bootstrap',bootstrap_jwk,token,bootstrap_fingerprint,rtrim(replace(replace(replace(encode(sha256(decode(token||'=', 'base64')),'base64'),E'\n',''),'+','-'),'/','_'),'='),'remembered','{"version":1,"mode":"remembered"}'::jsonb,bootstrap_bundle,'first');
  begin
    perform public.approve_device((response->>'request_id')::uuid,member_id,bootstrap_fingerprint,token,repeat('A',512),(legacy_migration->>'target_generation')::uuid,null,null);
    raise exception 'null bootstrap approver approved another member first device';
  exception when sqlstate '42501' then null;
  end;
  delete from public.vault_devices where id='23232323-2323-4232-8232-232323232323';
  response:=public.request_device('21212121-2121-4212-8212-212121212121',admin_id,'admin bootstrap',bootstrap_jwk,token,bootstrap_fingerprint,rtrim(replace(replace(replace(encode(sha256(decode(token||'=', 'base64')),'base64'),E'\n',''),'+','-'),'/','_'),'='),'remembered','{"version":1,"mode":"remembered"}'::jsonb,bootstrap_bundle,'first');
  begin
    perform public.approve_device((response->>'request_id')::uuid,admin_id,bootstrap_fingerprint,token,repeat('A',512),source_generation,null,null);
    raise exception 'null bootstrap approved a source-generation wrapper';
  exception when sqlstate '42501' then null;
  end;
  response:=public.approve_device((response->>'request_id')::uuid,admin_id,bootstrap_fingerprint,token,repeat('A',512),(legacy_migration->>'target_generation')::uuid,null,null);
  if response->>'status'<>'approved' then raise exception 'own admin first bootstrap device was rejected'; end if;
  delete from public.vault_devices where id='21212121-2121-4212-8212-212121212121';
  perform set_config('request.jwt.claim.sub',member_id::text,true);
  begin
    perform public.get_pending_envelope_migration(null,null);
    raise exception 'non-admin read device-less legacy pending migration';
  exception when sqlstate '42501' then null;
  end;
  begin
    perform public.abandon_envelope_migration((legacy_migration->>'migration_id')::uuid,null,null);
    raise exception 'non-admin abandoned device-less legacy migration';
  exception when sqlstate '42501' then null;
  end;
  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  response:=public.abandon_envelope_migration((legacy_migration->>'migration_id')::uuid,null,null);
  if response->>'status'<>'abandoned' or (select envelope_status from public.vault_state where singleton)<>'legacy' then raise exception 'device-less legacy abandonment failed'; end if;
  insert into public.vault_devices(id,owner_id,status,request_kind,enrollment_fingerprint,public_jwk,public_key_fingerprint,authorization_token_digest,label,protection_mode,protection,encrypted_private_bundle,lease_expires_at)
  select d.id,d.owner_id,'active','first',token,jwk,public.qv_public_key_fingerprint(jwk),rtrim(replace(replace(replace(encode(sha256(decode(token||'=', 'base64')),'base64'),E'\n',''),'+','-'),'/','_'),'='),'migration', 'remembered','{"version":1,"mode":"remembered"}',bundle,now()+interval '1 day'
  from (values (admin_device,admin_id),(member_device,member_id)) d(id,owner_id),
       (select jsonb_build_object('kty','RSA','n',rtrim(replace(replace(replace(encode(decode('80'||repeat('00',383),'hex'),'base64'),E'\n',''),'+','-'),'/','_'),'='),'e','AQAB') jwk,
               jsonb_build_object('version',2,'iv','AAAAAAAAAAAAAAAA','data','AAAAAAAAAAAAAAAAAAAAAA==') bundle) k
  on conflict (id) do update set status='active', lease_expires_at=excluded.lease_expires_at;
  insert into public.vault_recovery_keys(id,owner_id,status,public_jwk,public_key_fingerprint,encrypted_private_key,kdf,confirmed_at)
  select key_id,owner_id,'active',jwk,public.qv_public_key_fingerprint(jwk),bundle,
    jsonb_build_object('version',1,'salt','AAAAAAAAAAAAAAAAAAAAAA==','iterations',600000),now()
  from (values (recovery_id,member_id),(admin_recovery_id,admin_id)) owners(key_id,owner_id)
  cross join (select jsonb_build_object('kty','RSA','n',rtrim(replace(replace(replace(encode(decode('80'||repeat('00',383),'hex'),'base64'),E'\n',''),'+','-'),'/','_'),'='),'e','AQAB') jwk,
               jsonb_build_object('version',2,'iv','AAAAAAAAAAAAAAAA','data','AAAAAAAAAAAAAAAAAAAAAA==') bundle) k
  on conflict (id) do update set status='active', confirmed_at=excluded.confirmed_at;
  update public.vault_state set envelope_status='active' where singleton;
  insert into public.quotes(id,text,author,context,quote_date,created_at,user_id,vault_generation)
  values (quote_id,cipher,'ENCRYPTED','ENCRYPTED',null,'2026-09-22T12:34:56.123456Z',admin_id,source_generation)
  on conflict (id) do update set text=excluded.text, vault_generation=excluded.vault_generation;
  source_revision := (select revision from public.vault_state where singleton);
  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  begin
    perform public.prepare_envelope_migration(source_generation,source_revision+1,admin_device,token,target_generation,'{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb);
    raise exception 'prepare accepted source revision drift';
  exception when sqlstate '40001' then null;
  end;
  begin
    perform public.prepare_envelope_migration(gen_random_uuid(),source_revision,admin_device,token,target_generation,'{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb);
    raise exception 'prepare accepted source generation drift';
  exception when sqlstate '40001' then null;
  end;
  perform set_config('request.jwt.claim.sub',member_id::text,true);
  begin
    perform public.prepare_envelope_migration(source_generation,source_revision,member_device,token,target_generation,'{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb);
    raise exception 'non-admin prepared migration';
  exception when sqlstate '42501' then null;
  end;
  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  begin
    perform public.prepare_envelope_migration(source_generation,source_revision,admin_device,'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',target_generation,'{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb);
    raise exception 'wrong-token prepared migration';
  exception when sqlstate '42501' then null;
  end;
  begin
    perform public.prepare_envelope_migration(source_generation,source_revision,admin_device,token,source_generation,'{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb);
    raise exception 'prepare accepted identical generations';
  exception when sqlstate '22023' then null;
  end;
  insert into public.quotes(id,text,author,context,quote_date,created_at,user_id,vault_generation)
  values('12121212-1212-4121-8121-121212121212',cipher,'ENCRYPTED','ENCRYPTED',current_date,'2026-09-22T12:34:56.123456Z',admin_id,target_generation);
  source_revision := (select revision from public.vault_state where singleton);
  begin
    perform public.prepare_envelope_migration(source_generation,source_revision,admin_device,token,target_generation,'{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb);
    raise exception 'reused quote generation was accepted';
  exception when sqlstate '22023' then null;
  end;
  delete from public.quotes where id='12121212-1212-4121-8121-121212121212';
  source_revision := (select revision from public.vault_state where singleton);
  insert into public.vault_device_wrappers(device_id,generation,purpose,wrapped_key) values(admin_device,target_generation,'active',repeat('A',512));
  begin
    perform public.prepare_envelope_migration(source_generation,source_revision,admin_device,token,target_generation,'{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb);
    raise exception 'reused device wrapper generation was accepted';
  exception when sqlstate '22023' then null;
  end;
  delete from public.vault_device_wrappers where device_id=admin_device and generation=target_generation;
  insert into public.vault_recovery_wrappers(recovery_key_id,generation,wrapped_key) values(recovery_id,target_generation,repeat('A',512));
  begin
    perform public.prepare_envelope_migration(source_generation,source_revision,admin_device,token,target_generation,'{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb);
    raise exception 'reused recovery wrapper generation was accepted';
  exception when sqlstate '22023' then null;
  end;
  delete from public.vault_recovery_wrappers where recovery_key_id=recovery_id and generation=target_generation;
  insert into public.vault_migrations(source_generation,target_generation,target_verifier,source_revision,expected_quote_count,status,initiating_device_id,source_state)
  values(target_generation,'13131313-1313-4131-8131-131313131313','{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}',0,0,'abandoned',admin_device,'{}');
  begin
    perform public.prepare_envelope_migration(source_generation,source_revision,admin_device,token,target_generation,'{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb);
    raise exception 'prior migration source generation was accepted';
  exception when sqlstate '22023' then null;
  end;
  delete from public.vault_migrations m where m.source_generation='99999999-9999-4999-8999-999999999999' and m.target_generation='13131313-1313-4131-8131-131313131313';
  insert into public.vault_migrations(source_generation,target_generation,target_verifier,source_revision,expected_quote_count,status,initiating_device_id,source_state)
  values('14141414-1414-4141-8141-141414141414',target_generation,'{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}',0,0,'abandoned',admin_device,'{}');
  begin
    perform public.prepare_envelope_migration(source_generation,source_revision,admin_device,token,target_generation,'{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb);
    raise exception 'prior migration target generation was accepted';
  exception when sqlstate '22023' then null;
  end;
  delete from public.vault_migrations m where m.source_generation='14141414-1414-4141-8141-141414141414' and m.target_generation='99999999-9999-4999-8999-999999999999';
  source_revision := (select revision from public.vault_state where singleton);
  abandoned := public.prepare_envelope_migration(source_generation,source_revision,admin_device,token,'99999999-9999-4999-8999-999999999998','{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb);
  if public.get_pending_envelope_migration(admin_device,token)->>'migration_id' <> abandoned->>'migration_id' then raise exception 'pending migration status was unavailable'; end if;
  response := public.abandon_envelope_migration((abandoned->>'migration_id')::uuid,admin_device,token);
  if response->>'status' <> 'abandoned'
     or (select envelope_status from public.vault_state where singleton)<>'active'
     or (select count(*) from public.vault_state where singleton and active_migration_id is null and prepared_generation is null) <> 1 then raise exception 'migration abandonment was not atomic: %',(select to_jsonb(v) from public.vault_state v where singleton); end if;
  migration := public.prepare_envelope_migration(source_generation,source_revision,admin_device,token,target_generation,'{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb);
  if migration is null or (select envelope_status from public.vault_state where singleton) <> 'preparing' then raise exception 'prepare did not preserve preparing'; end if;
  row := jsonb_build_object('id',quote_id,'text',cipher,'author','ENCRYPTED','context','ENCRYPTED','quote_date',null,'created_at','2026-09-22T12:34:56.123456Z','user_id',admin_id,'vault_generation',target_generation);
  begin
    perform public.stage_envelope_quotes((migration->>'migration_id')::uuid,admin_device,token,jsonb_build_array(jsonb_set(row,'{text}',to_jsonb('$$E2E$${"version":1,"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::text))));
    raise exception 'malformed v2 target was staged';
  exception when sqlstate '22023' then null;
  end;
  begin
    perform public.stage_envelope_quotes((migration->>'migration_id')::uuid,admin_device,token,jsonb_build_array(jsonb_set(row,'{author}','null'::jsonb)));
    raise exception 'null author target was staged';
  exception when sqlstate '22023' then null;
  end;
  begin
    perform public.stage_envelope_quotes((migration->>'migration_id')::uuid,admin_device,token,jsonb_build_array(jsonb_set(row,'{context}','null'::jsonb)));
    raise exception 'null context target was staged';
  exception when sqlstate '22023' then null;
  end;
  begin
    perform public.stage_envelope_quotes((migration->>'migration_id')::uuid,admin_device,token,jsonb_build_array(jsonb_set(row,'{created_at}','"2026-09-22T12:34:56.123Z"'::jsonb)));
    raise exception 'short fractional timestamp was staged';
  exception when sqlstate '22023' then null;
  end;
  begin
    perform public.stage_envelope_quotes((migration->>'migration_id')::uuid,admin_device,token,jsonb_build_array(jsonb_set(row,'{created_at}','"2026-09-22T12:34:56Z"'::jsonb)));
    raise exception 'whole-second timestamp was staged';
  exception when sqlstate '22023' then null;
  end;
  begin
    perform public.activate_envelope_migration((migration->>'migration_id')::uuid,admin_device,token);
    raise exception 'missing staged IDs activated';
  exception when sqlstate '40001' then null;
  end;
  begin
    perform public.stage_envelope_quotes((migration->>'migration_id')::uuid,admin_device,token,jsonb_build_array(row));
    raise exception 'quote staging bypassed enrollment readiness';
  exception when sqlstate '40001' then null;
  end;
  perform public.stage_envelope_wrappers((migration->>'migration_id')::uuid,admin_device,token,
    jsonb_build_array(jsonb_build_object('device_id',admin_device,'wrapped_key',repeat('A',512)),jsonb_build_object('device_id',member_device,'wrapped_key',repeat('A',512))),
    jsonb_build_array(jsonb_build_object('recovery_key_id',recovery_id,'wrapped_key',repeat('A',512)),jsonb_build_object('recovery_key_id',admin_recovery_id,'wrapped_key',repeat('A',512))));
  update public.vault_devices set protection_mode='passkey-prf',protection=jsonb_build_object('version',1,'rpId','quotes.darkmg1.dev','credentialId',token,'prfSalt',token,'kdf','HKDF-SHA-256') where id=admin_device;
  response:=public.get_passkey_restore_devices();
  if response->>'generation'<>target_generation::text or response::text not like '%'||admin_device::text||'%' then raise exception 'cleared-browser passkey restore omitted its prepared wrapper'; end if;
  update public.vault_devices set protection_mode='remembered',protection='{"version":1,"mode":"remembered"}'::jsonb where id=admin_device;
  snapshot:=public.get_envelope_migration_coverage((migration->>'migration_id')::uuid,admin_device,token);
  if snapshot::text like '%wrapped_key%' or snapshot::text like '%encrypted_private%' or snapshot::text not like '%no_recent_empty_queue%' then raise exception 'pre-sync coverage leaked secrets or omitted queue blocker'; end if;
  begin
    perform public.report_envelope_migration_empty_queue((migration->>'migration_id')::uuid,source_revision,admin_device,token);
    raise exception 'queue report without successful sync was accepted';
  exception when sqlstate '40001' then null;
  end;
  perform public.sync_quotes(source_generation,source_revision,'[]'::jsonb,admin_device,token);
  begin
    perform public.report_envelope_migration_empty_queue((migration->>'migration_id')::uuid,source_revision+1,admin_device,token);
    raise exception 'queue report with wrong source revision was accepted';
  exception when sqlstate '40001' then null;
  end;
  perform set_config('request.jwt.claim.sub',member_id::text,true);
  perform public.sync_quotes(source_generation,source_revision,'[]'::jsonb,member_device,token);
  perform public.report_envelope_migration_empty_queue((migration->>'migration_id')::uuid,source_revision,member_device,token);
  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  perform public.report_envelope_migration_empty_queue((migration->>'migration_id')::uuid,source_revision,admin_device,token);
  staged := public.stage_envelope_quotes((migration->>'migration_id')::uuid,admin_device,token,jsonb_build_array(row));
  if staged->>'status' <> 'ready' then raise exception 'valid staged target did not become ready after enrollment'; end if;
  if public.stage_envelope_quotes((migration->>'migration_id')::uuid,admin_device,token,jsonb_build_array(row)) <> staged then raise exception 'identical staging replay changed'; end if;
  begin
    perform public.stage_envelope_quotes((migration->>'migration_id')::uuid,admin_device,token,jsonb_build_array(row || jsonb_build_object('text','$$E2E$${"version":2,"iv":"AAAAAAAAAAAAAAAA","data":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}')));
    raise exception 'changed staging replay was accepted';
  exception when sqlstate '40001' then null;
  end;
  begin
    perform public.stage_envelope_quotes((migration->>'migration_id')::uuid,admin_device,token,jsonb_build_array(jsonb_set(row,'{id}','"77777777-7777-4777-8777-777777777777"'::jsonb)));
    perform public.stage_envelope_wrappers((migration->>'migration_id')::uuid,admin_device,token,
      jsonb_build_array(jsonb_build_object('device_id',admin_device,'wrapped_key',repeat('A',512)),jsonb_build_object('device_id',member_device,'wrapped_key',repeat('A',512))),
      jsonb_build_array(jsonb_build_object('recovery_key_id',recovery_id,'wrapped_key',repeat('A',512)),jsonb_build_object('recovery_key_id',admin_recovery_id,'wrapped_key',repeat('A',512))));
    perform public.activate_envelope_migration((migration->>'migration_id')::uuid,admin_device,token);
    raise exception 'extra staged ID activated';
  exception when sqlstate '40001' then null;
  end;
  perform public.stage_envelope_wrappers((migration->>'migration_id')::uuid,admin_device,token,
    jsonb_build_array(jsonb_build_object('device_id',admin_device,'wrapped_key',repeat('A',512)),jsonb_build_object('device_id',member_device,'wrapped_key',repeat('A',512))),
    jsonb_build_array(jsonb_build_object('recovery_key_id',recovery_id,'wrapped_key',repeat('A',512)),jsonb_build_object('recovery_key_id',admin_recovery_id,'wrapped_key',repeat('A',512))));
  update public.vault_devices set status='revoked',revoked_at=now() where id=member_device;
  if public.qv_migration_ready((select m from public.vault_migrations m where m.id=(migration->>'migration_id')::uuid)) then raise exception 'member without active device was ready'; end if;
  update public.vault_devices set status='active',revoked_at=null where id=member_device;
  update public.vault_recovery_keys set status='revoked',revoked_at=now() where id=recovery_id;
  if public.qv_migration_ready((select m from public.vault_migrations m where m.id=(migration->>'migration_id')::uuid)) then raise exception 'member without active recovery was ready'; end if;
  update public.vault_recovery_keys set status='active',revoked_at=null where id=recovery_id;
  delete from public.vault_device_wrappers where device_id=member_device and generation=target_generation;
  perform set_config('request.jwt.claim.sub',member_id::text,true);
  if public.create_recovery_key('45454545-4545-4545-8545-454545454545',(select public_jwk from public.vault_devices where id=member_device),(select public_key_fingerprint from public.vault_devices where id=member_device),'{"version":2,"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb,'{"version":1,"salt":"AAAAAAAAAAAAAAAAAAAAAA==","iterations":600000}'::jsonb,target_generation,repeat('A',512),member_device,token) is not null then raise exception 'prepared recovery accepted an unwrapped device'; end if;
  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  perform public.stage_envelope_wrappers((migration->>'migration_id')::uuid,admin_device,token,jsonb_build_array(jsonb_build_object('device_id',member_device,'wrapped_key',repeat('A',512))),'[]'::jsonb);
  delete from public.vault_recovery_keys where id=recovery_id;
  perform set_config('request.jwt.claim.sub',member_id::text,true);
  response:=public.create_recovery_key(recovery_id,(select public_jwk from public.vault_devices where id=member_device),(select public_key_fingerprint from public.vault_devices where id=member_device),'{"version":2,"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb,'{"version":1,"salt":"AAAAAAAAAAAAAAAAAAAAAA==","iterations":600000}'::jsonb,target_generation,repeat('A',512),member_device,token);
  if response->>'recovery_key_id'<>recovery_id::text or response->>'generation'<>target_generation::text then raise exception 'prepared target recovery bootstrap failed'; end if;
  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  snapshot := public.get_envelope_migration_coverage((migration->>'migration_id')::uuid,admin_device,token);
  if snapshot->>'status'<>'ready' or snapshot::text like '%wrapped_key%' or snapshot::text like '%encrypted_private%' or snapshot::text not like '%member@example.invalid%' then raise exception 'migration coverage leaked secrets or omitted usable blocker state'; end if;
  begin
    perform public.get_envelope_migration_coverage((migration->>'migration_id')::uuid,admin_device,'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB');
    raise exception 'wrong-token migration coverage was accepted';
  exception when sqlstate '40001' then null;
  end;
  perform set_config('request.jwt.claim.sub',member_id::text,true);
  begin
    perform public.get_envelope_migration_coverage((migration->>'migration_id')::uuid,member_device,token);
    raise exception 'non-admin migration coverage was accepted';
  exception when sqlstate '42501' then null;
  end;
  response := public.report_envelope_migration_empty_queue((migration->>'migration_id')::uuid,source_revision,member_device,token);
  if response->>'device_id'<>member_device::text or response->>'ready'<>'true' then raise exception 'queue report replay lost ready state'; end if;
  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  begin
    perform public.report_envelope_migration_empty_queue((migration->>'migration_id')::uuid,source_revision,admin_device,'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB');
    raise exception 'wrong-token queue report was accepted';
  exception when sqlstate '40001' then null;
  end;
  response := public.report_envelope_migration_empty_queue((migration->>'migration_id')::uuid,source_revision,admin_device,token);
  if response->>'status'<>'ready' or response->>'ready'<>'true' then raise exception 'final queue report did not make migration ready'; end if;
  update public.vault_migration_queue_reports set reported_at=now()-interval '16 minutes' where migration_id=(migration->>'migration_id')::uuid and device_id=admin_device;
  if public.qv_migration_ready((select m from public.vault_migrations m where m.id=(migration->>'migration_id')::uuid)) then raise exception 'stale queue report was ready'; end if;
  snapshot:=public.get_envelope_migration_coverage((migration->>'migration_id')::uuid,admin_device,token);
  if snapshot->>'status'<>'staging' or snapshot->>'ready'<>'false' then raise exception 'coverage retained stale ready state'; end if;
  perform set_config('request.jwt.claim.sub',member_id::text,true);
  response:=public.report_envelope_migration_empty_queue((migration->>'migration_id')::uuid,source_revision,member_device,token);
  if response->>'status'<>'staging' or response->>'ready'<>'false' then raise exception 'fresh other-device report retained stale ready state'; end if;
  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  perform public.report_envelope_migration_empty_queue((migration->>'migration_id')::uuid,source_revision,admin_device,token);
  update public.vault_migration_quote_copies c set encrypted_row=jsonb_set(row,'{user_id}',to_jsonb(member_id::text)) where c.migration_id=(migration->>'migration_id')::uuid and c.copy_kind='staged' and c.quote_id=(row->>'id')::uuid;
  begin
    perform public.activate_envelope_migration((migration->>'migration_id')::uuid,admin_device,token);
    raise exception 'staged user_id metadata tamper activated';
  exception when sqlstate '40001' then null;
  end;
  update public.vault_migration_quote_copies c set encrypted_row=row where c.migration_id=(migration->>'migration_id')::uuid and c.copy_kind='staged' and c.quote_id=(row->>'id')::uuid;
  update public.vault_migration_quote_copies c set encrypted_row=jsonb_set(row,'{created_at}','"2026-09-22T12:34:56.123457Z"'::jsonb) where c.migration_id=(migration->>'migration_id')::uuid and c.copy_kind='staged' and c.quote_id=(row->>'id')::uuid;
  begin
    perform public.activate_envelope_migration((migration->>'migration_id')::uuid,admin_device,token);
    raise exception 'staged created_at metadata tamper activated';
  exception when sqlstate '40001' then null;
  end;
  update public.vault_migration_quote_copies c set encrypted_row=row where c.migration_id=(migration->>'migration_id')::uuid and c.copy_kind='staged' and c.quote_id=(row->>'id')::uuid;
  update public.vault_migration_quote_copies c set encrypted_row=jsonb_set(row,'{quote_date}',to_jsonb((current_date+1)::text)) where c.migration_id=(migration->>'migration_id')::uuid and c.copy_kind='staged' and c.quote_id=(row->>'id')::uuid;
  begin
    perform public.activate_envelope_migration((migration->>'migration_id')::uuid,admin_device,token);
    raise exception 'staged quote_date metadata tamper activated';
  exception when sqlstate '40001' then null;
  end;
  update public.vault_migration_quote_copies c set encrypted_row=row where c.migration_id=(migration->>'migration_id')::uuid and c.copy_kind='staged' and c.quote_id=(row->>'id')::uuid;
  response := public.activate_envelope_migration((migration->>'migration_id')::uuid,admin_device,token);
  if response->>'status' <> 'activated' or (select envelope_status from public.vault_state where singleton) <> 'maintenance'
     or (select vault_generation from public.quotes where id=quote_id) <> target_generation then raise exception 'activation was not atomic'; end if;
  snapshot := public.get_envelope_migration_snapshot((migration->>'migration_id')::uuid,admin_device,token);
  if snapshot->>'generation' <> target_generation::text or jsonb_array_length(snapshot->'quotes') <> 1 or snapshot->'quotes'->0->>'created_at'<>'2026-09-22T12:34:56.123456Z' then raise exception 'maintenance snapshot was unavailable or truncated microseconds'; end if;
  if public.get_pending_envelope_migration(admin_device,token)->>'status'<>'activated' then raise exception 'activated maintenance migration was not resumable'; end if;
  begin
    perform public.get_envelope_migration_snapshot((migration->>'migration_id')::uuid,admin_device,'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB');
    raise exception 'wrong-token maintenance snapshot was accepted';
  exception when sqlstate '40001' then null;
  end;
  perform set_config('request.jwt.claim.sub',member_id::text,true);
  begin
    perform public.get_envelope_migration_snapshot((migration->>'migration_id')::uuid,member_device,token);
    raise exception 'non-admin maintenance snapshot was accepted';
  exception when sqlstate '42501' then null;
  end;
  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  if public.edit_quote(target_generation,quote_id,cipher,cipher,current_date,admin_device,token) is not null
     or public.checked_import(target_generation,0,'[]'::jsonb,admin_device,token) is not null then raise exception 'maintenance permitted active mutations'; end if;
  response:=public.renew_device_lease(admin_device,token);
  if response is null or response->>3<>target_generation::text then raise exception 'maintenance reload could not renew its target-generation device'; end if;
  response:=public.complete_device(admin_device,token,target_generation);
  if response->>'generation'<>target_generation::text or response->>'wrapped_key'<>repeat('A',512) then raise exception 'maintenance reload could not fetch its target wrapper'; end if;
  begin
    update public.quotes set text='$$E2E$${"version":2,"iv":"AAAAAAAAAAAAAAAA","data":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}' where id=quote_id;
    perform public.finalize_envelope_migration((migration->>'migration_id')::uuid,admin_device,token);
    raise exception 'tampered active target finalized';
  exception when sqlstate '40001' then null;
  end;
  begin
    update public.vault_state set generation=gen_random_uuid() where singleton;
    perform public.finalize_envelope_migration((migration->>'migration_id')::uuid,admin_device,token);
    raise exception 'finalize accepted target generation drift';
  exception when sqlstate '40001' then null;
  end;
  begin
    update public.vault_state set revision=revision+1 where singleton;
    perform public.finalize_envelope_migration((migration->>'migration_id')::uuid,admin_device,token);
    raise exception 'finalize accepted target revision drift';
  exception when sqlstate '40001' then null;
  end;
  begin
    update public.vault_state set prepared_generation=null where singleton;
    perform public.finalize_envelope_migration((migration->>'migration_id')::uuid,admin_device,token);
    raise exception 'finalize accepted prepared generation drift';
  exception when sqlstate '40001' then null;
  end;
  perform set_config('qv.migration_internal','on',true);
  begin
    update public.vault_devices set label='attacker mutation' where id=admin_device;
    raise exception 'maintenance bypass was accepted';
  exception when sqlstate '40001' then null;
  end;
  if public.sync_quotes(target_generation, null, '[]'::jsonb, admin_device, token) is not null then raise exception 'maintenance permitted writes'; end if;
  delete from public.vault_migration_quote_copies c where c.migration_id=(migration->>'migration_id')::uuid and c.copy_kind='rollback' and c.quote_id=(row->>'id')::uuid;
  begin
    perform public.rollback_envelope_migration((migration->>'migration_id')::uuid,admin_device,token);
    raise exception 'incomplete rollback set was accepted';
  exception when sqlstate '40001' then null;
  end;
  if (select vault_generation from public.quotes where id=quote_id) is distinct from target_generation then raise exception 'failed rollback changed target quote'; end if;
  insert into public.vault_migration_quote_copies(migration_id,copy_kind,quote_id,encrypted_row,vault_generation)
  values((migration->>'migration_id')::uuid,'rollback',quote_id,jsonb_set(row,'{vault_generation}',to_jsonb(source_generation::text)),source_generation);
  perform public.rollback_envelope_migration((migration->>'migration_id')::uuid,admin_device,token);
  if (select envelope_status from public.vault_state where singleton) <> 'active'
     or (select text from public.quotes where id=quote_id) <> cipher
     or (select vault_generation from public.quotes where id=quote_id) <> source_generation
     or (select created_at from public.quotes where id=quote_id) <> '2026-09-22T12:34:56.123456Z'::timestamptz
     or (select revision from public.vault_state where singleton) <> source_revision
     or (select prepared_generation is null and active_migration_id is null from public.vault_state where singleton) is not true then raise exception 'rollback did not exactly restore source'; end if;
  retry := public.prepare_envelope_migration(source_generation,source_revision,admin_device,token,'88888888-8888-4888-8888-888888888888','{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb);
  if retry is null then raise exception 'rollback prevented future migration'; end if;
  perform public.stage_envelope_wrappers((retry->>'migration_id')::uuid,admin_device,token,
    jsonb_build_array(jsonb_build_object('device_id',admin_device,'wrapped_key',repeat('A',512)),jsonb_build_object('device_id',member_device,'wrapped_key',repeat('A',512))),
    jsonb_build_array(jsonb_build_object('recovery_key_id',recovery_id,'wrapped_key',repeat('A',512)),jsonb_build_object('recovery_key_id',admin_recovery_id,'wrapped_key',repeat('A',512))));
  perform public.sync_quotes(source_generation,(select m.source_revision from public.vault_migrations m where m.id=(retry->>'migration_id')::uuid),'[]'::jsonb,admin_device,token);
  perform set_config('request.jwt.claim.sub',member_id::text,true);
  perform public.sync_quotes(source_generation,(select m.source_revision from public.vault_migrations m where m.id=(retry->>'migration_id')::uuid),'[]'::jsonb,member_device,token);
  perform public.report_envelope_migration_empty_queue((retry->>'migration_id')::uuid,(select m.source_revision from public.vault_migrations m where m.id=(retry->>'migration_id')::uuid),member_device,token);
  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  perform public.report_envelope_migration_empty_queue((retry->>'migration_id')::uuid,(select m.source_revision from public.vault_migrations m where m.id=(retry->>'migration_id')::uuid),admin_device,token);
  perform public.stage_envelope_quotes((retry->>'migration_id')::uuid,admin_device,token,jsonb_build_array(jsonb_set(row,'{vault_generation}',to_jsonb('88888888-8888-4888-8888-888888888888'::text))));
  response:=public.refresh_envelope_migration_source((retry->>'migration_id')::uuid,(select revision from public.vault_state where singleton),admin_device,token);
  if response->>'reset'<>'false' or (select count(*) from public.vault_migration_quote_copies where migration_id=(retry->>'migration_id')::uuid and copy_kind='staged')<>1
     or (select count(*) from public.vault_migration_queue_reports where migration_id=(retry->>'migration_id')::uuid)<>2 then raise exception 'same-revision refresh discarded resumable staging'; end if;
  if public.stage_envelope_quotes((retry->>'migration_id')::uuid,admin_device,token,jsonb_build_array(jsonb_set(row,'{vault_generation}',to_jsonb('88888888-8888-4888-8888-888888888888'::text)))) is null then raise exception 'same-revision refresh blocked staging resume'; end if;
  begin
    update public.vault_state set generation=gen_random_uuid() where singleton;
    perform public.activate_envelope_migration((retry->>'migration_id')::uuid,admin_device,token);
    raise exception 'source generation drift activated a migration';
  exception when sqlstate '40001' then null;
  end;
  update public.quotes set author=author where id=quote_id;
  begin
    perform public.activate_envelope_migration((retry->>'migration_id')::uuid,admin_device,token);
    raise exception 'source revision drift activated a migration';
  exception when sqlstate '40001' then null;
  end;
  begin
    perform public.refresh_envelope_migration_source((retry->>'migration_id')::uuid,(select revision-1 from public.vault_state where singleton),admin_device,token);
    raise exception 'refresh accepted stale current revision';
  exception when sqlstate '40001' then null;
  end;
  response:=public.refresh_envelope_migration_source((retry->>'migration_id')::uuid,(select revision from public.vault_state where singleton),admin_device,token);
  snapshot:=public.get_envelope_migration_coverage((retry->>'migration_id')::uuid,admin_device,token);
  if response->>'status'<>'staging' or response->>'reset'<>'true' or snapshot->>'staged_quote_count'<>'0' or snapshot::text not like '%no_recent_empty_queue%'
     or (select count(*) from public.vault_migration_quote_copies where migration_id=(retry->>'migration_id')::uuid and copy_kind='staged')<>0
     or (select count(*) from public.vault_migration_queue_reports where migration_id=(retry->>'migration_id')::uuid)<>0
     or (select source_state->>'envelope_status' from public.vault_migrations where id=(retry->>'migration_id')::uuid)<>'active'
     or (select count(*) from public.vault_device_wrappers where generation='88888888-8888-4888-8888-888888888888')<>2
     or (select count(*) from public.vault_recovery_wrappers where generation='88888888-8888-4888-8888-888888888888')<>2 then raise exception 'refresh did not reset only stale staging state'; end if;
  -- Reset the intentionally drifted retry fixture, then verify finalization and expiry cleanup.
  delete from public.vault_migration_quote_copies where migration_id=(retry->>'migration_id')::uuid;
  delete from public.vault_device_wrappers where generation='88888888-8888-4888-8888-888888888888';
  delete from public.vault_recovery_wrappers where generation='88888888-8888-4888-8888-888888888888';
  update public.vault_state set envelope_status='active',prepared_generation=null,active_migration_id=null where singleton;
  retry := public.prepare_envelope_migration(source_generation,(select revision from public.vault_state where singleton),admin_device,token,'77777777-7777-4777-8777-777777777777','{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb);
  perform public.stage_envelope_wrappers((retry->>'migration_id')::uuid,admin_device,token,
    jsonb_build_array(jsonb_build_object('device_id',admin_device,'wrapped_key',repeat('A',512)),jsonb_build_object('device_id',member_device,'wrapped_key',repeat('A',512))),
    jsonb_build_array(jsonb_build_object('recovery_key_id',recovery_id,'wrapped_key',repeat('A',512)),jsonb_build_object('recovery_key_id',admin_recovery_id,'wrapped_key',repeat('A',512))));
  perform public.sync_quotes(source_generation,(select m.source_revision from public.vault_migrations m where m.id=(retry->>'migration_id')::uuid),'[]'::jsonb,admin_device,token);
  perform set_config('request.jwt.claim.sub',member_id::text,true);
  perform public.sync_quotes(source_generation,(select m.source_revision from public.vault_migrations m where m.id=(retry->>'migration_id')::uuid),'[]'::jsonb,member_device,token);
  perform public.report_envelope_migration_empty_queue((retry->>'migration_id')::uuid,(select m.source_revision from public.vault_migrations m where m.id=(retry->>'migration_id')::uuid),member_device,token);
  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  perform public.report_envelope_migration_empty_queue((retry->>'migration_id')::uuid,(select m.source_revision from public.vault_migrations m where m.id=(retry->>'migration_id')::uuid),admin_device,token);
  perform public.stage_envelope_quotes((retry->>'migration_id')::uuid,admin_device,token,jsonb_build_array(jsonb_set(row,'{vault_generation}','"77777777-7777-4777-8777-777777777777"'::jsonb)));
  perform public.report_envelope_migration_empty_queue((retry->>'migration_id')::uuid,(select m.source_revision from public.vault_migrations m where m.id=(retry->>'migration_id')::uuid),admin_device,token);
  perform set_config('request.jwt.claim.sub',member_id::text,true);
  perform public.report_envelope_migration_empty_queue((retry->>'migration_id')::uuid,(select m.source_revision from public.vault_migrations m where m.id=(retry->>'migration_id')::uuid),member_device,token);
  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  perform public.activate_envelope_migration((retry->>'migration_id')::uuid,admin_device,token);
  perform public.finalize_envelope_migration((retry->>'migration_id')::uuid,admin_device,token);
  if exists(select 1 from public.vault_migration_quote_copies where migration_id=(retry->>'migration_id')::uuid) or (select envelope_status from public.vault_state where singleton)<>'active' then raise exception 'finalize did not release copies and state'; end if;
  retry := public.prepare_envelope_migration('77777777-7777-4777-8777-777777777777',(select revision from public.vault_state where singleton),admin_device,token,'66666666-6666-4666-8666-666666666666','{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb);
  perform public.stage_envelope_wrappers((retry->>'migration_id')::uuid,admin_device,token,
    jsonb_build_array(jsonb_build_object('device_id',admin_device,'wrapped_key',repeat('A',512)),jsonb_build_object('device_id',member_device,'wrapped_key',repeat('A',512))),
    jsonb_build_array(jsonb_build_object('recovery_key_id',recovery_id,'wrapped_key',repeat('A',512)),jsonb_build_object('recovery_key_id',admin_recovery_id,'wrapped_key',repeat('A',512))));
  perform public.sync_quotes('77777777-7777-4777-8777-777777777777',(select m.source_revision from public.vault_migrations m where m.id=(retry->>'migration_id')::uuid),'[]'::jsonb,admin_device,token);
  perform set_config('request.jwt.claim.sub',member_id::text,true);
  perform public.sync_quotes('77777777-7777-4777-8777-777777777777',(select m.source_revision from public.vault_migrations m where m.id=(retry->>'migration_id')::uuid),'[]'::jsonb,member_device,token);
  perform public.report_envelope_migration_empty_queue((retry->>'migration_id')::uuid,(select m.source_revision from public.vault_migrations m where m.id=(retry->>'migration_id')::uuid),member_device,token);
  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  perform public.report_envelope_migration_empty_queue((retry->>'migration_id')::uuid,(select m.source_revision from public.vault_migrations m where m.id=(retry->>'migration_id')::uuid),admin_device,token);
  perform public.stage_envelope_quotes((retry->>'migration_id')::uuid,admin_device,token,jsonb_build_array(jsonb_set(row,'{vault_generation}','"66666666-6666-4666-8666-666666666666"'::jsonb)));
  perform public.report_envelope_migration_empty_queue((retry->>'migration_id')::uuid,(select m.source_revision from public.vault_migrations m where m.id=(retry->>'migration_id')::uuid),admin_device,token);
  perform set_config('request.jwt.claim.sub',member_id::text,true);
  perform public.report_envelope_migration_empty_queue((retry->>'migration_id')::uuid,(select m.source_revision from public.vault_migrations m where m.id=(retry->>'migration_id')::uuid),member_device,token);
  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  perform public.activate_envelope_migration((retry->>'migration_id')::uuid,admin_device,token);
  update public.vault_migrations set rollback_expires_at=now() where id=(retry->>'migration_id')::uuid;
  begin
    perform public.rollback_envelope_migration((retry->>'migration_id')::uuid,admin_device,token);
    raise exception 'rollback succeeded at expiry';
  exception when sqlstate '40001' then null;
  end;
  if public.purge_expired_vault_rollback()<>1 then raise exception 'expired purge did not select migration'; end if;
  response := jsonb_build_object('copies',(select count(*) from public.vault_migration_quote_copies where migration_id=(retry->>'migration_id')::uuid),'status',(select envelope_status from public.vault_state where singleton));
  if response->>'copies'<>'0' or response->>'status'<>'active' then raise exception 'expired purge did not release copies and state: %',response; end if;
  delete from public.quotes where id=quote_id;
  retry:=public.prepare_envelope_migration((select generation from public.vault_state where singleton),(select revision from public.vault_state where singleton),admin_device,token,'56565656-5656-4565-8565-565656565656','{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb);
  if retry->>'expected_quote_count'<>'0' then raise exception 'empty migration captured quotes'; end if;
  perform public.stage_envelope_wrappers((retry->>'migration_id')::uuid,admin_device,token,
    jsonb_build_array(jsonb_build_object('device_id',admin_device,'wrapped_key',repeat('A',512)),jsonb_build_object('device_id',member_device,'wrapped_key',repeat('A',512))),
    jsonb_build_array(jsonb_build_object('recovery_key_id',recovery_id,'wrapped_key',repeat('A',512)),jsonb_build_object('recovery_key_id',admin_recovery_id,'wrapped_key',repeat('A',512))));
  perform public.sync_quotes((select generation from public.vault_state where singleton),(select m.source_revision from public.vault_migrations m where m.id=(retry->>'migration_id')::uuid),'[]'::jsonb,admin_device,token);
  perform set_config('request.jwt.claim.sub',member_id::text,true);
  perform public.sync_quotes((select generation from public.vault_state where singleton),(select m.source_revision from public.vault_migrations m where m.id=(retry->>'migration_id')::uuid),'[]'::jsonb,member_device,token);
  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  perform public.report_envelope_migration_empty_queue((retry->>'migration_id')::uuid,(select m.source_revision from public.vault_migrations m where m.id=(retry->>'migration_id')::uuid),admin_device,token);
  perform set_config('request.jwt.claim.sub',member_id::text,true);
  response:=public.report_envelope_migration_empty_queue((retry->>'migration_id')::uuid,(select m.source_revision from public.vault_migrations m where m.id=(retry->>'migration_id')::uuid),member_device,token);
  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  if response->>'status'<>'ready' or response->>'ready'<>'true' then raise exception 'empty migration did not become ready after reports'; end if;
  perform public.abandon_envelope_migration((retry->>'migration_id')::uuid,admin_device,token);
  if has_table_privilege('authenticated','public.vault_migration_quote_copies','select') then raise exception 'migration copies were directly readable'; end if;
  if has_table_privilege('authenticated','public.vault_migration_queue_reports','select') then raise exception 'migration queue reports were directly readable'; end if;
end $test$;

do $cron$
declare scheduled boolean;
begin
  if exists(select 1 from pg_extension where extname='pg_cron') and to_regnamespace('cron') is not null then
    execute $$select exists(select 1 from cron.job where jobname='quotevault-purge-expired-vault-rollback')$$ into scheduled;
    if not scheduled then raise exception 'pg_cron purge job was not scheduled'; end if;
  end if;
end $cron$;

set local role authenticated;
do $direct$
begin
  begin
    perform 1 from public.vault_migration_quote_copies;
    raise exception 'authenticated role read migration ciphertext copies';
  exception when insufficient_privilege then null;
  end;
end $direct$;
reset role;

rollback;
