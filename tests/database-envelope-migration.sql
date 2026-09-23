-- The migration state machine is deliberately exercised through its RPC boundary.
begin;

do $test$
declare
  admin_id uuid := 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  admin_device uuid := '11111111-1111-4111-8111-111111111111';
  member_id uuid := 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  member_device uuid := '22222222-2222-4222-8222-222222222222';
  recovery_id uuid := '55555555-5555-4555-8555-555555555555';
  token text := 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
  source_generation uuid := (select generation from public.vault_state where singleton);
  target_generation uuid := '99999999-9999-4999-8999-999999999999';
  quote_id uuid := '66666666-6666-4666-8666-666666666666';
  migration jsonb;
  staged jsonb;
  response jsonb;
  snapshot jsonb;
  retry jsonb;
  row jsonb;
  source_revision bigint;
  cipher text := '$$E2E$${"version":2,"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}';
begin
  insert into public.allowlist(id,email,created_at) values
    (admin_id,'darkmgdevelopment@gmail.com',now()), (member_id,'member@example.invalid',now())
  on conflict do nothing;
  insert into auth.users(instance_id,id,aud,role,email,encrypted_password,email_confirmed_at) values
    (gen_random_uuid(),admin_id,'authenticated','authenticated','darkmgdevelopment@gmail.com','x',now()),
    (gen_random_uuid(),member_id,'authenticated','authenticated','member@example.invalid','x',now())
  on conflict do nothing;
  insert into public.vault_devices(id,owner_id,status,request_kind,enrollment_fingerprint,public_jwk,public_key_fingerprint,authorization_token_digest,label,protection_mode,protection,encrypted_private_bundle,lease_expires_at)
  select d.id,d.owner_id,'active','first',token,jwk,public.qv_public_key_fingerprint(jwk),rtrim(replace(replace(replace(encode(sha256(decode(token||'=', 'base64')),'base64'),E'\n',''),'+','-'),'/','_'),'='),'migration', 'remembered','{"version":1,"mode":"remembered"}',bundle,now()+interval '1 day'
  from (values (admin_device,admin_id),(member_device,member_id)) d(id,owner_id),
       (select jsonb_build_object('kty','RSA','n',rtrim(replace(replace(replace(encode(decode('80'||repeat('00',383),'hex'),'base64'),E'\n',''),'+','-'),'/','_'),'='),'e','AQAB') jwk,
               jsonb_build_object('version',2,'iv','AAAAAAAAAAAAAAAA','data','AAAAAAAAAAAAAAAAAAAAAA==') bundle) k
  on conflict (id) do update set status='active', lease_expires_at=excluded.lease_expires_at;
  insert into public.vault_recovery_keys(id,owner_id,status,public_jwk,public_key_fingerprint,encrypted_private_key,kdf,confirmed_at)
  select recovery_id,member_id,'active',jwk,public.qv_public_key_fingerprint(jwk),bundle,
    jsonb_build_object('version',1,'salt','AAAAAAAAAAAAAAAAAAAAAA==','iterations',600000),now()
  from (select jsonb_build_object('kty','RSA','n',rtrim(replace(replace(replace(encode(decode('80'||repeat('00',383),'hex'),'base64'),E'\n',''),'+','-'),'/','_'),'='),'e','AQAB') jwk,
               jsonb_build_object('version',2,'iv','AAAAAAAAAAAAAAAA','data','AAAAAAAAAAAAAAAAAAAAAA==') bundle) k
  on conflict (id) do update set status='active', confirmed_at=excluded.confirmed_at;
  insert into public.quotes(id,text,author,context,quote_date,created_at,user_id,vault_generation)
  values (quote_id,cipher,'ENCRYPTED','ENCRYPTED',current_date,'2026-09-22T12:34:56Z',admin_id,source_generation)
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
  migration := public.prepare_envelope_migration(source_generation,source_revision,admin_device,token,target_generation,'{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb);
  if migration is null or (select envelope_status from public.vault_state where singleton) <> 'preparing' then raise exception 'prepare did not preserve preparing'; end if;
  row := jsonb_build_object('id',quote_id,'text',cipher,'author','ENCRYPTED','context','ENCRYPTED','quote_date',current_date::text,'created_at','2026-09-22T12:34:56.000Z','user_id',admin_id,'vault_generation',target_generation);
  begin
    perform public.stage_envelope_quotes((migration->>'migration_id')::uuid,admin_device,token,jsonb_build_array(jsonb_set(row,'{text}',to_jsonb('$$E2E$${"version":1,"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::text))));
    raise exception 'malformed v2 target was staged';
  exception when sqlstate '22023' then null;
  end;
  begin
    perform public.activate_envelope_migration((migration->>'migration_id')::uuid,admin_device,token);
    raise exception 'missing staged IDs activated';
  exception when sqlstate '40001' then null;
  end;
  staged := public.stage_envelope_quotes((migration->>'migration_id')::uuid,admin_device,token,jsonb_build_array(row));
  if staged->>'status' <> 'staging' then raise exception 'valid staged target was not staged'; end if;
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
      jsonb_build_array(jsonb_build_object('recovery_key_id',recovery_id,'wrapped_key',repeat('A',512))));
    perform public.activate_envelope_migration((migration->>'migration_id')::uuid,admin_device,token);
    raise exception 'extra staged ID activated';
  exception when sqlstate '40001' then null;
  end;
  perform public.stage_envelope_wrappers((migration->>'migration_id')::uuid,admin_device,token,
    jsonb_build_array(jsonb_build_object('device_id',admin_device,'wrapped_key',repeat('A',512)),jsonb_build_object('device_id',member_device,'wrapped_key',repeat('A',512))),
    jsonb_build_array(jsonb_build_object('recovery_key_id',recovery_id,'wrapped_key',repeat('A',512))));
  response := public.activate_envelope_migration((migration->>'migration_id')::uuid,admin_device,token);
  if response->>'status' <> 'activated' or (select envelope_status from public.vault_state where singleton) <> 'maintenance'
     or (select vault_generation from public.quotes where id=quote_id) <> target_generation then raise exception 'activation was not atomic'; end if;
  snapshot := public.get_envelope_migration_snapshot((migration->>'migration_id')::uuid,admin_device,token);
  if snapshot->>'generation' <> target_generation::text or jsonb_array_length(snapshot->'quotes') <> 1 then raise exception 'maintenance snapshot was unavailable'; end if;
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
     or public.checked_import(target_generation,0,'[]'::jsonb,admin_device,token) is not null
     or public.renew_device_lease(admin_device,token) is not null then raise exception 'maintenance permitted active mutations'; end if;
  begin
    update public.quotes set text='$$E2E$${"version":2,"iv":"AAAAAAAAAAAAAAAA","data":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}' where id=quote_id;
    perform public.finalize_envelope_migration((migration->>'migration_id')::uuid,admin_device,token);
    raise exception 'tampered active target finalized';
  exception when sqlstate '40001' then null;
  end;
  perform set_config('qv.migration_internal','on',true);
  begin
    update public.vault_devices set label='attacker mutation' where id=admin_device;
    raise exception 'maintenance bypass was accepted';
  exception when sqlstate '40001' then null;
  end;
  if public.sync_quotes(target_generation, null, '[]'::jsonb, admin_device, token) is not null then raise exception 'maintenance permitted writes'; end if;
  perform public.rollback_envelope_migration((migration->>'migration_id')::uuid,admin_device,token);
  if (select envelope_status from public.vault_state where singleton) <> 'legacy'
     or (select text from public.quotes where id=quote_id) <> cipher
     or (select vault_generation from public.quotes where id=quote_id) <> source_generation
     or (select revision from public.vault_state where singleton) <> source_revision
     or (select prepared_generation is null and active_migration_id is null from public.vault_state where singleton) is not true then raise exception 'rollback did not exactly restore source'; end if;
  retry := public.prepare_envelope_migration(source_generation,source_revision,admin_device,token,'88888888-8888-4888-8888-888888888888','{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb);
  if retry is null then raise exception 'rollback prevented future migration'; end if;
  perform public.stage_envelope_quotes((retry->>'migration_id')::uuid,admin_device,token,jsonb_build_array(jsonb_set(row,'{vault_generation}',to_jsonb('88888888-8888-4888-8888-888888888888'::text))));
  perform public.stage_envelope_wrappers((retry->>'migration_id')::uuid,admin_device,token,
    jsonb_build_array(jsonb_build_object('device_id',admin_device,'wrapped_key',repeat('A',512)),jsonb_build_object('device_id',member_device,'wrapped_key',repeat('A',512))),
    jsonb_build_array(jsonb_build_object('recovery_key_id',recovery_id,'wrapped_key',repeat('A',512))));
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
  -- Reset the intentionally drifted retry fixture, then verify finalization and expiry cleanup.
  delete from public.vault_migration_quote_copies where migration_id=(retry->>'migration_id')::uuid;
  delete from public.vault_device_wrappers where generation='88888888-8888-4888-8888-888888888888';
  delete from public.vault_recovery_wrappers where generation='88888888-8888-4888-8888-888888888888';
  update public.vault_state set envelope_status='legacy',prepared_generation=null,active_migration_id=null where singleton;
  retry := public.prepare_envelope_migration(source_generation,(select revision from public.vault_state where singleton),admin_device,token,'77777777-7777-4777-8777-777777777777','{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb);
  perform public.stage_envelope_quotes((retry->>'migration_id')::uuid,admin_device,token,jsonb_build_array(jsonb_set(row,'{vault_generation}','"77777777-7777-4777-8777-777777777777"'::jsonb)));
  perform public.stage_envelope_wrappers((retry->>'migration_id')::uuid,admin_device,token,
    jsonb_build_array(jsonb_build_object('device_id',admin_device,'wrapped_key',repeat('A',512)),jsonb_build_object('device_id',member_device,'wrapped_key',repeat('A',512))),
    jsonb_build_array(jsonb_build_object('recovery_key_id',recovery_id,'wrapped_key',repeat('A',512))));
  perform public.activate_envelope_migration((retry->>'migration_id')::uuid,admin_device,token);
  perform public.finalize_envelope_migration((retry->>'migration_id')::uuid,admin_device,token);
  if exists(select 1 from public.vault_migration_quote_copies where migration_id=(retry->>'migration_id')::uuid) or (select envelope_status from public.vault_state where singleton)<>'active' then raise exception 'finalize did not release copies and state'; end if;
  retry := public.prepare_envelope_migration('77777777-7777-4777-8777-777777777777',(select revision from public.vault_state where singleton),admin_device,token,'66666666-6666-4666-8666-666666666666','{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb);
  perform public.stage_envelope_quotes((retry->>'migration_id')::uuid,admin_device,token,jsonb_build_array(jsonb_set(row,'{vault_generation}','"66666666-6666-4666-8666-666666666666"'::jsonb)));
  perform public.stage_envelope_wrappers((retry->>'migration_id')::uuid,admin_device,token,
    jsonb_build_array(jsonb_build_object('device_id',admin_device,'wrapped_key',repeat('A',512)),jsonb_build_object('device_id',member_device,'wrapped_key',repeat('A',512))),
    jsonb_build_array(jsonb_build_object('recovery_key_id',recovery_id,'wrapped_key',repeat('A',512))));
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
  if has_table_privilege('authenticated','public.vault_migration_quote_copies','select') then raise exception 'migration copies were directly readable'; end if;
end $test$;

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
