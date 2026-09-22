-- Focused additive envelope foundation checks. Run after all current migrations
-- and 20260922020000_envelope_foundation.sql.
begin;

do $$
declare
  member_id uuid := 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  admin_id uuid := 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  other_id uuid := 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  generation uuid;
  request_id uuid;
  expired_request_id uuid;
  device_id uuid;
  requested_device_id uuid := 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
  prepared_device_id uuid := '11111111-1111-4111-8111-111111111111';
  prepared_gen uuid;
  prepared_request_id uuid;
  first_lease timestamptz;
  token text := 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
  token_digest text := rtrim(replace(replace(replace(encode(sha256(decode(token || '=', 'base64')), 'base64'), E'\n', ''), '+', '-'), '/', '_'), '=');
  public_jwk jsonb := jsonb_build_object('kty', 'RSA', 'n', rtrim(replace(replace(replace(encode(decode('80' || repeat('00', 383), 'hex'), 'base64'), E'\n', ''), '+', '-'), '/', '_'), '='), 'e', 'AQAB');
  protection jsonb := '{"version":1,"mode":"remembered"}'::jsonb;
  fingerprint text := repeat('B', 43);
  public_fingerprint text := public.qv_public_key_fingerprint(public_jwk);
  bundle jsonb := jsonb_build_object('version', 2, 'iv', 'AAAAAAAAAAAAAAAA', 'data', 'AAAAAAAAAAAAAAAAAAAAAA==');
  response jsonb;
begin
  select vs.generation into generation from public.vault_state vs where singleton;
  insert into public.allowlist(id, email, created_at)
  values (member_id, 'member@example.invalid', now()), (admin_id, 'darkmgdevelopment@gmail.com', now()), (other_id, 'other@example.invalid', now())
  on conflict (id) do nothing;
  insert into auth.users(instance_id, id, aud, role, email, encrypted_password, email_confirmed_at)
  values (gen_random_uuid(), member_id, 'authenticated', 'authenticated', 'member@example.invalid', 'x', now()),
         (gen_random_uuid(), admin_id, 'authenticated', 'authenticated', 'darkmgdevelopment@gmail.com', 'x', now())
         ,(gen_random_uuid(), other_id, 'authenticated', 'authenticated', 'other@example.invalid', 'x', now())
  on conflict (id) do nothing;
  insert into public.quotes(id, text, author, context, quote_date, created_at, user_id, vault_generation)
  values ('dddddddd-dddd-4ddd-8ddd-dddddddddddd', chr(36)||chr(36)||'E2E'||chr(36)||chr(36) || jsonb_build_object('iv', repeat('A', 16), 'data', repeat('A', 24))::text,
          'ENCRYPTED', 'ENCRYPTED', current_date, now(), member_id, generation)
  on conflict (id) do nothing;

  perform set_config('request.jwt.claim.sub', member_id::text, true);
  if public.qv_authorize_device('00000000-0000-4000-8000-000000000000', token, generation, 'sync') is not null then
    raise exception 'missing device authorized';
  end if;

  response := public.request_device(
    requested_device_id, member_id, 'new-device', public_jwk, fingerprint, public_fingerprint, token_digest, 'remembered', protection, bundle, 'first');
  request_id := (response->>'request_id')::uuid;
  device_id := (response->>'device_id')::uuid;
  if device_id <> requested_device_id then raise exception 'request did not preserve caller device id'; end if;
  if response ? 'wrapped_key' then raise exception 'pending request exposed wrapper'; end if;
  if not exists (select 1 from public.vault_devices where id = device_id and status = 'pending') then
    raise exception 'pending device was not stored';
  end if;
  response := public.get_device_request(request_id);
  if response->>'authorization_token_digest' <> token_digest or response ? 'encrypted_private_bundle' then
    raise exception 'request material response was unsafe or incomplete';
  end if;

  perform set_config('request.jwt.claim.sub', admin_id::text, true);
  begin
    perform public.approve_device(request_id, member_id, public_fingerprint, repeat('D', 43), 'wrapped', generation, null, null);
    raise exception 'changed enrollment fingerprint approved';
  exception when sqlstate '40001' then null;
  end;
  if not exists (select 1 from public.vault_devices where id = request_id and status = 'pending')
     or exists (select 1 from public.vault_device_wrappers w where w.device_id = request_id) then
    raise exception 'failed approval changed request state';
  end if;
  response := public.approve_device(request_id, member_id, public_fingerprint, fingerprint, 'wrapped', generation, null, null);
  if response->>'status' <> 'approved' then raise exception 'approval did not succeed'; end if;
  if (select count(*) from public.vault_device_wrappers w where w.device_id = (response->>'device_id')::uuid) <> 1 then
    raise exception 'approval did not store exactly one wrapper';
  end if;
  begin
    perform public.approve_device(request_id, member_id, public_fingerprint, fingerprint, 'wrapped-again', generation, null, null);
    raise exception 'approval replay succeeded';
  exception when sqlstate '40001' then null;
  end;

  perform set_config('request.jwt.claim.sub', member_id::text, true);
  if (public.complete_device(device_id, token, generation)->>'device_id')::uuid <> device_id then
    raise exception 'device completion failed';
  end if;
  select lease_expires_at into first_lease from public.vault_devices where id = device_id;
  response := public.complete_device(device_id, token, generation);
  if (response->>'lease_expires_at')::timestamptz <> first_lease then
    raise exception 'repeat completion changed lease';
  end if;
  update public.vault_devices set lease_expires_at = now() - interval '1 second' where id = device_id;
  if public.complete_device(device_id, token, generation) is not null then
    raise exception 'expired completion succeeded';
  end if;
  update public.vault_devices set lease_expires_at = now() + interval '1 day' where id = device_id;
  prepared_gen := gen_random_uuid();
  update public.vault_state set envelope_status = 'preparing', prepared_generation = prepared_gen where singleton;
  perform set_config('request.jwt.claim.sub', member_id::text, true);
  response := public.request_device(prepared_device_id, member_id, 'prepared-device', public_jwk, fingerprint, public_fingerprint, token_digest, 'remembered', protection, bundle, 'additional');
  prepared_request_id := (response->>'request_id')::uuid;
  perform set_config('request.jwt.claim.sub', admin_id::text, true);
  response := public.approve_device(prepared_request_id, member_id, public_fingerprint, fingerprint, 'prepared-wrapped', prepared_gen, null, null);
  perform set_config('request.jwt.claim.sub', member_id::text, true);
  if public.complete_device(prepared_device_id, token, prepared_gen) is null then raise exception 'prepared completion failed'; end if;
  if public.qv_authorize_device(prepared_device_id, token, prepared_gen, 'sync') is not null then raise exception 'prepared generation authorized data'; end if;
  update public.vault_state set envelope_status = 'legacy', prepared_generation = null where singleton;
  if public.complete_device(device_id, repeat('B', 43), generation) is not null then
    raise exception 'wrong token completed device';
  end if;
  if public.complete_device(device_id, token, gen_random_uuid()) is not null then
    raise exception 'wrong generation completed device';
  end if;
  update public.vault_devices set lease_expires_at = now() - interval '1 second' where id = device_id;
  if public.qv_authorize_device(device_id, token, generation, 'sync') is not null then raise exception 'expired lease authorized sync'; end if;
  if public.qv_authorize_device(device_id, token, generation, 'lease_renewal') is null then raise exception 'expired lease could not renew'; end if;
  perform set_config('request.jwt.claim.sub', other_id::text, true);
  if public.complete_device(device_id, token, generation) is not null then
    raise exception 'cross-account completed device';
  end if;
  perform set_config('request.jwt.claim.sub', member_id::text, true);
  update public.vault_devices set lease_expires_at = now() + interval '1 day' where id = device_id;
  response := public.revoke_own_device(device_id, token);
  if response->>'status' <> 'revoked' then raise exception 'device revoke did not succeed'; end if;
  if not exists (select 1 from public.vault_devices where id = device_id and status = 'revoked' and revoked_at is not null) then raise exception 'revocation row was not updated'; end if;
  if public.qv_authorize_device(device_id, token, generation, 'sync') is not null then
    raise exception 'revoked device authorized';
  end if;

  perform set_config('request.jwt.claim.sub', member_id::text, true);
  response := public.request_device('ffffffff-ffff-4fff-8fff-ffffffffffff', member_id, 'expired-device', public_jwk, fingerprint, public_fingerprint, token_digest, 'remembered', protection, bundle, 'additional');
  expired_request_id := (response->>'request_id')::uuid;
  update public.vault_devices set expires_at = now() - interval '1 second' where id = expired_request_id;
  perform set_config('request.jwt.claim.sub', admin_id::text, true);
  begin
    perform public.approve_device(expired_request_id, member_id, public_fingerprint, fingerprint, 'wrapped', generation, null, null);
    raise exception 'expired request approved';
  exception when sqlstate '40001' then null;
  end;

  -- A null approver is rejected once the vault is active, even for an admin.
  update public.vault_state set envelope_status = 'active' where singleton;
  response := public.request_device('22222222-2222-4222-8222-222222222222', member_id, 'active-null-approver', public_jwk, fingerprint, public_fingerprint, token_digest, 'remembered', protection, bundle, 'additional');
  begin
    perform public.approve_device((response->>'request_id')::uuid, member_id, public_fingerprint, fingerprint, 'wrapped', generation, null, null);
    raise exception 'active admin null approver approved';
  exception when sqlstate '42501' then null;
  end;
  if public.get_device_request((response->>'request_id')::uuid) is null then
    raise exception 'active null-approver request was not left pending';
  end if;
  update public.vault_state set envelope_status = 'legacy' where singleton;
end $$;

-- Direct quote reads remain available in legacy mode and are hidden once active.
set local role authenticated;
select set_config('request.jwt.claim.sub', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', true);
do $$
declare
  visible_count integer;
begin
  select count(*) into visible_count from public.quotes;
  if visible_count = 0 then raise exception 'legacy encrypted quote fixture was not visible'; end if;
  perform public.sync_quotes((public.get_vault_state()->>'generation')::uuid, null, '[]'::jsonb);
end $$;

reset role;
update public.vault_state set envelope_status = 'active' where singleton;
set local role authenticated;
do $$
declare
  visible_count integer;
begin
  select count(*) into visible_count from public.quotes;
  if visible_count <> 0 then raise exception 'direct quote select bypassed device authorization'; end if;
  begin
    perform count(*) from public.vault_device_wrappers;
    raise exception 'direct device wrapper select bypassed RPC boundary';
  exception when insufficient_privilege then null;
  end;
end $$;

reset role;
do $$
declare
  migration_id uuid := gen_random_uuid();
  target_generation uuid := gen_random_uuid();
  copy_row jsonb := jsonb_build_object(
    'id', 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
    'text', 'encrypted', 'author', 'ENCRYPTED', 'context', 'ENCRYPTED',
    'quote_date', '2026-09-22', 'created_at', '2026-09-22T00:00:00.000Z',
    'user_id', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    'vault_generation', (public.get_vault_state()->>'generation'));
begin
  insert into public.vault_migrations(id, source_generation, target_generation, target_verifier, source_revision, expected_quote_count, status, initiating_device_id)
  values (migration_id, (public.get_vault_state()->>'generation')::uuid, target_generation, '{"version":1}'::jsonb, 0, 1, 'prepared', '11111111-1111-4111-8111-111111111111');
  begin
    insert into public.vault_migration_quote_copies(migration_id, copy_kind, quote_id, encrypted_row, vault_generation)
    values (migration_id, 'staged', gen_random_uuid(), copy_row, (public.get_vault_state()->>'generation')::uuid);
    raise exception 'migration copy accepted mismatched quote id';
  exception when check_violation then null;
  end;
  copy_row := jsonb_set(copy_row, '{id}', to_jsonb('dddddddd-dddd-4ddd-8ddd-dddddddddddd'::text));
  copy_row := jsonb_set(copy_row, '{vault_generation}', to_jsonb(target_generation));
  begin
    insert into public.vault_migration_quote_copies(migration_id, copy_kind, quote_id, encrypted_row, vault_generation)
    values (migration_id, 'rollback', 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', copy_row, (public.get_vault_state()->>'generation')::uuid);
    raise exception 'migration copy accepted mismatched generation';
  exception when check_violation then null;
  end;
end $$;

rollback;
